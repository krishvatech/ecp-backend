"""
Runs the WordPress Blog import pipeline.

    importer = WordPressBlogImporter(client, commit=False)
    report = importer.run()                      # dry run of the whole category
    report = importer.run(post_ids=[157765])     # dry run of one post

Writes happen only when `commit=True` AND explicit post IDs are given (Batch 3
sample imports). Each committed post is applied in its own transaction.
"""
import logging
import time

from django.conf import settings
from django.db import transaction

from blogs.models import BlogCategory, BlogPost, BlogTag

from .client import EMBED_PER_PAGE, WordPressBlogAPIError
from .parser import WordPressPostParseError, parse_wordpress_post
from .planner import PlanningContext, plan_import
from .report import build_report
from .types import ACTION_CREATE, ACTION_ERROR, ACTION_UPDATE, ImportPlan

logger = logging.getLogger(__name__)

MAX_COMMIT_POSTS = 10


class ImportAborted(Exception):
    """The run cannot proceed (bad configuration, category mismatch, unsafe request)."""


class WritesDisabledError(RuntimeError):
    """Raised if anything tries to write during a dry run."""


class WordPressBlogImporter:
    def __init__(self, client, *, commit=False, category_id=None, expected_category_slug=None):
        self.client = client
        self.commit = commit
        self.category_id = int(category_id or getattr(settings, "WP_IMAA_BLOG_CATEGORY_ID", 58))
        self.expected_category_slug = (
            expected_category_slug if expected_category_slug is not None
            else getattr(settings, "WP_IMAA_BLOG_CATEGORY_SLUG", "blog")
        )

    # ------------------------------------------------------------------ run --
    def run(self, *, post_ids=None, limit=None, allow_category_mismatch=False):
        started = time.monotonic()
        post_ids = [int(i) for i in dict.fromkeys(post_ids or [])]
        if self.commit and not post_ids:
            raise ImportAborted("Bulk commit is disabled in Batch 3: pass explicit --post-id values.")
        if self.commit and len(post_ids) > MAX_COMMIT_POSTS:
            raise ImportAborted(f"At most {MAX_COMMIT_POSTS} posts can be committed per run in Batch 3.")

        category = self._validate_category(allow_category_mismatch)
        logger.info("WordPress Blog import started (commit=%s, posts=%s)", self.commit, post_ids or "all")

        # Cheap listing first (ids + slugs): REST total, known Blog slugs for
        # link classification, and the post order for content paging.
        listing = [
            p for p in self.client.iter_posts(self.category_id, embed=False, fields=["id", "slug"])
            if isinstance(p, dict) and isinstance(p.get("id"), int)
        ]
        known_slugs = {p.get("slug") for p in listing}
        if post_ids:
            raw_posts, fetch_errors = self._fetch_selected(post_ids)
        else:
            ids = [p["id"] for p in listing]
            if limit:
                ids = ids[: int(limit)]
            raw_posts, fetch_errors = self._fetch_all(ids)

        context = PlanningContext()
        entries = list(fetch_errors)
        for raw in raw_posts:
            entries.append(self._process(raw, context, known_slugs))

        report = build_report(
            entries,
            source=self.client.base_url,
            category=category,
            stats=self.client.stats,
            mode="commit" if self.commit else "dry-run",
            selected_post_ids=post_ids,
            duration=time.monotonic() - started,
        )
        logger.info(
            "WordPress Blog import finished: %s",
            {k: v for k, v in report["plan"].items()},
        )
        return report

    # -------------------------------------------------------------- helpers --
    def _validate_category(self, allow_mismatch):
        category = self.client.get_category(self.category_id)
        info = {
            "id": category.get("id"),
            "name": category.get("name", ""),
            "slug": category.get("slug", ""),
            "count": category.get("count"),
            "taxonomy": category.get("taxonomy", "category"),
        }
        expected = (self.expected_category_slug or "").lower()
        if info["taxonomy"] != "category" or (expected and info["slug"].lower() != expected):
            message = (
                f"WordPress category {self.category_id} is '{info['name']}' (slug '{info['slug']}'), "
                f"expected slug '{self.expected_category_slug}'. Refusing to import other content."
            )
            if not allow_mismatch:
                raise ImportAborted(message)
            logger.warning(message)
        return info

    def _fetch_all(self, ids):
        """Full posts in pages of EMBED_PER_PAGE. A page that keeps failing is
        re-fetched post by post, so one slow/broken post cannot sink the run."""
        posts, errors = [], []
        for index in range(0, len(ids), EMBED_PER_PAGE):
            chunk = ids[index : index + EMBED_PER_PAGE]
            page_no = index // EMBED_PER_PAGE + 1
            try:
                page = self.client.list_posts(self.category_id, page=page_no, per_page=EMBED_PER_PAGE, embed=True)
                self.client.stats.content_pages_fetched += 1
                by_id = {p.get("id"): p for p in page.posts if isinstance(p, dict)}
            except WordPressBlogAPIError as exc:
                logger.warning("Content page %s failed (%s); fetching its posts one by one", page_no, exc)
                by_id = {}
            for post_id in chunk:
                if post_id in by_id:
                    posts.append(by_id[post_id])
                    continue
                self.client.stats.single_post_fallbacks += 1
                try:
                    posts.append(self.client.get_post(post_id, embed=True))
                except WordPressBlogAPIError as exc:
                    errors.append(self._error_entry(post_id, f"fetch failed: {exc}"))
        return posts, errors

    def _fetch_selected(self, post_ids):
        posts, errors = [], []
        for post_id in post_ids:
            try:
                post = self.client.get_post(post_id, embed=True)
            except WordPressBlogAPIError as exc:
                errors.append(self._error_entry(post_id, str(exc)))
                continue
            categories = post.get("categories") or []
            if self.category_id not in categories:
                errors.append(self._error_entry(post_id, f"post is not in WordPress category {self.category_id}"))
                continue
            posts.append(post)
        return posts, errors

    @staticmethod
    def _error_entry(post_id, message, post=None):
        plan = ImportPlan(wp_post_id=post_id or 0, action=ACTION_ERROR, reasons=[message])
        return {"plan": plan, "post": post, "applied": None, "error": message}

    def _process(self, raw, context, known_slugs):
        raw_id = raw.get("id") if isinstance(raw, dict) else None
        try:
            post = parse_wordpress_post(
                raw, site_url=self.client.base_url, client=self.client, known_blog_slugs=known_slugs
            )
        except WordPressPostParseError as exc:
            logger.warning("WordPress post %s could not be parsed: %s", raw_id, exc)
            return self._error_entry(raw_id, f"parse error: {exc}")
        except Exception as exc:  # isolate one bad post
            logger.exception("Unexpected error parsing WordPress post %s", raw_id)
            return self._error_entry(raw_id, f"unexpected parse error: {exc.__class__.__name__}")

        try:
            plan = plan_import(post, context)
        except Exception as exc:
            logger.exception("Unexpected error planning WordPress post %s", post.wp_post_id)
            return self._error_entry(post.wp_post_id, f"unexpected planning error: {exc.__class__.__name__}", post)

        for warning in plan.warnings:
            logger.debug("WordPress post %s warning: %s %s", post.wp_post_id, warning.code, warning.detail)
        entry = {"plan": plan, "post": post, "applied": None, "error": None}
        if plan.action == ACTION_ERROR:
            logger.warning("WordPress post %s cannot be imported: %s", post.wp_post_id, "; ".join(plan.reasons))
        if self.commit and plan.action in (ACTION_CREATE, ACTION_UPDATE):
            try:
                blog = apply_plan(plan, commit=True)
                entry["applied"] = {"blog_post_id": blog.pk, "action": plan.action}
            except Exception as exc:
                logger.error("WordPress post %s import failed and was rolled back: %s", post.wp_post_id, exc)
                entry["error"] = f"import failed and was rolled back: {exc}"
                entry["plan"].action = ACTION_ERROR
                entry["plan"].reasons.append(str(exc))
        return entry


def _get_or_create_term(model, term):
    existing = model.objects.filter(slug__iexact=term["slug"]).first() or model.objects.filter(
        name__iexact=term["name"]
    ).first()
    if existing:
        return existing
    return model.objects.create(name=term["name"], slug=term["slug"] or "")


def apply_plan(plan, *, commit):
    """Write one planned post atomically. Refuses to run unless commit=True."""
    if not commit:
        raise WritesDisabledError("apply_plan called during a dry run")
    if plan.action not in (ACTION_CREATE, ACTION_UPDATE):
        raise ValueError(f"cannot apply a {plan.action} plan")

    with transaction.atomic():
        categories = [_get_or_create_term(BlogCategory, term) for term in plan.categories]
        tags = [_get_or_create_term(BlogTag, term) for term in plan.tags]
        if plan.action == ACTION_CREATE:
            if BlogPost.objects.filter(wp_post_id=plan.wp_post_id).exists():
                raise ValueError(f"wp_post_id {plan.wp_post_id} already exists; re-plan before importing")
            blog = BlogPost(status=BlogPost.STATUS_PUBLISHED, **plan.values)
        else:
            blog = BlogPost.objects.select_for_update().get(pk=plan.existing_post_id, wp_post_id=plan.wp_post_id)
            for field, value in plan.values.items():
                setattr(blog, field, value)
        blog.full_clean(exclude=["featured_image"])
        blog.save()
        blog.categories.set(categories)
        blog.tags.set(tags)
    return blog
