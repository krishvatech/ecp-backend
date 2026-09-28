"""
Runs the WordPress Blog import pipeline.

    importer = WordPressBlogImporter(client, commit=False)
    report = importer.run()                      # dry run of the whole category
    report = importer.run(post_ids=[157765])     # dry run of one post

Writes happen only when `commit=True` AND explicit post IDs are given (sample
imports), or when the caller is the controlled bulk workflow (`allow_bulk=True`,
used only by blogs.wordpress.sync / the Celery task). Each committed post is
applied in its own transaction.

The same steps (collect -> parse -> plan_and_apply) power the management
command, the Celery task and the admin-triggered import.

Source modes:
  * public (default): published posts as anonymous visitors see them.
  * editorial (`editorial=True`, authenticated client): every supported
    WordPress status. Discovery uses the authenticated context=edit listing
    (status, membership flag). Article content is always read from the
    collection endpoint in view context:
      - public published posts: anonymously, exactly as in public mode, so
        ECP never publishes more than WordPress shows to anonymous readers;
      - drafts/pending/future/private and members-only posts: authenticated,
        which returns the full article.
    (context=edit `content.rendered` is not used: WordPress renders the wrong
    Elementor document for some posts in that context.)
"""
import logging
import time

from django.conf import settings
from django.db import transaction

from blogs.models import BlogCategory, BlogPost, BlogTag

from .client import EMBED_PER_PAGE, WordPressBlogAPIError, WordPressBlogAuthError
from .normalizer import is_members_only_teaser
from .parser import WordPressPostParseError, parse_wordpress_post
from .planner import PlanningContext, plan_import
from .report import build_report
from .types import (
    ACTION_CREATE,
    ACTION_ERROR,
    ACTION_RESTRICTED,
    ACTION_UPDATE,
    RESTRICTION_CLASS_LIST,
    RESTRICTION_PUBLIC_TEASER,
    SUPPORTED_WP_STATUSES,
    ImportPlan,
)

# WooCommerce Memberships adds this post class to restricted content (the
# class is the same whoever asks; access-granted/-restricted vary per viewer).
MEMBERSHIP_POST_CLASS = "membership-content"

logger = logging.getLogger(__name__)

MAX_COMMIT_POSTS = 10


class ImportAborted(Exception):
    """The run cannot proceed (bad configuration, category mismatch, unsafe request)."""


class WritesDisabledError(RuntimeError):
    """Raised if anything tries to write during a dry run."""


class WordPressBlogImporter:
    def __init__(self, client, *, commit=False, category_id=None, expected_category_slug=None, allow_bulk=False,
                 editorial=False):
        self.client = client
        self.commit = commit
        self.allow_bulk = allow_bulk
        self.editorial = editorial
        self._editorial = {}  # wp_post_id -> editorial facts passed to the parser
        self.category_id = int(category_id or getattr(settings, "WP_IMAA_BLOG_CATEGORY_ID", 58))
        self.expected_category_slug = (
            expected_category_slug if expected_category_slug is not None
            else getattr(settings, "WP_IMAA_BLOG_CATEGORY_SLUG", "blog")
        )

    # ------------------------------------------------------------------ run --
    def run(self, *, post_ids=None, limit=None, allow_category_mismatch=False, on_entry=None):
        started = time.monotonic()
        post_ids = [int(i) for i in dict.fromkeys(post_ids or [])]
        self.check_commit_scope(post_ids)
        category = self.validate_category(allow_category_mismatch)
        logger.info("WordPress Blog import started (commit=%s, editorial=%s, posts=%s)",
                    self.commit, self.editorial, post_ids or "all")

        raw_posts, fetch_errors, known_slugs = self.collect(post_ids=post_ids, limit=limit)
        context = PlanningContext()
        entries = list(fetch_errors)
        for raw in raw_posts:
            entry = self.parse(raw, known_slugs)
            if entry.get("post") is not None and entry["error"] is None:
                entry = self.plan_and_apply(entry["post"], context)
            entries.append(entry)
            if on_entry:
                on_entry(entry)

        report = build_report(
            entries,
            source=self.client.base_url,
            category=category,
            stats=self.client.stats,
            mode="commit" if self.commit else "dry-run",
            selected_post_ids=post_ids,
            duration=time.monotonic() - started,
        )
        logger.info("WordPress Blog import finished: %s", dict(report["plan"]))
        return report

    # ------------------------------------------------------- reusable steps --
    def check_commit_scope(self, post_ids):
        if self.commit and not post_ids and not self.allow_bulk:
            raise ImportAborted("Bulk commit is disabled here: pass explicit --post-id values.")
        if self.commit and not self.allow_bulk and len(post_ids) > MAX_COMMIT_POSTS:
            raise ImportAborted(f"At most {MAX_COMMIT_POSTS} posts can be committed per sample run.")

    def validate_category(self, allow_mismatch=False):
        return self._validate_category(allow_mismatch)

    def collect(self, *, post_ids=None, limit=None):
        """Fetch raw posts. Returns (raw_posts, fetch_error_entries, known_blog_slugs)."""
        if self.editorial:
            return self._collect_editorial(post_ids=post_ids, limit=limit)
        # Cheap listing first (ids + slugs): REST total, known Blog slugs for
        # link classification.
        listing = [
            p for p in self.client.iter_posts(self.category_id, embed=False, fields=["id", "slug"])
            if isinstance(p, dict) and isinstance(p.get("id"), int)
        ]
        known_slugs = {p.get("slug") for p in listing}
        if post_ids:
            ids = post_ids
        else:
            ids = [p["id"] for p in listing]
            if limit:
                ids = ids[: int(limit)]
        raw_posts, fetch_errors = self._fetch_included(ids, public=True)
        return raw_posts, fetch_errors, known_slugs

    def _collect_editorial(self, *, post_ids=None, limit=None):
        """Authenticated all-status collection (see module docstring)."""
        manifest = self.client.editorial_manifest(self.category_id, SUPPORTED_WP_STATUSES)
        # Link classification only knows published Blog URLs (as in public mode).
        known_slugs = {p.get("slug") for p in manifest if p.get("status") == "publish"}
        fetch_errors = []
        if post_ids:
            wanted = set(post_ids)
            selected = [p for p in manifest if p["id"] in wanted]
            found = {p["id"] for p in selected}
            fetch_errors = [
                self._error_entry(post_id, f"post is not in WordPress category {self.category_id} "
                                           "or its WordPress status is not imported")
                for post_id in post_ids if post_id not in found
            ]
        else:
            selected = manifest[: int(limit)] if limit else manifest

        self._editorial = {}
        for item in selected:
            restricted = MEMBERSHIP_POST_CLASS in (item.get("class_list") or [])
            self._editorial[item["id"]] = {
                "status": item["status"],
                "restricted": restricted,
                "restriction_source": RESTRICTION_CLASS_LIST if restricted else "",
                "generated_slug": item.get("generated_slug") or "",
            }
        public_ids = [i for i, facts in self._editorial.items() if facts["status"] == "publish" and not facts["restricted"]]
        public_posts, errors = self._fetch_included(public_ids, public=True)
        fetch_errors += errors
        # Fallback detection: WordPress served a members-only teaser to anonymous
        # readers although the post class did not say so.
        kept = []
        for raw in public_posts:
            if is_members_only_teaser(((raw.get("content") or {}).get("rendered")) or ""):
                self._editorial[raw["id"]].update(restricted=True, restriction_source=RESTRICTION_PUBLIC_TEASER)
            else:
                kept.append(raw)
        editorial_ids = [i for i, facts in self._editorial.items() if facts["restricted"] or facts["status"] != "publish"]
        editorial_posts, errors = self._fetch_included(editorial_ids, public=False, status=SUPPORTED_WP_STATUSES)
        fetch_errors += errors
        raw_posts = sorted(kept + editorial_posts, key=lambda raw: raw["id"])
        return raw_posts, fetch_errors, known_slugs

    def parse(self, raw, known_slugs):
        """Raw payload -> {'post': NormalizedWordPressBlog} or an error entry."""
        raw_id = raw.get("id") if isinstance(raw, dict) else None
        try:
            post = parse_wordpress_post(
                raw, site_url=self.client.base_url, client=self.client, known_blog_slugs=known_slugs,
                editorial=self._editorial.get(raw_id),
            )
        except WordPressPostParseError as exc:
            logger.warning("WordPress post %s could not be parsed: %s", raw_id, exc)
            return self._error_entry(raw_id, f"parse error: {exc}")
        except Exception as exc:  # isolate one bad post
            logger.exception("Unexpected error parsing WordPress post %s", raw_id)
            return self._error_entry(raw_id, f"unexpected parse error: {exc.__class__.__name__}")
        return {"plan": None, "post": post, "applied": None, "error": None}

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

    def _fetch_included(self, ids, *, public, status="publish"):
        """Full posts through the collection endpoint (`include=`, EMBED_PER_PAGE
        per request). Every path uses this same request shape: WordPress renders
        some fields by endpoint (an auto-generated excerpt is 55 words on the
        single-post endpoint but shorter on the list endpoint), so mixing
        endpoints would make re-imports flip between CREATE/UPDATE.

        A chunk that keeps failing is retried post by post (still `include=`),
        so one slow/broken post cannot sink the run."""
        posts, errors = [], []
        not_found = (f"post is not in WordPress category {self.category_id} or is not published"
                     if public else f"post is not in WordPress category {self.category_id} or its status is not imported")
        for index in range(0, len(ids), EMBED_PER_PAGE):
            chunk = ids[index : index + EMBED_PER_PAGE]
            try:
                page = self.client.list_posts(self.category_id, page=1, per_page=EMBED_PER_PAGE, embed=True,
                                              include=chunk, status=status, public=public)
                self.client.stats.content_pages_fetched += 1
                by_id = {p.get("id"): p for p in page.posts if isinstance(p, dict)}
            except WordPressBlogAuthError:
                raise
            except WordPressBlogAPIError as exc:
                logger.warning("Content request for %d posts failed (%s); fetching them one by one", len(chunk), exc)
                by_id = None
            for post_id in chunk:
                if by_id is not None:
                    if post_id in by_id:
                        posts.append(by_id[post_id])
                    else:
                        errors.append(self._error_entry(post_id, not_found))
                    continue
                self.client.stats.single_post_fallbacks += 1
                try:
                    single = self.client.list_posts(self.category_id, page=1, per_page=1, embed=True,
                                                    include=[post_id], status=status, public=public)
                except WordPressBlogAuthError:
                    raise
                except WordPressBlogAPIError as exc:
                    errors.append(self._error_entry(post_id, f"fetch failed: {exc}"))
                    continue
                match = [p for p in single.posts if isinstance(p, dict) and p.get("id") == post_id]
                if match:
                    posts.append(match[0])
                else:
                    errors.append(self._error_entry(post_id, not_found))
        return posts, errors

    @staticmethod
    def _error_entry(post_id, message, post=None):
        plan = ImportPlan(wp_post_id=post_id or 0, action=ACTION_ERROR, reasons=[message])
        return {"plan": plan, "post": post, "applied": None, "error": message}

    def plan_and_apply(self, post, context):
        """Plan one parsed post and, when committing, apply it atomically."""
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
        elif plan.action == ACTION_RESTRICTED:
            logger.info("WordPress post %s is members-only and only a teaser is available; not imported",
                        post.wp_post_id)
        if self.commit and plan.action in (ACTION_CREATE, ACTION_UPDATE):
            try:
                blog = apply_plan(plan, commit=True)
                entry["applied"] = {"blog_post_id": blog.pk, "action": plan.action}
            except Exception as exc:
                logger.error("WordPress post %s import failed and was rolled back: %s", post.wp_post_id, exc)
                entry["error"] = f"import failed and was rolled back: {exc.__class__.__name__}"
                entry["plan"].action = ACTION_ERROR
                entry["plan"].reasons.append(f"import failed and was rolled back: {exc.__class__.__name__}")
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
            blog = BlogPost(status=plan.ecp_status, wp_status_managed=plan.status_managed, **plan.values)
        else:
            blog = BlogPost.objects.select_for_update().get(pk=plan.existing_post_id, wp_post_id=plan.wp_post_id)
            for field, value in plan.values.items():
                setattr(blog, field, value)
            blog.status = plan.ecp_status
            blog.wp_status_managed = plan.status_managed
        blog.full_clean(exclude=["featured_image"])
        blog.save()
        blog.categories.set(categories)
        blog.tags.set(tags)
    return blog
