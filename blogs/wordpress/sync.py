"""
Full WordPress Blog sync, used by the Celery task (and any future scheduler or
webhook). It reuses the Batch 3 importer steps; nothing here parses or plans
content itself.

    run = start_wordpress_import(user, enqueue=...)   # API: create run + queue
    execute_import_run(run)                            # Celery task body

Phases (persisted in BlogImportRun.current_step):
    fetching -> planning -> syncing_blogs -> migrating_media
    -> rewriting_links -> finalizing -> completed

Policy: additive/update only. Nothing is ever deleted or unpublished because it
disappeared from WordPress. Members-only teasers are counted as `restricted`.
"""
import logging
import time
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from blogs.models import BlogImportRun, BlogPost

from .client import WordPressBlogClient
from .importer import WordPressBlogImporter
from .media import MediaStore, SafeMediaFetcher, allowed_media_hosts
from .planner import PlanningContext
from .report import build_report
from .rewrite import blog_slug_mapping, rewrite_blog_links, rewrite_inline_media, sync_featured_image
from .types import (
    ACTION_CREATE,
    ACTION_ERROR,
    ACTION_RESTRICTED,
    ACTION_SKIP,
    ACTION_UPDATE,
    W_MEMBERS_ONLY,
)

logger = logging.getLogger(__name__)

STALE_QUEUED_AFTER = timedelta(minutes=30)
STALE_RUNNING_AFTER = timedelta(minutes=75)  # > task hard time limit (60 min)
PROGRESS_INTERVAL_SECONDS = 2.0
MAX_REPORT_ITEMS = 200


class ImportAlreadyRunning(Exception):
    def __init__(self, run):
        super().__init__("An import is already running.")
        self.run = run


class ImportNotConfigured(Exception):
    pass


# ------------------------------------------------------------------ start --
def expire_stale_runs(now=None):
    """Release the lock held by runs whose worker died (no heartbeat)."""
    now = now or timezone.now()
    stale = BlogImportRun.objects.filter(
        status=BlogImportRun.STATUS_QUEUED, updated_at__lt=now - STALE_QUEUED_AFTER
    ) | BlogImportRun.objects.filter(
        status=BlogImportRun.STATUS_RUNNING, updated_at__lt=now - STALE_RUNNING_AFTER
    )
    return stale.update(
        status=BlogImportRun.STATUS_FAILED,
        current_step="failed",
        error_message="Import stopped responding and was marked as failed.",
        finished_at=now,
    )


def start_wordpress_import(user, *, enqueue):
    """Create a queued run and enqueue it after commit. Raises ImportAlreadyRunning."""
    base_url = (getattr(settings, "WP_IMAA_BLOG_BASE_URL", "") or "").strip()
    if not base_url:
        raise ImportNotConfigured("WordPress Blog import is not configured (WP_IMAA_BLOG_BASE_URL).")
    expire_stale_runs()
    try:
        with transaction.atomic():
            run = BlogImportRun.objects.create(requested_by=user, source_url=base_url[:500])
    except IntegrityError:
        active = BlogImportRun.objects.filter(
            source=BlogImportRun.SOURCE_WORDPRESS, status__in=BlogImportRun.ACTIVE_STATUSES
        ).first()
        raise ImportAlreadyRunning(active)
    transaction.on_commit(lambda: _enqueue(run, enqueue))
    return run


def _enqueue(run, enqueue):
    try:
        task_id = enqueue(run)
    except Exception as exc:  # broker unavailable: do not leave the lock held
        logger.error("Could not queue WordPress Blog import %s: %s", run.pk, exc.__class__.__name__)
        BlogImportRun.objects.filter(pk=run.pk).update(
            status=BlogImportRun.STATUS_FAILED, current_step="failed",
            error_message="The import could not be queued. Please try again later.",
            finished_at=timezone.now(),
        )
        return
    BlogImportRun.objects.filter(pk=run.pk).update(celery_task_id=str(task_id or "")[:255])


# -------------------------------------------------------------- progress --
class Progress:
    """Batched progress writes (at most one UPDATE per interval, plus forced flushes)."""

    def __init__(self, run, interval=PROGRESS_INTERVAL_SECONDS):
        self.run = run
        self.interval = interval
        self._last = 0.0
        self.fields = {}

    def set(self, force=False, **fields):
        self.fields.update(fields)
        for name, value in fields.items():
            setattr(self.run, name, value)
        now = time.monotonic()
        if force or now - self._last >= self.interval:
            self.flush()

    def add(self, name, amount=1):
        self.set(**{name: getattr(self.run, name) + amount})

    def flush(self):
        if self.fields:
            BlogImportRun.objects.filter(pk=self.run.pk).update(updated_at=timezone.now(), **self.fields)
            self.fields = {}
        self._last = time.monotonic()


# ------------------------------------------------------------------- run --
def execute_import_run(run, *, client=None, media_store=None, storage=None, post_ids=None):
    """Run the full sync for `run`. Returns the final status. Never raises for
    per-post/per-media problems; raises WordPressBlogAPIError/ImportAborted for
    source-level failures so the task can decide about retries.

    `post_ids` limits the run to selected WordPress posts (operations/sample
    verification only; the admin API and Celery task always run everything)."""
    started = time.monotonic()
    client = client or WordPressBlogClient.from_settings()
    hosts = allowed_media_hosts(client.base_url)
    store = media_store or MediaStore(SafeMediaFetcher(hosts), storage=storage)
    progress = Progress(run)
    progress.set(force=True, status=BlogImportRun.STATUS_RUNNING, current_step="fetching",
                 started_at=run.started_at or timezone.now(), error_message="")

    importer = WordPressBlogImporter(client, commit=True, allow_bulk=True)
    category = importer.validate_category()
    raw_posts, fetch_errors, known_slugs = importer.collect(post_ids=post_ids)

    # Phase A: discovery (parse everything, no writes yet).
    progress.set(force=True, current_step="planning", total_discovered=len(raw_posts) + len(fetch_errors))
    parsed, entries = [], list(fetch_errors)
    for raw in raw_posts:
        entry = importer.parse(raw, known_slugs)
        if entry["error"]:
            entries.append(entry)
        else:
            parsed.append(entry["post"])
    restricted_posts = [p for p in parsed if any(w.code == W_MEMBERS_ONLY for w in p.all_warnings())]
    progress.set(force=True, total_importable=len(parsed) - len(restricted_posts),
                 failed_count=len(entries))

    # Phase B: Blog record sync (per-post transactions inside the importer).
    progress.set(force=True, current_step="syncing_blogs")
    context = PlanningContext()
    synced = []
    for post in parsed:
        entry = importer.plan_and_apply(post, context)
        entries.append(entry)
        action = entry["plan"].action
        counter = {
            ACTION_CREATE: "created_count", ACTION_UPDATE: "updated_count", ACTION_SKIP: "skipped_count",
            ACTION_RESTRICTED: "restricted_count", ACTION_ERROR: "failed_count",
        }[action]
        progress.add(counter)
        if action != ACTION_RESTRICTED:
            progress.add("processed_count")
        if action in (ACTION_CREATE, ACTION_UPDATE, ACTION_SKIP):
            synced.append(post)
    progress.flush()

    # Phase C: media (featured + inline) for every synced post, idempotent via the ledger.
    media_total = sum(len(p.content.inline_images) + int(p.featured_media is not None) for p in synced)
    progress.set(force=True, current_step="migrating_media", media_found_count=media_total)
    blogs = {b.wp_post_id: b for b in BlogPost.objects.filter(wp_post_id__in=[p.wp_post_id for p in synced])}
    media_summary = {"featured": {}, "inline": {}}
    media_failures = []
    outcome_counter = {
        "migrated": "media_migrated_count", "reused": "media_reused_count", "unchanged": "media_reused_count",
        "already_migrated": "media_reused_count", "external": "media_skipped_count",
        "ecp_owned": "media_skipped_count", "ecp_removed": "media_skipped_count", "failed": "media_failed_count",
    }

    def count_media(outcome):
        fields = {"media_processed_count": min(run.media_processed_count + 1, max(media_total, run.media_processed_count + 1))}
        if outcome in outcome_counter:
            field = outcome_counter[outcome]
            fields[field] = getattr(run, field) + 1
        progress.set(**fields)

    for post in synced:
        blog = blogs.get(post.wp_post_id)
        if blog is None:
            continue
        updates = {}
        outcome, featured_updates, failure = sync_featured_image(blog, post.featured_media, store, hosts=hosts)
        media_summary["featured"][outcome] = media_summary["featured"].get(outcome, 0) + 1
        if outcome != "none":
            count_media(outcome)
        updates.update(featured_updates)
        if failure:
            media_failures.append({"wp_post_id": post.wp_post_id, "kind": "featured", **failure})
        html, stats, failures = rewrite_inline_media(
            blog.content_html, store, base_url=client.base_url, hosts=hosts, on_image=count_media
        )
        for key, value in stats.items():
            media_summary["inline"][key] = media_summary["inline"].get(key, 0) + value
        media_failures.extend({"wp_post_id": post.wp_post_id, "kind": "inline", **f} for f in failures)
        if html != blog.content_html:
            updates["content_html"] = html
        if updates:
            BlogPost.objects.filter(pk=blog.pk).update(updated_at=timezone.now(), **updates)
            for field, value in updates.items():
                setattr(blog, field, value)
    progress.set(force=True, media_found_count=max(media_total, run.media_processed_count),
                 media_processed_count=max(media_total, run.media_processed_count))

    # Phase D: Blog-to-Blog links, once every target exists.
    progress.set(force=True, current_step="rewriting_links")
    imported = BlogPost.objects.filter(wp_post_id__isnull=False).values_list("wp_source_url", "slug")
    mapping = blog_slug_mapping(imported, base_url=client.base_url, known_blog_slugs=known_slugs)
    restricted_slugs = {p.slug for p in restricted_posts}
    link_summary = {}
    for post in synced:
        blog = blogs.get(post.wp_post_id)
        if blog is None:
            continue
        html, stats = rewrite_blog_links(
            blog.content_html, mapping, base_url=client.base_url,
            restricted_slugs=restricted_slugs, known_blog_slugs=known_slugs,
        )
        for key, value in stats.items():
            link_summary[key] = link_summary.get(key, 0) + value
        if html != blog.content_html:
            BlogPost.objects.filter(pk=blog.pk).update(content_html=html, updated_at=timezone.now())
            blog.content_html = html
        progress.set(links_rewritten_count=run.links_rewritten_count + stats.get("rewritten", 0))
    progress.flush()

    # Finalize.
    progress.set(force=True, current_step="finalizing")
    report = build_report(
        entries, source=client.base_url, category=category, stats=client.stats, mode="commit",
        selected_post_ids=[], duration=time.monotonic() - started,
    )
    status = (
        BlogImportRun.STATUS_PARTIAL if (run.failed_count or run.media_failed_count)
        else BlogImportRun.STATUS_SUCCEEDED
    )
    progress.set(
        force=True,
        status=status,
        current_step="completed",
        finished_at=timezone.now(),
        report_json=compact_report(report, media_summary, media_failures, link_summary),
    )
    return status


def compact_report(report, media_summary, media_failures, link_summary):
    """Admin-facing JSON: counts and IDs only (no article HTML, no stack traces)."""
    def ids(action):
        return [p["wp_post_id"] for p in report["posts"] if p["action"] == action][:MAX_REPORT_ITEMS]

    return {
        "source": report["source"],
        "category": report["category"],
        "fetch": report["fetch"],
        "formats": report["formats"],
        "plan": report["plan"],
        "created_post_ids": ids(ACTION_CREATE),
        "updated_post_ids": ids(ACTION_UPDATE),
        "skipped_post_ids": ids(ACTION_SKIP),
        "restricted_post_ids": report["restricted_post_ids"][:MAX_REPORT_ITEMS],
        "errors": [
            {"wp_post_id": e["wp_post_id"], "message": "; ".join(e["reasons"])[:300]}
            for e in report["errors"][:MAX_REPORT_ITEMS]
        ],
        "authors": {k: v for k, v in report["authors"].items() if k != "unmapped_ids"},
        "warnings": report["warnings"],
        "media": {"featured": media_summary["featured"], "inline": media_summary["inline"]},
        "media_failures": media_failures[:MAX_REPORT_ITEMS],
        "links": link_summary,
        "duration_seconds": report["duration_seconds"],
    }


def mark_failed(run, message, *, report=None):
    fields = {
        "status": BlogImportRun.STATUS_FAILED,
        "current_step": "failed",
        "error_message": message[:500],
        "finished_at": timezone.now(),
        "updated_at": timezone.now(),
    }
    if report is not None:
        fields["report_json"] = report
    BlogImportRun.objects.filter(pk=run.pk).update(**fields)
