"""
Celery tasks for the Blog app.

`blogs.run_wordpress_blog_import` only orchestrates: all fetching, parsing,
planning, media and link work lives in blogs.wordpress (shared with the
management command). The task receives nothing but the BlogImportRun id.
"""
import logging

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone

from blogs.models import BlogImportRun
from blogs.wordpress.client import WordPressBlogAPIError
from blogs.wordpress.importer import ImportAborted
from blogs.wordpress.sync import execute_import_run, mark_failed

logger = logging.getLogger(__name__)

# A full import migrates hundreds of images; the global 5 minute limit is too
# short for this one task, so it gets its own limit (the global stays as is).
IMPORT_SOFT_TIME_LIMIT = 55 * 60
IMPORT_TIME_LIMIT = 60 * 60
SOURCE_RETRY_DELAY = 60


@shared_task(
    bind=True,
    name="blogs.run_wordpress_blog_import",
    max_retries=2,
    soft_time_limit=IMPORT_SOFT_TIME_LIMIT,
    time_limit=IMPORT_TIME_LIMIT,
)
def run_wordpress_blog_import(self, run_id):
    run = BlogImportRun.objects.filter(pk=run_id).first()
    if run is None:
        logger.warning("WordPress Blog import run %s no longer exists", run_id)
        return None
    if run.status in BlogImportRun.TERMINAL_STATUSES:
        return run.status  # duplicate delivery: nothing to do

    try:
        return execute_import_run(run)
    except WordPressBlogAPIError as exc:
        # WordPress itself is unavailable. Everything already written is
        # idempotent, so a retry re-plans safely and skips finished work.
        if self.request.retries < self.max_retries:
            BlogImportRun.objects.filter(pk=run.pk).update(
                current_step="waiting_retry", error_message=f"WordPress unavailable, retrying: {exc}"[:500]
            )
            raise self.retry(exc=exc, countdown=SOURCE_RETRY_DELAY)
        mark_failed(run, f"WordPress was unavailable after retries: {exc}")
        return BlogImportRun.STATUS_FAILED
    except ImportAborted as exc:
        mark_failed(run, str(exc))
        return BlogImportRun.STATUS_FAILED
    except SoftTimeLimitExceeded:
        mark_failed(run, "The import took too long and was stopped. Completed posts were kept; run it again to continue.")
        return BlogImportRun.STATUS_FAILED
    except Exception as exc:
        logger.exception("WordPress Blog import %s failed", run.pk)
        mark_failed(run, f"Unexpected error ({exc.__class__.__name__}). Completed posts were kept.")
        return BlogImportRun.STATUS_FAILED
    finally:
        # Never leave the lock held: any run still active here has failed.
        BlogImportRun.objects.filter(pk=run.pk, status__in=BlogImportRun.ACTIVE_STATUSES).exclude(
            current_step="waiting_retry"
        ).update(status=BlogImportRun.STATUS_FAILED, current_step="failed",
                 error_message="The import stopped unexpectedly.", finished_at=timezone.now())
