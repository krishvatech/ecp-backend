"""Recovery helpers for durable Newsletter -> Mautic sync events."""

import logging
from datetime import timedelta

from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from .models import NewsletterSyncEvent
from .tasks import process_newsletter_sync_event


logger = logging.getLogger(__name__)


def _dispatch_event_ids(event_ids: list[int]) -> tuple[int, int]:
    dispatched = 0
    failed = 0

    for event_id in event_ids:
        try:
            process_newsletter_sync_event.delay(event_id)
            dispatched += 1
        except Exception:
            failed += 1
            logger.exception(
                "Could not dispatch newsletter recovery event_id=%s; "
                "durable state retained",
                event_id,
            )

    return dispatched, failed


def due_sync_event_ids(batch_size: int = 100) -> list[int]:
    """Return pending, due-retry, and stale-processing events in FIFO order."""
    now = timezone.now()
    stale_before = now - timedelta(
        seconds=max(
            1,
            int(
                getattr(
                    settings,
                    "MAUTIC_SYNC_PROCESSING_TIMEOUT_SECONDS",
                    600,
                )
            ),
        )
    )

    due = (
        Q(status=NewsletterSyncEvent.Status.PENDING)
        | Q(
            status=NewsletterSyncEvent.Status.RETRYING,
            next_retry_at__isnull=True,
        )
        | Q(
            status=NewsletterSyncEvent.Status.RETRYING,
            next_retry_at__lte=now,
        )
        | Q(
            status=NewsletterSyncEvent.Status.PROCESSING,
            processing_started_at__lte=stale_before,
        )
    )

    return list(
        NewsletterSyncEvent.objects.filter(due)
        .order_by("created_at")
        .values_list("pk", flat=True)[: max(1, int(batch_size))]
    )


def dispatch_due_sync_events(batch_size: int = 100) -> dict:
    """Best-effort dispatch of recoverable durable newsletter sync events."""
    if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
        return {
            "disabled": True,
            "selected": 0,
            "dispatched": 0,
            "failed": 0,
        }

    event_ids = due_sync_event_ids(batch_size=batch_size)
    dispatched, failed = _dispatch_event_ids(event_ids)
    return {
        "disabled": False,
        "selected": len(event_ids),
        "dispatched": dispatched,
        "failed": failed,
    }
