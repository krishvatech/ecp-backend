"""Recovery helpers for durable newsletter campaign send events.

Only states that represent dispatch loss or a worker crash before the provider
boundary are automatically recovered here. FAILED events are intentionally not
selected: they may represent a permanent Mautic preparation rejection and can
instead be safely redispatched by an explicit Send Now request.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from .models import NewsletterCampaignSendEvent
from .tasks import process_newsletter_campaign_send_event


logger = logging.getLogger(__name__)


def due_campaign_send_event_ids(batch_size: int = 100) -> list[int]:
    """Return only safely auto-recoverable campaign send events in FIFO order."""
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
        Q(
            status=NewsletterCampaignSendEvent.Status.PENDING,
            provider_send_started_at__isnull=True,
        )
        | Q(
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            provider_send_started_at__isnull=True,
            processing_started_at__isnull=False,
            processing_started_at__lte=stale_before,
        )
    )

    return list(
        NewsletterCampaignSendEvent.objects.filter(due)
        .order_by("created_at")
        .values_list("pk", flat=True)[: max(1, int(batch_size))]
    )


def _dispatch_campaign_send_event_ids(
    event_ids: list[int],
) -> tuple[int, int]:
    dispatched = 0
    failed = 0

    for event_id in event_ids:
        try:
            process_newsletter_campaign_send_event.delay(event_id)
            dispatched += 1
        except Exception:
            failed += 1
            logger.exception(
                "Could not dispatch newsletter campaign send recovery "
                "event_id=%s; durable state retained",
                event_id,
            )

    return dispatched, failed


def dispatch_due_campaign_send_events(batch_size: int = 100) -> dict:
    """Best-effort dispatch of safe pre-provider campaign send recovery work."""
    if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
        return {
            "disabled": True,
            "selected": 0,
            "dispatched": 0,
            "failed": 0,
        }

    event_ids = due_campaign_send_event_ids(batch_size=batch_size)
    dispatched, failed = _dispatch_campaign_send_event_ids(event_ids)
    return {
        "disabled": False,
        "selected": len(event_ids),
        "dispatched": dispatched,
        "failed": failed,
    }
