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
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .campaign_send_events import (
    create_scheduled_campaign_send_event,
    dispatch_campaign_send_event_safely,
)
from .models import NewsletterCampaign, NewsletterCampaignSendEvent
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
        .exclude(campaign__status=NewsletterCampaign.Status.CANCELLED)
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


def due_scheduled_campaign_ids(batch_size: int = 100) -> list[int]:
    """Return due scheduled campaigns in stable FIFO order."""
    now = timezone.now()
    return list(
        NewsletterCampaign.objects.filter(
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at__isnull=False,
            scheduled_at__lte=now,
        )
        .order_by("scheduled_at", "created_at", "pk")
        .values_list("pk", flat=True)[: max(1, int(batch_size))]
    )


def dispatch_due_scheduled_campaigns(batch_size: int = 100) -> dict:
    """Create and dispatch durable events for due scheduled campaigns."""
    if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
        return {
            "disabled": True,
            "selected": 0,
            "created": 0,
            "dispatched": 0,
            "failed": 0,
        }

    selected = due_scheduled_campaign_ids(batch_size=batch_size)
    created = 0
    dispatched = 0
    failed = 0

    for campaign_id in selected:
        event = None
        with transaction.atomic():
            campaign = (
                NewsletterCampaign.objects.select_for_update()
                .filter(
                    pk=campaign_id,
                    status=NewsletterCampaign.Status.SCHEDULED,
                    scheduled_at__isnull=False,
                    scheduled_at__lte=timezone.now(),
                )
                .first()
            )
            if campaign is None:
                continue

            existing = NewsletterCampaignSendEvent.objects.filter(
                campaign_id=campaign.pk
            ).first()
            if existing is None:
                event = create_scheduled_campaign_send_event(
                    campaign,
                    requested_by=campaign.updated_by,
                )
                created += 1
            else:
                event = existing

            if not (
                event.status == NewsletterCampaignSendEvent.Status.PENDING
                and event.provider_send_started_at is None
            ):
                continue

        if dispatch_campaign_send_event_safely(event.pk):
            dispatched += 1
        else:
            failed += 1

    return {
        "disabled": False,
        "selected": len(selected),
        "created": created,
        "dispatched": dispatched,
        "failed": failed,
    }
