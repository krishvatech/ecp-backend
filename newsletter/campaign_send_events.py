"""Durable newsletter campaign send-event creation helpers."""

from __future__ import annotations

import logging

from django.db import transaction

from .models import NewsletterCampaign, NewsletterCampaignSendEvent


logger = logging.getLogger(__name__)


def dispatch_campaign_send_event_safely(event_id: int) -> bool:
    """Best-effort dispatch of a durable campaign send event.

    Broker failure must not make the API request fail. The event stays in its
    durable database state and can be safely redispatched later when its
    provider-send boundary has not been crossed.
    """
    try:
        from .tasks import process_newsletter_campaign_send_event

        process_newsletter_campaign_send_event.delay(event_id)
        return True
    except Exception:
        logger.exception(
            "Could not dispatch newsletter campaign send event_id=%s; "
            "durable state retained",
            event_id,
        )
        return False


def build_campaign_send_idempotency_key(campaign: NewsletterCampaign) -> str:
    """Return the stable single-use send key for one campaign."""
    if not getattr(campaign, "pk", None):
        raise ValueError("Saved newsletter campaign is required")
    return f"mautic:newsletter:campaign:{campaign.uuid}:send"


def create_campaign_send_event(
    campaign: NewsletterCampaign,
    *,
    requested_by=None,
) -> NewsletterCampaignSendEvent:
    """Create or reuse the one durable send event for a campaign.

    The campaign row is locked so concurrent send requests cannot create
    duplicate events. Once any send event exists, it is always reused,
    including after failure; creating a second event would make a second
    broadcast possible.
    """
    if not getattr(campaign, "pk", None):
        raise ValueError("Saved newsletter campaign is required")

    with transaction.atomic():
        locked = NewsletterCampaign.objects.select_for_update().get(pk=campaign.pk)

        existing = NewsletterCampaignSendEvent.objects.filter(
            campaign=locked
        ).first()
        if existing is not None:
            return existing

        if locked.status != NewsletterCampaign.Status.DRAFT:
            raise ValueError(
                "Only draft newsletter campaigns can request a send."
            )

        return NewsletterCampaignSendEvent.objects.create(
            campaign=locked,
            requested_by=requested_by,
            idempotency_key=build_campaign_send_idempotency_key(locked),
        )


def create_scheduled_campaign_send_event(
    campaign: NewsletterCampaign,
    *,
    requested_by=None,
) -> NewsletterCampaignSendEvent:
    """Create or reuse the one durable send event for a due scheduled campaign."""
    if not getattr(campaign, "pk", None):
        raise ValueError("Saved newsletter campaign is required")

    with transaction.atomic():
        locked = NewsletterCampaign.objects.select_for_update().get(pk=campaign.pk)

        existing = NewsletterCampaignSendEvent.objects.filter(
            campaign=locked
        ).first()
        if existing is not None:
            return existing

        if locked.status != NewsletterCampaign.Status.SCHEDULED:
            raise ValueError(
                "Only scheduled newsletter campaigns can request a scheduled send."
            )

        return NewsletterCampaignSendEvent.objects.create(
            campaign=locked,
            requested_by=requested_by,
            idempotency_key=build_campaign_send_idempotency_key(locked),
        )
