"""Durable newsletter campaign send-event creation helpers."""

from __future__ import annotations

from django.db import transaction

from .models import NewsletterCampaign, NewsletterCampaignSendEvent


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
