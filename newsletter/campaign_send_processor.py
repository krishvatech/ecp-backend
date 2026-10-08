"""Safe processor for one durable newsletter campaign broadcast event.

A campaign broadcast is intentionally different from preference synchronization:
once the provider send request starts, the result may be ambiguous after a
transport failure. Such events are terminal and must never be automatically
retried.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .campaign_services import (
    CampaignMauticSyncFailed,
    CampaignMauticUnavailable,
    CampaignMauticValidationError,
    sync_campaign_for_worker_delivery,
)
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.exceptions import MauticRequestNotSentError
from .mautic.payloads import build_campaign_email_payload
from .models import NewsletterCampaign, NewsletterCampaignSendEvent


logger = logging.getLogger(__name__)


_PRE_PROVIDER_ERRORS = (
    CampaignMauticValidationError,
    CampaignMauticUnavailable,
    CampaignMauticSyncFailed,
    TemporaryMauticError,
    PermanentMauticError,
)


def _claim_send_event(event_id: int) -> NewsletterCampaignSendEvent | None:
    """Claim a pending or safely retryable pre-provider send event.

    A stale PROCESSING event may be recovered only if the provider-send
    boundary has not been crossed. Once provider_send_started_at is set, the
    event is never claimable again because delivery may already have started.
    """
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

    with transaction.atomic():
        event = (
            NewsletterCampaignSendEvent.objects.select_for_update()
            .filter(pk=event_id)
            .first()
        )
        if event is None:
            return None

        claimable = event.status == NewsletterCampaignSendEvent.Status.PENDING
        if (
            event.status == NewsletterCampaignSendEvent.Status.FAILED
            and event.provider_send_started_at is None
        ):
            claimable = True
        if (
            event.status == NewsletterCampaignSendEvent.Status.PROCESSING
            and event.provider_send_started_at is None
            and event.processing_started_at
            and event.processing_started_at <= stale_before
        ):
            claimable = True

        if not claimable:
            return None

        campaign = (
            NewsletterCampaign.objects.select_for_update()
            .filter(pk=event.campaign_id)
            .first()
        )
        if (
            campaign is not None
            and campaign.status == NewsletterCampaign.Status.SCHEDULED
            and (
                campaign.scheduled_at is None
                or campaign.scheduled_at > now
            )
        ):
            return None

        event.status = NewsletterCampaignSendEvent.Status.PROCESSING
        event.attempt_count += 1
        event.processing_started_at = now
        event.completed_at = None
        event.last_error = ""
        event.save(
            update_fields=[
                "status",
                "attempt_count",
                "processing_started_at",
                "completed_at",
                "last_error",
                "updated_at",
            ]
        )
        return event


def _record_pre_provider_failure(event_id: int, campaign_id: int, error: str) -> None:
    """Fail the event while keeping pre-provider campaign state safe."""
    now = timezone.now()
    message = str(error or "Newsletter campaign preparation failed.")[:500]

    with transaction.atomic():
        NewsletterCampaignSendEvent.objects.filter(
            pk=event_id,
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            provider_send_started_at__isnull=True,
        ).update(
            status=NewsletterCampaignSendEvent.Status.FAILED,
            last_error=message,
            completed_at=now,
            updated_at=now,
        )
        NewsletterCampaign.objects.filter(
            pk=campaign_id,
            status__in=[
                NewsletterCampaign.Status.DRAFT,
                NewsletterCampaign.Status.SCHEDULED,
            ],
        ).update(
            last_error=message,
            updated_at=now,
        )


def _mark_provider_send_started(
    event_id: int,
) -> tuple[NewsletterCampaignSendEvent, NewsletterCampaign] | None:
    """Cross the no-retry boundary immediately before the provider send call."""
    now = timezone.now()

    with transaction.atomic():
        event = (
            NewsletterCampaignSendEvent.objects.select_for_update()
            .filter(
                pk=event_id,
                status=NewsletterCampaignSendEvent.Status.PROCESSING,
                provider_send_started_at__isnull=True,
            )
            .first()
        )
        if event is None:
            return None

        campaign = (
            NewsletterCampaign.objects.select_for_update()
            .filter(
                pk=event.campaign_id,
                status__in=[
                    NewsletterCampaign.Status.DRAFT,
                    NewsletterCampaign.Status.SCHEDULED,
                ],
            )
            .first()
        )
        if campaign is None:
            return None

        event.provider_send_started_at = now
        event.save(
            update_fields=[
                "provider_send_started_at",
                "updated_at",
            ]
        )

        campaign.status = NewsletterCampaign.Status.SENDING
        campaign.send_started_at = now
        campaign.sent_at = None
        campaign.last_error = ""
        update_fields = [
            "status",
            "send_started_at",
            "sent_at",
            "last_error",
            "updated_at",
        ]
        if event.requested_by_id:
            campaign.updated_by = event.requested_by
            update_fields.append("updated_by")
        campaign.save(update_fields=update_fields)

        return event, campaign


def _record_terminal_send_failure(event_id: int, campaign_id: int, error: str) -> None:
    """Record an ambiguous/rejected provider send without retrying it."""
    now = timezone.now()
    message = str(error or "Newsletter campaign broadcast failed.")[:500]

    with transaction.atomic():
        NewsletterCampaignSendEvent.objects.filter(
            pk=event_id,
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            provider_send_started_at__isnull=False,
        ).update(
            status=NewsletterCampaignSendEvent.Status.FAILED,
            last_error=message,
            completed_at=now,
            updated_at=now,
        )
        NewsletterCampaign.objects.filter(
            pk=campaign_id,
            status=NewsletterCampaign.Status.SENDING,
        ).update(
            status=NewsletterCampaign.Status.FAILED,
            last_error=message,
            updated_at=now,
        )


UNCERTAIN_SEND_MESSAGE = (
    "Mautic did not confirm this broadcast send. Delivery may have completed "
    "or may still be in progress, so it will not be retried automatically. "
    "Check the email's send statistics in Mautic before taking any action."
)


def _record_uncertain_send(event_id: int, campaign_id: int, error: str) -> None:
    """Record a send whose outcome is unknown without claiming it failed.

    The request reached Mautic (or may have), and Mautic sends synchronously
    inside that request, so a lost response says nothing about delivery. The
    campaign stays SENDING and the event stays PROCESSING with its provider
    boundary set: neither recovery nor a repeated Send Now can claim it again,
    so it is never resent.
    """
    now = timezone.now()
    message = f"{UNCERTAIN_SEND_MESSAGE} ({str(error or 'no response')[:200]})"[:500]

    with transaction.atomic():
        NewsletterCampaignSendEvent.objects.filter(
            pk=event_id,
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            provider_send_started_at__isnull=False,
        ).update(last_error=message, updated_at=now)
        NewsletterCampaign.objects.filter(
            pk=campaign_id,
            status=NewsletterCampaign.Status.SENDING,
        ).update(last_error=message, updated_at=now)


def _provider_sent_count(result: dict) -> int:
    try:
        return max(0, int(result.get("sentCount") or 0))
    except (TypeError, ValueError):
        return 0


def _provider_failed_recipients(result: dict) -> list:
    failed_recipients = result.get("failedRecipients") or []
    if isinstance(failed_recipients, list):
        return failed_recipients
    return []


def _record_send_success(event_id: int, campaign_id: int, result: dict) -> None:
    now = timezone.now()
    failed_recipients = _provider_failed_recipients(result)

    with transaction.atomic():
        NewsletterCampaignSendEvent.objects.filter(
            pk=event_id,
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            provider_send_started_at__isnull=False,
        ).update(
            status=NewsletterCampaignSendEvent.Status.SUCCEEDED,
            last_error="",
            provider_sent_count=_provider_sent_count(result),
            provider_failed_count=len(failed_recipients),
            provider_failed_recipients=failed_recipients,
            completed_at=now,
            updated_at=now,
        )
        NewsletterCampaign.objects.filter(
            pk=campaign_id,
            status=NewsletterCampaign.Status.SENDING,
        ).update(
            status=NewsletterCampaign.Status.SENT,
            sent_at=now,
            last_error="",
            updated_at=now,
        )


def _uncertain_result(event_id: int) -> dict:
    return {
        "event_id": event_id,
        "status": NewsletterCampaignSendEvent.Status.PROCESSING,
        "processed": True,
        "retry_safe": False,
        "outcome": "uncertain",
    }


def process_campaign_send_event(event_id: int) -> dict:
    """Process one campaign send event with a strict no-retry provider boundary."""
    if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
        existing = (
            NewsletterCampaignSendEvent.objects.filter(pk=event_id)
            .values_list("status", flat=True)
            .first()
        )
        return {
            "event_id": event_id,
            "status": existing or "missing",
            "processed": False,
            "reason": "mautic_sync_disabled",
        }

    event = _claim_send_event(event_id)
    if event is None:
        existing = (
            NewsletterCampaignSendEvent.objects.filter(pk=event_id)
            .values_list("status", flat=True)
            .first()
        )
        return {
            "event_id": event_id,
            "status": existing or "missing",
            "processed": False,
        }

    campaign = (
        NewsletterCampaign.objects.prefetch_related("audiences")
        .filter(pk=event.campaign_id)
        .first()
    )
    if campaign is None:
        _record_pre_provider_failure(
            event.pk,
            event.campaign_id,
            "Newsletter campaign no longer exists.",
        )
        return {
            "event_id": event.pk,
            "status": NewsletterCampaignSendEvent.Status.FAILED,
            "processed": True,
        }

    if campaign.status not in {
        NewsletterCampaign.Status.DRAFT,
        NewsletterCampaign.Status.SCHEDULED,
    }:
        _record_pre_provider_failure(
            event.pk,
            campaign.pk,
            "Newsletter campaign is no longer eligible for delivery.",
        )
        return {
            "event_id": event.pk,
            "status": NewsletterCampaignSendEvent.Status.FAILED,
            "processed": True,
        }

    try:
        campaign = sync_campaign_for_worker_delivery(
            campaign,
            actor=event.requested_by,
        )
        publish_payload = build_campaign_email_payload(campaign, publish=True)
        segment_ids = list(publish_payload.get("lists") or [])
        email_id = str(campaign.mautic_email_id or "").strip()
        if not email_id:
            raise TemporaryMauticError(
                "Mautic campaign synchronization returned no email ID"
            )
        if not segment_ids:
            raise PermanentMauticError(
                "Newsletter campaign has no Mautic audience segments"
            )

        client = MauticClient()
        client.update_email(email_id, publish_payload)
    except _PRE_PROVIDER_ERRORS as exc:
        _record_pre_provider_failure(event.pk, campaign.pk, str(exc))
        return {
            "event_id": event.pk,
            "status": NewsletterCampaignSendEvent.Status.FAILED,
            "processed": True,
            "retry_safe": True,
        }
    except Exception:
        logger.exception(
            "Unexpected newsletter campaign preparation failure event_id=%s",
            event.pk,
        )
        _record_pre_provider_failure(
            event.pk,
            campaign.pk,
            "Unexpected newsletter campaign preparation failure",
        )
        return {
            "event_id": event.pk,
            "status": NewsletterCampaignSendEvent.Status.FAILED,
            "processed": True,
            "retry_safe": True,
        }

    boundary = _mark_provider_send_started(event.pk)
    if boundary is None:
        _record_pre_provider_failure(
            event.pk,
            campaign.pk,
            "Newsletter campaign send could not enter provider-send state.",
        )
        return {
            "event_id": event.pk,
            "status": NewsletterCampaignSendEvent.Status.FAILED,
            "processed": True,
            "retry_safe": True,
        }

    _, sending_campaign = boundary

    try:
        result = client.send_email_to_segments(email_id, segment_ids)
    except (MauticRequestNotSentError, PermanentMauticError) as exc:
        # Definitive: the request never reached Mautic, or Mautic rejected it.
        _record_terminal_send_failure(
            event.pk,
            sending_campaign.pk,
            str(exc),
        )
        return {
            "event_id": event.pk,
            "status": NewsletterCampaignSendEvent.Status.FAILED,
            "processed": True,
            "retry_safe": False,
        }
    except TemporaryMauticError as exc:
        # A timeout, dropped connection or 5xx after Mautic may have started
        # sending: the outcome is unknown, never "failed".
        logger.warning(
            "Newsletter campaign broadcast outcome uncertain event_id=%s: %s",
            event.pk,
            exc,
        )
        _record_uncertain_send(event.pk, sending_campaign.pk, str(exc))
        return _uncertain_result(event.pk)
    except Exception:
        logger.exception(
            "Unexpected newsletter campaign broadcast failure event_id=%s",
            event.pk,
        )
        _record_uncertain_send(
            event.pk,
            sending_campaign.pk,
            "Unexpected newsletter campaign broadcast failure",
        )
        return _uncertain_result(event.pk)

    _record_send_success(event.pk, sending_campaign.pk, result)
    return {
        "event_id": event.pk,
        "status": NewsletterCampaignSendEvent.Status.SUCCEEDED,
        "processed": True,
        "sent_count": result.get("sentCount"),
        "failed_recipients": result.get("failedRecipients"),
    }
