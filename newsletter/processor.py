"""Synchronous Newsletter -> Mautic event processor.

Celery integration is intentionally separate. This processor owns durable event
claiming, stale-event protection, provider calls, and retry state transitions.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .models import (
    MauticContactMapping,
    NewsletterSubscription,
    NewsletterSyncEvent,
)


logger = logging.getLogger(__name__)


def retry_delay_seconds(attempt_count: int) -> int:
    """Return bounded exponential retry delay for a 1-based attempt count."""
    base = max(
        1,
        int(getattr(settings, "MAUTIC_SYNC_RETRY_BASE_SECONDS", 30)),
    )
    maximum = max(
        base,
        int(getattr(settings, "MAUTIC_SYNC_RETRY_MAX_SECONDS", 3600)),
    )
    exponent = max(0, int(attempt_count) - 1)
    return min(maximum, base * (2**exponent))


def _claim_event(event_id: int) -> NewsletterSyncEvent | None:
    """Atomically claim a due event, including stale PROCESSING recovery."""
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
            NewsletterSyncEvent.objects.select_for_update()
            .select_related("category")
            .filter(pk=event_id)
            .first()
        )
        if event is None:
            return None

        claimable = event.status in {
            NewsletterSyncEvent.Status.PENDING,
            NewsletterSyncEvent.Status.RETRYING,
        }
        if (
            event.status == NewsletterSyncEvent.Status.PROCESSING
            and event.processing_started_at
            and event.processing_started_at <= stale_before
        ):
            claimable = True

        if event.next_retry_at and event.next_retry_at > now:
            claimable = False

        if not claimable:
            return None

        event.status = NewsletterSyncEvent.Status.PROCESSING
        event.attempt_count += 1
        event.processing_started_at = now
        event.next_retry_at = None
        event.last_error = ""
        event.save(
            update_fields=[
                "status",
                "attempt_count",
                "processing_started_at",
                "next_retry_at",
                "last_error",
                "updated_at",
            ]
        )
        return event


def _finish(event_id: int, status: str, error: str = "") -> None:
    now = timezone.now()
    NewsletterSyncEvent.objects.filter(
        pk=event_id,
        status=NewsletterSyncEvent.Status.PROCESSING,
    ).update(
        status=status,
        last_error=(error or "")[:2000],
        completed_at=now,
        next_retry_at=None,
        updated_at=now,
    )


def _schedule_retry(event: NewsletterSyncEvent, error: str) -> int:
    delay = retry_delay_seconds(event.attempt_count)
    now = timezone.now()
    NewsletterSyncEvent.objects.filter(
        pk=event.pk,
        status=NewsletterSyncEvent.Status.PROCESSING,
    ).update(
        status=NewsletterSyncEvent.Status.RETRYING,
        last_error=(error or "Temporary Mautic failure")[:2000],
        next_retry_at=now + timedelta(seconds=delay),
        completed_at=None,
        updated_at=now,
    )
    return delay


def mark_retry_exhausted(event_id: int) -> None:
    """Move an already-retrying event into a terminal failure state."""
    now = timezone.now()
    NewsletterSyncEvent.objects.filter(
        pk=event_id,
        status=NewsletterSyncEvent.Status.RETRYING,
    ).update(
        status=NewsletterSyncEvent.Status.FAILED,
        last_error="Mautic retry limit exhausted",
        next_retry_at=None,
        completed_at=now,
        updated_at=now,
    )


def _build_contact_payload(user) -> dict:
    email = str(getattr(user, "email", "") or "").strip().lower()
    if not email:
        raise PermanentMauticError("Email is required for Mautic newsletter sync")

    return {
        "email": email,
        "firstname": str(getattr(user, "first_name", "") or "").strip(),
        "lastname": str(getattr(user, "last_name", "") or "").strip(),
    }


def _contact_id_from_result(contact: dict) -> str:
    contact_id = str(contact.get("id") or "").strip()
    if not contact_id:
        raise TemporaryMauticError("Mautic contact response is missing contact ID")
    return contact_id


def _resolve_mautic_contact(
    client: MauticClient,
    user,
    *,
    create_if_missing: bool,
) -> tuple[str | None, bool]:
    """Return (contact_id, created).

    Existing mappings are reused. Without a mapping we search by normalized
    email first. A missing contact is created only for subscribe operations;
    unsubscribe never creates a new Mautic contact just to remove it.
    """
    payload = _build_contact_payload(user)
    mapping = MauticContactMapping.objects.filter(user=user).first()

    if mapping is not None:
        contact = client.update_contact(mapping.mautic_contact_id, payload)
        return _contact_id_from_result(contact), False

    contact = client.find_contact_by_email(payload["email"])
    if contact is None:
        if not create_if_missing:
            return None, False
        contact = client.create_contact(payload)
        created = True
    else:
        contact_id = _contact_id_from_result(contact)
        contact = client.update_contact(contact_id, payload)
        created = False

    contact_id = _contact_id_from_result(contact)
    MauticContactMapping.objects.update_or_create(
        user=user,
        defaults={"mautic_contact_id": contact_id},
    )
    return contact_id, created


def process_newsletter_sync_event(event_id: int) -> dict:
    """Synchronously process one durable NewsletterSyncEvent."""
    if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
        existing = (
            NewsletterSyncEvent.objects.filter(pk=event_id)
            .values_list("status", flat=True)
            .first()
        )
        return {
            "event_id": event_id,
            "status": existing or "missing",
            "processed": False,
            "reason": "mautic_sync_disabled",
        }

    event = _claim_event(event_id)
    if event is None:
        existing = (
            NewsletterSyncEvent.objects.filter(pk=event_id)
            .values_list("status", flat=True)
            .first()
        )
        return {
            "event_id": event_id,
            "status": existing or "missing",
            "processed": False,
        }

    if not event.category.is_active:
        _finish(
            event.pk,
            NewsletterSyncEvent.Status.SKIPPED,
            "Newsletter category is inactive",
        )
        return {
            "event_id": event.pk,
            "status": NewsletterSyncEvent.Status.SKIPPED,
            "processed": True,
        }

    segment_id = str(event.category.mautic_segment_id or "").strip()
    if not segment_id:
        _finish(
            event.pk,
            NewsletterSyncEvent.Status.FAILED,
            "Mautic segment ID is not configured for newsletter category",
        )
        return {
            "event_id": event.pk,
            "status": NewsletterSyncEvent.Status.FAILED,
            "processed": True,
        }

    User = get_user_model()
    try:
        user = User.objects.filter(pk=event.user_id).first()
    except (TypeError, ValueError):
        user = None

    if user is None:
        _finish(
            event.pk,
            NewsletterSyncEvent.Status.SKIPPED,
            "ECP user no longer exists",
        )
        return {
            "event_id": event.pk,
            "status": NewsletterSyncEvent.Status.SKIPPED,
            "processed": True,
        }

    subscription = NewsletterSubscription.objects.filter(
        user=user,
        category=event.category,
    ).first()
    if subscription is None:
        _finish(
            event.pk,
            NewsletterSyncEvent.Status.SKIPPED,
            "Newsletter subscription no longer exists",
        )
        return {
            "event_id": event.pk,
            "status": NewsletterSyncEvent.Status.SKIPPED,
            "processed": True,
        }

    if bool(subscription.is_subscribed) != bool(event.desired_subscribed):
        _finish(
            event.pk,
            NewsletterSyncEvent.Status.SKIPPED,
            "Newsletter sync event was superseded by a newer preference",
        )
        return {
            "event_id": event.pk,
            "status": NewsletterSyncEvent.Status.SKIPPED,
            "processed": True,
            "reason": "superseded",
        }

    try:
        client = MauticClient()
        contact_id, created = _resolve_mautic_contact(
            client,
            user,
            create_if_missing=bool(event.desired_subscribed),
        )

        if contact_id is not None:
            if event.desired_subscribed:
                client.add_contact_to_segment(segment_id, contact_id)
            else:
                client.remove_contact_from_segment(segment_id, contact_id)
    except TemporaryMauticError as exc:
        delay = _schedule_retry(event, str(exc))
        exc.retry_delay = delay
        raise
    except PermanentMauticError as exc:
        _finish(event.pk, NewsletterSyncEvent.Status.FAILED, str(exc))
        return {
            "event_id": event.pk,
            "status": NewsletterSyncEvent.Status.FAILED,
            "processed": True,
        }
    except Exception:
        logger.exception(
            "Unexpected Mautic newsletter failure for event_id=%s",
            event.pk,
        )
        error = TemporaryMauticError("Unexpected Mautic newsletter failure")
        error.retry_delay = _schedule_retry(event, str(error))
        raise error

    synced_at = timezone.now()
    with transaction.atomic():
        if contact_id is not None:
            MauticContactMapping.objects.filter(
                user=user,
                mautic_contact_id=contact_id,
            ).update(
                last_synced_at=synced_at,
                updated_at=synced_at,
            )
        NewsletterSyncEvent.objects.filter(
            pk=event.pk,
            status=NewsletterSyncEvent.Status.PROCESSING,
        ).update(
            status=NewsletterSyncEvent.Status.SUCCEEDED,
            last_error="",
            next_retry_at=None,
            completed_at=synced_at,
            updated_at=synced_at,
        )

    return {
        "event_id": event.pk,
        "status": NewsletterSyncEvent.Status.SUCCEEDED,
        "processed": True,
        "mautic_contact_id": contact_id,
        "created": created,
    }
