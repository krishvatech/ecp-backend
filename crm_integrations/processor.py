"""Synchronous CRM event processor used by Celery and focused tests."""

import logging
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from .events import USER_DEACTIVATED
from .models import CRMObjectMapping, CRMSyncEvent
from .providers import get_crm_provider
from .providers.base import PermanentCRMError, TemporaryCRMError
from .services import build_user_contact_payload


logger = logging.getLogger(__name__)


def retry_delay_seconds(attempt_count: int) -> int:
    base = max(1, int(getattr(settings, "CRM_SYNC_RETRY_BASE_SECONDS", 30)))
    maximum = max(base, int(getattr(settings, "CRM_SYNC_RETRY_MAX_SECONDS", 3600)))
    exponent = max(0, int(attempt_count) - 1)
    return min(maximum, base * (2**exponent))


def _claim_event(event_id: int) -> CRMSyncEvent | None:
    now = timezone.now()
    stale_before = now - timedelta(
        seconds=max(
            1,
            int(getattr(settings, "CRM_SYNC_PROCESSING_TIMEOUT_SECONDS", 600)),
        )
    )
    with transaction.atomic():
        event = (
            CRMSyncEvent.objects.select_for_update()
            .select_related("connection")
            .filter(pk=event_id)
            .first()
        )
        if event is None:
            return None
        claimable = event.status in {
            CRMSyncEvent.Status.PENDING,
            CRMSyncEvent.Status.RETRYING,
        }
        if (
            event.status == CRMSyncEvent.Status.PROCESSING
            and event.processing_started_at
            and event.processing_started_at <= stale_before
        ):
            claimable = True
        if event.next_retry_at and event.next_retry_at > now:
            claimable = False
        if not claimable:
            return None

        event.status = CRMSyncEvent.Status.PROCESSING
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
    CRMSyncEvent.objects.filter(
        pk=event_id,
        status=CRMSyncEvent.Status.PROCESSING,
    ).update(
        status=status,
        last_error=(error or "")[:2000],
        completed_at=timezone.now(),
        next_retry_at=None,
        updated_at=timezone.now(),
    )


def _schedule_retry(event: CRMSyncEvent, error: str) -> int:
    delay = retry_delay_seconds(event.attempt_count)
    CRMSyncEvent.objects.filter(
        pk=event.pk,
        status=CRMSyncEvent.Status.PROCESSING,
    ).update(
        status=CRMSyncEvent.Status.RETRYING,
        last_error=(error or "Temporary CRM failure")[:2000],
        next_retry_at=timezone.now() + timedelta(seconds=delay),
        completed_at=None,
        updated_at=timezone.now(),
    )
    return delay


def mark_retry_exhausted(event_id: int) -> None:
    CRMSyncEvent.objects.filter(
        pk=event_id,
        status=CRMSyncEvent.Status.RETRYING,
    ).update(
        status=CRMSyncEvent.Status.FAILED,
        last_error="CRM retry limit exhausted",
        next_retry_at=None,
        completed_at=timezone.now(),
        updated_at=timezone.now(),
    )


def process_sync_event(event_id: int) -> dict:
    if not getattr(settings, "CRM_SYNC_ENABLED", False):
        existing = CRMSyncEvent.objects.filter(pk=event_id).values_list("status", flat=True).first()
        return {
            "event_id": event_id,
            "status": existing or "missing",
            "processed": False,
            "reason": "crm_sync_disabled",
        }
    event = _claim_event(event_id)
    if event is None:
        existing = CRMSyncEvent.objects.filter(pk=event_id).values_list("status", flat=True).first()
        return {"event_id": event_id, "status": existing or "missing", "processed": False}

    if not event.connection.is_active:
        _finish(event.pk, CRMSyncEvent.Status.SKIPPED, "CRM connection is inactive")
        return {"event_id": event.pk, "status": CRMSyncEvent.Status.SKIPPED, "processed": True}

    if event.object_type != "user":
        _finish(event.pk, CRMSyncEvent.Status.FAILED, "Unsupported CRM object type")
        return {"event_id": event.pk, "status": CRMSyncEvent.Status.FAILED, "processed": True}

    User = get_user_model()
    try:
        user_id = int(event.object_id)
    except (TypeError, ValueError):
        _finish(event.pk, CRMSyncEvent.Status.FAILED, "Invalid ECP user ID")
        return {"event_id": event.pk, "status": CRMSyncEvent.Status.FAILED, "processed": True}

    user = User.objects.filter(pk=user_id).first()
    if user is None:
        _finish(event.pk, CRMSyncEvent.Status.SKIPPED, "ECP user no longer exists")
        return {"event_id": event.pk, "status": CRMSyncEvent.Status.SKIPPED, "processed": True}

    payload = build_user_contact_payload(user)
    try:
        provider = get_crm_provider(event.connection)
        if event.event_type == USER_DEACTIVATED:
            mapping = CRMObjectMapping.objects.filter(
                connection=event.connection,
                local_object_type="user",
                local_object_id=str(user.pk),
            ).first()
            result = provider.deactivate_contact(
                mapping.external_id if mapping else "",
                payload,
            )
        else:
            result = provider.upsert_contact(payload)
    except TemporaryCRMError as exc:
        delay = _schedule_retry(event, str(exc))
        exc.retry_delay = delay
        raise
    except PermanentCRMError as exc:
        _finish(event.pk, CRMSyncEvent.Status.FAILED, str(exc))
        return {"event_id": event.pk, "status": CRMSyncEvent.Status.FAILED, "processed": True}
    except Exception:
        logger.exception("Unexpected CRM provider failure for event_id=%s", event.pk)
        error = TemporaryCRMError("Unexpected CRM provider failure")
        error.retry_delay = _schedule_retry(event, str(error))
        raise error

    synced_at = timezone.now()
    with transaction.atomic():
        CRMObjectMapping.objects.update_or_create(
            connection=event.connection,
            local_object_type="user",
            local_object_id=str(user.pk),
            defaults={
                "external_object_type": result.external_object_type,
                "external_id": result.external_id,
                "last_synced_at": synced_at,
            },
        )
        CRMSyncEvent.objects.filter(
            pk=event.pk,
            status=CRMSyncEvent.Status.PROCESSING,
        ).update(
            payload=payload,
            status=CRMSyncEvent.Status.SUCCEEDED,
            last_error="",
            next_retry_at=None,
            completed_at=synced_at,
            updated_at=synced_at,
        )

    return {
        "event_id": event.pk,
        "status": CRMSyncEvent.Status.SUCCEEDED,
        "processed": True,
        "external_id": result.external_id,
        "created": result.created,
    }
