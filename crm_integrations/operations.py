"""Operational health, recovery, and manual retry helpers."""

import logging
from datetime import timedelta

from django.conf import settings
from django.db.models import Q, QuerySet
from django.utils import timezone

from .models import CRMConnection, CRMSyncEvent
from .providers import get_crm_provider
from .providers.base import CRMProviderError
from .tasks import process_crm_sync_event


logger = logging.getLogger(__name__)


def check_connection_health(connection: CRMConnection) -> dict:
    checked_at = timezone.now()
    try:
        provider = get_crm_provider(connection)
        healthy = bool(provider.health_check())
        error = "" if healthy else "CRM provider health check returned unhealthy"
    except CRMProviderError as exc:
        healthy = False
        error = str(exc)[:2000]
    except Exception:
        logger.exception("Unexpected CRM health-check failure for connection_id=%s", connection.pk)
        healthy = False
        error = "Unexpected CRM health-check failure"

    CRMConnection.objects.filter(pk=connection.pk).update(
        last_health_check_at=checked_at,
        last_health_check_status=healthy,
        last_error=error,
        updated_at=checked_at,
    )
    connection.last_health_check_at = checked_at
    connection.last_health_check_status = healthy
    connection.last_error = error
    return {"healthy": healthy, "checked_at": checked_at, "error": error}


def _dispatch_event_ids(event_ids: list[int]) -> tuple[int, int]:
    dispatched = 0
    failed = 0
    for event_id in event_ids:
        try:
            process_crm_sync_event.delay(event_id)
            dispatched += 1
        except Exception:
            failed += 1
            logger.exception(
                "Could not dispatch CRM recovery event_id=%s; state retained",
                event_id,
            )
    return dispatched, failed


def due_sync_event_ids(batch_size: int = 100) -> list[int]:
    now = timezone.now()
    stale_before = now - timedelta(
        seconds=max(
            1,
            int(getattr(settings, "CRM_SYNC_PROCESSING_TIMEOUT_SECONDS", 600)),
        )
    )
    due = (
        Q(status=CRMSyncEvent.Status.PENDING)
        | Q(
            status=CRMSyncEvent.Status.RETRYING,
            next_retry_at__isnull=True,
        )
        | Q(
            status=CRMSyncEvent.Status.RETRYING,
            next_retry_at__lte=now,
        )
        | Q(
            status=CRMSyncEvent.Status.PROCESSING,
            processing_started_at__lte=stale_before,
        )
    )
    return list(
        CRMSyncEvent.objects.filter(connection__is_active=True)
        .filter(due)
        .order_by("created_at")
        .values_list("pk", flat=True)[: max(1, int(batch_size))]
    )


def dispatch_due_sync_events(batch_size: int = 100) -> dict:
    if not getattr(settings, "CRM_SYNC_ENABLED", False):
        return {"disabled": True, "selected": 0, "dispatched": 0, "failed": 0}
    event_ids = due_sync_event_ids(batch_size=batch_size)
    dispatched, failed = _dispatch_event_ids(event_ids)
    return {
        "disabled": False,
        "selected": len(event_ids),
        "dispatched": dispatched,
        "failed": failed,
    }


def requeue_sync_events(queryset: QuerySet[CRMSyncEvent]) -> dict:
    event_ids = list(
        queryset.exclude(status=CRMSyncEvent.Status.SUCCEEDED)
        .order_by("created_at")
        .values_list("pk", flat=True)
    )
    if not event_ids:
        return {"selected": 0, "dispatched": 0, "failed": 0}

    CRMSyncEvent.objects.filter(pk__in=event_ids).update(
        status=CRMSyncEvent.Status.PENDING,
        last_error="",
        next_retry_at=None,
        processing_started_at=None,
        completed_at=None,
        updated_at=timezone.now(),
    )
    if getattr(settings, "CRM_SYNC_ENABLED", False):
        dispatched, failed = _dispatch_event_ids(event_ids)
    else:
        dispatched, failed = 0, 0
    return {
        "selected": len(event_ids),
        "dispatched": dispatched,
        "failed": failed,
    }
