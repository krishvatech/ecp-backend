"""Asynchronous CRM synchronization tasks."""

from celery import shared_task
from celery.exceptions import MaxRetriesExceededError
from django.conf import settings

from .processor import mark_retry_exhausted, process_sync_event
from .providers.base import TemporaryCRMError


@shared_task(bind=True, name="crm_integrations.process_sync_event")
def process_crm_sync_event(self, event_id: int):
    try:
        return process_sync_event(event_id)
    except TemporaryCRMError as exc:
        countdown = int(getattr(exc, "retry_delay", 30))
        try:
            raise self.retry(
                exc=exc,
                countdown=countdown,
                max_retries=int(getattr(settings, "CRM_SYNC_MAX_RETRIES", 5)),
            )
        except MaxRetriesExceededError:
            mark_retry_exhausted(event_id)
            return {
                "event_id": event_id,
                "status": "failed",
                "processed": True,
                "reason": "retry_limit_exhausted",
            }


@shared_task(name="crm_integrations.dispatch_due_sync_events")
def dispatch_due_crm_sync_events(batch_size: int = 100):
    # Local import avoids an import cycle: operations dispatches the processor
    # task defined above.
    from .operations import dispatch_due_sync_events

    return dispatch_due_sync_events(batch_size=batch_size)
