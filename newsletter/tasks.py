"""Asynchronous Mautic newsletter synchronization tasks."""

from celery import shared_task
from celery.exceptions import MaxRetriesExceededError
from django.conf import settings

from .mautic import TemporaryMauticError
from .processor import (
    mark_retry_exhausted,
    process_newsletter_sync_event as process_sync_event,
)


@shared_task(bind=True, name="newsletter.process_sync_event")
def process_newsletter_sync_event(self, event_id: int):
    """Process one durable newsletter sync event with Celery retry handling."""
    try:
        return process_sync_event(event_id)
    except TemporaryMauticError as exc:
        countdown = int(getattr(exc, "retry_delay", 30))
        try:
            raise self.retry(
                exc=exc,
                countdown=countdown,
                max_retries=int(
                    getattr(settings, "MAUTIC_SYNC_MAX_RETRIES", 5)
                ),
            )
        except MaxRetriesExceededError:
            mark_retry_exhausted(event_id)
            return {
                "event_id": event_id,
                "status": "failed",
                "processed": True,
                "reason": "retry_limit_exhausted",
            }


@shared_task(name="newsletter.dispatch_due_sync_events")
def dispatch_due_newsletter_sync_events(batch_size: int = 100):
    """Dispatch due/stale durable events for recovery processing."""
    from .operations import dispatch_due_sync_events

    return dispatch_due_sync_events(batch_size=batch_size)
