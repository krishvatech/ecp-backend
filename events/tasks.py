"""
Celery tasks for the events app.

At this stage, a simple placeholder task is defined.  In later phases,
tasks may include processing recordings or sending notifications.
"""
from celery import shared_task
from django.core.files.base import ContentFile
from django.utils import timezone
import requests


@shared_task
def example_cleanup_task() -> str:
    """Return a string with the current timestamp to verify Celery runs."""
    return f"Cleanup ran at {timezone.now().isoformat()}"

@shared_task
def download_event_recording(event_id: int, file_url: str) -> str:
    """
    Download a recording for an event and save it via django-storages.
    In this sandbox environment, we simply set the event.recording_url.
    """
    from events.models import Event
    event = Event.objects.get(pk=event_id)
    # In production: stream file and store to S3/GCS via default_storage.save(...)
    # For now, just update the URL.
    event.recording_url = file_url
    event.save(update_fields=["recording_url", "updated_at"])
    return f"Stored recording for event {event_id}"