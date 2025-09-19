"""
Celery tasks for the events app.

At this stage, a simple placeholder task is defined.  In later phases,
tasks may include processing recordings or sending notifications.
"""
from celery import shared_task
from django.core.files.base import ContentFile
from django.utils import timezone
import requests
import logging

logger = logging.getLogger(__name__)



@shared_task
def example_cleanup_task() -> str:
    """Return a string with the current timestamp to verify Celery runs."""
    return f"Cleanup ran at {timezone.now().isoformat()}"

@shared_task
def download_event_recording(event_id: int, file_url: str) -> str:
    """
    Download a recording for an event and save it.
    For now, just update the recording_url in the Event model.
    """
    from .models import Event
    try:
        event = Event.objects.get(id=event_id)
        event.recording_url = file_url
        event.save(update_fields=["recording_url"])
    except Event.DoesNotExist:
        print(f"[ERROR] Event {event_id} not found")