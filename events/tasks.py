from celery import shared_task
from django.utils import timezone
import logging

logger = logging.getLogger('events')

@shared_task
def example_cleanup_task() -> str:
    """Return a string with the current timestamp to verify Celery runs."""
    return f"Cleanup ran at {timezone.now().isoformat()}"



