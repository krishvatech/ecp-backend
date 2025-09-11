"""
Celery tasks for the events app.

At this stage, a simple placeholder task is defined.  In later phases,
tasks may include processing recordings or sending notifications.
"""
from celery import shared_task
from django.utils import timezone


@shared_task
def example_cleanup_task() -> str:
    """Return a string with the current timestamp to verify Celery runs."""
    return f"Cleanup ran at {timezone.now().isoformat()}"