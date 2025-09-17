"""
Signal handlers for the messaging app.

Increment analytics metrics when new messages are created.  Only
dispatch on creation to avoid counting edits or status updates.
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Message


@receiver(post_save, sender=Message)
def on_message_created(sender, instance: Message, created: bool, **kwargs) -> None:
    """Increment message count metric on creation."""
    if created:
        try:
            from ecp_backend.analytics.tasks import increment_metric  # local import

            # Messages are not associated with an event or organization
            increment_metric.delay(
                metric_name="message_count",
                org_id=None,
                event_id=None,
                value=1,
            )
        except Exception:
            pass
