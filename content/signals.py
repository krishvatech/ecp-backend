"""
Signal handlers for the content app.

When a new ``Resource`` is created and marked as published, a Celery
task is dispatched to record the activity in the feed.  This decouples
feed generation from the request/response cycle.
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.contenttypes.models import ContentType
from .models import Resource
from activity_feed.tasks import create_feed_item_task

@receiver(post_save, sender=Resource)
def on_resource_created(sender, instance: Resource, created: bool, **kwargs) -> None:
    """Dispatch a feed item when a resource is created and published."""
    if created and instance.is_published:
        metadata = {
            "title": instance.title,
            "type": instance.type,
            "tags": list(instance.tags or []),
        }
        ct = ContentType.objects.get_for_model(Resource)
        create_feed_item_task.delay(
            verb="uploaded_resource",
            target_content_type_id=ct.id,
            target_object_id=instance.id,
            organization_id=instance.organization_id,
            event_id=instance.event_id,
            actor_id=instance.uploaded_by_id,
            metadata=metadata,
        )
