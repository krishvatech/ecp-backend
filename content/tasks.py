# content/tasks.py
from celery import shared_task
from django.utils import timezone
from django.contrib.contenttypes.models import ContentType

from .models import Resource
from activity_feed.tasks import create_feed_item_task


def _dispatch_feed(resource: Resource):
    """Create an activity feed item when a resource becomes public."""
    metadata = {
        "title": resource.title,
        "resource_type": resource.type,
        "tags": list(resource.tags or []),
        "actor_name": getattr(resource.uploaded_by, "username", "Unknown")
        if resource.uploaded_by else "Unknown",
    }
    ct = ContentType.objects.get_for_model(Resource)
    create_feed_item_task.delay(
        verb="uploaded_resource",
        target_content_type_id=ct.id,
        target_object_id=resource.id,
        community_id=resource.community_id,
        event_id=resource.event_id,
        actor_id=resource.uploaded_by_id,
        metadata=metadata,
    )


@shared_task
def publish_resource_task(resource_id: int) -> int:
    """Publish a single resource if due. Returns 1 if published else 0."""
    try:
        r = Resource.objects.get(id=resource_id)
    except Resource.DoesNotExist:
        return 0

    now = timezone.now()
    if r.is_published:
        return 0
    if r.publish_at and r.publish_at > now:
        return 0

    r.is_published = True
    r.save(update_fields=["is_published", "updated_at"])
    _dispatch_feed(r)
    return 1


@shared_task
def publish_due_resources_task() -> int:
    """
    Publish all overdue scheduled resources.
    Returns the number of resources published.
    """
    now = timezone.now()
    count = 0
    qs = Resource.objects.filter(
        is_published=False,
        publish_at__isnull=False,
        publish_at__lte=now,
    ).select_related("uploaded_by")

    for r in qs:
        r.is_published = True
        r.save(update_fields=["is_published", "updated_at"])
        _dispatch_feed(r)
        count += 1

    return count
