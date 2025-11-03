"""
Signal handlers for the content app.
Covers:
  - created & already published
  - unpublished → published transitions (scheduled or manual)
"""
import logging
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.contrib.contenttypes.models import ContentType

from .models import Resource
from activity_feed.tasks import create_feed_item_task

logger = logging.getLogger(__name__)


# Track whether the object was published before save
@receiver(pre_save, sender=Resource, dispatch_uid="resource_track_prev_publish_state")
def _track_previous_publish_state(sender, instance: Resource, **kwargs):
    if instance.pk:
        try:
            prev = sender.objects.only("is_published").get(pk=instance.pk)
            instance._was_published = bool(prev.is_published)
        except sender.DoesNotExist:
            instance._was_published = False
    else:
        instance._was_published = False


@receiver(post_save, sender=Resource, dispatch_uid="resource_feed_item_created_or_published")
def on_resource_saved(sender, instance: Resource, created: bool, **kwargs) -> None:
    """
    Dispatch a feed item when:
      a) the resource is created and already published, OR
      b) it transitioned from not-published → published.
    Also increments analytics once on publish.
    """
    was_published = getattr(instance, "_was_published", False)
    became_published = (created and instance.is_published) or (
        not created and (not was_published) and instance.is_published
    )

    # helpful debug
    print(
        f"🔔 SIGNAL Resource: created={created} "
        f"was_published={was_published} now_published={instance.is_published} "
        f"title={instance.title}"
    )

    if not became_published:
        return

    metadata = {
        "title": instance.title,
        "resource_type": instance.type,
        "tags": list(instance.tags or []),
        "actor_name": getattr(instance.uploaded_by, "username", "Unknown") if instance.uploaded_by else "Unknown",
    }
    ct = ContentType.objects.get_for_model(Resource)

    # Activity feed
    try:
        create_feed_item_task.delay(
            verb="uploaded_resource",
            target_content_type_id=ct.id,
            target_object_id=instance.id,
            community_id=instance.community_id,
            event_id=instance.event_id,
            actor_id=instance.uploaded_by_id,
            metadata=metadata,
        )
        print("✅ Feed item task dispatched")
    except Exception as e:
        logger.error(f"Error creating feed item: {e}")
        print(f"❌ Error: {e}")

    # Analytics (only when it actually becomes published)
    try:
        from analytics.tasks import increment_metric
        increment_metric.delay(
            metric_name="resource_count",
            org_id=instance.community_id,
            event_id=instance.event_id,
            value=1,
        )
    except Exception:
        pass
