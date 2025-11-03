"""
Celery tasks for the activity feed app.

Defining tasks in a dedicated module allows Celery to auto‑discover
them via the app configuration.  Currently only a single task for
creating feed items exists; however additional tasks (e.g. email
notifications) can be added here in the future.
"""
from celery import shared_task
from .models import FeedItem

@shared_task
def create_feed_item_task(
    verb: str,
    target_content_type_id: int,
    target_object_id: int,
    community_id: int | None = None,
    event_id: int | None = None,
    actor_id: int | None = None,
    metadata: dict | None = None,
) -> str:
    """
    Create a new feed item asynchronously.  The caller must provide the
    generic target content type id and object id, along with optional
    references to an community, event and actor.  The metadata argument
    should be a JSON‑serializable dictionary.
    """
    FeedItem.objects.create(
        community_id=community_id,
        event_id=event_id,
        actor_id=actor_id,
        verb=verb,
        target_content_type_id=target_content_type_id,
        target_object_id=target_object_id,
        metadata=metadata or {},
    )
    return f"Feed item recorded: {verb}"