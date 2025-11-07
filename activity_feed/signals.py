# activity_feed/signals.py

from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver

from .models import FeedItem, Poll


@receiver(pre_save, sender=FeedItem)
def feeditem_set_community_from_group(sender, instance: FeedItem, **kwargs):
    """
    If a FeedItem only has group info in metadata, infer and set community_id
    before save. (Still useful for non-poll feed items.)
    """
    if instance.community_id:
        return

    meta = instance.metadata or {}
    gid = meta.get("group_id") or (meta.get("group") or {}).get("id")
    if not gid:
        return

    Group = apps.get_model("groups", "Group")
    community_id = (
        Group.objects.filter(id=gid).values_list("community_id", flat=True).first()
    )
    if community_id:
        instance.community_id = community_id


def _create_feed_item_for_poll(poll: Poll):
    """
    Create a FeedItem when a new activity_feed.Poll is created.
    Ensures options (and their vote counts) are present by running after commit.
    """
    ct = ContentType.objects.get_for_model(Poll)

    # Resolve actor
    actor_id = (
        getattr(poll, "created_by_id", None)
        or getattr(poll, "owner_id", None)
        or getattr(poll, "author_id", None)
    )

    # Resolve community (prefer explicit poll.community; else inherit from group)
    community = getattr(poll, "community", None)
    if not community and getattr(poll, "group_id", None):
        try:
            community = poll.group.community
        except Exception:
            community = None

    # Options (ordered if index exists) with vote counts
    try:
        opts_qs = poll.options.order_by("index")
    except Exception:
        opts_qs = poll.options.all()

    options = [
        {
            "id": o.id,
            "text": getattr(o, "text", None) or getattr(o, "label", None) or str(o),
            "vote_count": getattr(o, "votes", None).count() if hasattr(o, "votes") else 0,
            "index": getattr(o, "index", None),
        }
        for o in opts_qs
    ]

    metadata = {
        "type": "poll",
        "poll_id": poll.id,
        "question": getattr(poll, "question", None),
        "options": options,
        "is_closed": bool(getattr(poll, "is_closed", False)),
        "group_id": getattr(poll, "group_id", None),
        "community_id": getattr(poll, "community_id", None) or (getattr(community, "id", None)),
        "allows_multiple": bool(getattr(poll, "allows_multiple", False)),
        "is_anonymous": bool(getattr(poll, "is_anonymous", False)),
        "ends_at": getattr(poll, "ends_at", None),
    }

    FeedItem.objects.create(
        community_id=getattr(community, "id", None),
        group_id=getattr(poll, "group_id", None),
        actor_id=actor_id,
        verb="created_poll",
        target_content_type=ct,
        target_object_id=poll.id,
        metadata=metadata,
    )


@receiver(post_save, sender=Poll)
def poll_post_save(sender, instance: Poll, created, **kwargs):
    """
    When a new activity_feed.Poll is created, drop a FeedItem after the DB
    transaction commits so options exist by the time we serialize.
    """
    if not created:
        return
    transaction.on_commit(lambda: _create_feed_item_for_poll(instance))
