# activity_feed/signals.py
from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver

from .models import FeedItem

@receiver(pre_save, sender=FeedItem)
def feeditem_set_community_from_group(sender, instance: FeedItem, **kwargs):
    # If already set, skip
    if instance.community_id:
        return

    meta = instance.metadata or {}
    # support either {"group_id": 5} or {"group": {"id": 5}}
    gid = meta.get("group_id") or (meta.get("group") or {}).get("id")
    if not gid:
        return

    Group = apps.get_model("groups", "Group")
    community_id = (
        Group.objects.filter(id=gid).values_list("community_id", flat=True).first()
    )
    if community_id:
        instance.community_id = community_id


# ----- NEW: create a FeedItem when a GroupPoll is created -----

def _safe_poll_options_list(poll) -> list[str]:
    """Return a list of option labels for the poll, best-effort without hard field assumptions."""
    labels: list[str] = []
    try:
        opts_rel = getattr(poll, "options", None)
        if not opts_rel:
            return labels
        qs = getattr(opts_rel, "all", lambda: [])()
        # Preserve ordering if an 'index' field exists; otherwise just iterate.
        try:
            qs = qs.order_by("index")
        except Exception:
            pass
        for o in qs:
            label = getattr(o, "text", None) or getattr(o, "label", None) or str(o)
            labels.append(label)
    except Exception:
        pass
    return labels


def _create_feed_item_for_poll(poll):
    GroupPoll = poll.__class__
    ct = ContentType.objects.get_for_model(GroupPoll)

    # Prefer typical creator fields; fall back gracefully
    actor_id = (
        getattr(poll, "created_by_id", None)
        or getattr(poll, "owner_id", None)
        or getattr(poll, "author_id", None)
    )

    metadata = {
        "type": "poll",
        "group_id": getattr(poll, "group_id", None),
        "poll_id": poll.id,
        "question": getattr(poll, "question", None),
        "options": [
            {
                "id": o.id,
                "text": getattr(o, "text", None) or getattr(o, "label", None) or str(o),
                "vote_count": getattr(o, "votes", None).count() if hasattr(o, "votes") else 0,
            }
            for o in getattr(poll, "options").order_by("index")
        ],
        "is_closed": bool(getattr(poll, "is_closed", False)),
    }
    FeedItem.objects.create(
        actor_id=actor_id,
        verb="created_poll",
        target_content_type=ct,
        target_object_id=poll.id,
        metadata=metadata,
    )


def _group_poll_post_save(sender, instance, created, **kwargs):
    if not created:
        return
    # Run after the transaction commits (so related options are in DB)
    transaction.on_commit(lambda: _create_feed_item_for_poll(instance))


def _connect_group_poll_signal():
    # Attach the post_save handler dynamically so we don’t need a direct import
    try:
        GroupPoll = apps.get_model("groups", "GroupPoll")
    except Exception:
        return
    post_save.connect(
        _group_poll_post_save,
        sender=GroupPoll,
        dispatch_uid="activity_feed.group_poll_post_save",
    )


# Connect on import (apps are ready because ActivityFeedConfig.ready() imports this module)
_connect_group_poll_signal()
