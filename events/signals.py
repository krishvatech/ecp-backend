# events/signals.py
import json
import datetime as dt
from django.db.models.signals import post_save
from django.dispatch import receiver
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder

from .models import Event


def _iso(v):
    """Return ISO-8601 string for datetime/date values; pass through others."""
    if isinstance(v, (dt.datetime, dt.date)):
        if isinstance(v, dt.datetime) and timezone.is_naive(v):
            v = timezone.make_aware(v, timezone.utc)
        return v.isoformat()
    return v  # str/None stays as-is


def _shape_event_post(e: Event) -> dict:
    """Shape an Event instance into the LiveFeed 'post' payload (no DB writes)."""
    creator = getattr(e, "created_by", None)
    actor_name = (
        getattr(creator, "get_full_name", lambda: "")() or
        getattr(creator, "username", "") or
        "Event"
    )

    return {
        "id": f"event-{e.id}",
        "type": "event",
        "text": (getattr(e, "description", "") or "")[:2000],
        "created_at": _iso(getattr(e, "created_at", None) or getattr(e, "start_time", None)),
        "visibility": "community",
        "community_id": getattr(e, "community_id", None),
        "author": {"id": getattr(creator, "id", None), "name": actor_name},
        "metrics": {"likes": 0, "comments": 0, "shares": 0},
        "event": {
            "id": e.id,
            "title": getattr(e, "title", "Event"),
            "when": _iso(getattr(e, "start_time", None)),
            "where": getattr(e, "location", "") or "",
        },
    }


@receiver(post_save, sender=Event)
def push_event_to_livefeed(sender, instance: Event, created, **kwargs):
    """Broadcast a realtime LiveFeed message when a new Event is created."""
    if not created:
        return

    payload = {"type": "new_post", "post": _shape_event_post(instance)}
    community_id = getattr(instance, "community_id", None) or "public"

    channel_layer = get_channel_layer()
    if channel_layer is None:
        return  # Channels not configured; safely no-op

    async_to_sync(channel_layer.group_send)(
        f"livefeed_{community_id}",
        {
            "type": "broadcast.json",
            # Use DjangoJSONEncoder as an extra guard, although _iso already stringifies
            "text": json.dumps(payload, cls=DjangoJSONEncoder),
        },
    )
