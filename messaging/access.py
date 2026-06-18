"""Shared messaging access helpers.

Keep event-chat permission logic in one place so conversation list,
ensure-event, message creation, and model checks cannot drift apart.
"""
from __future__ import annotations

from typing import Optional


def user_can_access_event_chat(user, *, event=None, event_id: Optional[int] = None) -> bool:
    """Return True only when user is allowed to see/send chat for this event.

    Rules:
    - platform staff/superuser, event creator, and community owner can access;
    - event staff participants can access;
    - normal attendees need an active confirmed registration and must not be banned;
    - guest sessions are limited to their own event only.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False

    if event is None:
        if not event_id:
            return False
        from events.models import Event

        try:
            event = Event.objects.select_related("community").get(pk=event_id)
        except Event.DoesNotExist:
            return False

    if getattr(user, "is_guest", False):
        guest = getattr(user, "guest", None)
        return bool(guest and guest.event_id == event.id)

    user_id = getattr(user, "id", None)
    if not user_id:
        return False

    if getattr(user, "is_staff", False) or getattr(user, "is_superuser", False):
        return True

    if event.created_by_id == user_id:
        return True

    if getattr(getattr(event, "community", None), "owner_id", None) == user_id:
        return True

    from events.models import EventParticipant, EventRegistration

    if EventParticipant.objects.filter(
        event_id=event.id,
        user_id=user_id,
        participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
    ).exists():
        return True

    return EventRegistration.objects.filter(
        event_id=event.id,
        user_id=user_id,
        status="registered",
        attendee_status="confirmed",
        is_banned=False,
    ).exists()
