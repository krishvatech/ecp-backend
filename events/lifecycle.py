"""Shared event lifecycle rules used by API serializers and live actions.

The persisted ``status`` can remain ``published`` for imported/external events
whose scheduled end time has already passed.  These helpers provide one safe,
consistent interpretation without changing the stored status automatically.
"""

from datetime import timedelta

from django.utils import timezone


def is_event_effectively_ended(event, *, now=None):
    """Return True when the main event can no longer be registered/hosted.

    A genuinely live event is allowed to continue beyond its scheduled end time;
    this avoids interrupting meetings that run overtime.  A stale ``published``
    event, however, is treated as ended as soon as its end time passes.
    """

    if event is None:
        return False

    status = str(getattr(event, "status", "") or "").lower()
    if status == "ended":
        return True

    if bool(getattr(event, "is_live", False)):
        return False

    end_time = getattr(event, "end_time", None)
    if not end_time:
        return False

    now = now or timezone.now()
    return end_time <= now


def is_post_event_lounge_open(event, *, now=None):
    """Return True only during the configured post-event Social Lounge window."""

    if event is None or not bool(getattr(event, "lounge_enabled_after", False)):
        return False

    live_ended_at = getattr(event, "live_ended_at", None)
    if not live_ended_at:
        return False

    try:
        buffer_minutes = max(0, int(getattr(event, "lounge_after_buffer", 0) or 0))
    except (TypeError, ValueError):
        return False

    if buffer_minutes <= 0:
        return False

    now = now or timezone.now()
    return live_ended_at <= now < live_ended_at + timedelta(minutes=buffer_minutes)


def is_replay_ready_for_signup(event, *, now=None):
    """Return True when a past event has a participant-visible playable replay."""

    if not is_event_effectively_ended(event, now=now):
        return False

    return bool(
        getattr(event, "replay_enabled", False)
        and getattr(event, "replay_visible_to_participants", False)
        and (
            getattr(event, "replay_video_url", None)
            or getattr(event, "recording_url", None)
        )
    )
