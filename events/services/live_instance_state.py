"""Safe live-meeting scale-in instance tracking helpers.

This module provides a thin, defensive layer over the Django cache (Redis-backed
in this project) to track which instances are serving live meetings, how many
active sessions each instance holds, and whether an instance is safe to drain
during a safe scale-in.

Design goals:
* Never raise an exception into the request/consumer flow. Every public helper
  swallows errors, logs a warning, and returns a safe default.
* Use only the Django cache API plus the standard library. No new dependencies.
* Make no AWS calls beyond reading the local EC2 instance metadata (IMDSv2).
"""

import json
import logging
import socket
import urllib.request
from datetime import datetime

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)

_INSTANCE_PREFIX = "live_instance"
_EVENT_PREFIX = "live_event"

_IMDS_TOKEN_URL = "http://169.254.169.254/latest/api/token"
_IMDS_INSTANCE_ID_URL = "http://169.254.169.254/latest/meta-data/instance-id"
_IMDS_TIMEOUT_SECONDS = 1.0
_IMDS_TOKEN_TTL_SECONDS = "21600"

_DRAINING_TTL_SECONDS = 24 * 60 * 60
_COLLECTION_TTL_SECONDS = _DRAINING_TTL_SECONDS

_cached_instance_id = None


# ---------------------------------------------------------------------------
# Instance identity
# ---------------------------------------------------------------------------
def get_instance_id():
    """Return this host's EC2 instance id, falling back to hostname.

    Uses IMDSv2 with a short timeout. Never raises.
    """
    global _cached_instance_id

    if _cached_instance_id:
        return _cached_instance_id

    instance_id = None

    try:
        token_request = urllib.request.Request(
            _IMDS_TOKEN_URL,
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": _IMDS_TOKEN_TTL_SECONDS},
        )
        with urllib.request.urlopen(token_request, timeout=_IMDS_TIMEOUT_SECONDS) as resp:
            token = resp.read().decode("utf-8").strip()

        id_request = urllib.request.Request(
            _IMDS_INSTANCE_ID_URL,
            method="GET",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with urllib.request.urlopen(id_request, timeout=_IMDS_TIMEOUT_SECONDS) as resp:
            instance_id = resp.read().decode("utf-8").strip()
    except Exception:
        instance_id = None

    if not instance_id:
        try:
            instance_id = socket.gethostname()
        except Exception:
            instance_id = "unknown-host"

    _cached_instance_id = instance_id
    return instance_id


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------
def instance_key(instance_id, suffix):
    """Return cache key: live_instance:{instance_id}:{suffix}."""
    return f"{_INSTANCE_PREFIX}:{instance_id}:{suffix}"


def event_key(event_id, suffix):
    """Return cache key: live_event:{event_id}:{suffix}."""
    return f"{_EVENT_PREFIX}:{event_id}:{suffix}"


def instance_event_sessions_key(instance_id, event_id):
    """Return cache key: live_instance:{instance_id}:event:{event_id}:active_sessions."""
    return f"{_INSTANCE_PREFIX}:{instance_id}:event:{event_id}:active_sessions"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _now_iso():
    return timezone.now().isoformat()


def _parse_iso(value):
    """Parse ISO timestamp into aware datetime, or return None."""
    if not value or not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None

    if timezone.is_naive(parsed):
        try:
            parsed = timezone.make_aware(parsed, timezone.get_default_timezone())
        except Exception:
            return None

    return parsed


def _age_seconds(value):
    """Return age in seconds for ISO timestamp, or None."""
    parsed = _parse_iso(value)
    if parsed is None:
        return None

    return (timezone.now() - parsed).total_seconds()


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# JSON-list collection helpers
# ---------------------------------------------------------------------------
def _read_collection(key):
    """Read JSON-list collection from cache. Returns [] on any error."""
    try:
        raw = cache.get(key)
    except Exception:
        logger.warning(
            "live_instance_state: failed reading collection %s",
            key,
            exc_info=True,
        )
        return []

    if raw is None:
        return []

    if isinstance(raw, (list, set, tuple)):
        return [str(item) for item in raw]

    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            return []

        if isinstance(value, list):
            return [str(item) for item in value]

    return []


def _write_collection(key, items):
    """Write collection as JSON list. Returns normalized list."""
    normalized = []
    for item in items:
        value = str(item)
        if value not in normalized:
            normalized.append(value)

    try:
        cache.set(key, json.dumps(normalized), _COLLECTION_TTL_SECONDS)
    except Exception:
        logger.warning(
            "live_instance_state: failed writing collection %s",
            key,
            exc_info=True,
        )

    return normalized


def _add_to_collection(key, member):
    """Add member to JSON-list collection."""
    member = str(member)
    items = _read_collection(key)

    if member not in items:
        items.append(member)
        items = _write_collection(key, items)

    return items


def _remove_from_collection(key, member):
    """Remove member from JSON-list collection.

    Keeps an empty list in cache for predictable reads.
    Never raises.
    """
    member = str(member)
    items = _read_collection(key)

    if member in items:
        items = [item for item in items if item != member]
        items = _write_collection(key, items)

    return items


# ---------------------------------------------------------------------------
# Heartbeat / draining
# ---------------------------------------------------------------------------
def heartbeat_instance(instance_id=None):
    """Record heartbeat for an instance and ensure draining flag exists."""
    if instance_id is None:
        instance_id = get_instance_id()

    timestamp_iso = _now_iso()

    try:
        ttl = int(getattr(settings, "LIVE_MEETING_INSTANCE_HEARTBEAT_TTL_SECONDS", 90))
        cache.set(instance_key(instance_id, "heartbeat"), timestamp_iso, ttl)

        draining_key = instance_key(instance_id, "draining")
        if cache.get(draining_key) is None:
            cache.set(draining_key, False, _DRAINING_TTL_SECONDS)
    except Exception:
        logger.warning(
            "live_instance_state: heartbeat failed for %s",
            instance_id,
            exc_info=True,
        )

    return {"instance_id": instance_id, "heartbeat": timestamp_iso}


def mark_instance_draining(instance_id=None, draining=True):
    """Set draining flag for an instance."""
    if instance_id is None:
        instance_id = get_instance_id()

    draining = bool(draining)

    try:
        cache.set(instance_key(instance_id, "draining"), draining, _DRAINING_TTL_SECONDS)
    except Exception:
        logger.warning(
            "live_instance_state: failed setting draining for %s",
            instance_id,
            exc_info=True,
        )

    return {"instance_id": instance_id, "draining": draining}


def is_instance_draining(instance_id=None):
    """Return whether an instance is marked draining. False on error."""
    if instance_id is None:
        instance_id = get_instance_id()

    try:
        return bool(cache.get(instance_key(instance_id, "draining"), False))
    except Exception:
        logger.warning(
            "live_instance_state: failed reading draining for %s",
            instance_id,
            exc_info=True,
        )
        return False


# ---------------------------------------------------------------------------
# Session tracking
# ---------------------------------------------------------------------------
def increment_live_session(event_id, session_id=None, instance_id=None):
    """Record start of a live session on this instance.

    session_id is accepted for future per-session tracking but is not required.
    Never crashes request/consumer flow.
    """
    if instance_id is None:
        instance_id = get_instance_id()

    sessions_key = instance_key(instance_id, "active_sessions")
    event_sessions_key = instance_event_sessions_key(instance_id, event_id)

    try:
        current = _safe_int(cache.get(sessions_key), 0) + 1
        cache.set(sessions_key, current, _COLLECTION_TTL_SECONDS)

        event_current = _safe_int(cache.get(event_sessions_key), 0) + 1
        cache.set(event_sessions_key, event_current, _COLLECTION_TTL_SECONDS)

        _add_to_collection(instance_key(instance_id, "active_events"), event_id)
        _add_to_collection(event_key(event_id, "instances"), instance_id)

        cache.set(
            instance_key(instance_id, "last_active_at"),
            _now_iso(),
            _COLLECTION_TTL_SECONDS,
        )

        return {
            "instance_id": instance_id,
            "event_id": str(event_id),
            "active_sessions": current,
            "event_active_sessions": event_current,
        }
    except Exception:
        logger.warning(
            "live_instance_state: increment_live_session failed event=%s instance=%s",
            event_id,
            instance_id,
            exc_info=True,
        )
        return {
            "instance_id": instance_id,
            "event_id": str(event_id),
            "active_sessions": None,
            "event_active_sessions": None,
        }


def decrement_live_session(event_id, session_id=None, instance_id=None):
    """Record end of a live session on this instance.

    Decrements both the total and the per-event session counters, never below 0.
    When the per-event count reaches 0, removes this event from active_events and
    removes this instance from the event's instances. When the total count reaches
    0, refreshes last_active_at. Never crashes request/consumer flow.
    """
    if instance_id is None:
        instance_id = get_instance_id()

    sessions_key = instance_key(instance_id, "active_sessions")
    event_sessions_key = instance_event_sessions_key(instance_id, event_id)

    try:
        current = _safe_int(cache.get(sessions_key), 0) - 1
        if current < 0:
            current = 0
        cache.set(sessions_key, current, _COLLECTION_TTL_SECONDS)

        event_current = _safe_int(cache.get(event_sessions_key), 0) - 1
        if event_current < 0:
            event_current = 0
        cache.set(event_sessions_key, event_current, _COLLECTION_TTL_SECONDS)

        if event_current == 0:
            _remove_from_collection(instance_key(instance_id, "active_events"), event_id)
            _remove_from_collection(event_key(event_id, "instances"), instance_id)

        if current == 0:
            cache.set(
                instance_key(instance_id, "last_active_at"),
                _now_iso(),
                _COLLECTION_TTL_SECONDS,
            )

        return {
            "instance_id": instance_id,
            "event_id": str(event_id),
            "active_sessions": current,
            "event_active_sessions": event_current,
        }
    except Exception:
        logger.warning(
            "live_instance_state: decrement_live_session failed event=%s instance=%s",
            event_id,
            instance_id,
            exc_info=True,
        )
        return {
            "instance_id": instance_id,
            "event_id": str(event_id),
            "active_sessions": None,
            "event_active_sessions": None,
        }


# ---------------------------------------------------------------------------
# State inspection
# ---------------------------------------------------------------------------
def get_instance_state(instance_id):
    """Return tracked state snapshot for an instance. Never raises."""
    state = {
        "instance_id": instance_id,
        "heartbeat": None,
        "draining": False,
        "active_sessions": 0,
        "active_events": [],
        "event_active_sessions": {},
        "last_active_at": None,
        "heartbeat_age_seconds": None,
        "last_active_age_seconds": None,
    }

    try:
        heartbeat = cache.get(instance_key(instance_id, "heartbeat"))
        last_active_at = cache.get(instance_key(instance_id, "last_active_at"))

        state["heartbeat"] = heartbeat
        state["draining"] = bool(cache.get(instance_key(instance_id, "draining"), False))
        state["active_sessions"] = _safe_int(
            cache.get(instance_key(instance_id, "active_sessions")),
            0,
        )
        active_events = _read_collection(instance_key(instance_id, "active_events"))
        state["active_events"] = active_events
        state["event_active_sessions"] = {
            event_id: _safe_int(
                cache.get(instance_event_sessions_key(instance_id, event_id)),
                0,
            )
            for event_id in active_events
        }
        state["last_active_at"] = last_active_at
        state["heartbeat_age_seconds"] = _age_seconds(heartbeat)
        state["last_active_age_seconds"] = _age_seconds(last_active_at)
    except Exception:
        logger.warning(
            "live_instance_state: get_instance_state failed for %s",
            instance_id,
            exc_info=True,
        )

    return state


def is_instance_safe_to_drain(instance_id, idle_seconds=None):
    """Return whether an instance is safe to drain.

    Safe only when:
    - not already draining
    - active_sessions == 0
    - active_events empty
    - heartbeat exists and is fresh
    - last_active_at is missing or older than idle_seconds
    """
    if idle_seconds is None:
        idle_seconds = int(getattr(settings, "LIVE_MEETING_DRAIN_IDLE_SECONDS", 300))

    reasons = []
    state = get_instance_state(instance_id)

    try:
        if state.get("draining"):
            reasons.append("instance is marked draining")

        if _safe_int(state.get("active_sessions"), 0) != 0:
            reasons.append("active_sessions is not zero")

        if state.get("active_events"):
            reasons.append("active_events is not empty")

        heartbeat_age = state.get("heartbeat_age_seconds")
        heartbeat_ttl = int(getattr(settings, "LIVE_MEETING_INSTANCE_HEARTBEAT_TTL_SECONDS", 90))

        if not state.get("heartbeat") or heartbeat_age is None:
            reasons.append("heartbeat missing")
        elif heartbeat_age > heartbeat_ttl:
            reasons.append("heartbeat is stale")

        last_active_age = state.get("last_active_age_seconds")
        if last_active_age is not None and last_active_age < idle_seconds:
            reasons.append("instance was active too recently")
    except Exception:
        logger.warning(
            "live_instance_state: is_instance_safe_to_drain failed for %s",
            instance_id,
            exc_info=True,
        )
        reasons.append("error evaluating drain safety")

    return {
        "safe": len(reasons) == 0,
        "reasons": reasons,
        "state": state,
    }