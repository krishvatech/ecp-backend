import math
import logging
from datetime import timedelta

import boto3
from django.conf import settings
from django.utils import timezone

from events.models import Event

logger = logging.getLogger(__name__)

_EVENT_FIELD_CANDIDATES = {
    "id",
    "title",
    "status",
    "is_live",
    "max_participants",
    "max_attendees",
    "capacity",
    "attendee_limit",
    "registration_limit",
    "start_time",
    "start_datetime",
    "starts_at",
    "start_date",
    "end_time",
    "end_datetime",
    "ends_at",
    "end_date",
}


def _event_only_fields():
    model_fields = {f.name for f in Event._meta.get_fields()}
    fields = sorted(_EVENT_FIELD_CANDIDATES & model_fields)
    if not fields and Event._meta.pk and Event._meta.pk.name in model_fields:
        fields = [Event._meta.pk.name]
    return fields


def get_registered_count(event):
    """
    Adjust this if your registration related_name is different.
    """
    if hasattr(event, "registrations"):
        return event.registrations.count()

    if hasattr(event, "attendees"):
        return event.attendees.count()

    return 0


def get_event_capacity(event):
    """
    Use real event capacity if field exists.
    Otherwise fall back to registered count.
    """
    for field in [
        "max_participants",
        "max_attendees",
        "capacity",
        "attendee_limit",
        "registration_limit",
    ]:
        value = getattr(event, field, None)
        if value:
            return int(value)

    return get_registered_count(event)


def get_expected_users(event):
    registered = get_registered_count(event)
    capacity = get_event_capacity(event)

    late_buffer = max(
        settings.LIVE_MEETING_LATE_REGISTRATION_BUFFER_MIN,
        math.ceil(registered * settings.LIVE_MEETING_LATE_REGISTRATION_BUFFER_PERCENT / 100),
    )

    # Important:
    # If event has fixed capacity, use capacity.
    # If open registration can grow, use registered + late buffer.
    return max(registered, capacity, registered + late_buffer)


def required_instances_for_users(user_count):
    if user_count <= 0:
        return settings.LIVE_MEETING_ASG_MIN_CAPACITY

    required = math.ceil(user_count / settings.LIVE_MEETING_SAFE_USERS_PER_INSTANCE)
    required += settings.LIVE_MEETING_BUFFER_INSTANCES

    return max(
        settings.LIVE_MEETING_ASG_MIN_CAPACITY,
        min(required, settings.LIVE_MEETING_ASG_MAX_CAPACITY),
    )


def event_start_time(event):
    for field in ["start_time", "start_datetime", "starts_at", "start_date"]:
        value = getattr(event, field, None)
        if value:
            return value
    return None


def event_end_time(event):
    for field in ["end_time", "end_datetime", "ends_at", "end_date"]:
        value = getattr(event, field, None)
        if value:
            return value
    return None


def get_event_sessions(event):
    sessions = getattr(event, "sessions", None)
    if not sessions:
        return []

    try:
        return list(sessions.all())
    except Exception:
        # Some environments may have schema drift (e.g. sessions table missing).
        logger.exception("Failed to fetch sessions for event_id=%s", getattr(event, "id", None))
        return []


def get_session_start_time(session):
    for field in ["start_time", "start_datetime", "starts_at", "start_date"]:
        value = getattr(session, field, None)
        if value:
            return value
    return None


def get_session_end_time(session):
    for field in ["end_time", "end_datetime", "ends_at", "end_date"]:
        value = getattr(session, field, None)
        if value:
            return value
    return None


def get_capacity_windows_for_event(event):
    """
    Returns time windows where this event needs backend capacity.

    Single-day event:
      use event start/end.

    Multi-day event:
      use session start/end times (one window per session).
    """
    sessions = get_event_sessions(event)

    if sessions:
        windows = []
        for session in sessions:
            start = get_session_start_time(session)
            end = get_session_end_time(session)
            if start and end:
                windows.append((start, end))
        return windows

    start = event_start_time(event)
    end = event_end_time(event)
    if start and end:
        return [(start, end)]

    return []


def get_capacity_relevant_events():
    """
    Includes:
    - live meetings
    - meetings starting soon
    - meetings host may start early
    - recently ended meetings for cooldown
    """
    now = timezone.now()
    relevant = []

    # Avoid selecting all columns because some environments may have schema drift
    # (e.g. a model field exists but its DB column isn't migrated yet).
    qs = Event.objects.only(*_event_only_fields())

    for event in qs.iterator():
        status = getattr(event, "status", None)
        if status in ["draft", "cancelled", "canceled", "deleted", "archived"]:
            continue

        is_live = bool(getattr(event, "is_live", False)) or status == "live"

        if is_live:
            relevant.append(event)
            continue

        windows = get_capacity_windows_for_event(event)
        for start, end in windows:
            window_start = start - timedelta(
                minutes=max(
                    settings.LIVE_MEETING_PREWARM_MINUTES,
                    settings.LIVE_MEETING_HOST_EARLY_START_MINUTES,
                )
            )
            window_end = end + timedelta(minutes=settings.LIVE_MEETING_COOLDOWN_MINUTES)
            if window_start <= now <= window_end:
                relevant.append(event)
                break

    return relevant


def calculate_required_capacity():
    events = get_capacity_relevant_events()

    total_expected_users = 0
    event_details = []

    for event in events:
        expected = get_expected_users(event)
        total_expected_users += expected
        event_details.append(
            {
                "id": str(event.id),
                "title": getattr(event, "title", ""),
                "expected_users": expected,
                "is_live": bool(getattr(event, "is_live", False)),
                "status": getattr(event, "status", None),
            }
        )

    desired = required_instances_for_users(total_expected_users)

    return {
        "total_expected_users": total_expected_users,
        "desired_instances": desired,
        "min_instances": desired,
        "max_instances": max(desired, settings.LIVE_MEETING_ASG_MAX_CAPACITY),
        "events": event_details,
    }


def get_current_asg_capacity():
    client = boto3.client("autoscaling", region_name=settings.LIVE_MEETING_ASG_REGION)

    resp = client.describe_auto_scaling_groups(AutoScalingGroupNames=[settings.LIVE_MEETING_ASG_NAME])

    groups = resp.get("AutoScalingGroups", [])
    if not groups:
        raise RuntimeError(f"ASG not found: {settings.LIVE_MEETING_ASG_NAME}")

    group = groups[0]

    return {
        "min": group["MinSize"],
        "desired": group["DesiredCapacity"],
        "max": group["MaxSize"],
    }


def scale_asg_if_needed(reason="scheduled_check", scale_down_allowed=True):
    if not settings.LIVE_MEETING_ASG_AUTOSCALE_ENABLED:
        logger.info("Live meeting ASG autoscale disabled")
        return {"changed": False, "reason": "disabled"}

    required = calculate_required_capacity()
    current = get_current_asg_capacity()

    desired = required["desired_instances"]

    has_capacity_window = required["total_expected_users"] > 0 or bool(required["events"])

    # During live/upcoming/cooldown windows, never reduce capacity.
    # Downscale is allowed only when there is no relevant meeting window.
    if desired < current["desired"] and (not scale_down_allowed or has_capacity_window):
        logger.info(
            "Keeping current ASG desired capacity. reason=%s current_desired=%s calculated_desired=%s has_capacity_window=%s",
            reason,
            current["desired"],
            desired,
            has_capacity_window,
        )
        desired = current["desired"]

    if desired == current["desired"] and desired == current["min"]:
        logger.info("ASG already at required capacity: %s", current)
        return {
            "changed": False,
            "current": current,
            "required": required,
        }

    client = boto3.client("autoscaling", region_name=settings.LIVE_MEETING_ASG_REGION)

    logger.warning(
        "Updating ASG capacity reason=%s current=%s required=%s",
        reason,
        current,
        required,
    )

    client.update_auto_scaling_group(
        AutoScalingGroupName=settings.LIVE_MEETING_ASG_NAME,
        MinSize=desired,
        DesiredCapacity=desired,
        MaxSize=max(desired, settings.LIVE_MEETING_ASG_MAX_CAPACITY),
    )

    return {
        "changed": True,
        "from": current,
        "to": {
            "min": desired,
            "desired": desired,
            "max": max(desired, settings.LIVE_MEETING_ASG_MAX_CAPACITY),
        },
        "required": required,
    }
