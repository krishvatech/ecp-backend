import math
import logging
from datetime import timedelta

import boto3
from django.conf import settings
from django.core.cache import cache
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


def is_session_live(session):
    status = getattr(session, "status", None)
    return bool(getattr(session, "is_live", False)) or status == "live"


def has_live_session(event):
    sessions = get_event_sessions(event)

    for session in sessions:
        if is_session_live(session):
            return True

    return False

def is_multi_day_event(event):
    """
    Treat an event as multi-day if either:
    - explicit is_multi_day=True, or
    - event start/end fall on different calendar dates.
    """
    if bool(getattr(event, "is_multi_day", False)):
        return True

    start = event_start_time(event)
    end = event_end_time(event)
    if start and end:
        return start.date() != end.date()

    return False

def get_capacity_windows_for_event(event):
    """
    Returns time windows where this event needs backend capacity.

    Single-day event:
      use parent event start/end time.

    Multi-day event:
      use ONLY session start/end times.
      If there are no sessions, return no capacity window so ASG can downscale.
    """
    if is_multi_day_event(event):
        sessions = get_event_sessions(event)

        if not sessions:
            logger.info(
                "Multi-day event has no sessions; skipping ASG capacity window. event_id=%s title=%s",
                getattr(event, "id", None),
                getattr(event, "title", ""),
            )
            return []

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

        multi_day = is_multi_day_event(event)
        is_live = bool(getattr(event, "is_live", False)) or status == "live"

        if multi_day:
            # For multi-day events, parent event time/live flag should NOT hold capacity.
            # Only real sessions should protect capacity. No sessions => allow downscale.
            if has_live_session(event):
                relevant.append(event)
                continue
        else:
            # For single-day events, parent event live flag/start/end is valid.
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
        "min_instances": settings.LIVE_MEETING_ASG_MIN_CAPACITY,
        "max_instances": settings.LIVE_MEETING_ASG_MAX_CAPACITY,
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


LIVE_MEETING_CAPACITY_STATUS_CACHE_KEY = "live_meeting:capacity_status:v1"
LIVE_MEETING_ASG_SCALE_LOCK_CACHE_KEY = "live_meeting:asg_scale_lock:v1"


def get_capacity_status_cached():
    """
    Cache expensive capacity calculation + ASG current capacity lookup.

    This prevents every /rtk/join/ request from re-running the capacity scan and AWS query.
    """
    ttl = int(getattr(settings, "LIVE_MEETING_CAPACITY_CHECK_CACHE_TTL_SECONDS", 15))

    try:
        cached = cache.get(LIVE_MEETING_CAPACITY_STATUS_CACHE_KEY)
        if cached:
            return cached
    except Exception:
        logger.warning("Failed to read live meeting capacity cache", exc_info=True)

    required = calculate_required_capacity()
    current = get_current_asg_capacity()

    status = {
        "required": required,
        "current": current,
        "checked_at": timezone.now().isoformat(),
    }

    try:
        cache.set(LIVE_MEETING_CAPACITY_STATUS_CACHE_KEY, status, timeout=ttl)
    except Exception:
        logger.warning("Failed to write live meeting capacity cache", exc_info=True)

    return status


def clear_capacity_status_cache():
    try:
        cache.delete(LIVE_MEETING_CAPACITY_STATUS_CACHE_KEY)
    except Exception:
        logger.warning("Failed to clear live meeting capacity cache", exc_info=True)


def acquire_asg_scale_lock():
    """
    Allow only one request/process to trigger ASG scaling within lock TTL.
    """
    ttl = int(getattr(settings, "LIVE_MEETING_ASG_SCALE_LOCK_TTL_SECONDS", 60))

    try:
        return cache.add(
            LIVE_MEETING_ASG_SCALE_LOCK_CACHE_KEY,
            timezone.now().isoformat(),
            timeout=ttl,
        )
    except Exception:
        # Fail open: if cache is down, allow scaling attempt rather than blocking capacity preparation.
        logger.warning("Failed to acquire ASG scale lock; allowing scale attempt", exc_info=True)
        return True


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

        # Safe scale-in: during an active capacity window we never reduce desired
        # directly. Instead, when the feature flag is enabled, delegate to the
        # safe scale-in functions which only ever drain/terminate a single
        # already-idle instance (and only when dry_run is False). This branch
        # never calls update_auto_scaling_group to downscale.
        if has_capacity_window and getattr(settings, "LIVE_MEETING_SAFE_SCALE_IN_ENABLED", False):
            # Imported lazily to avoid a circular import: live_safe_scale_in
            # imports calculate_required_capacity/get_current_asg_capacity from
            # this module.
            from events.services.live_safe_scale_in import (
                continue_safe_scale_in_draining_instances,
                execute_safe_scale_in_one_step,
            )

            dry_run = getattr(settings, "LIVE_MEETING_SAFE_SCALE_IN_DRY_RUN", True)

            try:
                # Stage 1: finish off any instance already draining from a prior cycle.
                continue_result = continue_safe_scale_in_draining_instances(
                    reason=reason,
                    dry_run=dry_run,
                )
                logger.info(
                    "Safe scale-in continue-draining reason=%s dry_run=%s changed=%s result_reason=%s",
                    reason,
                    dry_run,
                    continue_result.get("changed"),
                    continue_result.get("reason"),
                )

                if continue_result.get("changed"):
                    return {
                        "changed": True,
                        "safe_scale_in": True,
                        "stage": "continue_draining",
                        "result": continue_result,
                        "current": current,
                        "required": required,
                    }

                # Stage 2: nothing was draining (or nothing changed) — try to start
                # or complete one safe scale-in step on a fresh candidate.
                start_result = execute_safe_scale_in_one_step(
                    reason=reason,
                    dry_run=dry_run,
                )
                logger.info(
                    "Safe scale-in one-step reason=%s dry_run=%s changed=%s result_reason=%s",
                    reason,
                    dry_run,
                    start_result.get("changed"),
                    start_result.get("reason"),
                )

                if start_result.get("changed"):
                    return {
                        "changed": True,
                        "safe_scale_in": True,
                        "stage": "start_or_complete_one_step",
                        "result": start_result,
                        "current": current,
                        "required": required,
                    }
            except Exception:
                # The safe scale-in helpers are already defensive; this is a final
                # guard so the autoscaler can never be broken by them.
                logger.warning(
                    "Safe scale-in execution failed; keeping current capacity", exc_info=True
                )

        # Conservative fallback (unchanged behavior): during a capacity window, or
        # when safe scale-in is disabled / dry-run / waiting for a drain, never
        # reduce desired capacity below the current value.
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

    target_min = settings.LIVE_MEETING_ASG_MIN_CAPACITY
    target_max = settings.LIVE_MEETING_ASG_MAX_CAPACITY

    client.update_auto_scaling_group(
        AutoScalingGroupName=settings.LIVE_MEETING_ASG_NAME,
        MinSize=target_min,
        DesiredCapacity=desired,
        MaxSize=target_max,
    )

    return {
        "changed": True,
        "from": current,
        "to": {
            "min": target_min,
            "desired": desired,
            "max": target_max,
        },
        "required": required,
    }
