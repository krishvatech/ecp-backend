"""
Service functions for 1:1 networking meeting slot calculations.
"""
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import models
from pytz import timezone as pytz_timezone
from django.core.exceptions import ValidationError

from events.models import (
    EventNetworkingSettings,
    NetworkingMeeting,
    EventSession,
)


def get_available_networking_slots(
    event,
    requester_registration,
    recipient_registration,
    duration_minutes,
):
    """
    Calculate available 1:1 networking meeting slots for two attendees.

    Args:
        event: Event instance
        requester_registration: EventRegistration instance (person requesting)
        recipient_registration: EventRegistration instance (person being requested)
        duration_minutes: int - desired meeting duration in minutes

    Returns:
        List of dicts with format:
        [
            {
                "start_time": "2026-06-10T10:30:00+05:30",
                "end_time": "2026-06-10T10:40:00+05:30"
            }
        ]

    Raises:
        ValidationError: If settings invalid, duration not allowed, etc.
    """

    try:
        settings = EventNetworkingSettings.objects.get(event=event)
    except EventNetworkingSettings.DoesNotExist:
        raise ValidationError("Networking settings not configured for this event.")

    if not settings.enabled:
        raise ValidationError("Networking is not enabled for this event.")

    if duration_minutes not in settings.duration_options_minutes:
        raise ValidationError(
            f"Duration {duration_minutes} not allowed. "
            f"Allowed durations: {settings.duration_options_minutes}"
        )

    # Get event timezone
    event_tz = _get_event_timezone(event)

    # Check if allowed_windows is configured
    if not settings.allowed_windows:
        raise ValidationError(
            "No networking windows configured. Please set 'Allowed Networking Windows' in event settings."
        )

    # Convert allowed windows to timezone-aware datetime ranges
    datetime_ranges = _parse_allowed_windows(settings.allowed_windows, event_tz)

    if not datetime_ranges:
        raise ValidationError(
            "Failed to parse networking windows. Check that dates and times are in correct format "
            "(date: YYYY-MM-DD, time: HH:MM or HH:MM AM/PM)."
        )

    # Split ranges into slots based on duration
    all_slots = []
    for start_dt, end_dt in datetime_ranges:
        slots = _split_into_slots(start_dt, end_dt, duration_minutes)
        all_slots.extend(slots)

    # NOTE: We don't filter by event bounds because networking windows are
    # independently configured and may span beyond the main event hours.
    # For example, a pre-event or post-event networking window.

    # Remove slots conflicting with EventSession/programme blocks
    all_slots = _remove_session_conflicts(all_slots, event)

    # Remove slots where requester has ACCEPTED meetings
    all_slots = _remove_requester_conflicts(all_slots, requester_registration)

    # Remove slots where recipient has ACCEPTED meetings
    all_slots = _remove_recipient_conflicts(all_slots, recipient_registration)

    # Format as output
    return _format_slots(all_slots, event_tz)


def _get_event_timezone(event):
    """Get pytz timezone object for event."""
    try:
        return pytz_timezone(event.timezone)
    except Exception:
        return pytz_timezone('UTC')


def _parse_allowed_windows(allowed_windows_data, event_tz):
    """
    Convert allowed_windows JSONField data to list of (start_dt, end_dt) tuples.

    Expected format:
    [
        {
            "date": "2026-06-10",
            "start": "10:30",  or "10:30 AM"
            "end": "11:30"     or "05:00 PM"
        }
    ]

    Returns:
        List of (start_datetime, end_datetime) tuples (timezone-aware)
    """
    if not allowed_windows_data:
        return []

    def parse_time_str(time_str):
        """Parse time in either HH:MM (24h) or HH:MM AM/PM (12h) format."""
        time_str = time_str.strip()

        # Try 24-hour format first
        try:
            return datetime.strptime(time_str, "%H:%M").time()
        except ValueError:
            pass

        # Try 12-hour format with AM/PM
        for fmt in ["%I:%M %p", "%I:%M%p"]:
            try:
                return datetime.strptime(time_str, fmt).time()
            except ValueError:
                pass

        # If all fail, raise error
        raise ValueError(f"Invalid time format: {time_str}")

    datetime_ranges = []

    for window in allowed_windows_data:
        try:
            date_str = window.get("date")
            start_str = window.get("start")
            end_str = window.get("end")

            if not all([date_str, start_str, end_str]):
                continue

            # Parse date and times
            date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
            start_time = parse_time_str(start_str)
            end_time = parse_time_str(end_str)

            # Combine into naive datetime then localize
            start_dt_naive = datetime.combine(date_obj, start_time)
            end_dt_naive = datetime.combine(date_obj, end_time)

            start_dt = event_tz.localize(start_dt_naive)
            end_dt = event_tz.localize(end_dt_naive)

            # Validate end > start
            if end_dt > start_dt:
                datetime_ranges.append((start_dt, end_dt))

        except (KeyError, ValueError, TypeError):
            continue

    return datetime_ranges


def _split_into_slots(start_dt, end_dt, duration_minutes):
    """
    Split a datetime range into non-overlapping slots of given duration.

    Returns:
        List of (slot_start, slot_end) tuples
    """
    slots = []
    current = start_dt

    while current + timedelta(minutes=duration_minutes) <= end_dt:
        slot_end = current + timedelta(minutes=duration_minutes)
        slots.append((current, slot_end))
        current = slot_end

    return slots


def _filter_by_event_bounds(slots, event):
    """Remove slots outside event start/end dates."""
    if not event.start_time or not event.end_time:
        return slots

    filtered = []
    for slot_start, slot_end in slots:
        if slot_start >= event.start_time and slot_end <= event.end_time:
            filtered.append((slot_start, slot_end))

    return filtered


def _remove_session_conflicts(slots, event):
    """
    Remove slots overlapping with EventSession/programme blocks.

    Only blocks sessions that are NOT "networking" type, since 1:1 meetings
    can happen during dedicated networking sessions.
    """
    # Get all non-networking EventSession blocks for this event
    # (allow 1:1 meetings during dedicated networking sessions)
    sessions = EventSession.objects.filter(event=event).exclude(session_type="networking")

    filtered_slots = []
    for slot_start, slot_end in slots:
        has_conflict = False

        for session in sessions:
            # Check overlap: start_a < end_b and end_a > start_b
            if slot_start < session.end_time and slot_end > session.start_time:
                has_conflict = True
                break

        if not has_conflict:
            filtered_slots.append((slot_start, slot_end))

    return filtered_slots


def _remove_requester_conflicts(slots, requester_registration):
    """Remove slots where requester has ACCEPTED meetings overlapping."""
    # Get ACCEPTED meetings for requester
    accepted_meetings = NetworkingMeeting.objects.filter(
        requester=requester_registration,
        status="accepted"
    )

    return _remove_slots_with_overlaps(slots, accepted_meetings)


def _remove_recipient_conflicts(slots, recipient_registration):
    """Remove slots where recipient has ACCEPTED meetings overlapping."""
    # Get ACCEPTED meetings for recipient
    accepted_meetings = NetworkingMeeting.objects.filter(
        recipient=recipient_registration,
        status="accepted"
    )

    return _remove_slots_with_overlaps(slots, accepted_meetings)


def _remove_slots_with_overlaps(slots, meetings):
    """
    Generic helper to remove slots overlapping with meetings.

    Only checks ACCEPTED meetings (status="accepted").
    Uses overlap rule: start_a < end_b and end_a > start_b
    """
    filtered_slots = []

    for slot_start, slot_end in slots:
        has_conflict = False

        for meeting in meetings:
            # Check overlap
            if slot_start < meeting.end_time and slot_end > meeting.start_time:
                has_conflict = True
                break

        if not has_conflict:
            filtered_slots.append((slot_start, slot_end))

    return filtered_slots


def _format_slots(slots, event_tz):
    """
    Format slots as output with ISO 8601 datetime strings including timezone.

    Returns:
        List of dicts with start_time and end_time (ISO format with timezone)
    """
    formatted = []

    for slot_start, slot_end in slots:
        formatted.append({
            "start_time": slot_start.isoformat(),
            "end_time": slot_end.isoformat(),
        })

    return formatted


def check_duplicate_pending_meeting(requester_registration, recipient_registration):
    """
    Check if there's already an active pending or suggested meeting between these two attendees.

    Returns:
        Existing meeting if found, None otherwise
    """
    existing = NetworkingMeeting.objects.filter(
        event_id=requester_registration.event_id,
        status__in=['pending', 'suggested']
    ).filter(
        (models.Q(requester=requester_registration, recipient=recipient_registration) |
         models.Q(requester=recipient_registration, recipient=requester_registration))
    ).first()

    return existing


def check_attendee_meeting_overlaps(registration, proposed_start_time, proposed_end_time, exclude_meeting_id=None):
    """
    Check if attendee has any ACCEPTED meeting overlapping with proposed time.

    Args:
        registration: EventRegistration instance
        proposed_start_time: datetime
        proposed_end_time: datetime
        exclude_meeting_id: ID of meeting to exclude from check (for reschedules)

    Returns:
        List of overlapping ACCEPTED meetings (empty list if none)
    """
    overlaps = NetworkingMeeting.objects.filter(
        status='accepted'
    ).filter(
        models.Q(requester=registration) | models.Q(recipient=registration)
    ).filter(
        start_time__lt=proposed_end_time,
        end_time__gt=proposed_start_time
    )

    if exclude_meeting_id:
        overlaps = overlaps.exclude(id=exclude_meeting_id)

    return list(overlaps)


def check_table_availability(table, proposed_start_time, proposed_end_time, exclude_meeting_id=None):
    """
    Check if table has any ACCEPTED meeting overlapping with proposed time.

    Args:
        table: NetworkingTable instance
        proposed_start_time: datetime
        proposed_end_time: datetime
        exclude_meeting_id: ID of meeting to exclude from check

    Returns:
        List of overlapping ACCEPTED meetings using table
    """
    overlaps = NetworkingMeeting.objects.filter(
        table=table,
        status='accepted',
        start_time__lt=proposed_end_time,
        end_time__gt=proposed_start_time
    )

    if exclude_meeting_id:
        overlaps = overlaps.exclude(id=exclude_meeting_id)

    return list(overlaps)
