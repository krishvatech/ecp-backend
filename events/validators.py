"""
Timezone-aware event date-time validation helpers.

All validations work with user-selected timezone, not server time.
Comparisons are done in UTC after converting through the event's timezone.
"""

from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from django.utils import timezone
from datetime import timezone as dt_timezone
from rest_framework import serializers


def _resolve_tz(tz_name: str) -> ZoneInfo:
    """Return ZoneInfo for tz_name; fall back to UTC if invalid."""
    try:
        return ZoneInfo(tz_name or "UTC")
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def get_local_now(tz_name: str):
    """
    Returns (now_utc, today_local) where:
    - now_utc: current UTC-aware datetime
    - today_local: date object representing "today" in the given timezone

    Example:
        now_utc, today = get_local_now("America/New_York")
        # If it's 2026-03-27 05:00 UTC, and NY is UTC-4:
        # now_utc = 2026-03-27 05:00+00:00
        # today = 2026-03-27 (in NY local date)
    """
    now_utc = timezone.now()
    tz = _resolve_tz(tz_name)
    today_local = now_utc.astimezone(tz).date()
    return now_utc, today_local


def to_local_date(dt, tz_name: str):
    """
    Convert an aware datetime to a date in the given timezone.
    Returns None if dt is None.
    """
    if dt is None:
        return None
    tz = _resolve_tz(tz_name)
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, tz)
    return dt.astimezone(tz).date()



def _is_unchanged(new_dt, old_dt, tolerance_seconds=60):
    """
    True if new_dt and old_dt differ by <= tolerance_seconds.
    Used to bypass validation on PATCH requests where the time field
    hasn't actually changed (e.g. user edited other fields).
    """
    if not new_dt or not old_dt:
        return False
    old_utc = old_dt
    if timezone.is_naive(old_dt):
        old_utc = timezone.make_aware(old_dt, dt_timezone.utc)
    return abs((new_dt - old_utc).total_seconds()) <= tolerance_seconds


def validate_non_multiday_event(start_time, end_time, tz_name: str, instance=None):
    """
    Validate times for non-multiday events.

    Rules:
    - start_date must be today or a future date (in user's timezone)
    - if start_date == today: start_time >= now + 30 minutes
    - if start_date > today: any time 00:00–23:59 is allowed (no current-time restriction)
    - end_time must always be greater than start_time
    - end_time must be provided if start_time is provided

    On PATCH requests: if the time field hasn't changed (within 60s tolerance),
    bypass the validation to allow metadata-only updates on past events.

    Args:
        start_time: UTC-aware datetime or None
        end_time: UTC-aware datetime or None
        tz_name: IANA timezone string (e.g. "America/New_York", "Asia/Kolkata")
        instance: The existing Event instance (for PATCH). None for POST.

    Raises:
        rest_framework.serializers.ValidationError with field-level errors
    """
    errors = {}
    now_utc, today_local = get_local_now(tz_name)
    tz = _resolve_tz(tz_name)
    now_local = now_utc.astimezone(tz)
    min_start_local = now_local + timedelta(minutes=30)

    existing_start = getattr(instance, "start_time", None)
    existing_end = getattr(instance, "end_time", None)

    # Check: start_time must be today or future
    if start_time:
        start_date = to_local_date(start_time, tz_name)

        if start_date < today_local:
            # Past date
            if not _is_unchanged(start_time, existing_start):
                errors["start_time"] = "Event date cannot be in the past."
        elif start_date == today_local:
            # Today: must be at least 30 minutes ahead
            start_local = start_time
            if timezone.is_naive(start_local):
                start_local = timezone.make_aware(start_local, tz)
            else:
                start_local = start_local.astimezone(tz)
            if start_local < min_start_local:
                if not _is_unchanged(start_time, existing_start):
                    errors["start_time"] = (
                        "Start time must be at least 30 minutes from now "
                        "when the event is scheduled for today."
                    )
        # else: start_date > today — any time is valid; no restriction

    # Check: end_time > start_time
    if end_time and start_time and end_time <= start_time:
        errors["end_time"] = "End time must be after start time."

    # Check: if end_time provided, start_time must also be provided
    if end_time and not start_time:
        errors["start_time"] = "Provide start_time when setting end_time."

    if errors:
        raise serializers.ValidationError(errors)


def validate_multiday_event(start_time, end_time, tz_name: str, instance=None):
    """
    Validate times for multiday events.

    Rules:
    - start_date >= today (in user's timezone)
    - end_date >= start_date (date-level comparison, not time-level)
    - end_time must be provided if start_time is provided

    On PATCH requests: if the time field hasn't changed, bypass validation.

    Args:
        start_time: UTC-aware datetime or None
        end_time: UTC-aware datetime or None
        tz_name: IANA timezone string
        instance: The existing Event instance (for PATCH). None for POST.

    Raises:
        rest_framework.serializers.ValidationError with field-level errors
    """
    errors = {}
    now_utc, today_local = get_local_now(tz_name)

    existing_start = getattr(instance, "start_time", None)

    # Check: start_date >= today
    if start_time:
        start_date = to_local_date(start_time, tz_name)
        if start_date < today_local:
            if not _is_unchanged(start_time, existing_start):
                errors["start_time"] = "Event start date must be today or a future date."

    # Check: end_date >= start_date (date-level)
    if start_time and end_time:
        start_date = to_local_date(start_time, tz_name)
        end_date = to_local_date(end_time, tz_name)
        if end_date < start_date:
            errors["end_time"] = "Event end date must be on or after the start date."

    # Check: if end_time provided, start_time must also be provided
    if end_time and not start_time:
        errors["start_time"] = "Provide start_time when setting end_time."

    if errors:
        raise serializers.ValidationError(errors)


def validate_session_datetimes(sess_start, sess_end, event, instance=None):
    """
    Validate session times within an event.

    Rules:
    - end_time must be greater than start_time (always)
    - Session times must be within event boundaries
    - If the event is a single-day event scheduled for today:
      - session start_time >= now + 30 minutes
    - If the event is scheduled for a future date:
      - sessions can start at any time (within event bounds)

    The "today" check and "now + 30 minutes" are computed in the event's timezone.

    Args:
        sess_start: UTC-aware datetime or None (session start)
        sess_end: UTC-aware datetime or None (session end)
        event: Event instance with start_time, end_time, timezone attributes
        instance: The existing EventSession instance (for PATCH). None for POST.

    Raises:
        rest_framework.serializers.ValidationError with field-level errors
    """
    errors = {}
    tz_name = (getattr(event, "timezone", None) or "UTC")
    now_utc, today_local = get_local_now(tz_name)
    tz = _resolve_tz(tz_name)
    now_local = now_utc.astimezone(tz)
    min_start_local = now_local + timedelta(minutes=30)

    existing_start = getattr(instance, "start_time", None)

    # Rule: end > start
    if sess_start and sess_end and sess_end <= sess_start:
        errors["end_time"] = "Session end time must be after start time."
        raise serializers.ValidationError(errors)  # early exit; rest depends on valid order

    event_start_date = to_local_date(event.start_time, tz_name) if event.start_time else None
    event_end_date = to_local_date(event.end_time, tz_name) if event.end_time else None
    sess_start_date = to_local_date(sess_start, tz_name) if sess_start else None
    sess_end_date = to_local_date(sess_end, tz_name) if sess_end else None
    is_multi_day = bool(getattr(event, "is_multi_day", False))
    if not is_multi_day and event_start_date and event_end_date and event_end_date > event_start_date:
        # Fallback: treat as multi-day when date span is > 1 day even if flag wasn't set
        is_multi_day = True

    # If event is single-day today, apply 30-minute buffer to sessions
    if event_start_date and event_end_date and event_start_date == event_end_date == today_local:
        if sess_start:
            sess_start_local = sess_start
            if timezone.is_naive(sess_start_local):
                sess_start_local = timezone.make_aware(sess_start_local, tz)
            else:
                sess_start_local = sess_start_local.astimezone(tz)
        else:
            sess_start_local = None

        if sess_start_local and sess_start_local < min_start_local:
            if not _is_unchanged(sess_start, existing_start):
                errors["start_time"] = (
                    "Session start time must be at least 30 minutes from now "
                    "for an event scheduled today."
                )
        if sess_end:
            sess_end_local = sess_end
            if timezone.is_naive(sess_end_local):
                sess_end_local = timezone.make_aware(sess_end_local, tz)
            else:
                sess_end_local = sess_end_local.astimezone(tz)
            end_of_day_local = datetime.combine(today_local, time(23, 59, 59, tzinfo=tz))
            if sess_end_local > end_of_day_local:
                errors["end_time"] = (
                    "Session end time must be no later than 23:59 for an event scheduled today."
                )

    if is_multi_day:
        # Multi-day: validate by date range only (00:00–23:59 on each day)
        if event_start_date and sess_start_date and sess_start_date < event_start_date:
            errors["start_time"] = "Session cannot start before the event start date."
        if event_end_date and sess_end_date and sess_end_date > event_end_date:
            errors["end_time"] = "Session cannot end after the event end date."
    else:
        # Single-day: session must fall within event datetime bounds
        if event.start_time and sess_start and sess_start < event.start_time:
            if "start_time" not in errors:  # don't overwrite 30-min error above
                errors["start_time"] = (
                    f"Session cannot start before the event starts ({event.start_time.isoformat()})."
                )

        # Check: session must not end after event ends
        # Special case: if event ends at midnight (00:00:00), allow full last day
        if event.end_time and sess_end:
            cutoff = event.end_time
            if cutoff.hour == 0 and cutoff.minute == 0 and cutoff.second == 0:
                cutoff = cutoff + timedelta(days=1)
            if sess_end > cutoff:
                errors["end_time"] = (
                    f"Session cannot end after the event ends ({event.end_time.isoformat()})."
                )

    if errors:
        raise serializers.ValidationError(errors)


# ==================== Form File Validators ====================

def validate_headshot(file_obj):
    """
    Validate speaker headshot image.

    Requirements:
    - JPG or PNG format
    - Maximum 10 MB
    - Minimum 1500 x 1500 px

    Args:
        file_obj: UploadedFile instance

    Raises:
        ValidationError: If validation fails
    """
    from django.core.exceptions import ValidationError
    from PIL import Image
    from io import BytesIO

    if not file_obj:
        return

    # Check file size (10 MB = 10 * 1024 * 1024 bytes)
    max_size = 10 * 1024 * 1024
    if file_obj.size > max_size:
        raise ValidationError(
            f"Headshot file is too large. Maximum size is 10 MB, but file is {file_obj.size / 1024 / 1024:.1f} MB."
        )

    # Check file format
    content_type = file_obj.content_type
    if content_type not in ['image/jpeg', 'image/png']:
        raise ValidationError(
            f"Invalid image format. Only JPG and PNG are allowed, but got {content_type}."
        )

    # Check file extension
    file_name = file_obj.name.lower()
    if not (file_name.endswith('.jpg') or file_name.endswith('.jpeg') or file_name.endswith('.png')):
        raise ValidationError(
            "Invalid file extension. Only .jpg, .jpeg, and .png files are allowed."
        )

    # Validate image dimensions
    try:
        # Read image from uploaded file
        img = Image.open(BytesIO(file_obj.read()))
        file_obj.seek(0)  # Reset file pointer for later use

        width, height = img.size
        min_size = 1500

        if width < min_size or height < min_size:
            raise ValidationError(
                f"Image dimensions are too small. Minimum size is {min_size}x{min_size} px, "
                f"but image is {width}x{height} px."
            )
    except (AttributeError, OSError, IOError) as e:
        raise ValidationError(
            f"Unable to read image file. Please ensure the file is a valid image: {str(e)}"
        )


def validate_slide_deck(file_obj):
    """
    Validate speaker slide deck file.

    Requirements:
    - PDF or PPTX format
    - Maximum 50 MB

    Args:
        file_obj: UploadedFile instance

    Raises:
        ValidationError: If validation fails
    """
    from django.core.exceptions import ValidationError

    if not file_obj:
        return

    # Check file size (50 MB = 50 * 1024 * 1024 bytes)
    max_size = 50 * 1024 * 1024
    if file_obj.size > max_size:
        raise ValidationError(
            f"Slide deck file is too large. Maximum size is 50 MB, but file is {file_obj.size / 1024 / 1024:.1f} MB."
        )

    # Check file format and extension
    file_name = file_obj.name.lower()
    content_type = file_obj.content_type

    allowed_content_types = [
        'application/pdf',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    ]

    allowed_extensions = ['.pdf', '.pptx']

    if not any(file_name.endswith(ext) for ext in allowed_extensions):
        raise ValidationError(
            "Invalid file extension. Only .pdf and .pptx files are allowed."
        )

    if content_type not in allowed_content_types:
        raise ValidationError(
            f"Invalid file format. Only PDF and PPTX are allowed, but got {content_type}."
        )


def validate_speaker_bio(bio_text, field_name='bio'):
    """
    Validate speaker bio text (programme_bio).

    Requirements:
    - 100-200 words
    - Third person

    Args:
        bio_text: String containing bio text
        field_name: Name of field for error message

    Returns:
        dict: {'word_count': int, 'valid': bool, 'errors': list}
    """
    if not bio_text:
        return {
            'word_count': 0,
            'valid': False,
            'errors': [f'{field_name} is required']
        }

    # Count words
    words = [w for w in bio_text.split() if w.strip()]
    word_count = len(words)

    errors = []
    if word_count < 100:
        errors.append(f'Bio is too short. Minimum 100 words, but got {word_count} words.')
    if word_count > 200:
        errors.append(f'Bio is too long. Maximum 200 words, but got {word_count} words.')

    return {
        'word_count': word_count,
        'valid': len(errors) == 0,
        'errors': errors
    }


def validate_short_bio(bio_text):
    """
    Validate short bio character count (max 200 characters).

    Args:
        bio_text: String containing short bio

    Raises:
        ValidationError: If bio exceeds 200 characters
    """
    from django.core.exceptions import ValidationError

    if not bio_text:
        raise ValidationError("Short bio is required")

    if len(bio_text) > 200:
        raise ValidationError(
            f"Short bio is too long. Maximum 200 characters, but got {len(bio_text)} characters."
        )


# ==================== SPONSOR MODULES VALIDATORS ====================

def validate_organisation_logo(file_obj, field_name='logo'):
    """Validate organisation logo (PNG, JPEG, SVG, max 5MB)."""
    from django.core.exceptions import ValidationError

    if not file_obj:
        return

    max_size = 5 * 1024 * 1024
    if file_obj.size > max_size:
        raise ValidationError(f'{field_name} is too large. Max 5 MB.')

    allowed_types = ['image/jpeg', 'image/png', 'image/svg+xml']
    if file_obj.content_type not in allowed_types:
        raise ValidationError(f'Invalid format. PNG, JPEG, or SVG only.')


def validate_organisation_description(text):
    """Validate organisation description (50-150 words)."""
    if not text:
        return {'valid': False, 'errors': ['Description is required']}

    words = len([w for w in text.split() if w.strip()])
    errors = []

    if words < 50:
        errors.append(f'Too short. Minimum 50 words, got {words}.')
    if words > 150:
        errors.append(f'Too long. Maximum 150 words, got {words}.')

    return {
        'valid': len(errors) == 0,
        'word_count': words,
        'errors': errors
    }


# ==================== STARTUP MODULES VALIDATORS ====================

def validate_startup_pitch(pitch_text):
    """Validate one-line pitch (max 140 characters)."""
    from django.core.exceptions import ValidationError

    if not pitch_text:
        raise ValidationError('One-line pitch is required')

    if len(pitch_text) > 140:
        raise ValidationError(
            f'Pitch too long. Maximum 140 characters, got {len(pitch_text)}.'
        )


def validate_startup_description(text):
    """Validate startup description (50-100 words)."""
    if not text:
        return {'valid': False, 'errors': ['Description is required']}

    words = len([w for w in text.split() if w.strip()])
    errors = []

    if words < 50:
        errors.append(f'Too short. Minimum 50 words, got {words}.')
    if words > 100:
        errors.append(f'Too long. Maximum 100 words, got {words}.')

    return {
        'valid': len(errors) == 0,
        'word_count': words,
        'errors': errors
    }


def validate_pitch_deck(file_obj):
    """Validate public pitch deck (PDF, max 25MB)."""
    from django.core.exceptions import ValidationError

    if not file_obj:
        return

    max_size = 25 * 1024 * 1024
    if file_obj.size > max_size:
        raise ValidationError('Pitch deck too large. Max 25 MB.')

    if file_obj.content_type != 'application/pdf':
        raise ValidationError('Pitch deck must be PDF format.')


def validate_founder_photos(files):
    """Validate founder photos (JPEG/PNG, max 3MB each, max 3 files)."""
    from django.core.exceptions import ValidationError

    if not files:
        return

    # Handle both single file and list
    files_list = files if isinstance(files, list) else [files]

    if len(files_list) > 3:
        raise ValidationError(f'Too many files. Maximum 3, got {len(files_list)}.')

    for file_obj in files_list:
        if not file_obj:
            continue

        max_size = 3 * 1024 * 1024
        if file_obj.size > max_size:
            raise ValidationError(f'{file_obj.name}: File too large. Max 3 MB each.')

        if file_obj.content_type not in ['image/jpeg', 'image/png']:
            raise ValidationError(f'{file_obj.name}: JPEG or PNG only.')


# ==================== INVESTOR MODULES VALIDATORS ====================

def validate_thesis_tagline(tagline):
    """Validate investment thesis tagline (max 200 characters)."""
    from django.core.exceptions import ValidationError

    if not tagline:
        raise ValidationError('Thesis tagline is required')

    if len(tagline) > 200:
        raise ValidationError(
            f'Tagline too long. Maximum 200 characters, got {len(tagline)}.'
        )
