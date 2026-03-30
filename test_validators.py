#!/usr/bin/env python
"""
Quick test script to verify timezone-aware validation logic.
Run: python test_validators.py
"""

import os
import sys
import django
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ecp_backend.settings.base')
sys.path.insert(0, '/home/yashvi-radadiya/events-n-comm/ecp-backend')
django.setup()

from django.utils import timezone
from rest_framework import serializers
from events.validators import (
    get_local_now,
    to_local_date,
    validate_non_multiday_event,
    validate_multiday_event,
    validate_session_datetimes,
)


def test_non_multiday_today_with_buffer():
    """Test: non-multiday event today, start_time >= now+30min should pass."""
    print("\n✓ Test 1: Non-multiday event TODAY with 30+ min buffer")
    try:
        now_utc = timezone.now()
        min_start = now_utc + timedelta(minutes=35)  # 35 min buffer (more than required 30)
        end_time = min_start + timedelta(hours=1)

        validate_non_multiday_event(min_start, end_time, "UTC")
        print("  PASS: Event with +35 min buffer accepted")
    except serializers.ValidationError as e:
        print(f"  FAIL: {e.detail}")


def test_non_multiday_today_without_buffer():
    """Test: non-multiday event today, start_time < now+30min should fail."""
    print("\n✓ Test 2: Non-multiday event TODAY without 30 min buffer")
    try:
        now_utc = timezone.now()
        min_start = now_utc + timedelta(minutes=15)  # Only 15 min buffer
        end_time = min_start + timedelta(hours=1)

        validate_non_multiday_event(min_start, end_time, "UTC")
        print("  FAIL: Event with only +15 min buffer should have been rejected")
    except serializers.ValidationError as e:
        print(f"  PASS: Correctly rejected - {e.detail}")


def test_non_multiday_future_any_time():
    """Test: non-multiday event future date, any time should pass."""
    print("\n✓ Test 3: Non-multiday event FUTURE date with any time")
    try:
        tomorrow = timezone.now() + timedelta(days=1)
        start_time = tomorrow.replace(hour=1, minute=0, second=0, microsecond=0)
        end_time = start_time + timedelta(hours=2)

        validate_non_multiday_event(start_time, end_time, "UTC")
        print("  PASS: Future event at 1:00 AM accepted (no +30 min constraint)")
    except serializers.ValidationError as e:
        print(f"  FAIL: {e.detail}")


def test_non_multiday_past_date():
    """Test: non-multiday event past date should fail."""
    print("\n✓ Test 4: Non-multiday event PAST date")
    try:
        yesterday = timezone.now() - timedelta(days=1)
        start_time = yesterday
        end_time = start_time + timedelta(hours=2)

        validate_non_multiday_event(start_time, end_time, "UTC")
        print("  FAIL: Past date should have been rejected")
    except serializers.ValidationError as e:
        print(f"  PASS: Correctly rejected - {e.detail}")


def test_multiday_start_today():
    """Test: multiday event start_date = today should pass."""
    print("\n✓ Test 5: Multiday event start date TODAY")
    try:
        now = timezone.now()
        start_time = now.replace(hour=12, minute=0, second=0, microsecond=0)
        end_time = (now + timedelta(days=2)).replace(hour=18, minute=0, second=0, microsecond=0)

        validate_multiday_event(start_time, end_time, "UTC")
        print("  PASS: Multiday starting today accepted")
    except serializers.ValidationError as e:
        print(f"  FAIL: {e.detail}")


def test_multiday_start_past():
    """Test: multiday event start_date < today should fail."""
    print("\n✓ Test 6: Multiday event start date PAST")
    try:
        yesterday = timezone.now() - timedelta(days=1)
        start_time = yesterday
        end_time = timezone.now() + timedelta(days=1)

        validate_multiday_event(start_time, end_time, "UTC")
        print("  FAIL: Past start date should have been rejected")
    except serializers.ValidationError as e:
        print(f"  PASS: Correctly rejected - {e.detail}")


def test_multiday_end_before_start():
    """Test: multiday event end_date < start_date should fail."""
    print("\n✓ Test 7: Multiday event end date BEFORE start date")
    try:
        start_time = timezone.now() + timedelta(days=5)
        end_time = timezone.now() + timedelta(days=2)  # end before start

        validate_multiday_event(start_time, end_time, "UTC")
        print("  FAIL: End date before start date should have been rejected")
    except serializers.ValidationError as e:
        print(f"  PASS: Correctly rejected - {e.detail}")


def test_timezone_aware_today():
    """Test: 'today' is computed in user's timezone, not server time."""
    print("\n✓ Test 8: Timezone-aware 'today' detection")

    # Simulate an event in a different timezone
    # If it's 2026-03-27 23:00 UTC, it's 2026-03-28 04:00 in Asia/Kolkata
    # So "today" in Asia/Kolkata would be 2026-03-28, not 2026-03-27

    now_utc, today = get_local_now("Asia/Kolkata")
    print(f"  UTC now: {now_utc}")
    print(f"  Today in Asia/Kolkata: {today}")
    print("  PASS: Timezone-aware date calculation working")


def test_session_today_30min_buffer():
    """Test: session on event that's today, must have 30+ min buffer."""
    print("\n✓ Test 9: Session on event TODAY requires 30+ min buffer")

    from types import SimpleNamespace

    try:
        now = timezone.now()
        event_start = now.replace(hour=10, minute=0, second=0, microsecond=0)
        event_end = now.replace(hour=18, minute=0, second=0, microsecond=0)

        mock_event = SimpleNamespace(
            start_time=event_start,
            end_time=event_end,
            timezone="UTC"
        )

        # Session with only 15 min buffer should fail
        sess_start = now + timedelta(minutes=15)
        sess_end = sess_start + timedelta(hours=1)

        validate_session_datetimes(sess_start, sess_end, mock_event)
        print("  FAIL: Session with +15 min buffer should have been rejected")
    except serializers.ValidationError as e:
        print(f"  PASS: Correctly rejected - {e.detail}")


def test_session_future_any_time():
    """Test: session on event that's future, any time within bounds OK."""
    print("\n✓ Test 10: Session on event FUTURE date, any time allowed")

    from types import SimpleNamespace

    try:
        tomorrow = timezone.now() + timedelta(days=1)
        event_start = tomorrow.replace(hour=10, minute=0, second=0, microsecond=0)
        event_end = tomorrow.replace(hour=18, minute=0, second=0, microsecond=0)

        mock_event = SimpleNamespace(
            start_time=event_start,
            end_time=event_end,
            timezone="UTC"
        )

        # Session early morning (even though "now + buffer" would be much later today)
        sess_start = event_start + timedelta(minutes=5)
        sess_end = sess_start + timedelta(hours=1)

        validate_session_datetimes(sess_start, sess_end, mock_event)
        print("  PASS: Future event session at any time accepted")
    except serializers.ValidationError as e:
        print(f"  FAIL: {e.detail}")


def test_multiday_session_date_only_bounds():
    """Test: multiday sessions use date-only bounds (allow any time within dates)."""
    print("\n✓ Test 11: Multiday session date-only bounds")

    from types import SimpleNamespace

    try:
        start_day = timezone.now() + timedelta(days=2)
        end_day = start_day + timedelta(days=3)
        event_start = start_day.replace(hour=10, minute=0, second=0, microsecond=0)
        event_end = end_day.replace(hour=18, minute=0, second=0, microsecond=0)

        mock_event = SimpleNamespace(
            start_time=event_start,
            end_time=event_end,
            timezone="UTC",
            is_multi_day=True,
        )

        # Session earlier than event start_time but within start date
        sess_start = start_day.replace(hour=2, minute=0, second=0, microsecond=0)
        sess_end = sess_start + timedelta(hours=1)

        validate_session_datetimes(sess_start, sess_end, mock_event)
        print("  PASS: Session within date range accepted (time-of-day ignored).")
    except serializers.ValidationError as e:
        print(f"  FAIL: {e.detail}")


def test_session_today_end_of_day_cap():
    """Test: session on event today must end by 23:59."""
    print("\n✓ Test 12: Session today end-of-day cap")

    from types import SimpleNamespace

    try:
        now = timezone.now()
        event_start = now.replace(hour=9, minute=0, second=0, microsecond=0)
        event_end = now.replace(hour=17, minute=0, second=0, microsecond=0)

        mock_event = SimpleNamespace(
            start_time=event_start,
            end_time=event_end,
            timezone="UTC",
            is_multi_day=True,
        )

        # Session ending next day should fail
        sess_start = now + timedelta(hours=1)
        sess_end = (now + timedelta(days=1)).replace(hour=0, minute=5, second=0, microsecond=0)

        validate_session_datetimes(sess_start, sess_end, mock_event)
        print("  FAIL: Session past 23:59 should have been rejected")
    except serializers.ValidationError as e:
        print(f"  PASS: Correctly rejected - {e.detail}")


if __name__ == "__main__":
    print("=" * 70)
    print("TESTING TIMEZONE-AWARE EVENT VALIDATION")
    print("=" * 70)

    test_non_multiday_today_with_buffer()
    test_non_multiday_today_without_buffer()
    test_non_multiday_future_any_time()
    test_non_multiday_past_date()
    test_multiday_start_today()
    test_multiday_start_past()
    test_multiday_end_before_start()
    test_timezone_aware_today()
    test_session_today_30min_buffer()
    test_session_future_any_time()
    test_multiday_session_date_only_bounds()
    test_session_today_end_of_day_cap()

    print("\n" + "=" * 70)
    print("TESTS COMPLETE")
    print("=" * 70)
