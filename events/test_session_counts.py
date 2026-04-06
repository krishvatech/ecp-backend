"""
Tests for session counts and hours calculation feature.
"""
from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from rest_framework.test import APIClient
from .models import Event, EventSession, Community


class SessionCountsTestCase(TestCase):
    """Test session counts by type and hours calculation."""

    def setUp(self):
        """Set up test data."""
        self.client = APIClient()

        # Create users
        self.admin_user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass'
        )
        self.regular_user = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='userpass'
        )

        # Create community
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community",
            created_by=self.admin_user
        )

        # Create multi-day event
        now = timezone.now()
        self.event = Event.objects.create(
            community=self.community,
            title="Multi-Day Event",
            slug="multi-day-event",
            description="Test event",
            start_time=now,
            end_time=now + timedelta(days=2),
            timezone="UTC",
            is_multi_day=True,
            created_by=self.admin_user,
            hours_calculation_session_types=["main", "breakout", "workshop"]
        )

        # Create sessions of different types
        base_time = now

        # 1 main session (2 hours)
        EventSession.objects.create(
            event=self.event,
            title="Main Session",
            session_type="main",
            start_time=base_time,
            end_time=base_time + timedelta(hours=2),
            display_order=1
        )

        # 2 breakout sessions (1 hour each)
        EventSession.objects.create(
            event=self.event,
            title="Breakout 1",
            session_type="breakout",
            start_time=base_time + timedelta(hours=3),
            end_time=base_time + timedelta(hours=4),
            display_order=2
        )
        EventSession.objects.create(
            event=self.event,
            title="Breakout 2",
            session_type="breakout",
            start_time=base_time + timedelta(hours=5),
            end_time=base_time + timedelta(hours=6),
            display_order=3
        )

        # 1 workshop (3 hours)
        EventSession.objects.create(
            event=self.event,
            title="Workshop",
            session_type="workshop",
            start_time=base_time + timedelta(hours=7),
            end_time=base_time + timedelta(hours=10),
            display_order=4
        )

        # 1 networking session (1.5 hours) - NOT included in default calculation
        EventSession.objects.create(
            event=self.event,
            title="Networking",
            session_type="networking",
            start_time=base_time + timedelta(hours=11),
            end_time=base_time + timedelta(hours=12, minutes=30),
            display_order=5
        )

    def test_session_counts(self):
        """Test that session counts are correct."""
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(f'/api/events/{self.event.id}/')

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Verify counts
        self.assertEqual(data['main_sessions_count'], 1, "Should have 1 main session")
        self.assertEqual(data['breakout_sessions_count'], 2, "Should have 2 breakout sessions")
        self.assertEqual(data['workshops_count'], 1, "Should have 1 workshop")
        self.assertEqual(data['networking_count'], 1, "Should have 1 networking session")

    def test_hours_calculation_with_default_types(self):
        """Test hours calculation with default session types (excludes networking)."""
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(f'/api/events/{self.event.id}/')

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Default: main (2h) + breakout (2h) + workshop (3h) = 7h
        self.assertEqual(data['calculated_hours_minutes'], 420, "Should be 7 hours = 420 minutes")
        self.assertEqual(data['calculated_hours_display'], "7h 0m", "Should display as '7h 0m'")

    def test_hours_calculation_with_all_types(self):
        """Test hours calculation including networking."""
        self.event.hours_calculation_session_types = ["main", "breakout", "workshop", "networking"]
        self.event.save()

        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(f'/api/events/{self.event.id}/')

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # All types: main (2h) + breakout (2h) + workshop (3h) + networking (1.5h) = 8.5h
        self.assertEqual(data['calculated_hours_minutes'], 510, "Should be 8.5 hours = 510 minutes")
        self.assertEqual(data['calculated_hours_display'], "8h 30m", "Should display as '8h 30m'")

    def test_hours_calculation_with_only_main(self):
        """Test hours calculation with only main sessions."""
        self.event.hours_calculation_session_types = ["main"]
        self.event.save()

        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(f'/api/events/{self.event.id}/')

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Only main: 2h = 120 minutes
        self.assertEqual(data['calculated_hours_minutes'], 120, "Should be 2 hours = 120 minutes")
        self.assertEqual(data['calculated_hours_display'], "2h 0m", "Should display as '2h 0m'")

    def test_hours_calculation_empty_list(self):
        """Test hours calculation with empty session types list."""
        self.event.hours_calculation_session_types = []
        self.event.save()

        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(f'/api/events/{self.event.id}/')

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Empty list uses default: main (2h) + breakout (2h) + workshop (3h) = 7h
        self.assertEqual(data['calculated_hours_minutes'], 420, "Should use default when empty")

    def test_admin_can_update_hours_calculation_types(self):
        """Test that admin can update hours_calculation_session_types."""
        self.client.force_authenticate(user=self.admin_user)

        response = self.client.patch(
            f'/api/events/{self.event.id}/',
            {
                'hours_calculation_session_types': ["main", "networking"]
            },
            format='json'
        )

        self.assertEqual(response.status_code, 200, "Admin update should succeed")
        data = response.json()
        self.assertEqual(data['hours_calculation_session_types'], ["main", "networking"])

    def test_non_admin_cannot_update_hours_calculation_types(self):
        """Test that non-admin users cannot update hours_calculation_session_types."""
        self.client.force_authenticate(user=self.regular_user)

        response = self.client.patch(
            f'/api/events/{self.event.id}/',
            {
                'title': 'Updated Title',  # This should work
                'hours_calculation_session_types': ["main", "networking"]  # This should fail
            },
            format='json'
        )

        # Should get validation error about hours_calculation_session_types
        self.assertEqual(response.status_code, 400, "Non-admin update should fail")
        data = response.json()
        self.assertIn('hours_calculation_session_types', data, "Should have error for hours_calculation_session_types")

    def test_unauthenticated_cannot_update_hours_calculation_types(self):
        """Test that unauthenticated users cannot update hours_calculation_session_types."""
        response = self.client.patch(
            f'/api/events/{self.event.id}/',
            {
                'hours_calculation_session_types': ["main", "networking"]
            },
            format='json'
        )

        self.assertEqual(response.status_code, 403, "Unauthenticated update should fail with 403")

    def test_backward_compatibility_missing_field(self):
        """Test that events created before this feature work with defaults."""
        # Create event without hours_calculation_session_types
        old_event = Event.objects.create(
            community=self.community,
            title="Old Event",
            slug="old-event",
            description="Event before feature",
            start_time=timezone.now(),
            end_time=timezone.now() + timedelta(days=1),
            timezone="UTC",
            is_multi_day=True,
            created_by=self.admin_user,
            # hours_calculation_session_types not set - will be []
        )

        # Add a session
        EventSession.objects.create(
            event=old_event,
            title="Session",
            session_type="main",
            start_time=timezone.now(),
            end_time=timezone.now() + timedelta(hours=1),
            display_order=1
        )

        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(f'/api/events/{old_event.id}/')

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Should use default calculation
        self.assertEqual(data['calculated_hours_minutes'], 60, "Should use default for old event")
        self.assertEqual(data['calculated_hours_display'], "1h 0m")
