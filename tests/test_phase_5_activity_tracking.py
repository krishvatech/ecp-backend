"""
Phase 5: Reduce last_activity_at DB writes for live meeting hot endpoints.

Tests verify that:
1. Hot endpoints skip last_activity_at updates
2. Normal endpoints still update last_activity_at
3. Session behavior unchanged
4. No middleware errors
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.utils import timezone
from events.models import Event, EventRegistration
from datetime import timedelta
import time

User = get_user_model()


class Phase5ActivityTrackingTest(TestCase):
    """Test Phase 5: Skip last_activity_at for hot endpoints"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass"
        )
        # Create user profile
        cls.user.profile.save()

        cls.event = Event.objects.create(
            title="Test Event",
            slug="test-event",
            status="live",
            is_live=True,
            start_time=timezone.now(),
            end_time=timezone.now() + timedelta(hours=2),
        )

    def setUp(self):
        """Reset user's last_activity_at before each test"""
        self.client = Client()
        self.user.profile.last_activity_at = None
        self.user.profile.save()

    def test_normal_api_request_updates_activity(self):
        """Test 1: Normal API request updates last_activity_at"""
        self.client.force_login(self.user)
        self.user.profile.refresh_from_db()
        initial_activity = self.user.profile.last_activity_at

        # Make a normal API request (not a hot endpoint)
        self.client.get(f'/api/events/{self.event.id}/')

        self.user.profile.refresh_from_db()
        new_activity = self.user.profile.last_activity_at

        # Activity should be updated
        self.assertIsNotNone(new_activity, "Activity should be updated for normal requests")
        if initial_activity:
            self.assertGreater(new_activity, initial_activity, "Activity timestamp should increase")
        print("✅ Test 1: Normal API request updates last_activity_at")

    def test_rtk_join_skips_activity_update(self):
        """Test 2: rtk/join/ hot endpoint skips last_activity_at update"""
        self.client.force_login(self.user)

        # Set initial activity time
        initial_time = timezone.now() - timedelta(seconds=120)
        self.user.profile.last_activity_at = initial_time
        self.user.profile.save()

        # Make rtk/join request (hot endpoint)
        self.client.post(f'/api/events/{self.event.id}/rtk/join/', data={})

        self.user.profile.refresh_from_db()
        final_activity = self.user.profile.last_activity_at

        # Activity should NOT be updated
        self.assertEqual(final_activity, initial_time,
                        f"rtk/join should skip activity update. Was: {initial_time}, Now: {final_activity}")
        print("✅ Test 2: rtk/join/ skips last_activity_at update")

    def test_rtk_rejoin_skips_activity_update(self):
        """Test 3: rtk/rejoin/ hot endpoint skips last_activity_at update"""
        self.client.force_login(self.user)

        initial_time = timezone.now() - timedelta(seconds=120)
        self.user.profile.last_activity_at = initial_time
        self.user.profile.save()

        # Make rtk/rejoin request (hot endpoint)
        self.client.post(f'/api/events/{self.event.id}/rtk/rejoin/', data={})

        self.user.profile.refresh_from_db()
        final_activity = self.user.profile.last_activity_at

        self.assertEqual(final_activity, initial_time,
                        "rtk/rejoin should skip activity update")
        print("✅ Test 3: rtk/rejoin/ skips last_activity_at update")

    def test_waiting_room_status_skips_activity_update(self):
        """Test 4: waiting-room/status/ polling endpoint skips activity update"""
        self.client.force_login(self.user)

        initial_time = timezone.now() - timedelta(seconds=120)
        self.user.profile.last_activity_at = initial_time
        self.user.profile.save()

        # Make waiting room status request (hot endpoint - polled frequently)
        self.client.get(f'/api/events/{self.event.id}/waiting-room/status/')

        self.user.profile.refresh_from_db()
        final_activity = self.user.profile.last_activity_at

        self.assertEqual(final_activity, initial_time,
                        "waiting-room/status should skip activity update")
        print("✅ Test 4: waiting-room/status/ skips last_activity_at update")

    def test_lounge_state_skips_activity_update(self):
        """Test 5: lounge-state/ polling endpoint skips activity update"""
        self.client.force_login(self.user)

        initial_time = timezone.now() - timedelta(seconds=120)
        self.user.profile.last_activity_at = initial_time
        self.user.profile.save()

        # Make lounge state request (hot endpoint - polled frequently)
        self.client.get(f'/api/events/{self.event.id}/lounge-state/')

        self.user.profile.refresh_from_db()
        final_activity = self.user.profile.last_activity_at

        self.assertEqual(final_activity, initial_time,
                        "lounge-state should skip activity update")
        print("✅ Test 5: lounge-state/ skips last_activity_at update")

    def test_lounge_join_table_skips_activity_update(self):
        """Test 6: lounge-join-table/ endpoint skips activity update"""
        self.client.force_login(self.user)

        initial_time = timezone.now() - timedelta(seconds=120)
        self.user.profile.last_activity_at = initial_time
        self.user.profile.save()

        # Make lounge join request (hot endpoint)
        self.client.post(f'/api/events/{self.event.id}/lounge-join-table/', data={})

        self.user.profile.refresh_from_db()
        final_activity = self.user.profile.last_activity_at

        self.assertEqual(final_activity, initial_time,
                        "lounge-join-table should skip activity update")
        print("✅ Test 6: lounge-join-table/ skips last_activity_at update")

    def test_lounge_leave_table_skips_activity_update(self):
        """Test 7: lounge-leave-table/ endpoint skips activity update"""
        self.client.force_login(self.user)

        initial_time = timezone.now() - timedelta(seconds=120)
        self.user.profile.last_activity_at = initial_time
        self.user.profile.save()

        # Make lounge leave request (hot endpoint)
        self.client.post(f'/api/events/{self.event.id}/lounge-leave-table/', data={})

        self.user.profile.refresh_from_db()
        final_activity = self.user.profile.last_activity_at

        self.assertEqual(final_activity, initial_time,
                        "lounge-leave-table should skip activity update")
        print("✅ Test 7: lounge-leave-table/ skips last_activity_at update")

    def test_multiple_hot_requests_no_db_writes(self):
        """Test 8: Multiple rapid hot requests don't cause DB writes"""
        self.client.force_login(self.user)

        initial_time = timezone.now() - timedelta(seconds=120)
        self.user.profile.last_activity_at = initial_time
        self.user.profile.save()

        # Make 10 hot endpoint requests rapidly
        for _ in range(10):
            self.client.get(f'/api/events/{self.event.id}/lounge-state/')

        self.user.profile.refresh_from_db()
        final_activity = self.user.profile.last_activity_at

        # Activity should remain unchanged (no DB writes)
        self.assertEqual(final_activity, initial_time,
                        "Multiple hot requests should not trigger activity updates")
        print("✅ Test 8: Multiple rapid hot requests skip DB writes")

    def test_hot_endpoint_then_normal_endpoint_updates_activity(self):
        """Test 9: After hot request, normal request updates activity"""
        self.client.force_login(self.user)

        initial_time = timezone.now() - timedelta(seconds=120)
        self.user.profile.last_activity_at = initial_time
        self.user.profile.save()

        # Make hot endpoint request (should skip)
        self.client.get(f'/api/events/{self.event.id}/lounge-state/')
        self.user.profile.refresh_from_db()
        after_hot = self.user.profile.last_activity_at
        self.assertEqual(after_hot, initial_time, "Hot request should skip activity")

        # Wait 2 seconds and make normal request (should update)
        time.sleep(2)
        self.client.get(f'/api/events/{self.event.id}/')
        self.user.profile.refresh_from_db()
        after_normal = self.user.profile.last_activity_at

        # Activity should be updated now
        self.assertGreater(after_normal, initial_time,
                          "Normal request should update activity after hot request")
        print("✅ Test 9: Hot request skips, normal request updates activity")

    def test_session_behavior_unchanged(self):
        """Test 10: Session/auth behavior unchanged by Phase 5"""
        # Login should still work
        response = self.client.post('/api/auth/login/', {
            'username': 'testuser',
            'password': 'testpass'
        })
        self.assertIn(response.status_code, [200, 201, 202],
                     "Login should succeed")

        # Session should be established
        self.assertIn('sessionid', self.client.cookies or {},
                     "Session cookie should be set")
        print("✅ Test 10: Session behavior unchanged")

    def test_unauthenticated_requests_unaffected(self):
        """Test 11: Unauthenticated requests are unaffected by Phase 5"""
        # Make request without authentication
        response = self.client.get(f'/api/events/{self.event.id}/')
        # Should not error due to middleware
        self.assertNotEqual(response.status_code, 500,
                           "Unauthenticated requests should not error")
        print("✅ Test 11: Unauthenticated requests unaffected")


class Phase5PerformanceMetricsTest(TestCase):
    """Test Phase 5 performance benefits"""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass"
        )
        cls.user.profile.save()
        cls.event = Event.objects.create(
            title="Test Event",
            slug="test-event",
            status="live",
            is_live=True,
        )

    def test_no_db_query_for_hot_endpoints(self):
        """Test 12: Hot endpoints don't trigger profile.save() DB query"""
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        self.client.force_login(self.user)

        # Set initial activity so we're not in the "first time" case
        self.user.profile.last_activity_at = timezone.now() - timedelta(seconds=120)
        self.user.profile.save()

        # Capture queries during hot endpoint request
        with CaptureQueriesContext(connection) as ctx:
            self.client.get(f'/api/events/{self.event.id}/lounge-state/')

        # Check if profile.save() was called (would show UPDATE on auth_user_profile)
        profile_updates = [q for q in ctx.captured_queries
                          if 'auth_user_profile' in q['sql'] and 'UPDATE' in q['sql']]

        self.assertEqual(len(profile_updates), 0,
                        f"Hot endpoint should not update profile. Found {len(profile_updates)} profile updates")
        print(f"✅ Test 12: Hot endpoint had {len(ctx.captured_queries)} queries (no profile update)")

    def test_normal_endpoint_triggers_db_query(self):
        """Test 13: Normal endpoints trigger profile.save() DB query when needed"""
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        self.client.force_login(self.user)

        # Set old activity so update is needed (>60s difference)
        self.user.profile.last_activity_at = timezone.now() - timedelta(minutes=2)
        self.user.profile.save()

        # Capture queries during normal endpoint request
        with CaptureQueriesContext(connection) as ctx:
            self.client.get(f'/api/events/{self.event.id}/')

        # Check if profile was updated
        profile_updates = [q for q in ctx.captured_queries
                          if 'auth_user_profile' in q['sql'] and 'UPDATE' in q['sql']
                          and 'last_activity_at' in q['sql']]

        self.assertGreater(len(profile_updates), 0,
                          "Normal endpoint should update profile when >60s have passed")
        print(f"✅ Test 13: Normal endpoint updated profile (found {len(profile_updates)} updates)")
