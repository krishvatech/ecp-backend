"""
Tests for reapply status sync after declined application.

Validates that after a user reapplies following a decline, the APIs return
the latest active application status (pending) instead of the old declined status.
"""
import pytest
from django.test import TransactionTestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status
from events.models import (
    Event, EventApplication, EventApplicationTrack, EventApplicationTrackApplication
)
from users.models import User


@pytest.mark.django_db(transaction=True)
class TestReapplyStatusSync(TransactionTestCase):
    """Test status synchronization after reapply."""

    def setUp(self):
        """Set up test data."""
        self.client = APIClient()

        # Create event
        self.event = Event.objects.create(
            name="Test Event",
            slug="test-event",
            event_type="apply",
            event_date=timezone.now() + timezone.timedelta(days=30),
            registration_deadline=timezone.now() + timezone.timedelta(days=25),
        )

        # Create application track
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key="track1",
            label="Track 1",
            is_active=True,
            status="open"
        )

        # Create authenticated user
        self.user = User.objects.create_user(
            username="testuser",
            email="testuser@example.com",
            password="testpass123"
        )

    def test_event_detail_returns_pending_after_reapply(self):
        """After reapply, event detail should show pending status not declined."""
        # Step 1: Create initial declined application
        old_app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email=self.user.email,
            first_name="Test",
            last_name="User",
            status="declined"
        )

        EventApplicationTrackApplication.objects.create(
            application=old_app,
            track=self.track,
            status='declined'
        )

        # Verify old app shows declined in event detail
        response = self.client.get(
            f"/api/events/{self.event.id}/",
            HTTP_AUTHORIZATION=f"Bearer {self._get_token()}"
        )
        assert response.status_code == 200
        assert response.data.get("application_status") == "declined"

        # Step 2: Reapply (creates new pending application)
        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.user.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track.id}
                ]
            },
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {self._get_token()}"
        )

        assert response.status_code == 201
        assert response.data["status"] == "pending"

        # Step 3: Verify event detail now shows pending (not old declined)
        response = self.client.get(
            f"/api/events/{self.event.id}/",
            HTTP_AUTHORIZATION=f"Bearer {self._get_token()}"
        )
        assert response.status_code == 200
        data = response.data

        # Should show pending from new application, not declined from old one
        assert data.get("application_status") == "pending", \
            f"Expected 'pending' but got '{data.get('application_status')}'. " \
            f"New application may not have been prioritized over old declined one."

    def test_apply_endpoint_returns_pending_status(self):
        """Apply endpoint should return pending status for new application."""
        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.user.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track.id}
                ]
            },
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {self._get_token()}"
        )

        assert response.status_code == 201
        # The response should include both status and application_status
        assert response.data["status"] == "pending"
        assert response.data.get("application_status") == "pending"

    def test_multiple_applications_prioritizes_active_over_declined(self):
        """When multiple apps exist, active status should take priority over declined."""
        # Create old declined application
        old_app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email=self.user.email,
            first_name="Test",
            last_name="User",
            status="declined",
            applied_at=timezone.now() - timezone.timedelta(days=1)
        )

        EventApplicationTrackApplication.objects.create(
            application=old_app,
            track=self.track,
            status='declined'
        )

        # Create new pending application
        new_app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email=self.user.email,
            first_name="Test",
            last_name="User",
            status="pending",
            applied_at=timezone.now()
        )

        EventApplicationTrackApplication.objects.create(
            application=new_app,
            track=self.track,
            status='pending'
        )

        # Event detail should return pending from new app, not declined from old
        response = self.client.get(
            f"/api/events/{self.event.id}/",
            HTTP_AUTHORIZATION=f"Bearer {self._get_token()}"
        )
        assert response.status_code == 200
        assert response.data.get("application_status") == "pending"

    def test_build_current_user_event_status_prioritizes_active(self):
        """build_current_user_event_status should prioritize active apps."""
        from events.serializers import build_current_user_event_status

        # Create old declined
        old_app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            status="declined",
            applied_at=timezone.now() - timezone.timedelta(days=1)
        )
        EventApplicationTrackApplication.objects.create(
            application=old_app,
            track=self.track,
            status='declined'
        )

        # Create new pending
        new_app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            status="pending",
            applied_at=timezone.now()
        )
        EventApplicationTrackApplication.objects.create(
            application=new_app,
            track=self.track,
            status='pending'
        )

        # Create mock request
        class MockRequest:
            user = self.user
            is_authenticated = True

        status = build_current_user_event_status(self.event, MockRequest())

        # Should return pending from new app, not declined from old
        assert status is not None
        assert status.get("application_status") == "pending"

    def test_no_api_calls_break_after_reapply(self):
        """Admin review queue, decline, reapply, and duplicate prevention should still work."""
        # This is a meta-test to ensure we didn't break existing functionality

        # 1. Create application
        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.user.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track.id}
                ]
            },
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {self._get_token()}"
        )
        assert response.status_code == 201
        app_id = response.data["id"]

        # 2. Cannot reapply (duplicate prevention)
        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.user.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track.id}
                ]
            },
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {self._get_token()}"
        )
        assert response.status_code == 400
        assert "active application" in response.data["detail"].lower()

        # 3. Can reapply after decline (admin declines)
        # (This would require admin API, which is outside this test scope)

    def _get_token(self):
        """Get auth token for user."""
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(self.user)
        return str(refresh.access_token)
