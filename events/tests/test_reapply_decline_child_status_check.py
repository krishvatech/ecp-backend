"""
Tests for reapply-after-decline with child track application status checking.

This test suite validates that the backend properly checks child EventApplicationTrackApplication
statuses instead of just checking parent EventApplication status when determining if a user
can reapply.
"""
import pytest
from django.test import TransactionTestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status
from events.models import (
    Event, EventApplication, EventApplicationTrack, EventApplicationTrackApplication
)


@pytest.mark.django_db(transaction=True)
class TestReapplyDeclineChildStatusCheck(TransactionTestCase):
    """Test child track application status checking for reapply logic."""

    def setUp(self):
        """Set up test data."""
        self.client = APIClient()

        # Create event
        self.event = Event.objects.create(
            name="Test Event",
            event_type="apply",
            event_date=timezone.now() + timezone.timedelta(days=30),
            registration_deadline=timezone.now() + timezone.timedelta(days=25),
        )

        # Create application tracks
        self.track1 = EventApplicationTrack.objects.create(
            event=self.event,
            key="track1",
            label="Track 1",
            is_active=True,
            status="open"
        )
        self.track2 = EventApplicationTrack.objects.create(
            event=self.event,
            key="track2",
            label="Track 2",
            is_active=True,
            status="open"
        )

        self.email = "testuser@example.com"

    def test_block_reapply_if_any_child_pending(self):
        """Should block reapply if ANY child has pending status."""
        # Create application with one pending and one declined child
        app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="pending"
        )

        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            status='pending'
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            status='declined'
        )

        # Try to reapply
        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id},
                    {"track_id": self.track2.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 400
        assert "active application" in response.data["detail"].lower()

    def test_block_reapply_if_any_child_preapproved(self):
        """Should block reapply if ANY child has pre_approved status."""
        app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="approved"
        )

        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            status='pre_approved'
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            status='declined'
        )

        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id},
                    {"track_id": self.track2.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 400

    def test_block_reapply_if_any_child_accepted(self):
        """Should block reapply if ANY child has accepted status."""
        app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="approved"
        )

        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            status='accepted'
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            status='declined'
        )

        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id},
                    {"track_id": self.track2.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 400

    def test_block_reapply_if_any_child_waitlisted(self):
        """Should block reapply if ANY child has waitlisted status."""
        app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="pending"
        )

        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            status='waitlisted'
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            status='declined'
        )

        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id},
                    {"track_id": self.track2.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 400

    def test_allow_reapply_if_all_children_declined(self):
        """Should allow reapply if ALL children are declined."""
        app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="declined"
        )

        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            status='declined'
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            status='declined'
        )

        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id},
                    {"track_id": self.track2.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 201
        assert response.data["status"] == "pending"

        # Verify application was reused
        assert EventApplication.objects.filter(
            event=self.event,
            email=self.email
        ).count() == 1

    def test_allow_reapply_if_all_children_cancelled(self):
        """Should allow reapply if ALL children are cancelled."""
        app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="cancelled"
        )

        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            status='cancelled'
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            status='cancelled'
        )

        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id},
                    {"track_id": self.track2.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 201
        assert response.data["status"] == "pending"

    def test_allow_reapply_if_all_children_mix_declined_cancelled(self):
        """Should allow reapply if ALL children are declined or cancelled."""
        app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="declined"
        )

        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            status='declined'
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            status='cancelled'
        )

        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id},
                    {"track_id": self.track2.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 201
        assert response.data["status"] == "pending"

    def test_parent_status_updated_to_declined_when_all_children_declined(self):
        """Should update parent status to declined when all children are declined."""
        app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="pending"
        )

        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            status='declined'
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            status='declined'
        )

        # The parent status should be updated to 'declined' by the apply endpoint
        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id},
                    {"track_id": self.track2.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 201

        # Verify parent status is now 'declined'
        app.refresh_from_db()
        assert app.status == 'declined'

    def test_reuse_application_deletes_old_declined_tracks(self):
        """When reusing an application, should delete old declined track applications."""
        app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="declined"
        )

        track_app1 = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            status='declined'
        )
        track_app2 = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            status='declined'
        )

        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id},
                    {"track_id": self.track2.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 201

        # Verify old track applications are deleted
        assert not EventApplicationTrackApplication.objects.filter(
            id__in=[track_app1.id, track_app2.id]
        ).exists()

        # Verify new ones are created with pending status
        new_tracks = list(app.track_applications.all())
        assert len(new_tracks) == 2
        for track_app in new_tracks:
            assert track_app.status == 'pending'

    def test_multiple_applications_checks_latest_first(self):
        """Should check applications in order (most recent first)."""
        # Create an old application (all declined)
        old_app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="declined",
            applied_at=timezone.now() - timezone.timedelta(days=10)
        )

        EventApplicationTrackApplication.objects.create(
            application=old_app,
            track=self.track1,
            status='declined'
        )

        # Create a newer application (has pending)
        new_app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="pending",
            applied_at=timezone.now()
        )

        EventApplicationTrackApplication.objects.create(
            application=new_app,
            track=self.track1,
            status='pending'
        )

        # Should block due to newer app having pending
        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 400

    def test_legacy_application_without_children(self):
        """Should handle legacy applications without track applications."""
        # Create legacy application (no children)
        app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="pending"
        )

        # Should block due to pending parent status
        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 400

    def test_legacy_declined_application_allows_reapply(self):
        """Should allow reapply for legacy declined applications without children."""
        app = EventApplication.objects.create(
            event=self.event,
            email=self.email,
            first_name="Test",
            last_name="User",
            status="declined"
        )

        response = self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "email": self.email,
                "first_name": "Test",
                "last_name": "User",
                "track_applications": [
                    {"track_id": self.track1.id}
                ]
            },
            format="json"
        )

        assert response.status_code == 201
