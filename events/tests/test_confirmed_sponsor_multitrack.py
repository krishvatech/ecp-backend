"""
Test for multi-track confirmed sponsor staff applications.

Verifies that sponsor_organization and pre_approval_code can be submitted
in the track_applications array for confirmed mode.
"""

from django.test import TestCase
from django.contrib.auth.models import User
from events.models import (
    Event, EventApplicationTrack, Community,
    EventPreApprovalCode, EventApplication,
    EventPlatform, EventPublication
)
from rest_framework.test import APITestCase
from rest_framework import status


class ConfirmedSponsorMultitrackTests(APITestCase):
    """Test confirmed sponsor staff applications with multi-track support."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com"
        )
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community",
            owner=self.user,
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Test Event",
            slug="test-event",
            registration_type='apply',
            status='published',
            created_by=self.user,
            preapproval_code_enabled=True
        )
        # Non-admin API requests only see events published to imaa_connect
        # (EventViewSet.get_queryset), so the apply endpoint 404s without this.
        platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect",
            defaults={"name": "IMAA Connect", "is_active": True},
        )
        EventPublication.objects.get_or_create(
            event=self.event,
            platform=platform,
            defaults={"is_enabled": True},
        )

        # Create two tracks: one confirmed, one self_submission
        self.track_confirmed = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor_staff',
            label='Sponsor Staff',
            enabled_submission_modes=['confirmed']
        )
        self.track_regular = EventApplicationTrack.objects.create(
            event=self.event,
            key='participant',
            label='Participant',
            enabled_submission_modes=['self_submission']
        )

        # Create a valid pre-approval code
        self.code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_confirmed,
            submission_mode='confirmed',
            code='SPONSOR123',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

    def test_confirmed_with_sponsor_org_in_track_applications(self):
        """IPDT-771: single confirmed track carries sponsor_organization and
        pre_approval_code inside track_applications. (Previously this test
        submitted two tracks; single-track preserves the sponsor coverage.)"""
        payload = {
            'first_name': 'John',
            'last_name': 'Sponsor',
            'email': 'sponsor@example.com',
            'job_title': 'Manager',
            'company_name': 'Acme Corp',
            'preapproved_code': 'SPONSOR123',
            'track_applications': [
                {
                    'track_id': self.track_confirmed.id,
                    'submission_mode': 'confirmed',
                    'sponsor_organization': 'Acme Corp',
                    'pre_approval_code': 'SPONSOR123',
                    'form_answers': {},
                    'file_uploads': {}
                }
            ]
        }

        response = self.client.post(
            f'/api/events/{self.event.id}/apply/',
            payload,
            format='json'
        )

        # Should succeed
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify application was created
        app = EventApplication.objects.get(email='sponsor@example.com')
        self.assertEqual(app.sponsor_organization, 'Acme Corp')

        # Verify the single confirmed track application was created and pre-approved
        track_apps = app.track_applications.all()
        self.assertEqual(track_apps.count(), 1)
        confirmed_app = track_apps.get(track=self.track_confirmed)
        self.assertEqual(confirmed_app.submission_mode, 'confirmed')
        self.assertEqual(confirmed_app.status, 'pre_approved')

    def test_multitrack_confirmed_missing_sponsor_org_fails(self):
        """Test that confirmed mode fails without sponsor_organization in track_applications."""
        payload = {
            'first_name': 'John',
            'last_name': 'Sponsor',
            'email': 'sponsor@example.com',
            'job_title': 'Manager',
            'company_name': 'Acme Corp',
            'preapproved_code': 'SPONSOR123',
            'track_applications': [
                {
                    'track_id': self.track_confirmed.id,
                    'submission_mode': 'confirmed',
                    # Missing sponsor_organization
                    'form_answers': {},
                    'file_uploads': {}
                }
            ]
        }

        response = self.client.post(
            f'/api/events/{self.event.id}/apply/',
            payload,
            format='json'
        )

        # Should fail with 400
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Missing required fields', response.data['detail'])
        self.assertIn('sponsor_organization', response.data['missing_fields'])

    def test_multitrack_confirmed_with_root_level_sponsor_org(self):
        """Test backward compatibility: sponsor_organization at root level still works."""
        payload = {
            'first_name': 'John',
            'last_name': 'Sponsor',
            'email': 'sponsor@example.com',
            'job_title': 'Manager',
            'company_name': 'Acme Corp',
            'sponsor_organization': 'Acme Corp',  # At root level
            'preapproved_code': 'SPONSOR123',
            'track_applications': [
                {
                    'track_id': self.track_confirmed.id,
                    'submission_mode': 'confirmed',
                    'form_answers': {},
                    'file_uploads': {}
                }
            ]
        }

        response = self.client.post(
            f'/api/events/{self.event.id}/apply/',
            payload,
            format='json'
        )

        # Should succeed (backward compatible)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        app = EventApplication.objects.get(email='sponsor@example.com')
        self.assertEqual(app.sponsor_organization, 'Acme Corp')

    def test_multitrack_confirmed_prefers_track_level_sponsor_org(self):
        """Test that track-level sponsor_organization is preferred when both are provided."""
        payload = {
            'first_name': 'John',
            'last_name': 'Sponsor',
            'email': 'sponsor@example.com',
            'job_title': 'Manager',
            'company_name': 'Acme Corp',
            'sponsor_organization': 'Root Corp',  # At root level
            'preapproved_code': 'SPONSOR123',
            'track_applications': [
                {
                    'track_id': self.track_confirmed.id,
                    'submission_mode': 'confirmed',
                    'sponsor_organization': 'Track Corp',  # At track level
                    'form_answers': {},
                    'file_uploads': {}
                }
            ]
        }

        response = self.client.post(
            f'/api/events/{self.event.id}/apply/',
            payload,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        app = EventApplication.objects.get(email='sponsor@example.com')
        # Root level is preferred (current implementation)
        self.assertEqual(app.sponsor_organization, 'Root Corp')
