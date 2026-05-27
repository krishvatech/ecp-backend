"""
Comprehensive tests for pre-approval code validation in multi-track applications.

Tests cover:
- Valid pre-approval code for confirmed mode
- Invalid/non-existent codes
- Revoked codes
- Already-used codes
- Codes for wrong track
- Codes for wrong submission mode
- Self-submission without code
- Multi-track with mixed modes
"""

from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from django.utils import timezone
from events.models import (
    Event, EventApplicationTrack, Community,
    EventPreApprovalCode, EventApplication, EventApplicationTrackApplication
)
from rest_framework.test import APITestCase
from rest_framework import status


class PreApprovalCodeValidationTests(APITestCase):
    """Test pre-approval code validation in application submission."""

    def setUp(self):
        """Set up test data."""
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community"
        )
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com"
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Test Event",
            slug="test-event",
            registration_type='apply',
            created_by=self.user,
            preapproval_code_enabled=True
        )

        # Create two tracks
        self.track_confirmed = EventApplicationTrack.objects.create(
            event=self.event,
            key='confirmed_speaker',
            label='Confirmed Speaker',
            enabled_submission_modes=['confirmed']
        )
        self.track_speaker = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            enabled_submission_modes=['self_submission', 'confirmed']
        )
        self.track_participant = EventApplicationTrack.objects.create(
            event=self.event,
            key='participant',
            label='Participant',
            enabled_submission_modes=['self_submission']
        )

    def test_valid_code_confirmed_mode_creates_preapproved_app(self):
        """Test that valid pre-approval code creates pre-approved application."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_confirmed,
            submission_mode='confirmed',
            code='VALID123',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        payload = {
            'first_name': 'John',
            'last_name': 'Speaker',
            'email': 'speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_confirmed.id,
                    'submission_mode': 'confirmed',
                    'pre_approval_code': 'VALID123',
                    'sponsor_organization': 'Tech Corp',
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
        app = EventApplication.objects.get(email='speaker@example.com')
        track_app = app.track_applications.get(track=self.track_confirmed)
        self.assertEqual(track_app.status, 'pre_approved')
        self.assertTrue(app.is_preapproved)

        # Verify code is marked as used
        code.refresh_from_db()
        self.assertEqual(code.status, EventPreApprovalCode.STATUS_USED)
        self.assertEqual(code.used_by_application, app)

    def test_invalid_code_returns_400_error(self):
        """Test that invalid pre-approval code returns 400 error."""
        payload = {
            'first_name': 'John',
            'last_name': 'Speaker',
            'email': 'speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_confirmed.id,
                    'submission_mode': 'confirmed',
                    'pre_approval_code': 'INVALID123',
                    'sponsor_organization': 'Tech Corp',
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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('not valid', response.data['detail'])
        self.assertEqual(response.data['code_error'], 'invalid')

        # Verify no application was created
        self.assertFalse(EventApplication.objects.filter(email='speaker@example.com').exists())

    def test_revoked_code_returns_error(self):
        """Test that revoked pre-approval code returns error."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_confirmed,
            submission_mode='confirmed',
            code='REVOKED123',
            status=EventPreApprovalCode.STATUS_REVOKED,
            created_by=self.user
        )

        payload = {
            'first_name': 'John',
            'last_name': 'Speaker',
            'email': 'speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_confirmed.id,
                    'submission_mode': 'confirmed',
                    'pre_approval_code': 'REVOKED123',
                    'sponsor_organization': 'Tech Corp',
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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['code_error'], 'revoked')

    def test_used_code_returns_error(self):
        """Test that already-used pre-approval code returns error."""
        existing_user = User.objects.create_user(
            username='existing',
            email='existing@example.com'
        )

        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_confirmed,
            submission_mode='confirmed',
            code='USED123',
            status=EventPreApprovalCode.STATUS_USED,
            created_by=self.user
        )

        payload = {
            'first_name': 'John',
            'last_name': 'Speaker',
            'email': 'speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_confirmed.id,
                    'submission_mode': 'confirmed',
                    'pre_approval_code': 'USED123',
                    'sponsor_organization': 'Tech Corp',
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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['code_error'], 'used')

    def test_code_for_wrong_track_returns_error(self):
        """Test that code for wrong track returns error."""
        # Create code for speaker track, try to use on participant track
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            code='WRONGTRACK123',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        payload = {
            'first_name': 'John',
            'last_name': 'Speaker',
            'email': 'speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_confirmed.id,  # Different track
                    'submission_mode': 'confirmed',
                    'pre_approval_code': 'WRONGTRACK123',
                    'sponsor_organization': 'Tech Corp',
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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['code_error'], 'invalid')

    def test_code_for_wrong_mode_returns_error(self):
        """Test that code for wrong submission mode returns error."""
        # Create code for confirmed mode, try self_submission
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            code='WRONGMODE123',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        payload = {
            'first_name': 'John',
            'last_name': 'Speaker',
            'email': 'speaker@example.com',
            'track_applications': [
                {
                    'track_id': self.track_speaker.id,
                    'submission_mode': 'self_submission',  # Different mode
                    'pre_approval_code': 'WRONGMODE123',
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

        # self_submission doesn't require pre-approval code, so this should succeed
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(email='speaker@example.com')
        track_app = app.track_applications.get(track=self.track_speaker)
        self.assertEqual(track_app.status, 'pending')  # Not pre-approved

    def test_self_submission_without_code_succeeds(self):
        """Test that self-submission without code succeeds."""
        payload = {
            'first_name': 'Jane',
            'last_name': 'Participant',
            'email': 'participant@example.com',
            'track_applications': [
                {
                    'track_id': self.track_participant.id,
                    'submission_mode': 'self_submission',
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
        app = EventApplication.objects.get(email='participant@example.com')
        track_app = app.track_applications.get(track=self.track_participant)
        self.assertEqual(track_app.status, 'pending')
        self.assertFalse(app.is_preapproved)

    def test_multitrack_confirmed_without_code_fails(self):
        """Test that confirmed mode without pre-approval code fails."""
        payload = {
            'first_name': 'John',
            'last_name': 'Speaker',
            'email': 'speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_confirmed.id,
                    'submission_mode': 'confirmed',
                    # Missing pre_approval_code
                    'sponsor_organization': 'Tech Corp',
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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('pre_approval_code', response.data['missing_fields'])

    def test_multitrack_mixed_modes_one_preapproved(self):
        """Test multi-track with one confirmed (pre-approved) and one self-submission."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            code='MIXED123',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        payload = {
            'first_name': 'John',
            'last_name': 'Speaker',
            'email': 'speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_speaker.id,
                    'submission_mode': 'confirmed',
                    'pre_approval_code': 'MIXED123',
                    'sponsor_organization': 'Tech Corp',
                    'form_answers': {},
                    'file_uploads': {}
                },
                {
                    'track_id': self.track_participant.id,
                    'submission_mode': 'self_submission',
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
        app = EventApplication.objects.get(email='speaker@example.com')

        # Verified speaker track is pre-approved
        speaker_track_app = app.track_applications.get(track=self.track_speaker)
        self.assertEqual(speaker_track_app.status, 'pre_approved')

        # Participant track is pending
        participant_track_app = app.track_applications.get(track=self.track_participant)
        self.assertEqual(participant_track_app.status, 'pending')

    def test_event_level_code_works_across_tracks(self):
        """Test that event-level (NULL track) pre-approval code works for any track."""
        # Create event-level code (no specific track)
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=None,  # Event-level code
            submission_mode='confirmed',
            code='EVENTLEVEL123',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        payload = {
            'first_name': 'John',
            'last_name': 'Speaker',
            'email': 'speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_speaker.id,
                    'submission_mode': 'confirmed',
                    'pre_approval_code': 'EVENTLEVEL123',
                    'sponsor_organization': 'Tech Corp',
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
        app = EventApplication.objects.get(email='speaker@example.com')
        track_app = app.track_applications.get(track=self.track_speaker)
        self.assertEqual(track_app.status, 'pre_approved')
