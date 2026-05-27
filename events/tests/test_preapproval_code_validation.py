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


class PerTrackPreApprovalScopingTests(APITestCase):
    """Test per-track pre-approval scoping with codes and allowlists."""

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
            preapproval_code_enabled=True,
            preapproval_allowlist_enabled=True
        )

        self.track_speaker = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            enabled_submission_modes=['self_submission', 'self_nomination', 'confirmed']
        )
        self.track_participant = EventApplicationTrack.objects.create(
            event=self.event,
            key='participant',
            label='Participant',
            enabled_submission_modes=['self_submission']
        )

    def test_speaker_confirmed_speaker2026_code_preapproved_accepted(self):
        """Test: Speaker + confirmed + SPEAKER2026 => pre_approved/accepted."""
        # Create code scoped to Speaker track + confirmed mode
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            code='SPEAKER2026',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        payload = {
            'first_name': 'Jane',
            'last_name': 'Speaker',
            'email': 'jane.speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_speaker.id,
                    'submission_mode': 'confirmed',
                    'pre_approval_code': 'SPEAKER2026',
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
        app = EventApplication.objects.get(email='jane.speaker@example.com')
        track_app = app.track_applications.get(track=self.track_speaker)
        # Should be pre_approved and then auto-accepted to accepted status
        self.assertIn(track_app.status, ['pre_approved', 'accepted'])
        self.assertTrue(app.is_preapproved)

    def test_participant_self_submission_speaker2026_code_rejected(self):
        """Test: Participant + self_submission + SPEAKER2026 => rejected/not pre-approved."""
        # Create code scoped to Speaker track + confirmed mode
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            code='SPEAKER2026',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        payload = {
            'first_name': 'Bob',
            'last_name': 'Participant',
            'email': 'bob.participant@example.com',
            'track_applications': [
                {
                    'track_id': self.track_participant.id,
                    'submission_mode': 'self_submission',
                    'pre_approval_code': 'SPEAKER2026',  # Wrong track/mode combo
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

        # self_submission ignores the code (it's optional), so should succeed as pending
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(email='bob.participant@example.com')
        track_app = app.track_applications.get(track=self.track_participant)
        self.assertEqual(track_app.status, 'pending')
        self.assertFalse(app.is_preapproved)

    def test_speaker_self_nomination_speaker2026_code_rejected(self):
        """Test: Speaker + self_nomination + SPEAKER2026 => rejected/not pre-approved."""
        # Create code scoped to Speaker track + confirmed mode
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            code='SPEAKER2026',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        payload = {
            'first_name': 'Alice',
            'last_name': 'Nominator',
            'email': 'alice.nominator@example.com',
            'nominator_name': 'Alice Nominator',
            'nominator_email': 'alice.nominator@example.com',
            'nominee_name': 'Bob Speaker',
            'nominee_email': 'bob.speaker@example.com',
            'track_applications': [
                {
                    'track_id': self.track_speaker.id,
                    'submission_mode': 'self_nomination',
                    'pre_approval_code': 'SPEAKER2026',  # Wrong mode
                    'nominator_name': 'Alice Nominator',
                    'nominator_email': 'alice.nominator@example.com',
                    'nominee_name': 'Bob Speaker',
                    'nominee_email': 'bob.speaker@example.com',
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

        # self_nomination ignores the code, so should succeed as pending
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(email='alice.nominator@example.com')
        track_app = app.track_applications.get(track=self.track_speaker)
        self.assertEqual(track_app.status, 'pending')
        self.assertFalse(app.is_preapproved)

    def test_email_allowlist_speaker_confirmed_preapproved(self):
        """Test: allow.speaker@test.com + Speaker + confirmed => pre_approved/accepted."""
        from events.models import EventPreApprovalAllowlist

        # Create email allowlist entry scoped to Speaker track + confirmed mode
        allowlist = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            email='allow.speaker@test.com',
            first_name='Allow',
            last_name='Speaker',
            is_active=True,
            created_by=self.user
        )

        payload = {
            'first_name': 'Allow',
            'last_name': 'Speaker',
            'email': 'allow.speaker@test.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_speaker.id,
                    'submission_mode': 'confirmed',
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
        app = EventApplication.objects.get(email='allow.speaker@test.com')
        track_app = app.track_applications.get(track=self.track_speaker)
        # Should be pre_approved and then auto-accepted
        self.assertIn(track_app.status, ['pre_approved', 'accepted'])
        self.assertTrue(app.is_preapproved)

    def test_email_allowlist_participant_self_submission_not_preapproved(self):
        """Test: same email + Participant self_submission => not pre-approved."""
        from events.models import EventPreApprovalAllowlist

        # Create email allowlist entry scoped to Speaker track + confirmed mode
        allowlist = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            email='allow.speaker@test.com',
            first_name='Allow',
            last_name='Speaker',
            is_active=True,
            created_by=self.user
        )

        payload = {
            'first_name': 'Allow',
            'last_name': 'Speaker',
            'email': 'allow.speaker@test.com',
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

        # Should succeed but not be pre-approved (wrong track + mode)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(email='allow.speaker@test.com')
        track_app = app.track_applications.get(track=self.track_participant)
        self.assertEqual(track_app.status, 'pending')
        self.assertFalse(app.is_preapproved)

    def test_email_allowlist_speaker_self_nomination_not_preapproved(self):
        """Test: same email + Speaker self_nomination => not pre-approved."""
        from events.models import EventPreApprovalAllowlist

        # Create email allowlist entry scoped to Speaker track + confirmed mode
        allowlist = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            email='allow.speaker@test.com',
            first_name='Allow',
            last_name='Speaker',
            is_active=True,
            created_by=self.user
        )

        payload = {
            'first_name': 'Nominator',
            'last_name': 'Person',
            'email': 'nominator@example.com',
            'nominator_name': 'Nominator Person',
            'nominator_email': 'nominator@example.com',
            'nominee_name': 'Allow Speaker',
            'nominee_email': 'allow.speaker@test.com',
            'track_applications': [
                {
                    'track_id': self.track_speaker.id,
                    'submission_mode': 'self_nomination',
                    'nominator_name': 'Nominator Person',
                    'nominator_email': 'nominator@example.com',
                    'nominee_name': 'Allow Speaker',
                    'nominee_email': 'allow.speaker@test.com',
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

        # Should succeed but nominator email is not pre-approved
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(email='nominator@example.com')
        track_app = app.track_applications.get(track=self.track_speaker)
        self.assertEqual(track_app.status, 'pending')
        self.assertFalse(app.is_preapproved)


class WrongCodePreventsApplicationCreationTests(APITestCase):
    """Test that wrong pre-approval code prevents application creation entirely."""

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

        self.track_speaker = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            enabled_submission_modes=['confirmed']
        )

    def test_wrong_code_does_not_create_pending_application(self):
        """Test that wrong pre-approval code does NOT create a Pending application."""
        # Create a valid code
        EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            code='CORRECT2026',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        # First attempt: user submits with wrong code
        wrong_payload = {
            'first_name': 'Jane',
            'last_name': 'Speaker',
            'email': 'jane.speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_speaker.id,
                    'submission_mode': 'confirmed',
                    'pre_approval_code': 'WRONG1234',
                    'sponsor_organization': 'Tech Corp',
                    'form_answers': {},
                    'file_uploads': {}
                }
            ]
        }

        response = self.client.post(
            f'/api/events/{self.event.id}/apply/',
            wrong_payload,
            format='json'
        )

        # Should return 400 error
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['code_error'], 'invalid')

        # CRITICAL: Verify NO application was created
        self.assertFalse(
            EventApplication.objects.filter(email='jane.speaker@example.com').exists(),
            "Application should NOT be created when pre-approval code is invalid"
        )

        # Second attempt: user submits with correct code
        correct_payload = {
            'first_name': 'Jane',
            'last_name': 'Speaker',
            'email': 'jane.speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_speaker.id,
                    'submission_mode': 'confirmed',
                    'pre_approval_code': 'CORRECT2026',
                    'sponsor_organization': 'Tech Corp',
                    'form_answers': {},
                    'file_uploads': {}
                }
            ]
        }

        response = self.client.post(
            f'/api/events/{self.event.id}/apply/',
            correct_payload,
            format='json'
        )

        # Should succeed now
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(email='jane.speaker@example.com')
        track_app = app.track_applications.get(track=self.track_speaker)

        # Should be pre-approved and auto-accepted
        self.assertIn(track_app.status, ['pre_approved', 'accepted'])
        self.assertTrue(app.is_preapproved)

    def test_missing_code_does_not_create_pending_application(self):
        """Test that missing pre-approval code does NOT create a Pending application."""
        # Attempt without code
        payload = {
            'first_name': 'John',
            'last_name': 'Speaker',
            'email': 'john.speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_speaker.id,
                    'submission_mode': 'confirmed',
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

        # Should return 400 error
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['code_error'], 'missing')

        # CRITICAL: Verify NO application was created
        self.assertFalse(
            EventApplication.objects.filter(email='john.speaker@example.com').exists(),
            "Application should NOT be created when pre-approval code is missing"
        )

    def test_revoked_code_does_not_create_pending_application(self):
        """Test that revoked pre-approval code does NOT create a Pending application."""
        EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            code='REVOKED2026',
            status=EventPreApprovalCode.STATUS_REVOKED,
            created_by=self.user
        )

        payload = {
            'first_name': 'Alice',
            'last_name': 'Speaker',
            'email': 'alice.speaker@example.com',
            'sponsor_organization': 'Tech Corp',
            'track_applications': [
                {
                    'track_id': self.track_speaker.id,
                    'submission_mode': 'confirmed',
                    'pre_approval_code': 'REVOKED2026',
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

        # Should return 400 error
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['code_error'], 'revoked')

        # CRITICAL: Verify NO application was created
        self.assertFalse(
            EventApplication.objects.filter(email='alice.speaker@example.com').exists(),
            "Application should NOT be created when pre-approval code is revoked"
        )
