"""
Comprehensive tests for confirmed sponsor staff application flow with pre-approval code validation.

Tests cover:
- Confirmed mode requires pre-approval code or allowlist entry
- Valid pre-approval code enables application
- Invalid/revoked/already_used codes are rejected
- Wrong track/mode code combinations are rejected
- Sponsor/Partner Organisation is required for confirmed mode
- Error messages include exact missing field names
- Pre-approval allowlist entry works for confirmed mode
- Self-submission without code works normally
- Code validation per track and submission_mode
"""

from django.test import TransactionTestCase
from django.contrib.auth.models import User
from django.utils import timezone
from events.models import (
    Event, EventApplication, EventApplicationTrack, Community,
    EventPreApprovalCode, EventPreApprovalAllowlist
)
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
import json


class ConfirmedSponsorStaffApplicationTests(APITestCase):
    """Tests for confirmed sponsor staff application flow."""

    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
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
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor-staff',
            label='Sponsor Staff',
            enabled_submission_modes=['self_submission', 'confirmed']
        )
        self.track_event_level_codes = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor-staff-2',
            label='Sponsor Staff 2',
            enabled_submission_modes=['self_submission', 'confirmed']
        )

    def test_confirmed_mode_requires_pre_approval_code(self):
        """Test that confirmed mode requires pre-approval code."""
        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            'sponsor_organization': 'Acme Corp',
            # Missing preapproved_code
        })

        self.assertEqual(response.status_code, 400)
        self.assertIn('pre_approval_code', response.data.get('missing_fields', []))
        self.assertEqual(response.data.get('submission_mode'), 'confirmed')

    def test_confirmed_mode_requires_sponsor_organization(self):
        """Test that confirmed mode requires sponsor_organization."""
        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            'preapproved_code': 'VALID123',
            # Missing sponsor_organization
        })

        self.assertEqual(response.status_code, 400)
        self.assertIn('sponsor_organization', response.data.get('missing_fields', []))

    def test_confirmed_mode_with_valid_code(self):
        """Test successful application with valid pre-approval code."""
        # Create a valid pre-approval code
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track,
            submission_mode='confirmed',
            code='VALID123',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            'sponsor_organization': 'Acme Corp',
            'preapproved_code': 'VALID123',
        })

        self.assertEqual(response.status_code, 201)
        app = EventApplication.objects.get(email='john@example.com')
        self.assertEqual(app.submission_mode, 'confirmed')
        self.assertEqual(app.sponsor_organization, 'Acme Corp')
        self.assertEqual(app.preapproval_code, code)
        self.assertTrue(app.is_preapproved)
        self.assertEqual(app.status, 'approved')

    def test_confirmed_mode_with_invalid_code(self):
        """Test that invalid code is rejected with specific error."""
        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            'sponsor_organization': 'Acme Corp',
            'preapproved_code': 'INVALID123',
        })

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.get('code_error'), 'invalid')
        self.assertIn('Invalid pre-approval code', response.data.get('detail'))

    def test_confirmed_mode_with_revoked_code(self):
        """Test that revoked code is rejected with specific error."""
        # Create a revoked pre-approval code
        EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track,
            submission_mode='confirmed',
            code='REVOKED123',
            status=EventPreApprovalCode.STATUS_REVOKED,
            created_by=self.user,
            revoked_by=self.user,
            revoked_at=timezone.now()
        )

        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            'sponsor_organization': 'Acme Corp',
            'preapproved_code': 'REVOKED123',
        })

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.get('code_error'), 'revoked')
        self.assertIn('revoked', response.data.get('detail').lower())

    def test_confirmed_mode_with_already_used_code(self):
        """Test that already used code is rejected with specific error."""
        # Create an already used pre-approval code
        old_app = EventApplication.objects.create(
            event=self.event,
            email='olduser@example.com',
            first_name='Old',
            last_name='User',
            submission_mode='confirmed',
            sponsor_organization='Old Corp'
        )
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track,
            submission_mode='confirmed',
            code='USED123',
            status=EventPreApprovalCode.STATUS_USED,
            created_by=self.user,
            used_by_application=old_app,
            used_by_email='olduser@example.com',
            used_at=timezone.now()
        )

        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            'sponsor_organization': 'Acme Corp',
            'preapproved_code': 'USED123',
        })

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.get('code_error'), 'already_used')
        self.assertIn('already been used', response.data.get('detail').lower())

    def test_confirmed_mode_with_wrong_track_code(self):
        """Test that code for wrong track is rejected."""
        other_track = EventApplicationTrack.objects.create(
            event=self.event,
            key='other-track',
            label='Other Track',
            enabled_submission_modes=['confirmed']
        )

        # Create code for other_track
        EventPreApprovalCode.objects.create(
            event=self.event,
            track=other_track,
            submission_mode='confirmed',
            code='WRONGTRACK123',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        # Try to use it for self.track
        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,  # Different track
            'sponsor_organization': 'Acme Corp',
            'preapproved_code': 'WRONGTRACK123',
        })

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.get('code_error'), 'wrong_track_mode')
        self.assertIn('not valid for this track', response.data.get('detail').lower())

    def test_confirmed_mode_with_event_level_code(self):
        """Test that event-level code (track=NULL) works for any track."""
        # Create event-level code
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=None,  # Event-level
            submission_mode='confirmed',
            code='EVENTLEVEL123',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        # Should work for any track
        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            'sponsor_organization': 'Acme Corp',
            'preapproved_code': 'EVENTLEVEL123',
        })

        self.assertEqual(response.status_code, 201)
        app = EventApplication.objects.get(email='john@example.com')
        self.assertEqual(app.preapproval_code, code)

    def test_confirmed_mode_with_allowlist_entry(self):
        """Test that allowlist entry enables application."""
        # Create allowlist entry
        EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track,
            submission_mode='confirmed',
            email='allowlisted@example.com',
            first_name='Jane',
            last_name='Smith',
            is_active=True
        )

        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'Jane',
            'last_name': 'Smith',
            'email': 'allowlisted@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            'sponsor_organization': 'Acme Corp',
            # No preapproved_code needed - allowlist entry sufficient
        })

        self.assertEqual(response.status_code, 201)
        app = EventApplication.objects.get(email='allowlisted@example.com')
        self.assertEqual(app.submission_mode, 'confirmed')
        self.assertTrue(app.is_preapproved)
        self.assertEqual(app.preapproval_source, 'email')

    def test_self_submission_without_code_still_works(self):
        """Test that self_submission mode works without pre-approval code."""
        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'self_submission',
            'track_id': self.track.id,
            # No preapproved_code
            # No sponsor_organization
        })

        self.assertEqual(response.status_code, 201)
        app = EventApplication.objects.get(email='john@example.com')
        self.assertEqual(app.submission_mode, 'self_submission')
        self.assertFalse(app.is_preapproved)
        self.assertEqual(app.status, 'pending')
        self.assertEqual(app.sponsor_organization, '')

    def test_form_schema_endpoint_returns_required_fields(self):
        """Test that form schema endpoint returns required fields per mode."""
        response = self.client.get(
            f'/events/{self.event.id}/application-tracks/{self.track.id}/form-schema/'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['id'], self.track.id)
        self.assertIn('required_fields_by_mode', response.data)

        # Check confirmed mode required fields
        confirmed_fields = response.data['required_fields_by_mode'].get('confirmed', [])
        self.assertIn('first_name', confirmed_fields)
        self.assertIn('last_name', confirmed_fields)
        self.assertIn('email', confirmed_fields)
        self.assertIn('sponsor_organization', confirmed_fields)
        self.assertIn('pre_approval_code', confirmed_fields)

        # Check self_submission doesn't require code/sponsor
        self_submission_fields = response.data['required_fields_by_mode'].get('self_submission', [])
        self.assertIn('first_name', self_submission_fields)
        self.assertNotIn('pre_approval_code', self_submission_fields)
        self.assertNotIn('sponsor_organization', self_submission_fields)

    def test_confirmed_mode_with_code_and_mode_mismatch(self):
        """Test that code valid for different mode is rejected."""
        # Create code for self_submission
        EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track,
            submission_mode='self_submission',  # Only for self_submission
            code='SELFONLY123',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        # Try to use for confirmed
        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            'sponsor_organization': 'Acme Corp',
            'preapproved_code': 'SELFONLY123',
        })

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.get('code_error'), 'wrong_track_mode')

    def test_error_messages_list_missing_fields(self):
        """Test that error messages list all missing required fields."""
        response = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            # Missing email
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            # Missing sponsor_organization
            # Missing preapproved_code
        })

        self.assertEqual(response.status_code, 400)
        missing = response.data.get('missing_fields', [])
        self.assertIn('email', missing)

    def test_confirmed_sponsor_staff_reapplication_after_cancel(self):
        """Test that sponsor staff can reapply with code after canceling."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track,
            submission_mode='confirmed',
            code='REAPPLY123',
            status=EventPreApprovalCode.STATUS_ACTIVE,
            created_by=self.user
        )

        # First application
        response1 = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            'sponsor_organization': 'Acme Corp',
            'preapproved_code': 'REAPPLY123',
        })
        self.assertEqual(response1.status_code, 201)

        # Cancel
        app = EventApplication.objects.get(email='john@example.com')
        app.status = 'cancelled'
        app.save()

        # Reapply with same code
        response2 = self.client.post(f'/events/{self.event.id}/apply/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'submission_mode': 'confirmed',
            'track_id': self.track.id,
            'sponsor_organization': 'Acme Corp Updated',
            'preapproved_code': 'REAPPLY123',
        })

        self.assertEqual(response2.status_code, 201)
        app.refresh_from_db()
        self.assertEqual(app.sponsor_organization, 'Acme Corp Updated')
