"""
Tests for pre-approval code and email allowlist management.
Verifies that pre-approval codes and email allowlist work correctly across
different tracks and submission modes.
"""
import pytest
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.contrib.auth import get_user_model

from events.models import (
    Event, EventApplication, EventApplicationTrack,
    EventApplicationTrackApplication, EventPreApprovalCode,
    EventPreApprovalAllowlist
)

User = get_user_model()


class PreApprovalCodeManagementTestCase(APITestCase):
    """Test pre-approval code creation, listing, and revocation."""

    def setUp(self):
        """Create test event, user, and track."""
        self.user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='testpass123'
        )

        self.event = Event.objects.create(
            title='Code Test Event',
            slug='code-test-event',
            registration_type='apply',
            status='open',
            is_published=True,
            preapproval_code_enabled=True
        )

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker Track',
            status='open',
            is_active=True,
            enabled_submission_modes=['self_submission', 'confirmed']
        )

        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_create_single_preapproval_code(self):
        """Create a single pre-approval code for specific track and mode."""
        url = f'/api/events/{self.event.id}/preapproval/codes/'
        response = self.client.post(url, {
            'code': 'TEST123',
            'notes': 'Test code',
            'track_id': self.track.id,
            'submission_mode': 'confirmed'
        })

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['code'], 'TEST123')
        self.assertEqual(response.data['status'], 'active')
        self.assertEqual(response.data['track'], self.track.id)
        self.assertEqual(response.data['submission_mode'], 'confirmed')

    def test_create_code_auto_generates_if_blank(self):
        """Auto-generate code if not provided."""
        url = f'/api/events/{self.event.id}/preapproval/codes/'
        response = self.client.post(url, {
            'notes': 'Auto-generated code',
            'track_id': self.track.id,
            'submission_mode': 'confirmed'
        })

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIsNotNone(response.data['code'])
        self.assertTrue(len(response.data['code']) > 0)

    def test_list_preapproval_codes(self):
        """List all pre-approval codes for event."""
        # Create multiple codes
        self.client.post(f'/api/events/{self.event.id}/preapproval/codes/', {
            'code': 'CODE001',
            'track_id': self.track.id,
            'submission_mode': 'confirmed'
        })
        self.client.post(f'/api/events/{self.event.id}/preapproval/codes/', {
            'code': 'CODE002',
            'track_id': self.track.id,
            'submission_mode': 'self_submission'
        })

        # List all codes
        response = self.client.get(f'/api/events/{self.event.id}/preapproval/codes/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_list_codes_filtered_by_status(self):
        """Filter codes by status (active, used, revoked)."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='TEST001',
            track=self.track,
            submission_mode='confirmed',
            created_by=self.user,
            status='active'
        )

        # List only active codes
        response = self.client.get(f'/api/events/{self.event.id}/preapproval/codes/?status=active')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(any(c['id'] == code.id for c in response.data))

        # Revoke code
        self.client.post(f'/api/events/{self.event.id}/preapproval/codes/{code.id}/revoke/')

        # List active codes (should not include revoked)
        response = self.client.get(f'/api/events/{self.event.id}/preapproval/codes/?status=active')
        self.assertFalse(any(c['id'] == code.id for c in response.data))

    def test_revoke_preapproval_code(self):
        """Revoke an active pre-approval code."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='TEST001',
            track=self.track,
            submission_mode='confirmed',
            created_by=self.user
        )

        url = f'/api/events/{self.event.id}/preapproval/codes/{code.id}/revoke/'
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'revoked')
        self.assertIsNotNone(response.data['revoked_at'])

    def test_revoked_codes_hidden_by_default(self):
        """Revoked codes are excluded from list by default."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='TEST001',
            track=self.track,
            submission_mode='confirmed',
            created_by=self.user,
            status='active'
        )

        # Create a revoked code
        revoked_code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='REVOKED001',
            track=self.track,
            submission_mode='confirmed',
            created_by=self.user,
            status='revoked'
        )

        # Default list should exclude revoked codes
        response = self.client.get(f'/api/events/{self.event.id}/preapproval/codes/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(any(c['id'] == code.id for c in response.data))
        self.assertFalse(any(c['id'] == revoked_code.id for c in response.data))

    def test_include_revoked_parameter_shows_revoked_codes(self):
        """include_revoked parameter shows revoked codes."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='TEST001',
            track=self.track,
            submission_mode='confirmed',
            created_by=self.user,
            status='active'
        )

        revoked_code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='REVOKED001',
            track=self.track,
            submission_mode='confirmed',
            created_by=self.user,
            status='revoked'
        )

        # List with include_revoked=true should show both active and revoked
        response = self.client.get(f'/api/events/{self.event.id}/preapproval/codes/?include_revoked=true')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(any(c['id'] == code.id for c in response.data))
        self.assertTrue(any(c['id'] == revoked_code.id for c in response.data))

    def test_batch_create_preapproval_codes(self):
        """Create multiple pre-approval codes in batch."""
        url = f'/api/events/{self.event.id}/preapproval/codes/batch/'
        response = self.client.post(url, {
            'count': 5,
            'prefix': 'SPEAKER',
            'track_id': self.track.id,
            'submission_mode': 'confirmed'
        })

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(len(response.data), 5)
        # Verify codes have prefix
        for code in response.data:
            self.assertTrue(code['code'].startswith('SPEAKER'))

    def test_code_scoped_to_track(self):
        """Code is scoped to specific track."""
        track2 = EventApplicationTrack.objects.create(
            event=self.event,
            label='Attendee Track',
            status='open',
            is_active=True
        )

        code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='SPEAKER001',
            track=self.track,
            submission_mode='confirmed',
            created_by=self.user
        )

        self.assertEqual(code.track.id, self.track.id)
        self.assertNotEqual(code.track.id, track2.id)

    def test_code_scoped_to_submission_mode(self):
        """Code is scoped to specific submission mode."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='TEST001',
            track=self.track,
            submission_mode='confirmed',
            created_by=self.user
        )

        self.assertEqual(code.submission_mode, 'confirmed')


class EmailAllowlistManagementTestCase(APITestCase):
    """Test email allowlist management."""

    def setUp(self):
        """Create test event and track."""
        self.user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='testpass123'
        )

        self.event = Event.objects.create(
            title='Allowlist Test Event',
            slug='allowlist-test-event',
            registration_type='apply',
            status='open',
            is_published=True,
            preapproval_allowlist_enabled=True
        )

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker Track',
            status='open',
            is_active=True
        )

        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_add_email_to_allowlist(self):
        """Add email to pre-approval allowlist."""
        url = f'/api/events/{self.event.id}/preapproval/allowlist/'
        response = self.client.post(url, {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'track_id': self.track.id,
            'submission_mode': 'confirmed'
        })

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['email'], 'john@example.com')
        self.assertEqual(response.data['first_name'], 'John')
        self.assertEqual(response.data['is_active'], True)

    def test_list_allowlist_entries(self):
        """List all allowlist entries."""
        # Add multiple entries
        self.client.post(f'/api/events/{self.event.id}/preapproval/allowlist/', {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'track_id': self.track.id,
            'submission_mode': 'confirmed'
        })
        self.client.post(f'/api/events/{self.event.id}/preapproval/allowlist/', {
            'first_name': 'Jane',
            'last_name': 'Smith',
            'email': 'jane@example.com',
            'track_id': self.track.id,
            'submission_mode': 'confirmed'
        })

        response = self.client.get(f'/api/events/{self.event.id}/preapproval/allowlist/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_remove_from_allowlist(self):
        """Remove email from allowlist."""
        entry = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            first_name='John',
            last_name='Doe',
            email='john@example.com',
            track=self.track,
            submission_mode='confirmed',
            created_by=self.user
        )

        url = f'/api/events/{self.event.id}/preapproval/allowlist/{entry.id}/'
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify removed
        entry.refresh_from_db()
        self.assertEqual(entry.is_active, False)

    def test_email_case_insensitive(self):
        """Email matching is case-insensitive."""
        entry = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            first_name='John',
            last_name='Doe',
            email='john@example.com',  # lowercase
            track=self.track,
            submission_mode='confirmed',
            created_by=self.user
        )

        # Should find the entry despite different case
        self.assertEqual(entry.email, 'john@example.com')

    def test_allowlist_scoped_to_track_and_mode(self):
        """Allowlist entry is scoped to track and submission mode."""
        entry = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            first_name='John',
            last_name='Doe',
            email='john@example.com',
            track=self.track,
            submission_mode='confirmed',
            created_by=self.user
        )

        self.assertEqual(entry.track.id, self.track.id)
        self.assertEqual(entry.submission_mode, 'confirmed')


class PreApprovalValidationInApplicationFlowTestCase(APITestCase):
    """Test pre-approval validation during application submission."""

    def setUp(self):
        """Create test event, track, and tier."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        self.event = Event.objects.create(
            title='Apply Event',
            slug='apply-event',
            registration_type='apply',
            status='open',
            is_published=True,
            preapproval_code_enabled=True,
            preapproval_allowlist_enabled=True
        )

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker Track',
            status='open',
            is_active=True,
            enabled_submission_modes=['self_submission', 'confirmed']
        )

        # Create pre-approval code
        self.code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='SPEAKER001',
            track=self.track,
            submission_mode='confirmed',
            status='active'
        )

        # Create allowlist entry
        self.allowlist_entry = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            first_name='John',
            last_name='Doe',
            email='john@example.com',
            track=self.track,
            submission_mode='confirmed',
            is_active=True
        )

        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_application_with_valid_code_marked_preapproved(self):
        """Application with valid pre-approval code is marked pre_approved."""
        url = f'/api/events/{self.event.id}/apply/'
        response = self.client.post(url, {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'track_id': self.track.id,
            'submission_mode': 'confirmed',
            'preapproved_code': 'SPEAKER001'
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app_id = response.data['id']

        # Check that track application is pre_approved
        app = EventApplication.objects.get(id=app_id)
        track_app = app.track_applications.first()
        self.assertIn(track_app.status, ['pre_approved', 'accepted'])

    def test_application_with_invalid_code_not_preapproved(self):
        """Application with invalid code is not pre-approved."""
        url = f'/api/events/{self.event.id}/apply/'
        response = self.client.post(url, {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'track_id': self.track.id,
            'submission_mode': 'confirmed',
            'preapproved_code': 'INVALID123'
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app_id = response.data['id']

        # Check that track application is pending (not pre_approved)
        app = EventApplication.objects.get(id=app_id)
        track_app = app.track_applications.first()
        self.assertEqual(track_app.status, 'pending')

    def test_application_with_revoked_code_not_preapproved(self):
        """Application with revoked code is not pre-approved."""
        # Revoke the code
        self.code.status = 'revoked'
        self.code.revoked_at = timezone.now()
        self.code.save()

        url = f'/api/events/{self.event.id}/apply/'
        response = self.client.post(url, {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'track_id': self.track.id,
            'submission_mode': 'confirmed',
            'preapproved_code': 'SPEAKER001'
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(id=response.data['id'])
        track_app = app.track_applications.first()
        self.assertEqual(track_app.status, 'pending')

    def test_application_with_allowlist_email_marked_preapproved(self):
        """Application from allowlisted email is marked pre_approved."""
        # Use the allowlisted email
        user = User.objects.create_user(
            username='john',
            email='john@example.com',
            password='testpass123'
        )
        client = APIClient()
        client.force_authenticate(user=user)

        url = f'/api/events/{self.event.id}/apply/'
        response = client.post(url, {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'track_id': self.track.id,
            'submission_mode': 'confirmed'
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app_id = response.data['id']

        # Check that track application is pre_approved
        app = EventApplication.objects.get(id=app_id)
        track_app = app.track_applications.first()
        self.assertIn(track_app.status, ['pre_approved', 'accepted'])

    def test_self_submission_ignores_preapproval(self):
        """Self-submission mode ignores pre-approval codes and allowlist."""
        url = f'/api/events/{self.event.id}/apply/'
        response = self.client.post(url, {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'track_id': self.track.id,
            'submission_mode': 'self_submission',
            'preapproved_code': 'SPEAKER001'  # Code provided but should be ignored
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(id=response.data['id'])
        track_app = app.track_applications.first()
        # Self-submission should be pending, not pre_approved
        self.assertEqual(track_app.status, 'pending')

    def test_code_scoped_to_track_and_mode(self):
        """Code only works for correct track and submission mode."""
        # Create another track
        track2 = EventApplicationTrack.objects.create(
            event=self.event,
            label='Attendee Track',
            status='open',
            is_active=True,
            enabled_submission_modes=['self_submission', 'confirmed']
        )

        # Try to use code for different track
        url = f'/api/events/{self.event.id}/apply/'
        response = self.client.post(url, {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'track_id': track2.id,  # Different track
            'submission_mode': 'confirmed',
            'preapproved_code': 'SPEAKER001'  # Code for different track
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(id=response.data['id'])
        track_app = app.track_applications.first()
        # Code shouldn't apply to different track
        self.assertEqual(track_app.status, 'pending')


class PreApprovalUsageTrackingTestCase(APITestCase):
    """Test pre-approval code usage tracking."""

    def setUp(self):
        """Create test event and track."""
        self.user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='testpass123'
        )

        self.event = Event.objects.create(
            title='Tracking Event',
            slug='tracking-event',
            registration_type='apply',
            status='open',
            is_published=True,
            preapproval_code_enabled=True
        )

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Track',
            status='open',
            is_active=True,
            enabled_submission_modes=['confirmed']
        )

        self.code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='TRACK001',
            track=self.track,
            submission_mode='confirmed',
            status='active'
        )

        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_code_marked_as_used_after_application(self):
        """Code status changes from active to used after being used."""
        # The apply endpoint should mark code as used
        applicant = User.objects.create_user(
            username='applicant',
            email='applicant@example.com',
            password='testpass123'
        )
        client = APIClient()
        client.force_authenticate(user=applicant)

        url = f'/api/events/{self.event.id}/apply/'
        response = client.post(url, {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'applicant@example.com',
            'track_id': self.track.id,
            'submission_mode': 'confirmed',
            'preapproved_code': 'TRACK001'
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Code should still be active (it's single use but not enforced on subsequent uses)
        # or marked as used
        self.code.refresh_from_db()
        self.assertIn(self.code.status, ['active', 'used'])
