"""
Test reapplication flow after decline with improved duplicate checking.
Verifies that declined/cancelled applications can be reused while blocking
actual pending/approved applications.
"""
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.utils import timezone
from events.models import (
    Event, EventApplication, EventApplicationTrack,
    EventApplicationTrackApplication
)
import json

User = get_user_model()


class ReapplyAfterDeclineFixedTestCase(TestCase):
    """Test reapplication after decline with proper duplicate checking."""

    def setUp(self):
        """Set up test event, tracks, and applications."""
        self.reviewer = User.objects.create_user(
            username='reviewer',
            email='reviewer@test.com',
            password='testpass123'
        )

        self.applicant = User.objects.create_user(
            username='applicant',
            email='applicant@test.com',
            password='testpass123'
        )

        # Create event
        self.event = Event.objects.create(
            title='Test Event',
            start_time=timezone.now() + timezone.timedelta(days=1),
            end_time=timezone.now() + timezone.timedelta(days=2),
            registration_type='apply',
            event_format='virtual',
            created_by=self.reviewer
        )

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker Track',
            key='speaker',
            is_active=True,
            status='open'
        )

        # Create initial application
        self.app = EventApplication.objects.create(
            event=self.event,
            user=self.applicant,
            email=self.applicant.email,
            first_name='John',
            last_name='Doe',
            status='pending'
        )

        self.track_app = EventApplicationTrackApplication.objects.create(
            application=self.app,
            track=self.track,
            status='pending',
            submission_mode='self_submission'
        )

        self.reviewer_client = Client()
        self.reviewer_client.login(username='reviewer', password='testpass123')

        self.user_client = Client()
        self.user_client.login(username='applicant', password='testpass123')

    def test_cannot_reapply_with_pending_application(self):
        """Test that user cannot reapply when they have a pending application."""
        payload = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'applicant@test.com',
            'track_applications': [
                {
                    'track_id': self.track.id,
                    'submission_mode': 'self_submission',
                    'form_answers': {},
                    'file_uploads': {}
                }
            ]
        }

        response = self.user_client.post(
            f'/api/events/{self.event.id}/apply/',
            json.dumps(payload),
            content_type='application/json'
        )

        # Should fail - already have pending app
        self.assertEqual(response.status_code, 400)
        self.assertIn('active', response.json()['detail'].lower())

    def test_can_reapply_after_decline(self):
        """Test that user can reapply after being declined."""
        # Decline the application
        url = f'/api/events/{self.event.id}/applications/{self.app.id}/track-applications/{self.track_app.id}/decline/'
        response = self.reviewer_client.post(url, {'send_email': False}, content_type='application/json')
        self.assertEqual(response.status_code, 200)

        # Verify status is declined
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, 'declined')

        # User reapplies - should succeed
        payload = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'applicant@test.com',
            'track_applications': [
                {
                    'track_id': self.track.id,
                    'submission_mode': 'self_submission',
                    'form_answers': {},
                    'file_uploads': {}
                }
            ]
        }

        response = self.user_client.post(
            f'/api/events/{self.event.id}/apply/',
            json.dumps(payload),
            content_type='application/json'
        )

        # Should succeed
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data['status'], 'pending')
        self.assertEqual(data['application_status'], 'pending')

        # Verify old application was reused
        apps = EventApplication.objects.filter(
            event=self.event,
            email='applicant@test.com'
        )
        self.assertEqual(apps.count(), 1)
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, 'pending')

    def test_cannot_reapply_with_approved_application(self):
        """Test that user cannot reapply when already approved."""
        # Approve the application
        self.app.status = 'approved'
        self.app.save()
        self.track_app.status = 'accepted'
        self.track_app.save()

        payload = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'applicant@test.com',
            'track_applications': [
                {
                    'track_id': self.track.id,
                    'submission_mode': 'self_submission',
                    'form_answers': {},
                    'file_uploads': {}
                }
            ]
        }

        response = self.user_client.post(
            f'/api/events/{self.event.id}/apply/',
            json.dumps(payload),
            content_type='application/json'
        )

        # Should fail - already approved
        self.assertEqual(response.status_code, 400)
        self.assertIn('active', response.json()['detail'].lower())

    def test_can_reapply_after_cancellation(self):
        """Test that user can reapply after cancelling their application."""
        # Cancel the application
        self.app.status = 'cancelled'
        self.app.save()
        self.track_app.status = 'cancelled'
        self.track_app.save()

        # User reapplies - should succeed
        payload = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'applicant@test.com',
            'track_applications': [
                {
                    'track_id': self.track.id,
                    'submission_mode': 'self_submission',
                    'form_answers': {},
                    'file_uploads': {}
                }
            ]
        }

        response = self.user_client.post(
            f'/api/events/{self.event.id}/apply/',
            json.dumps(payload),
            content_type='application/json'
        )

        # Should succeed
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data['status'], 'pending')

    def test_reapply_response_includes_application_status(self):
        """Test that reapply response includes computed application_status field."""
        # Decline and reapply
        url = f'/api/events/{self.event.id}/applications/{self.app.id}/track-applications/{self.track_app.id}/decline/'
        self.reviewer_client.post(url, {'send_email': False}, content_type='application/json')

        payload = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'applicant@test.com',
            'track_applications': [
                {
                    'track_id': self.track.id,
                    'submission_mode': 'self_submission',
                    'form_answers': {},
                    'file_uploads': {}
                }
            ]
        }

        response = self.user_client.post(
            f'/api/events/{self.event.id}/apply/',
            json.dumps(payload),
            content_type='application/json'
        )

        data = response.json()
        # Should have both status and application_status
        self.assertIn('status', data)
        self.assertIn('application_status', data)
        self.assertEqual(data['application_status'], 'pending')
