"""
Test user-side application status display after admin decline.
Ensures /api/events/{id}/apply/ GET returns correct declined status to user.
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


class UserSideDeclineStatusTestCase(TestCase):
    """Test that user sees correct declined status on event page."""

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

        # Create event with application track
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

        # Create application
        self.app = EventApplication.objects.create(
            event=self.event,
            user=self.applicant,
            email=self.applicant.email,
            first_name='John',
            last_name='Doe',
            status='pending'
        )

        # Create track application
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

    def test_user_sees_declined_status_in_apply_endpoint(self):
        """Test that user gets correct application_status=declined from /api/events/{id}/apply/."""
        # Decline the application
        url = f'/api/events/{self.event.id}/applications/{self.app.id}/track-applications/{self.track_app.id}/decline/'
        response = self.reviewer_client.post(url, {'send_email': False}, content_type='application/json')
        self.assertEqual(response.status_code, 200)

        # User checks their application status
        response = self.user_client.get(f'/api/events/{self.event.id}/apply/')
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Verify declined status in computed application_status field
        self.assertEqual(data['application_status'], 'declined')
        # Verify track applications also show declined
        self.assertEqual(len(data['track_applications']), 1)
        self.assertEqual(data['track_applications'][0]['status'], 'declined')

    def test_multi_track_user_sees_declined_when_all_declined(self):
        """Test that multi-track application shows declined only when all tracks are declined."""
        # Create second track
        track2 = EventApplicationTrack.objects.create(
            event=self.event,
            label='Attendee Track',
            key='attendee',
            is_active=True,
            status='open'
        )

        # Create second track application
        track_app2 = EventApplicationTrackApplication.objects.create(
            application=self.app,
            track=track2,
            status='pending',
            submission_mode='self_submission'
        )

        # Decline only first track
        url = f'/api/events/{self.event.id}/applications/{self.app.id}/track-applications/{self.track_app.id}/decline/'
        self.reviewer_client.post(url, {'send_email': False}, content_type='application/json')

        # User checks status - should still be pending (not all declined)
        response = self.user_client.get(f'/api/events/{self.event.id}/apply/')
        data = response.json()
        self.assertEqual(data['application_status'], 'pending')

        # Now decline second track
        url = f'/api/events/{self.event.id}/applications/{self.app.id}/track-applications/{track_app2.id}/decline/'
        self.reviewer_client.post(url, {'send_email': False}, content_type='application/json')

        # User checks status again - should now be declined (all declined)
        response = self.user_client.get(f'/api/events/{self.event.id}/apply/')
        data = response.json()
        self.assertEqual(data['application_status'], 'declined')

    def test_user_sees_declined_in_event_detail_user_status(self):
        """Test that event detail API returns declined in user_status field."""
        # Decline the application
        url = f'/api/events/{self.event.id}/applications/{self.app.id}/track-applications/{self.track_app.id}/decline/'
        self.reviewer_client.post(url, {'send_email': False}, content_type='application/json')

        # User gets event detail
        response = self.user_client.get(f'/api/events/{self.event.id}/')
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Verify user_status has declined application_status
        user_status = data.get('user_status')
        self.assertIsNotNone(user_status)
        self.assertEqual(user_status['application_status'], 'declined')

    def test_user_cannot_reapply_after_decline(self):
        """Test that user cannot reapply after being declined."""
        # Decline the application
        url = f'/api/events/{self.event.id}/applications/{self.app.id}/track-applications/{self.track_app.id}/decline/'
        self.reviewer_client.post(url, {'send_email': False}, content_type='application/json')

        # User tries to reapply
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

        # Should get 400 error - cannot reapply after decline
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn('decline', data['detail'].lower())
