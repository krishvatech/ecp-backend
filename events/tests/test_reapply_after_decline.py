"""
Test reapplication after application decline.
Allows users to reapply after being declined, reusing the declined application.
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


class ReapplyAfterDeclineTestCase(TestCase):
    """Test that users can reapply after being declined."""

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

    def test_user_can_reapply_after_decline(self):
        """Test that user can successfully reapply after being declined."""
        # Decline the application
        url = f'/api/events/{self.event.id}/applications/{self.app.id}/track-applications/{self.track_app.id}/decline/'
        response = self.reviewer_client.post(url, {'send_email': False}, content_type='application/json')
        self.assertEqual(response.status_code, 200)

        # Verify status is declined
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, 'declined')

        # User reapplies
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

        # Should succeed (not return 400)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['track_applications']), 1)

        # Verify application was reused and reset to pending
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, 'pending')

        # Old declined track app should be deleted, new pending one created
        track_apps = self.app.track_applications.all()
        self.assertEqual(track_apps.count(), 1)
        self.assertEqual(track_apps.first().status, 'pending')

    def test_reapply_shows_correct_status(self):
        """Test that after reapplication, user sees correct application_status."""
        # Decline
        url = f'/api/events/{self.event.id}/applications/{self.app.id}/track-applications/{self.track_app.id}/decline/'
        self.reviewer_client.post(url, {'send_email': False}, content_type='application/json')

        # Reapply
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
        self.assertEqual(response.status_code, 200)

        # Check status via GET endpoint
        response = self.user_client.get(f'/api/events/{self.event.id}/apply/')
        data = response.json()

        # Should show pending (not declined) after reapplication
        self.assertEqual(data['application_status'], 'pending')
        self.assertEqual(data['status'], 'pending')
        self.assertEqual(len(data['track_applications']), 1)
        self.assertEqual(data['track_applications'][0]['status'], 'pending')

    def test_multiple_reapplications(self):
        """Test that user can reapply multiple times after being declined."""
        for attempt in range(3):
            # Decline
            self.app.refresh_from_db()
            track_app = self.app.track_applications.first()
            url = f'/api/events/{self.event.id}/applications/{self.app.id}/track-applications/{track_app.id}/decline/'
            response = self.reviewer_client.post(url, {'send_email': False}, content_type='application/json')
            self.assertEqual(response.status_code, 200)

            # Reapply
            payload = {
                'first_name': 'John',
                'last_name': 'Doe',
                'email': 'applicant@test.com',
                'track_applications': [
                    {
                        'track_id': self.track.id,
                        'submission_mode': 'self_submission',
                        'form_answers': {'attempt': attempt + 2},
                        'file_uploads': {}
                    }
                ]
            }

            response = self.user_client.post(
                f'/api/events/{self.event.id}/apply/',
                json.dumps(payload),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 200)

            # Verify status is pending again
            self.app.refresh_from_db()
            self.assertEqual(self.app.status, 'pending')

        # Final check - should have only 1 application (reused)
        apps = EventApplication.objects.filter(
            event=self.event,
            email='applicant@test.com'
        )
        self.assertEqual(apps.count(), 1)
