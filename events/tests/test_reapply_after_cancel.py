"""
Tests for application resubmission after cancellation.
Verifies that users can reapply after cancelling their application,
and that duplicate active applications are properly rejected.
"""
import pytest
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.contrib.auth import get_user_model

from events.models import (
    Event, EventApplication, EventApplicationTrack,
    EventApplicationTrackApplication, TrackPricingTier
)

User = get_user_model()


class ReapplyAfterCancellationTestCase(APITestCase):
    """Test reapplication flow after cancelling an approved application."""

    def setUp(self):
        """Create test event, user, tracks, and tier."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        # Create application-required event
        self.event = Event.objects.create(
            title='App Required Event',
            slug='app-required-event',
            registration_type='apply',
            status='open',
            is_published=True
        )

        # Create application track
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker Track',
            status='open',
            is_active=True
        )

        # Create free tier
        self.tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Free',
            price=0
        )

        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_reapply_after_cancellation_creates_new_track_app(self):
        """After cancelling, reapply should reuse application and create fresh track app."""
        # 1. Submit application
        url = f'/api/events/{self.event.id}/apply/'
        payload = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'test@example.com',
            'track_id': self.track.id,
        }
        response = self.client.post(url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app_id = response.data['id']

        # 2. Verify application created
        app = EventApplication.objects.get(id=app_id)
        self.assertEqual(app.status, 'pending')
        self.assertEqual(app.email, 'test@example.com')
        self.assertEqual(app.first_name, 'John')

        # 3. Cancel the application
        cancel_url = f'/api/event-registrations/{app_id}/cancel/'
        response = self.client.delete(cancel_url)

        # 4. Verify application is now cancelled
        app.refresh_from_db()
        self.assertEqual(app.status, 'cancelled')

        # 5. Reapply with different data
        payload2 = {
            'first_name': 'Jane',
            'last_name': 'Smith',
            'email': 'test@example.com',
            'track_id': self.track.id,
        }
        response = self.client.post(url, payload2, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # 6. Verify same application was reused (not a new one)
        app.refresh_from_db()
        self.assertEqual(app.id, app_id)
        self.assertEqual(app.status, 'pending')
        self.assertEqual(app.first_name, 'Jane')  # Updated name
        self.assertEqual(app.last_name, 'Smith')  # Updated name

        # 7. Verify track applications were reset (old cancelled ones deleted)
        old_cancelled_count = app.track_applications.filter(status='cancelled').count()
        self.assertEqual(old_cancelled_count, 0)

        # 8. Verify new track application was created
        new_track_app = app.track_applications.filter(status='pending').first()
        self.assertIsNotNone(new_track_app)
        self.assertEqual(new_track_app.track.id, self.track.id)

    def test_cannot_reapply_if_active_application_exists(self):
        """Cannot submit new application if active application exists."""
        # 1. Submit application
        url = f'/api/events/{self.event.id}/apply/'
        payload = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'test@example.com',
            'track_id': self.track.id,
        }
        response = self.client.post(url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # 2. Try to apply again with same email (should fail)
        response = self.client.post(url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('already have an active application', response.data['detail'])

    def test_cannot_reapply_if_approved_application_exists(self):
        """Cannot submit new application if approved application exists."""
        # 1. Create approved application
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='test@example.com',
            first_name='John',
            last_name='Doe',
            status='approved'
        )

        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='accepted'
        )

        # 2. Try to apply again (should fail)
        url = f'/api/events/{self.event.id}/apply/'
        payload = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'test@example.com',
            'track_id': self.track.id,
        }
        response = self.client.post(url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('already have an active application', response.data['detail'])

    def test_cannot_reapply_if_declined(self):
        """Cannot reapply if application was declined."""
        # 1. Create declined application
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='test@example.com',
            first_name='John',
            last_name='Doe',
            status='declined'
        )

        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='declined'
        )

        # 2. Try to apply again (should fail with specific message)
        url = f'/api/events/{self.event.id}/apply/'
        payload = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'test@example.com',
            'track_id': self.track.id,
        }
        response = self.client.post(url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('declined', response.data['detail'].lower())
        self.assertIn('cannot reapply', response.data['detail'].lower())

    def test_duplicate_active_application_returns_clean_400(self):
        """Duplicate active application returns 400 with clear message."""
        # 1. Submit application
        url = f'/api/events/{self.event.id}/apply/'
        payload = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'test@example.com',
            'track_id': self.track.id,
        }
        response = self.client.post(url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # 2. Duplicate submission should return 400 with detail message
        response = self.client.post(url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('detail', response.data)
        self.assertTrue(len(response.data['detail']) > 0)

    def test_reapply_updates_application_fields(self):
        """Reapplication updates all application fields correctly."""
        # 1. Submit initial application
        url = f'/api/events/{self.event.id}/apply/'
        payload1 = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'test@example.com',
            'job_title': 'Engineer',
            'company_name': 'Old Company',
            'track_id': self.track.id,
        }
        response = self.client.post(url, payload1, format='json')
        app_id = response.data['id']

        # 2. Cancel application
        self.client.delete(f'/api/event-registrations/{app_id}/cancel/')

        # 3. Reapply with different data
        payload2 = {
            'first_name': 'Jane',
            'last_name': 'Smith',
            'email': 'test@example.com',
            'job_title': 'Manager',
            'company_name': 'New Company',
            'track_id': self.track.id,
        }
        response = self.client.post(url, payload2, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # 4. Verify all fields were updated
        app = EventApplication.objects.get(id=app_id)
        self.assertEqual(app.first_name, 'Jane')
        self.assertEqual(app.last_name, 'Smith')
        self.assertEqual(app.job_title, 'Manager')
        self.assertEqual(app.company_name, 'New Company')
        self.assertEqual(app.status, 'pending')

    def test_reapply_multiple_times(self):
        """User can cancel and reapply multiple times."""
        url = f'/api/events/{self.event.id}/apply/'
        app_id = None

        for i in range(3):
            # Apply
            payload = {
                'first_name': f'Name{i}',
                'last_name': 'Test',
                'email': 'test@example.com',
                'track_id': self.track.id,
            }
            response = self.client.post(url, payload, format='json')
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

            if app_id is None:
                app_id = response.data['id']
            else:
                # Verify same application is reused
                self.assertEqual(response.data['id'], app_id)

            # Cancel
            if i < 2:  # Don't cancel on last iteration
                response = self.client.delete(f'/api/event-registrations/{app_id}/cancel/')
                self.assertIn(response.status_code, [status.HTTP_204_NO_CONTENT])

        # Final state should be pending
        app = EventApplication.objects.get(id=app_id)
        self.assertEqual(app.status, 'pending')
        self.assertEqual(app.first_name, 'Name2')  # Last submitted name


class MultipleApplicationsTestCase(APITestCase):
    """Test handling of multiple applications from different users."""

    def setUp(self):
        """Create test event and users."""
        self.event = Event.objects.create(
            title='Multi App Event',
            slug='multi-app-event',
            registration_type='apply',
            status='open'
        )

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Track 1',
            status='open',
            is_active=True
        )

        self.user1 = User.objects.create_user(username='user1', email='user1@example.com', password='pass')
        self.user2 = User.objects.create_user(username='user2', email='user2@example.com', password='pass')

        self.client = APIClient()

    def test_multiple_users_different_applications(self):
        """Different users can have their own applications."""
        url = f'/api/events/{self.event.id}/apply/'

        # User 1 applies
        self.client.force_authenticate(user=self.user1)
        response1 = self.client.post(url, {
            'first_name': 'User1',
            'last_name': 'One',
            'email': 'user1@example.com',
            'track_id': self.track.id,
        }, format='json')
        self.assertEqual(response1.status_code, status.HTTP_201_CREATED)

        # User 2 applies
        self.client.force_authenticate(user=self.user2)
        response2 = self.client.post(url, {
            'first_name': 'User2',
            'last_name': 'Two',
            'email': 'user2@example.com',
            'track_id': self.track.id,
        }, format='json')
        self.assertEqual(response2.status_code, status.HTTP_201_CREATED)

        # Verify different applications created
        self.assertNotEqual(response1.data['id'], response2.data['id'])

        # Verify counts
        apps = EventApplication.objects.filter(event=self.event, status='pending')
        self.assertEqual(apps.count(), 2)
