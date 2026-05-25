"""
FIX 1 Tests: Application submit must create track applications

Verifies that POST /api/events/{eventId}/apply/ creates:
1. One EventApplication
2. One EventApplicationTrackApplication per selected track
3. Stores applicant identity, form answers, files, nominator details
4. Validates track belongs to event, track is open, submission mode is enabled
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch
from rest_framework.test import APIClient
from rest_framework import status
from events.models import (
    Event, EventApplicationTrack, EventApplication, EventApplicationTrackApplication,
    TrackPricingTier, EventRegistration
)

User = get_user_model()


class TrackApplicationCreationTest(TestCase):
    """Test that /apply/ creates EventApplicationTrackApplication records."""

    def setUp(self):
        """Create test event and tracks."""
        self.client = APIClient()
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='pass')
        self.client.force_authenticate(user=self.user)

        # Create event
        self.event = Event.objects.create(
            title='Test Event',
            slug='test-event',
            format='virtual',
            start_time=timezone.now() + timedelta(days=10),
            end_time=timezone.now() + timedelta(days=11),
            organizer_id=self.user.id,
            registration_type='apply',
            status='published'
        )

        # Create application tracks
        self.speaker_track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            status='open',
            is_active=True,
            enabled_submission_modes=['self_submission', 'confirmed'],
            role_mappings_on_acceptance=['speaker', 'attendee']
        )

        self.startup_track = EventApplicationTrack.objects.create(
            event=self.event,
            key='startup',
            label='Startup',
            status='open',
            is_active=True,
            enabled_submission_modes=['self_submission'],
            role_mappings_on_acceptance=['startup', 'attendee']
        )

        # Create pricing tiers
        self.speaker_tier_free = TrackPricingTier.objects.create(
            track=self.speaker_track,
            key='free',
            label='Free',
            price=0,
            is_active=True,
            sort_order=1
        )

        self.startup_tier_paid = TrackPricingTier.objects.create(
            track=self.startup_track,
            key='premium',
            label='Premium',
            price=100,
            is_active=True,
            sort_order=1
        )

    def test_single_track_creates_track_application(self):
        """Test: Single track_id creates one EventApplicationTrackApplication."""
        data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'track_id': self.speaker_track.id,
            'submission_mode': 'self_submission'
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')

        # Verify response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['first_name'], 'John')

        # Verify EventApplication created
        app = EventApplication.objects.get(email='john@example.com')
        self.assertEqual(app.event, self.event)
        self.assertEqual(app.submission_mode, 'self_submission')

        # CRITICAL: Verify EventApplicationTrackApplication created
        track_apps = EventApplicationTrackApplication.objects.filter(application=app)
        self.assertEqual(track_apps.count(), 1)

        track_app = track_apps.first()
        self.assertEqual(track_app.track, self.speaker_track)
        self.assertEqual(track_app.submission_mode, 'self_submission')

    def test_multiple_tracks_creates_multiple_applications(self):
        """Test: Multiple tracks create multiple EventApplicationTrackApplication records."""
        data = {
            'first_name': 'Jane',
            'last_name': 'Smith',
            'email': 'jane@example.com',
            'submission_mode': 'self_submission',
            'track_applications': [
                {'track_id': self.speaker_track.id},
                {'track_id': self.startup_track.id}
            ]
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')

        # Verify response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify EventApplication created
        app = EventApplication.objects.get(email='jane@example.com')
        self.assertEqual(app.event, self.event)

        # CRITICAL: Verify multiple EventApplicationTrackApplication records created
        track_apps = list(app.track_applications.all().order_by('track_id'))
        self.assertEqual(len(track_apps), 2)

        # Check first track application
        self.assertEqual(track_apps[0].track, self.speaker_track)
        self.assertEqual(track_apps[0].submission_mode, 'self_submission')

        # Check second track application
        self.assertEqual(track_apps[1].track, self.startup_track)
        self.assertEqual(track_apps[1].submission_mode, 'self_submission')

    def test_track_application_stores_form_answers_and_files(self):
        """Test: Form answers and files are stored in track application."""
        form_answers = {
            'question_1': 'Answer to question 1',
            'question_2': 'Answer to question 2'
        }
        file_uploads = {
            'file_1': 'https://example.com/file1.pdf',
            'file_2': 'https://example.com/file2.pdf'
        }

        data = {
            'first_name': 'Bob',
            'last_name': 'Johnson',
            'email': 'bob@example.com',
            'track_id': self.speaker_track.id,
            'submission_mode': 'self_submission',
            'form_answers': form_answers,
            'file_uploads': file_uploads
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')

        # Verify response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify data stored in track application
        app = EventApplication.objects.get(email='bob@example.com')
        track_app = app.track_applications.first()

        self.assertEqual(track_app.form_answers, form_answers)
        self.assertEqual(track_app.file_uploads, file_uploads)

    def test_validates_track_belongs_to_event(self):
        """Test: Rejects track that doesn't belong to event."""
        # Create another event with its own track
        other_event = Event.objects.create(
            title='Other Event',
            slug='other-event',
            format='virtual',
            start_time=timezone.now() + timedelta(days=20),
            end_time=timezone.now() + timedelta(days=21),
            organizer_id=self.user.id,
            registration_type='apply',
            status='published'
        )

        other_track = EventApplicationTrack.objects.create(
            event=other_event,
            key='speaker',
            label='Speaker',
            status='open',
            is_active=True
        )

        # Try to apply with other event's track
        data = {
            'first_name': 'Alice',
            'last_name': 'Wonder',
            'email': 'alice@example.com',
            'track_id': other_track.id,
            'submission_mode': 'self_submission'
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')

        # Should reject
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('not found', response.data['detail'].lower())

    def test_validates_submission_mode_enabled(self):
        """Test: Rejects submission mode not enabled for track."""
        # Create track with only self_submission enabled
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='limited',
            label='Limited Track',
            status='open',
            is_active=True,
            enabled_submission_modes=['self_submission']  # Only self_submission
        )

        # Try to apply with third_party_nomination (not enabled)
        data = {
            'first_name': 'Eve',
            'last_name': 'Green',
            'email': 'eve@example.com',
            'track_id': track.id,
            'submission_mode': 'third_party_nomination',
            'nominator_name': 'Someone',
            'nominator_email': 'nominator@example.com',
            'nominee_name': 'Eve',
            'nominee_email': 'eve@example.com'
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')

        # Should reject
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('not enabled', response.data['detail'].lower())

    def test_validates_tier_belongs_to_track(self):
        """Test: Validates tier belongs to requested track."""
        # Create tier for different track
        other_track = EventApplicationTrack.objects.create(
            event=self.event,
            key='investor',
            label='Investor',
            status='open',
            is_active=True
        )

        other_tier = TrackPricingTier.objects.create(
            track=other_track,
            key='premium',
            label='Premium',
            price=500
        )

        # Try to apply to speaker track with investor tier
        data = {
            'first_name': 'Charlie',
            'last_name': 'Brown',
            'email': 'charlie@example.com',
            'track_id': self.speaker_track.id,
            'submission_mode': 'self_submission',
            'tier_preference': other_tier.id  # Wrong tier
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')

        # Should still create application, but tier should be None
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        app = EventApplication.objects.get(email='charlie@example.com')
        track_app = app.track_applications.first()

        # Tier preference should be None since it doesn't belong to this track
        self.assertIsNone(track_app.tier_preference)

    def test_stores_nominator_details_for_third_party(self):
        """Test: Stores nominator details for third_party_nomination."""
        # Create track that enables third_party_nomination
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='nominate',
            label='Nominate',
            status='open',
            is_active=True,
            enabled_submission_modes=['third_party_nomination']
        )

        data = {
            'track_id': track.id,
            'submission_mode': 'third_party_nomination',
            'nominator_name': 'Nominator Name',
            'nominator_email': 'nominator@example.com',
            'nominee_name': 'Nominee Name',
            'nominee_email': 'nominee@example.com'
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')

        # Verify response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify application created
        app = EventApplication.objects.get(email='nominee@example.com')

        # Verify nominator details stored
        self.assertEqual(app.nominator_name, 'Nominator Name')
        self.assertEqual(app.nominator_email, 'nominator@example.com')
        self.assertEqual(app.nominee_name, 'Nominee Name')
        self.assertEqual(app.nominee_email, 'nominee@example.com')

    def test_track_is_open_validation(self):
        """Test: Rejects closed tracks."""
        # Create closed track
        closed_track = EventApplicationTrack.objects.create(
            event=self.event,
            key='closed',
            label='Closed',
            status='closed',
            is_active=False
        )

        data = {
            'first_name': 'David',
            'last_name': 'Gray',
            'email': 'david@example.com',
            'track_id': closed_track.id,
            'submission_mode': 'self_submission'
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(EventApplication.objects.filter(email='david@example.com').exists())
        self.assertFalse(EventApplicationTrackApplication.objects.filter(track=closed_track).exists())

    def test_no_open_tracks_blocks_application_without_side_effects(self):
        """Application-required events with no open tracks must not create legacy parent-only rows."""
        event = Event.objects.create(
            title='No Tracks Event',
            slug='no-tracks-event',
            format='virtual',
            start_time=timezone.now() + timedelta(days=10),
            end_time=timezone.now() + timedelta(days=11),
            organizer_id=self.user.id,
            registration_type='apply',
            status='published'
        )
        data = {
            'first_name': 'No',
            'last_name': 'Tracks',
            'email': 'no-tracks@example.com',
            'submission_mode': 'self_submission'
        }

        with patch('users.email_utils.send_application_acknowledgement_email') as mock_ack:
            response = self.client.post(f'/api/events/{event.id}/apply/', data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data['detail'],
            'Applications are not open yet. No application tracks are available for this event.'
        )
        self.assertEqual(EventApplication.objects.filter(event=event).count(), 0)
        self.assertEqual(EventApplicationTrackApplication.objects.filter(track__event=event).count(), 0)
        mock_ack.assert_not_called()

    def test_single_open_track_defaults_when_no_track_selected(self):
        """If exactly one open track exists, a legacy/simple payload is attached to that track."""
        event = Event.objects.create(
            title='Single Track Event',
            slug='single-track-event',
            format='virtual',
            start_time=timezone.now() + timedelta(days=10),
            end_time=timezone.now() + timedelta(days=11),
            organizer_id=self.user.id,
            registration_type='apply',
            status='published'
        )
        track = EventApplicationTrack.objects.create(
            event=event,
            key='general',
            label='General',
            status='open',
            is_active=True,
            enabled_submission_modes=['self_submission']
        )
        data = {
            'first_name': 'Single',
            'last_name': 'Track',
            'email': 'single-track@example.com'
        }

        response = self.client.post(f'/api/events/{event.id}/apply/', data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(event=event, email='single-track@example.com')
        track_app = EventApplicationTrackApplication.objects.get(application=app)
        self.assertEqual(track_app.track, track)
        self.assertEqual(track_app.status, EventApplicationTrackApplication.STATUS_PENDING)

        queue_response = self.client.get(f'/api/events/{event.id}/review-queue/')
        self.assertEqual(queue_response.status_code, status.HTTP_200_OK)
        results = queue_response.data.get('results', [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['id'], track_app.id)

    def test_multiple_open_tracks_require_track_selection(self):
        """Multiple open tracks must not create parent-only applications."""
        data = {
            'first_name': 'Multi',
            'last_name': 'Track',
            'email': 'multi-track@example.com',
            'submission_mode': 'self_submission'
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Please select an application track before applying.')
        self.assertFalse(EventApplication.objects.filter(event=self.event, email='multi-track@example.com').exists())

    def test_all_closed_or_inactive_tracks_block_application(self):
        """Closed/inactive tracks do not count as open application tracks."""
        event = Event.objects.create(
            title='Closed Tracks Event',
            slug='closed-tracks-event',
            format='virtual',
            start_time=timezone.now() + timedelta(days=10),
            end_time=timezone.now() + timedelta(days=11),
            organizer_id=self.user.id,
            registration_type='apply',
            status='published'
        )
        EventApplicationTrack.objects.create(
            event=event,
            key='closed',
            label='Closed',
            status='closed',
            is_active=True,
            enabled_submission_modes=['self_submission']
        )
        EventApplicationTrack.objects.create(
            event=event,
            key='inactive',
            label='Inactive',
            status='open',
            is_active=False,
            enabled_submission_modes=['self_submission']
        )
        data = {
            'first_name': 'Closed',
            'last_name': 'Tracks',
            'email': 'closed-tracks@example.com',
            'submission_mode': 'self_submission'
        }

        response = self.client.post(f'/api/events/{event.id}/apply/', data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data['detail'],
            'Applications are not open yet. No application tracks are available for this event.'
        )
        self.assertEqual(EventApplication.objects.filter(event=event).count(), 0)

    def test_normal_open_registration_still_works(self):
        """The application-track guard must not affect normal registration events."""
        event = Event.objects.create(
            title='Open Registration Event',
            slug='open-registration-event',
            format='virtual',
            start_time=timezone.now() + timedelta(days=10),
            end_time=timezone.now() + timedelta(days=11),
            organizer_id=self.user.id,
            registration_type='open',
            status='published'
        )

        response = self.client.post(f'/api/events/{event.id}/register/', {}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(EventRegistration.objects.filter(event=event, user=self.user).exists())


class ReviewQueueDisplayTest(TestCase):
    """Test that review queue displays track applications."""

    def setUp(self):
        """Create test data."""
        self.client = APIClient()
        self.user = User.objects.create_user(username='admin', email='admin@example.com', password='pass')
        self.user.is_staff = True
        self.user.is_superuser = True
        self.user.save()
        self.client.force_authenticate(user=self.user)

        # Create event
        self.event = Event.objects.create(
            title='Review Test Event',
            slug='review-test',
            format='virtual',
            start_time=timezone.now() + timedelta(days=10),
            end_time=timezone.now() + timedelta(days=11),
            organizer_id=self.user.id,
            registration_type='apply',
            status='published'
        )

        # Create track
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            status='open',
            is_active=True,
            enabled_submission_modes=['self_submission']
        )

        # Submit application with track
        data = {
            'first_name': 'Applicant',
            'last_name': 'Person',
            'email': 'applicant@example.com',
            'track_id': self.track.id,
            'submission_mode': 'self_submission'
        }
        self.response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')

    def test_review_queue_shows_track_applications(self):
        """Test: Review queue endpoint shows EventApplicationTrackApplication records."""
        # Login as admin
        self.client.force_authenticate(user=self.user)

        # Access review queue
        response = self.client.get(f'/api/events/{self.event.id}/review-queue/')

        # Verify response
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify track applications shown
        results = response.data.get('results', [])
        self.assertGreater(len(results), 0)

        # Verify track application data
        track_app = results[0]
        self.assertEqual(track_app['track']['id'], self.track.id)
        self.assertEqual(track_app['submission_mode'], 'self_submission')


class EventApplicationTrackConsistencyTest(TestCase):
    """Test consistency between EventApplication and EventApplicationTrackApplication."""

    def setUp(self):
        """Create test event and tracks."""
        self.client = APIClient()
        self.user = User.objects.create_user(username='user1', email='user1@example.com', password='pass')
        self.client.force_authenticate(user=self.user)

        self.event = Event.objects.create(
            title='Consistency Test',
            slug='consistency',
            format='hybrid',
            start_time=timezone.now() + timedelta(days=10),
            end_time=timezone.now() + timedelta(days=11),
            organizer_id=self.user.id,
            registration_type='apply',
            status='published'
        )

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='general',
            label='General',
            status='open',
            is_active=True,
            enabled_submission_modes=['self_submission', 'confirmed']
        )

    def test_submission_mode_consistent(self):
        """Test: submission_mode is same in EventApplication and EventApplicationTrackApplication."""
        data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'track_id': self.track.id,
            'submission_mode': 'confirmed',
            'sponsor_organization': 'Test Org'
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        app = EventApplication.objects.get(email='test@example.com')
        track_app = app.track_applications.first()

        # Both should have same submission mode
        self.assertEqual(app.submission_mode, 'confirmed')
        self.assertEqual(track_app.submission_mode, 'confirmed')

    def test_status_consistent(self):
        """Test: status is same in EventApplication and EventApplicationTrackApplication (initially)."""
        data = {
            'first_name': 'Status',
            'last_name': 'Test',
            'email': 'status@example.com',
            'track_id': self.track.id,
            'submission_mode': 'self_submission'
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        app = EventApplication.objects.get(email='status@example.com')
        track_app = app.track_applications.first()

        # Both should have pending status
        self.assertEqual(app.status, 'pending')
        self.assertEqual(track_app.status, 'pending')
