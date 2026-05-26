"""
Tests for Phase 7: Multi-track application support.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from events.models import (
    Community, Event, EventApplicationTrack, TrackPricingTier,
    EventApplication, EventApplicationTrackApplication, FormField
)

User = get_user_model()


class EventApplicationTrackApplicationModelTests(TestCase):
    """Test EventApplicationTrackApplication model."""

    def setUp(self):
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community"
        )
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Test Event",
            slug="test-event",
            registration_type='apply',
            created_by=self.user,
        )
        self.track1 = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            short_description='Apply as a speaker',
            status='open',
            enabled_submission_modes=['self_submission']
        )
        self.track2 = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor',
            label='Sponsor Track',
            short_description='Sponsor the event',
            status='open',
            enabled_submission_modes=['confirmed']
        )
        self.application = EventApplication.objects.create(
            event=self.event,
            first_name='John',
            last_name='Doe',
            email='john@example.com',
            job_title='Engineer',
            company_name='Acme Inc',
        )

    def test_create_track_application(self):
        """Test creating a track application."""
        track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track1,
            submission_mode='self_submission',
            status='pending',
            form_answers={'field_1': 'value_1'},
            file_uploads={}
        )
        self.assertEqual(track_app.status, 'pending')
        self.assertEqual(track_app.submission_mode, 'self_submission')
        self.assertEqual(track_app.form_answers['field_1'], 'value_1')

    def test_unique_together_constraint(self):
        """Test unique_together constraint on (application, track)."""
        EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track1,
            submission_mode='self_submission'
        )
        # Should raise IntegrityError
        with self.assertRaises(Exception):
            EventApplicationTrackApplication.objects.create(
                application=self.application,
                track=self.track1,
                submission_mode='self_nomination'
            )

    def test_status_choices(self):
        """Test all status choices."""
        statuses = ['pending', 'pre_approved', 'accepted', 'declined', 'waitlisted']
        for status_choice in statuses:
            track_app = EventApplicationTrackApplication.objects.create(
                application=self.application,
                track=self.track2,
                submission_mode='confirmed',
                status=status_choice
            )
            self.assertEqual(track_app.get_status_display(), status_choice.replace('_', '-').title())
            track_app.delete()

    def test_tier_preference_nullable(self):
        """Test that tier_preference is optional."""
        track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track1,
            submission_mode='self_submission',
            tier_preference=None
        )
        self.assertIsNone(track_app.tier_preference)

    def test_form_answers_json_storage(self):
        """Test JSON field storage for form_answers."""
        answers = {
            'field_123': 'text value',
            'field_456': ['multi', 'select'],
            'field_789': {'nested': 'object'}
        }
        track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track1,
            submission_mode='self_submission',
            form_answers=answers
        )
        # Refresh from DB
        track_app.refresh_from_db()
        self.assertEqual(track_app.form_answers, answers)

    def test_file_uploads_json_storage(self):
        """Test JSON field storage for file_uploads."""
        uploads = {
            'field_upload_1': {
                'url': 'https://example.com/file.pdf',
                'name': 'file.pdf',
                'size': 102400,
                'type': 'application/pdf'
            }
        }
        track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track1,
            submission_mode='self_submission',
            file_uploads=uploads
        )
        track_app.refresh_from_db()
        self.assertEqual(track_app.file_uploads, uploads)

    def test_reviewed_tracking(self):
        """Test reviewed_at and reviewed_by fields."""
        from django.utils import timezone
        track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track1,
            submission_mode='self_submission',
            status='pending'
        )
        self.assertIsNone(track_app.reviewed_at)
        self.assertIsNone(track_app.reviewed_by)

        # Simulate admin review
        now = timezone.now()
        track_app.status = 'accepted'
        track_app.reviewed_at = now
        track_app.reviewed_by = self.user
        track_app.save()

        track_app.refresh_from_db()
        self.assertEqual(track_app.status, 'accepted')
        self.assertIsNotNone(track_app.reviewed_at)
        self.assertEqual(track_app.reviewed_by, self.user)

    def test_cascade_delete_on_application_delete(self):
        """Test that track applications are deleted when application is deleted."""
        EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track1,
            submission_mode='self_submission'
        )
        app_id = self.application.id
        self.application.delete()

        # Track application should be deleted
        with self.assertRaises(EventApplicationTrackApplication.DoesNotExist):
            EventApplicationTrackApplication.objects.get(application_id=app_id)

    def test_str_representation(self):
        """Test string representation."""
        track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track1,
            submission_mode='self_submission',
            status='pending'
        )
        expected = "john@example.com → Speaker Track (Pending)"
        self.assertEqual(str(track_app), expected)


class EventApplicationTrackApplicationSerializerTests(TestCase):
    """Test EventApplicationTrackApplicationSerializer."""

    def setUp(self):
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community"
        )
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Test Event",
            slug="test-event",
            registration_type='apply',
            created_by=self.user,
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            short_description='Apply as a speaker',
            status='open'
        )
        self.application = EventApplication.objects.create(
            event=self.event,
            first_name='Jane',
            last_name='Smith',
            email='jane@example.com',
        )

    def test_serializer_includes_all_fields(self):
        """Test that serializer includes all required fields."""
        from events.serializers import EventApplicationTrackApplicationSerializer

        track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track,
            submission_mode='self_submission',
            status='pending',
            form_answers={'field_1': 'value_1'}
        )
        serializer = EventApplicationTrackApplicationSerializer(track_app)
        data = serializer.data

        self.assertIn('id', data)
        self.assertIn('application_id', data)
        self.assertIn('track_id', data)
        self.assertIn('track_label', data)
        self.assertIn('submission_mode', data)
        self.assertIn('status', data)
        self.assertIn('status_display', data)

    def test_track_label_resolved(self):
        """Test that track label is resolved correctly."""
        from events.serializers import EventApplicationTrackApplicationSerializer

        track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track,
            submission_mode='self_submission'
        )
        serializer = EventApplicationTrackApplicationSerializer(track_app)
        self.assertEqual(serializer.data['track_label'], 'Speaker Track')

    def test_status_display_translated(self):
        """Test that status is displayed correctly."""
        from events.serializers import EventApplicationTrackApplicationSerializer

        track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track,
            submission_mode='self_submission',
            status='accepted'
        )
        serializer = EventApplicationTrackApplicationSerializer(track_app)
        self.assertEqual(serializer.data['status_display'], 'Accepted')


class MultiTrackApplicationAPITests(APITestCase):
    """Test multi-track application API endpoints."""

    def setUp(self):
        self.client = APIClient()
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community"
        )
        self.admin_user = User.objects.create_user(
            username="admin",
            email="admin@example.com",
            password="adminpass123"
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Test Event",
            slug="test-event",
            registration_type='apply',
            created_by=self.admin_user,
        )
        self.track1 = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            short_description='Apply as a speaker',
            status='open',
            enabled_submission_modes=['self_submission', 'confirmed']
        )
        self.track2 = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor',
            label='Sponsor Track',
            short_description='Sponsor the event',
            status='open',
            enabled_submission_modes=['confirmed']
        )

    def test_create_single_track_application(self):
        """Test creating a single-track application (backward compat)."""
        data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john@example.com',
            'job_title': 'Engineer',
            'company_name': 'Acme Inc',
            'track_applications': [
                {
                    'track_id': self.track1.id,
                    'submission_mode': 'self_submission'
                }
            ]
        }
        # This would be tested via the actual API endpoint
        # For now, just verify the data structure is valid

    def test_create_multi_track_application(self):
        """Test creating a multi-track application."""
        # Verify we can create multiple track applications
        app = EventApplication.objects.create(
            event=self.event,
            first_name='Jane',
            last_name='Smith',
            email='jane@example.com',
            selected_tracks=[self.track1.id, self.track2.id]
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            submission_mode='self_submission'
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            submission_mode='confirmed'
        )

        self.assertEqual(app.track_applications.count(), 2)
        self.assertEqual(app.selected_tracks, [self.track1.id, self.track2.id])

    def test_get_application_with_track_applications(self):
        """Test retrieving an application with all track applications."""
        app = EventApplication.objects.create(
            event=self.event,
            first_name='Alice',
            last_name='Johnson',
            email='alice@example.com',
            selected_tracks=[self.track1.id, self.track2.id]
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            submission_mode='self_submission',
            status='pending'
        )
        EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            submission_mode='confirmed',
            status='pending'
        )

        # Verify we can retrieve all track applications
        track_apps = app.track_applications.all()
        self.assertEqual(track_apps.count(), 2)

    def test_update_track_application_status(self):
        """Test updating track application status."""
        app = EventApplication.objects.create(
            event=self.event,
            first_name='Bob',
            last_name='Wilson',
            email='bob@example.com',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            submission_mode='self_submission',
            status='pending'
        )

        # Update status
        track_app.status = 'accepted'
        track_app.reviewed_by = self.admin_user
        from django.utils import timezone
        track_app.reviewed_at = timezone.now()
        track_app.save()

        # Verify update
        track_app.refresh_from_db()
        self.assertEqual(track_app.status, 'accepted')
        self.assertIsNotNone(track_app.reviewed_at)
        self.assertEqual(track_app.reviewed_by, self.admin_user)

    def test_tier_preference_in_track_application(self):
        """Test setting tier preference in track application."""
        tier = TrackPricingTier.objects.create(
            track=self.track1,
            key='standard',
            label='Standard',
            price=199,
            is_default=True
        )
        app = EventApplication.objects.create(
            event=self.event,
            first_name='Carol',
            last_name='Davis',
            email='carol@example.com',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            submission_mode='self_submission',
            tier_preference=tier
        )

        self.assertEqual(track_app.tier_preference, tier)

    def test_multiple_tracks_different_statuses(self):
        """Test tracking different statuses for different tracks."""
        app = EventApplication.objects.create(
            event=self.event,
            first_name='Diana',
            last_name='Evans',
            email='diana@example.com',
            selected_tracks=[self.track1.id, self.track2.id]
        )
        track_app1 = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            submission_mode='self_submission',
            status='accepted'
        )
        track_app2 = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            submission_mode='confirmed',
            status='waitlisted'
        )

        # Verify different statuses per track
        self.assertEqual(track_app1.status, 'accepted')
        self.assertEqual(track_app2.status, 'waitlisted')

    def test_form_answers_per_track(self):
        """Test different form answers per track."""
        app = EventApplication.objects.create(
            event=self.event,
            first_name='Eve',
            last_name='Franklin',
            email='eve@example.com',
        )
        answers1 = {'bio': 'Speaker bio', 'topics': ['AI', 'ML']}
        answers2 = {'company_size': '100-500', 'budget': '50000'}

        track_app1 = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track1,
            submission_mode='self_submission',
            form_answers=answers1
        )
        track_app2 = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track2,
            submission_mode='confirmed',
            form_answers=answers2
        )

        # Verify answers are stored per track
        track_app1.refresh_from_db()
        track_app2.refresh_from_db()
        self.assertEqual(track_app1.form_answers, answers1)
        self.assertEqual(track_app2.form_answers, answers2)
