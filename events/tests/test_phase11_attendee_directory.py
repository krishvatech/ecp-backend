"""
Phase 11: Attendee Directory & Manual Mark-Paid - Comprehensive Test Suite
Tests for creation of attendee records, origin metadata, and payment status management.
"""
from django.test import TestCase
from django.utils import timezone
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch

from events.models import (
    Event,
    EventApplication,
    EventApplicationTrack,
    EventApplicationTrackApplication,
    TrackPricingTier,
    EventRegistration,
    EventRole,
    EventAttendeeOrigin,
    Community,
)


class AttendeeDirectoryCreationTestCase(TestCase):
    """Test attendee creation and origin metadata storage."""

    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.community = Community.objects.create(name='Test Community')
        self.manager = User.objects.create_user(username='manager', password='pass123', is_staff=True)
        self.applicant = User.objects.create_user(username='applicant', password='pass123')

        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.manager,
            registration_type='apply',
            waiting_room_enabled=False,
        )

        # Create track with free tier
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker',
            short_description='Speaker track',
        )

        self.free_tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Free',
            price=0,
            is_default=True,
        )

        self.paid_tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Premium',
            price=199.99,
        )

        # Create event role
        self.speaker_role = EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
        )

        # Add role config to track
        self.track.role_configs.create(role_name='speaker')

        # Create application
        self.application = EventApplication.objects.create(
            event=self.event,
            user=self.applicant,
            first_name='John',
            last_name='Doe',
            email='john@example.com',
        )

        self.track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track,
            submission_mode='self_submission',
            status='pending',
            tier_preference=self.free_tier,
        )

    def test_zero_cost_acceptance_creates_confirmed_attendee(self):
        """Test that accepting with zero-cost tier creates confirmed attendee."""
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.free_tier.id},
            format='json',
        )

        self.assertEqual(response.status_code, 200)

        # Verify EventRegistration created with confirmed status
        registration = EventRegistration.objects.get(event=self.event, user=self.applicant)
        self.assertEqual(registration.attendee_status, 'confirmed')
        self.assertEqual(registration.status, 'registered')

    def test_paid_acceptance_creates_payment_pending_attendee(self):
        """Test that accepting with paid tier creates payment_pending attendee."""
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.paid_tier.id},
            format='json',
        )

        self.assertEqual(response.status_code, 200)

        # Verify EventRegistration has payment_pending status
        registration = EventRegistration.objects.get(event=self.event, user=self.applicant)
        self.assertEqual(registration.attendee_status, 'payment_pending')

    def test_attendee_origin_metadata_stored(self):
        """Test that origin metadata is properly stored for accepted applications."""
        self.client.force_authenticate(self.manager)

        self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.free_tier.id},
            format='json',
        )

        # Verify EventAttendeeOrigin created with correct metadata
        registration = EventRegistration.objects.get(event=self.event, user=self.applicant)
        origins = EventAttendeeOrigin.objects.filter(registration=registration)

        self.assertEqual(origins.count(), 1)
        origin = origins.first()

        self.assertEqual(origin.track, self.track)
        self.assertEqual(origin.submission_mode, 'self_submission')
        self.assertEqual(origin.accepted_tier, self.free_tier)
        self.assertEqual(origin.accepted_by, self.manager)
        self.assertIsNotNone(origin.accepted_at)
        self.assertEqual(origin.status, 'active')

    def test_multiple_roles_create_multiple_origins(self):
        """Test that multiple roles create multiple origin records."""
        # Add another role config to track
        attendee_role = EventRole.objects.create(
            event=self.event,
            key='attendee',
            label='Attendee',
        )
        self.track.role_configs.create(role_name='attendee')

        self.client.force_authenticate(self.manager)

        self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.free_tier.id},
            format='json',
        )

        # Verify multiple origins created
        registration = EventRegistration.objects.get(event=self.event, user=self.applicant)
        origins = EventAttendeeOrigin.objects.filter(registration=registration)

        self.assertEqual(origins.count(), 2)

    def test_same_user_event_does_not_create_duplicate_registration(self):
        """Test that accepting multiple tracks for same user doesn't duplicate registration."""
        # Create another track and application
        track2 = EventApplicationTrack.objects.create(
            event=self.event,
            label='Sponsor',
            short_description='Sponsor track',
        )
        track2.role_configs.create(role_name='sponsor')

        tier2 = TrackPricingTier.objects.create(
            track=track2,
            label='Standard',
            price=0,
            is_default=True,
        )

        track_app2 = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=track2,
            submission_mode='self_submission',
            status='pending',
            tier_preference=tier2,
        )

        self.client.force_authenticate(self.manager)

        # Accept both tracks
        self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.free_tier.id},
            format='json',
        )

        self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{track_app2.id}/accept/',
            {'accepted_tier_id': tier2.id},
            format='json',
        )

        # Verify only one registration exists
        registrations = EventRegistration.objects.filter(event=self.event, user=self.applicant)
        self.assertEqual(registrations.count(), 1)

        # Verify two origins exist (one per role)
        registration = registrations.first()
        origins = EventAttendeeOrigin.objects.filter(registration=registration)
        self.assertGreaterEqual(origins.count(), 2)

    def test_nominator_info_stored_for_third_party_nomination(self):
        """Test that nominator info is stored when submission_mode is third_party_nomination."""
        # Create application with nominator info
        self.application.nominator_name = 'Jane Smith'
        self.application.nominator_email = 'jane@example.com'
        self.application.save()

        self.track_app.submission_mode = 'third_party_nomination'
        self.track_app.save()

        self.client.force_authenticate(self.manager)

        self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.free_tier.id},
            format='json',
        )

        # Verify origin has nominator info
        registration = EventRegistration.objects.get(event=self.event, user=self.applicant)
        origin = EventAttendeeOrigin.objects.get(registration=registration)

        self.assertEqual(origin.nominator_name, 'Jane Smith')
        self.assertEqual(origin.nominator_email, 'jane@example.com')


class MarkPaidTestCase(TestCase):
    """Test manual mark-paid functionality."""

    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.community = Community.objects.create(name='Test Community')
        self.manager = User.objects.create_user(username='manager', password='pass123', is_staff=True)
        self.other_user = User.objects.create_user(username='other', password='pass123')
        self.applicant = User.objects.create_user(username='applicant', password='pass123')

        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.manager,
            registration_type='apply',
            waiting_room_enabled=False,
        )

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker',
            short_description='Speaker track',
        )

        self.paid_tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Premium',
            price=199.99,
        )

        self.application = EventApplication.objects.create(
            event=self.event,
            user=self.applicant,
            first_name='John',
            last_name='Doe',
            email='john@example.com',
        )

        self.track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track,
            submission_mode='self_submission',
            status='pending',
            tier_preference=self.paid_tier,
        )

        # Accept with paid tier to create payment_pending registration
        self.client.force_authenticate(self.manager)
        self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.paid_tier.id},
            format='json',
        )

        self.registration = EventRegistration.objects.get(event=self.event, user=self.applicant)

    def test_mark_paid_changes_status_to_confirmed(self):
        """Test that mark-paid changes payment_pending → confirmed."""
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/registrations/{self.registration.id}/mark-paid/',
            {'payment_reference': 'INV-12345'},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['attendee_status'], 'confirmed')

        # Verify database updated
        self.registration.refresh_from_db()
        self.assertEqual(self.registration.attendee_status, 'confirmed')
        self.assertEqual(self.registration.marked_paid_by, self.manager)
        self.assertIsNotNone(self.registration.marked_paid_at)
        self.assertEqual(self.registration.payment_reference, 'INV-12345')

    def test_mark_paid_requires_manager_permission(self):
        """Test that non-managers cannot mark as paid."""
        self.client.force_authenticate(self.other_user)

        response = self.client.post(
            f'/events/{self.event.id}/registrations/{self.registration.id}/mark-paid/',
            {'payment_reference': 'INV-12345'},
            format='json',
        )

        self.assertEqual(response.status_code, 403)

    def test_mark_paid_fails_if_not_payment_pending(self):
        """Test that mark-paid fails if registration is not payment_pending."""
        # Create confirmed registration
        confirmed_reg = EventRegistration.objects.create(
            event=self.event,
            user=self.other_user,
            status='registered',
            attendee_status='confirmed',
        )

        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/registrations/{confirmed_reg.id}/mark-paid/',
            {'payment_reference': 'INV-12345'},
            format='json',
        )

        self.assertEqual(response.status_code, 400)

    def test_mark_paid_without_payment_reference(self):
        """Test that mark-paid works without payment reference."""
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/registrations/{self.registration.id}/mark-paid/',
            {},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.registration.refresh_from_db()
        self.assertEqual(self.registration.attendee_status, 'confirmed')
        self.assertEqual(self.registration.payment_reference, '')

    @patch('events.services.attendee_directory.trigger_post_acceptance_forms_hook')
    def test_mark_paid_triggers_post_acceptance_forms(self, mock_hook):
        """Test that mark-paid triggers post-acceptance forms hook."""
        self.client.force_authenticate(self.manager)

        self.client.post(
            f'/events/{self.event.id}/registrations/{self.registration.id}/mark-paid/',
            {'payment_reference': 'INV-12345'},
            format='json',
        )

        # Verify hook was called
        mock_hook.assert_called_once()


class AttendeeDirectoryFilteringTestCase(TestCase):
    """Test filtering attendees by role, tier, and status."""

    def setUp(self):
        """Set up test data with multiple attendees."""
        self.community = Community.objects.create(name='Test Community')
        self.manager = User.objects.create_user(username='manager', password='pass123', is_staff=True)

        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.manager,
            registration_type='apply',
        )

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Track 1',
            short_description='Track 1',
        )

        self.free_tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Free',
            price=0,
            is_default=True,
        )

        self.paid_tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Paid',
            price=100.0,
        )

        # Create speaker role
        self.speaker_role = EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
        )

        self.track.role_configs.create(role_name='speaker')

    def test_attendee_visibility_payment_pending(self):
        """Test that payment_pending attendees are visible in directory."""
        # Create attendee with payment_pending status
        applicant = User.objects.create_user(username='applicant', password='pass123')
        application = EventApplication.objects.create(
            event=self.event,
            user=applicant,
            first_name='John',
            last_name='Doe',
            email='john@example.com',
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=application,
            track=self.track,
            submission_mode='self_submission',
            status='pending',
            tier_preference=self.paid_tier,
        )

        # Accept with paid tier
        from events.services.application_decisions import accept_track_application
        accept_track_application(track_app, self.manager, accepted_tier=self.paid_tier)

        # Verify registration visible
        registration = EventRegistration.objects.get(event=self.event, user=applicant)
        self.assertEqual(registration.attendee_status, 'payment_pending')


class IntegrationTestCase(TestCase):
    """Integration tests for complete attendee directory workflow."""

    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.community = Community.objects.create(name='Test Community')
        self.manager = User.objects.create_user(username='manager', password='pass123', is_staff=True)
        self.applicant = User.objects.create_user(username='applicant', password='pass123')

        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.manager,
            registration_type='apply',
        )

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Track 1',
            short_description='Track 1',
        )

        self.free_tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Free',
            price=0,
            is_default=True,
        )

        self.paid_tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Paid',
            price=100.0,
        )

        EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
        )

        self.track.role_configs.create(role_name='speaker')

    def test_end_to_end_workflow(self):
        """Test complete workflow: apply → accept (paid) → mark paid."""
        # Create application
        application = EventApplication.objects.create(
            event=self.event,
            user=self.applicant,
            first_name='John',
            last_name='Doe',
            email='john@example.com',
        )

        track_app = EventApplicationTrackApplication.objects.create(
            application=application,
            track=self.track,
            submission_mode='self_submission',
            status='pending',
            tier_preference=self.paid_tier,
        )

        self.client.force_authenticate(self.manager)

        # Accept with paid tier
        response = self.client.post(
            f'/events/{self.event.id}/applications/{application.id}/track-applications/{track_app.id}/accept/',
            {'accepted_tier_id': self.paid_tier.id},
            format='json',
        )
        self.assertEqual(response.status_code, 200)

        # Verify payment_pending status
        registration = EventRegistration.objects.get(event=self.event, user=self.applicant)
        self.assertEqual(registration.attendee_status, 'payment_pending')

        # Verify origin metadata
        origins = EventAttendeeOrigin.objects.filter(registration=registration)
        self.assertGreater(origins.count(), 0)

        # Mark as paid
        response = self.client.post(
            f'/events/{self.event.id}/registrations/{registration.id}/mark-paid/',
            {'payment_reference': 'INV-001'},
            format='json',
        )
        self.assertEqual(response.status_code, 200)

        # Verify confirmed status
        registration.refresh_from_db()
        self.assertEqual(registration.attendee_status, 'confirmed')
        self.assertEqual(registration.payment_reference, 'INV-001')
