"""
Phase 10: Accept, Decline, Waitlist - Comprehensive Test Suite
Tests for application decision making with tier selection and notifications.
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
    TrackPricingTier,
    EventApplicationTrackApplication,
    EventRegistration,
    EventRole,
)
from community.models import Community


class AcceptTrackApplicationTestCase(TestCase):
    """Test accepting track applications with tier selection."""

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

        # Create track with tiers
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker',
            short_description='Speaker track',
        )

        # Free tier
        self.free_tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Free',
            price=0,
            is_default=True,
        )

        # Paid tier
        self.paid_tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Premium',
            price=199.99,
        )

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

    def test_accept_requires_auth(self):
        """Test that accept requires authentication."""
        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.free_tier.id},
            format='json',
        )
        self.assertEqual(response.status_code, 401)

    def test_accept_requires_manager(self):
        """Test that non-managers cannot accept applications."""
        other_user = User.objects.create_user(username='other', password='pass123')
        self.client.force_authenticate(other_user)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.free_tier.id},
            format='json',
        )
        self.assertEqual(response.status_code, 403)

    def test_accept_zero_cost_tier(self):
        """Test accepting with zero-cost tier creates confirmed attendee."""
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.free_tier.id},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'accepted')

        # Verify track application updated
        self.track_app.refresh_from_db()
        self.assertEqual(self.track_app.status, 'accepted')
        self.assertEqual(self.track_app.accepted_tier_id, self.free_tier.id)
        self.assertIsNotNone(self.track_app.accepted_at)
        self.assertEqual(self.track_app.reviewed_by, self.manager)

        # Verify EventRegistration created with confirmed status
        registration = EventRegistration.objects.get(event=self.event, user=self.applicant)
        self.assertEqual(registration.attendee_status, 'confirmed')
        self.assertEqual(registration.status, 'registered')

    def test_accept_paid_tier(self):
        """Test accepting with paid tier creates payment_pending attendee."""
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.paid_tier.id},
            format='json',
        )

        self.assertEqual(response.status_code, 200)

        # Verify track application
        self.track_app.refresh_from_db()
        self.assertEqual(self.track_app.accepted_tier_id, self.paid_tier.id)
        self.assertEqual(self.track_app.status, 'accepted')

        # Verify EventRegistration has payment_pending status
        registration = EventRegistration.objects.get(event=self.event, user=self.applicant)
        self.assertEqual(registration.attendee_status, 'payment_pending')

    def test_accept_uses_requested_tier_by_default(self):
        """Test that acceptance uses applicant's requested tier if no override."""
        # Update track app to have requested tier
        self.track_app.tier_preference = self.paid_tier
        self.track_app.save()

        self.client.force_authenticate(self.manager)

        # Accept without specifying tier
        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {},
            format='json',
        )

        self.assertEqual(response.status_code, 200)

        # Verify it used requested tier
        self.track_app.refresh_from_db()
        self.assertEqual(self.track_app.accepted_tier_id, self.paid_tier.id)

    def test_accept_uses_default_tier_fallback(self):
        """Test that acceptance uses track default tier if no requested."""
        # Track app has no requested tier
        self.track_app.tier_preference = None
        self.track_app.save()

        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {},
            format='json',
        )

        self.assertEqual(response.status_code, 200)

        # Verify it used default tier
        self.track_app.refresh_from_db()
        self.assertEqual(self.track_app.accepted_tier_id, self.free_tier.id)

    def test_accept_invalid_tier(self):
        """Test that accept rejects invalid tier."""
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': 99999},
            format='json',
        )

        self.assertEqual(response.status_code, 400)


class DeclineTrackApplicationTestCase(TestCase):
    """Test declining track applications."""

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
            label='Speaker',
            short_description='Speaker track',
        )

        self.application = EventApplication.objects.create(
            event=self.event,
            user=self.applicant,
            first_name='Jane',
            last_name='Smith',
            email='jane@example.com',
            opt_out_automated_communication=False,
        )

        self.track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track,
            submission_mode='self_submission',
            status='pending',
        )

    def test_decline_requires_auth(self):
        """Test that decline requires authentication."""
        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/decline/',
            {},
            format='json',
        )
        self.assertEqual(response.status_code, 401)

    def test_decline_updates_status(self):
        """Test that decline updates application status."""
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/decline/',
            {'notes': 'Not a good fit'},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'declined')

        # Verify track application updated
        self.track_app.refresh_from_db()
        self.assertEqual(self.track_app.status, 'declined')
        self.assertIsNotNone(self.track_app.declined_at)
        self.assertEqual(self.track_app.reviewed_by, self.manager)

    @patch('events.services.application_decisions.send_application_decision_email')
    def test_decline_sends_email(self, mock_send_email):
        """Test that decline sends email notification."""
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/decline/',
            {'send_email': True},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        mock_send_email.assert_called_once()

    @patch('events.services.application_decisions.send_application_decision_email')
    def test_decline_respects_opt_out(self, mock_send_email):
        """Test that email not sent if applicant opted out."""
        # Update application to opt out
        self.application.opt_out_automated_communication = True
        self.application.save()

        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/decline/',
            {'send_email': True},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        # Email should not be sent due to opt-out
        mock_send_email.assert_not_called()


class WaitlistTrackApplicationTestCase(TestCase):
    """Test waitlisting track applications."""

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
            label='Speaker',
            short_description='Speaker track',
        )

        self.application = EventApplication.objects.create(
            event=self.event,
            user=self.applicant,
            first_name='Bob',
            last_name='Johnson',
            email='bob@example.com',
            opt_out_automated_communication=False,
        )

        self.track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track,
            submission_mode='self_submission',
            status='pending',
        )

    def test_waitlist_requires_auth(self):
        """Test that waitlist requires authentication."""
        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/waitlist/',
            {},
            format='json',
        )
        self.assertEqual(response.status_code, 401)

    def test_waitlist_updates_status(self):
        """Test that waitlist updates application status."""
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/waitlist/',
            {},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'waitlisted')

        # Verify track application updated
        self.track_app.refresh_from_db()
        self.assertEqual(self.track_app.status, 'waitlisted')
        self.assertIsNotNone(self.track_app.waitlisted_at)
        self.assertEqual(self.track_app.reviewed_by, self.manager)

    @patch('events.services.application_decisions.send_application_decision_email')
    def test_waitlist_sends_email(self, mock_send_email):
        """Test that waitlist sends email notification."""
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/waitlist/',
            {'send_email': True},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        mock_send_email.assert_called_once()

    @patch('events.services.application_decisions.send_application_decision_email')
    def test_waitlist_respects_opt_out(self, mock_send_email):
        """Test that email not sent if applicant opted out."""
        self.application.opt_out_automated_communication = True
        self.application.save()

        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/waitlist/',
            {'send_email': True},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        mock_send_email.assert_not_called()


class DecisionIntegrationTestCase(TestCase):
    """Integration tests for decision workflow."""

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

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            label='Speaker',
            short_description='Speaker',
        )

        self.tier = TrackPricingTier.objects.create(
            track=self.track,
            label='Standard',
            price=0,
            is_default=True,
        )

    def test_full_workflow_accept_then_decline(self):
        """Test workflow: create app, accept, then decline another track."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.applicant,
            first_name='Test',
            last_name='User',
            email='test@example.com',
        )

        # Create two track applications
        track_app1 = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            submission_mode='self_submission',
            status='pending',
            tier_preference=self.tier,
        )

        track_app2 = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            submission_mode='self_nomination',
            status='pending',
        )

        self.client.force_authenticate(self.manager)

        # Accept first
        response1 = self.client.post(
            f'/events/{self.event.id}/applications/{app.id}/track-applications/{track_app1.id}/accept/',
            {'accepted_tier_id': self.tier.id},
            format='json',
        )
        self.assertEqual(response1.status_code, 200)

        # Decline second
        response2 = self.client.post(
            f'/events/{self.event.id}/applications/{app.id}/track-applications/{track_app2.id}/decline/',
            {},
            format='json',
        )
        self.assertEqual(response2.status_code, 200)

        # Verify states
        track_app1.refresh_from_db()
        track_app2.refresh_from_db()

        self.assertEqual(track_app1.status, 'accepted')
        self.assertEqual(track_app2.status, 'declined')

        # Verify EventRegistration created (from first acceptance)
        registration = EventRegistration.objects.get(event=self.event, user=self.applicant)
        self.assertEqual(registration.status, 'registered')
        self.assertEqual(registration.attendee_status, 'confirmed')
