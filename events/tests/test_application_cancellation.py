"""
Tests for application-required cancel flow with proper state management.

Scenarios:
- Cancel accepted free-tier application
- Cancel accepted paid-tier application
- Cancel pending application
- Double cancel (idempotent)
- Attend count never becomes negative
- Re-application after cancellation
- Application status updated to cancelled (not declined)
- Origins status updated to cancelled
- Review queue shows cancelled applications
"""
import pytest
from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from django.db import transaction
from rest_framework.test import APIClient
from rest_framework import status

from events.models import (
    Event,
    EventApplication,
    EventApplicationTrack,
    EventApplicationTrackApplication,
    EventRegistration,
    EventAttendeeOrigin,
    TrackPricingTier,
)
from community.models import Community


@pytest.mark.django_db(transaction=True)
class TestApplicationCancellation(TransactionTestCase):
    """
    Tests for comprehensive application cancellation flow.
    """

    def setUp(self):
        """Create test data."""
        self.client = APIClient()

        # Create users
        self.organizer = User.objects.create_user(
            username='organizer',
            email='organizer@test.com',
            password='testpass'
        )
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@test.com',
            password='testpass'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@test.com',
            password='testpass'
        )

        # Create community
        self.community = Community.objects.create(
            name='Test Community',
            slug='test-community'
        )

        # Create application-required event
        self.event = Event.objects.create(
            title='Application Event',
            community=self.community,
            created_by=self.organizer,
            registration_type='apply',
            is_free=True
        )

        # Create application track with free and paid tiers
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            is_active=True,
            status='open'
        )

        self.free_tier = TrackPricingTier.objects.create(
            track=self.track,
            key='free',
            label='Free Tier',
            price=0,
            is_default=True,
            is_active=True
        )

        self.paid_tier = TrackPricingTier.objects.create(
            track=self.track,
            key='paid',
            label='Paid Tier',
            price=99.99,
            is_active=True
        )

    def test_cancel_accepted_free_tier_application(self):
        """Test 1: Cancel accepted free-tier application"""
        # Create and accept application
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user1,
            email='user1@test.com',
            first_name='User',
            last_name='One',
            status='pending'
        )

        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
            tier_preference=self.free_tier
        )

        # Accept application
        from events.services.application_decisions import accept_track_application
        accept_track_application(track_app, self.organizer)

        # Verify registration created
        self.event.refresh_from_db()
        initial_count = self.event.attending_count
        self.assertEqual(initial_count, 1)

        app.refresh_from_db()
        self.assertEqual(app.status, 'approved')

        track_app.refresh_from_db()
        self.assertEqual(track_app.status, 'accepted')

        # Get registration and cancel it
        reg = EventRegistration.objects.get(event=self.event, user=self.user1)

        self.client.force_authenticate(user=self.user1)
        response = self.client.delete(f'/api/event-registrations/{reg.id}/')

        # Verify success
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify registration cancelled
        reg.refresh_from_db()
        self.assertEqual(reg.status, 'cancelled')
        self.assertEqual(reg.attendee_status, 'cancelled')

        # Verify application updated to cancelled (not declined)
        app.refresh_from_db()
        self.assertEqual(app.status, 'cancelled')
        self.assertIsNotNone(app.cancelled_at)

        # Verify track application cancelled
        track_app.refresh_from_db()
        self.assertEqual(track_app.status, 'cancelled')
        self.assertIsNotNone(track_app.cancelled_at)
        self.assertEqual(track_app.cancellation_reason, 'registration_cancelled')

        # Verify origins cancelled
        origins = app.track_applications.first().registration.origins.all()
        for origin in origins:
            if origin.status == 'cancelled':
                self.assertEqual(origin.origin_status, 'cancelled')

        # Verify attending_count decremented safely
        self.event.refresh_from_db()
        self.assertEqual(self.event.attending_count, 0)
        self.assertGreaterEqual(self.event.attending_count, 0)

    def test_cancel_accepted_paid_tier_application(self):
        """Test 2: Cancel accepted paid-tier application (payment_pending)"""
        # Create and accept application with paid tier
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user2,
            email='user2@test.com',
            first_name='User',
            last_name='Two',
            status='pending'
        )

        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
            tier_preference=self.paid_tier
        )

        # Accept with paid tier
        from events.services.application_decisions import accept_track_application
        accept_track_application(track_app, self.organizer, accepted_tier=self.paid_tier)

        # Verify registration in payment_pending
        reg = EventRegistration.objects.get(event=self.event, user=self.user2)
        self.assertEqual(reg.attendee_status, 'payment_pending')
        self.event.refresh_from_db()
        self.assertEqual(self.event.attending_count, 1)

        # Cancel registration
        self.client.force_authenticate(user=self.user2)
        response = self.client.delete(f'/api/event-registrations/{reg.id}/')

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify all statuses updated
        app.refresh_from_db()
        self.assertEqual(app.status, 'cancelled')

        reg.refresh_from_db()
        self.assertEqual(reg.status, 'cancelled')
        self.assertEqual(reg.attendee_status, 'cancelled')

        # Verify attending_count safe
        self.event.refresh_from_db()
        self.assertEqual(self.event.attending_count, 0)

    def test_cancel_pending_application(self):
        """Test 3: Cancel pending application (before acceptance)"""
        # Create pending application (not accepted)
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user1,
            email='user1@test.com',
            first_name='User',
            last_name='One',
            status='pending'
        )

        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
            tier_preference=self.free_tier
        )

        # No registration yet
        self.assertEqual(
            EventRegistration.objects.filter(event=self.event, user=self.user1).count(),
            0
        )

        # User decides to withdraw pending application via API
        # (This would be a new endpoint or through admin - for now testing the service)
        from events.services.application_cancellation import cancel_application
        cancel_application(app, cancellation_reason='user_withdrawal')

        # Verify application cancelled
        app.refresh_from_db()
        self.assertEqual(app.status, 'cancelled')

        # Verify track app cancelled
        track_app.refresh_from_db()
        self.assertEqual(track_app.status, 'cancelled')

        # No registration should be affected (none existed)
        self.assertEqual(
            EventRegistration.objects.filter(event=self.event, user=self.user1).count(),
            0
        )

    def test_double_cancel_idempotent(self):
        """Test 4: Double cancel is idempotent"""
        # Create, accept, and cancel application
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user1,
            email='user1@test.com',
            first_name='User',
            last_name='One',
            status='pending'
        )

        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
            tier_preference=self.free_tier
        )

        from events.services.application_decisions import accept_track_application
        accept_track_application(track_app, self.organizer)

        reg = EventRegistration.objects.get(event=self.event, user=self.user1)
        self.event.refresh_from_db()
        count_after_accept = self.event.attending_count

        # First cancel
        self.client.force_authenticate(user=self.user1)
        response1 = self.client.delete(f'/api/event-registrations/{reg.id}/')
        self.assertEqual(response1.status_code, status.HTTP_204_NO_CONTENT)

        count_after_first_cancel = self.event.attending_count

        # Try to cancel again (registration already cancelled)
        response2 = self.client.delete(f'/api/event-registrations/{reg.id}/')

        # Should fail with 404 (can't delete already cancelled reg) or succeed idempotently
        self.assertIn(
            response2.status_code,
            [status.HTTP_204_NO_CONTENT, status.HTTP_404_NOT_FOUND]
        )

        # Count should not change on second cancel
        self.event.refresh_from_db()
        self.assertEqual(self.event.attending_count, count_after_first_cancel)

        # Never negative
        self.assertGreaterEqual(self.event.attending_count, 0)

    def test_attending_count_never_negative(self):
        """Test 5: Attending count never becomes negative"""
        # Create and accept application
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user1,
            email='user1@test.com',
            first_name='User',
            last_name='One',
            status='pending'
        )

        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
            tier_preference=self.free_tier
        )

        from events.services.application_decisions import accept_track_application
        accept_track_application(track_app, self.organizer)

        reg = EventRegistration.objects.get(event=self.event, user=self.user1)

        # Manually corrupt attending_count to 0 (already at 0 from recalculation)
        self.event.attending_count = 0
        self.event.save(update_fields=['attending_count'])

        # Cancel should not go negative
        self.client.force_authenticate(user=self.user1)
        response = self.client.delete(f'/api/event-registrations/{reg.id}/')

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.event.refresh_from_db()
        self.assertGreaterEqual(self.event.attending_count, 0)

    def test_reapplication_after_cancellation(self):
        """Test 6: User can reapply after cancelling"""
        # Create, accept, and cancel application
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user1,
            email='user1@test.com',
            first_name='User',
            last_name='One',
            status='pending'
        )

        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
            tier_preference=self.free_tier
        )

        from events.services.application_decisions import accept_track_application
        accept_track_application(track_app, self.organizer)

        reg = EventRegistration.objects.get(event=self.event, user=self.user1)

        # Cancel
        self.client.force_authenticate(user=self.user1)
        self.client.delete(f'/api/event-registrations/{reg.id}/')

        app.refresh_from_db()
        self.assertEqual(app.status, 'cancelled')

        # Check that user can reapply
        from events.services.application_cancellation import allow_reapplication
        can_reapply = allow_reapplication(event_registration=reg)
        self.assertTrue(can_reapply)

        # Attempt to reapply (POST to apply endpoint)
        reapply_data = {
            'first_name': 'User',
            'last_name': 'One',
            'email': 'user1@test.com',
            'job_title': 'Developer',
            'company_name': 'TechCorp',
            'track_key': 'speaker',
            'submission_mode': 'self_submission'
        }

        response = self.client.post(f'/api/events/{self.event.id}/apply/', reapply_data)

        # Should succeed (not 409)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # New application created (different from the cancelled one)
        new_app = EventApplication.objects.filter(
            event=self.event,
            email='user1@test.com',
            status='pending'
        ).latest('applied_at')

        self.assertNotEqual(new_app.id, app.id)
        self.assertEqual(new_app.status, 'pending')

    def test_application_status_cancelled_not_declined(self):
        """Test 7: Cancelled status is distinct from declined"""
        # Create and accept application
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user1,
            email='user1@test.com',
            first_name='User',
            last_name='One',
            status='pending'
        )

        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
            tier_preference=self.free_tier
        )

        from events.services.application_decisions import accept_track_application
        accept_track_application(track_app, self.organizer)

        reg = EventRegistration.objects.get(event=self.event, user=self.user1)

        # Cancel registration
        from events.services.application_cancellation import cancel_registration_for_application
        cancel_registration_for_application(reg, cancellation_reason='registration_cancelled')

        # Verify status is 'cancelled', not 'declined'
        app.refresh_from_db()
        self.assertEqual(app.status, 'cancelled')
        self.assertNotEqual(app.status, 'declined')

        track_app.refresh_from_db()
        self.assertEqual(track_app.status, 'cancelled')
        self.assertNotEqual(track_app.status, 'declined')

    def test_origins_status_updated_to_cancelled(self):
        """Test 8: EventAttendeeOrigin status updated to cancelled"""
        # Create and accept application
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user1,
            email='user1@test.com',
            first_name='User',
            last_name='One',
            status='pending'
        )

        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending',
            tier_preference=self.free_tier
        )

        from events.services.application_decisions import accept_track_application
        accept_track_application(track_app, self.organizer)

        reg = EventRegistration.objects.get(event=self.event, user=self.user1)

        # Verify origins exist and are active
        origins = EventAttendeeOrigin.objects.filter(registration=reg, status='active')
        self.assertGreater(origins.count(), 0)

        # Cancel
        self.client.force_authenticate(user=self.user1)
        self.client.delete(f'/api/event-registrations/{reg.id}/')

        # Verify all origins now cancelled
        active_origins = EventAttendeeOrigin.objects.filter(registration=reg, status='active')
        self.assertEqual(active_origins.count(), 0)

        cancelled_origins = EventAttendeeOrigin.objects.filter(registration=reg, status='cancelled')
        self.assertGreater(cancelled_origins.count(), 0)

        # Verify origin_status is also cancelled
        for origin in cancelled_origins:
            self.assertEqual(origin.origin_status, 'cancelled')


class TestApplicationReviewQueueAfterCancellation(TestCase):
    """Test that review queue shows cancelled applications correctly."""

    def setUp(self):
        self.organizer = User.objects.create_user(
            username='organizer',
            email='org@test.com',
            password='test'
        )
        self.community = Community.objects.create(name='Community', slug='comm')
        self.event = Event.objects.create(
            title='Event',
            community=self.community,
            created_by=self.organizer,
            registration_type='apply'
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            is_active=True
        )

    def test_review_queue_excludes_cancelled_from_active(self):
        """Cancelled applications should not appear in active review queue."""
        # Create pending application
        app = EventApplication.objects.create(
            event=self.event,
            user=User.objects.create_user(username='user', email='user@test.com'),
            email='user@test.com',
            first_name='User',
            status='pending'
        )

        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='pending'
        )

        # Verify it appears in pending list
        pending = EventApplicationTrackApplication.objects.filter(
            track=self.track,
            status='pending'
        )
        self.assertEqual(pending.count(), 1)

        # Cancel it
        from events.services.application_cancellation import cancel_application
        cancel_application(app, cancellation_reason='user_withdrawal')

        # Should not appear in pending anymore
        pending = EventApplicationTrackApplication.objects.filter(
            track=self.track,
            status='pending'
        )
        self.assertEqual(pending.count(), 0)

        # Should appear in cancelled
        cancelled = EventApplicationTrackApplication.objects.filter(
            track=self.track,
            status='cancelled'
        )
        self.assertEqual(cancelled.count(), 1)
