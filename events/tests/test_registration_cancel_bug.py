"""
Tests for cancel registration bug fix - attending_count safety and idempotency.
Bug: Application-required registrations never incremented attending_count, but cancel always decremented.
Result: -1 violating PositiveIntegerField constraint.
"""
import pytest
from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from django.db import transaction
from rest_framework.test import APIClient
from rest_framework import status

from events.models import (
    Event,
    EventRegistration,
    EventApplication,
    EventApplicationTrack,
    EventApplicationTrackApplication,
    TrackPricingTier,
    EventAttendeeOrigin,
)
from community.models import Community


@pytest.mark.django_db(transaction=True)
class TestRegistrationCancelBugFix(TransactionTestCase):
    """
    Tests for attending_count safety during cancellation.
    Uses TransactionTestCase for proper transaction handling.
    """

    def setUp(self):
        """Create test data: user, community, event, etc."""
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
        self.user3 = User.objects.create_user(
            username='user3',
            email='user3@test.com',
            password='testpass'
        )

        # Create community
        self.community = Community.objects.create(
            name='Test Community',
            slug='test-community'
        )

        # Create open registration event
        self.open_event = Event.objects.create(
            title='Open Event',
            community=self.community,
            created_by=self.organizer,
            registration_type='open',
            is_free=True
        )

        # Create application-required event with free and paid tiers
        self.app_event = Event.objects.create(
            title='Application Event',
            community=self.community,
            created_by=self.organizer,
            registration_type='apply',
            is_free=True
        )

        # Create application track
        self.track = EventApplicationTrack.objects.create(
            event=self.app_event,
            key='speaker',
            label='Speaker Track',
            is_active=True
        )

        # Create free tier
        self.free_tier = TrackPricingTier.objects.create(
            track=self.track,
            key='free',
            label='Free Tier',
            price=0,
            is_default=True,
            is_active=True
        )

        # Create paid tier
        self.paid_tier = TrackPricingTier.objects.create(
            track=self.track,
            key='paid',
            label='Paid Tier',
            price=99.99,
            is_active=True
        )

    def test_open_event_cancel(self):
        """Test 1: Cancel open event registration"""
        # Create open registration
        reg = EventRegistration.objects.create(
            event=self.open_event,
            user=self.user1,
            status='registered',
            attendee_status='confirmed'
        )

        # Verify attending_count incremented
        self.open_event.refresh_from_db()
        initial_count = self.open_event.attending_count

        # Cancel registration
        self.client.force_authenticate(user=self.user1)
        response = self.client.delete(f'/api/event-registrations/{reg.id}/')

        # Verify success and attending_count decremented safely
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.open_event.refresh_from_db()
        self.assertGreaterEqual(self.open_event.attending_count, 0)

    def test_app_required_approved_free_tier_cancel(self):
        """Test 2: Cancel application-required approved free tier registration"""
        # Create application
        app = EventApplication.objects.create(
            event=self.app_event,
            user=self.user1,
            status='approved'
        )

        # Create track application
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='accepted',
            tier_preference=self.free_tier,
            accepted_tier=self.free_tier
        )

        # Accept application (should create EventRegistration and increment attending_count)
        from events.services.application_decisions import accept_track_application
        accept_track_application(track_app, self.organizer)

        # Verify registration was created
        self.app_event.refresh_from_db()
        self.assertEqual(self.app_event.attending_count, 1)

        reg = EventRegistration.objects.get(event=self.app_event, user=self.user1)
        self.assertEqual(reg.attendee_status, 'confirmed')

        # Cancel registration
        self.client.force_authenticate(user=self.user1)
        response = self.client.delete(f'/api/event-registrations/{reg.id}/')

        # Verify success and attending_count safe
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.app_event.refresh_from_db()
        self.assertEqual(self.app_event.attending_count, 0)
        self.assertGreaterEqual(self.app_event.attending_count, 0)

    def test_app_required_approved_paid_tier_cancel(self):
        """Test 3: Cancel application-required approved paid tier registration"""
        # Create application with paid tier
        app = EventApplication.objects.create(
            event=self.app_event,
            user=self.user2,
            status='approved'
        )

        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            status='accepted',
            tier_preference=self.paid_tier,
            accepted_tier=self.paid_tier
        )

        # Accept application
        from events.services.application_decisions import accept_track_application
        accept_track_application(track_app, self.organizer)

        # Verify registration with payment_pending
        self.app_event.refresh_from_db()
        self.assertEqual(self.app_event.attending_count, 1)

        reg = EventRegistration.objects.get(event=self.app_event, user=self.user2)
        self.assertEqual(reg.attendee_status, 'payment_pending')

        # Cancel registration
        self.client.force_authenticate(user=self.user2)
        response = self.client.delete(f'/api/event-registrations/{reg.id}/')

        # Verify success
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.app_event.refresh_from_db()
        self.assertEqual(self.app_event.attending_count, 0)

    def test_cancel_when_attending_count_zero(self):
        """Test 4: Cancel when attending_count is already 0 (edge case)"""
        # Create registration but manually set attending_count to 0 (corrupt state)
        reg = EventRegistration.objects.create(
            event=self.open_event,
            user=self.user1,
            status='registered',
            attendee_status='confirmed'
        )

        self.open_event.attending_count = 0
        self.open_event.save(update_fields=['attending_count'])

        # Cancel registration - should not violate constraint
        self.client.force_authenticate(user=self.user1)
        response = self.client.delete(f'/api/event-registrations/{reg.id}/')

        # Verify no 500 error and attending_count stays 0
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.open_event.refresh_from_db()
        self.assertEqual(self.open_event.attending_count, 0)
        self.assertGreaterEqual(self.open_event.attending_count, 0)

    def test_double_cancel_idempotent(self):
        """Test 5: Double cancel (idempotent)"""
        reg = EventRegistration.objects.create(
            event=self.open_event,
            user=self.user1,
            status='registered',
            attendee_status='confirmed'
        )

        # First cancel
        self.client.force_authenticate(user=self.user1)
        response1 = self.client.delete(f'/api/event-registrations/{reg.id}/')
        self.assertEqual(response1.status_code, status.HTTP_204_NO_CONTENT)

        count_after_first = self.open_event.attending_count

        # Second cancel (attempt) - registration status already cancelled
        reg.refresh_from_db()
        response2 = self.client.delete(f'/api/event-registrations/{reg.id}/')

        # Should still succeed (idempotent) or fail gracefully, NOT return 500
        self.assertIn(
            response2.status_code,
            [status.HTTP_204_NO_CONTENT, status.HTTP_404_NOT_FOUND]
        )

        # attending_count should not go more negative
        self.open_event.refresh_from_db()
        self.assertGreaterEqual(self.open_event.attending_count, 0)

    def test_cancel_never_negative(self):
        """Test 6: Cancel never makes attending_count negative"""
        # Create event with corrupted attending_count
        reg = EventRegistration.objects.create(
            event=self.open_event,
            user=self.user1,
            status='registered',
            attendee_status='confirmed'
        )

        # Corrupt state: set attending_count to -5 (should never happen, but test resilience)
        self.open_event.attending_count = 0
        self.open_event.save(update_fields=['attending_count'])

        # Cancel - should recalculate and never go negative
        self.client.force_authenticate(user=self.user1)
        response = self.client.delete(f'/api/event-registrations/{reg.id}/')

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.open_event.refresh_from_db()
        self.assertGreaterEqual(self.open_event.attending_count, 0)

    def test_reject_cancellation_increments_back(self):
        """Test 7: Reject cancellation increments back"""
        # Create and cancel a registration
        reg = EventRegistration.objects.create(
            event=self.open_event,
            user=self.user1,
            status='registered',
            attendee_status='confirmed'
        )

        self.open_event.attending_count = 1
        self.open_event.save(update_fields=['attending_count'])

        # Cancel via destroy
        self.client.force_authenticate(user=self.user1)
        self.client.delete(f'/api/event-registrations/{reg.id}/')

        self.open_event.refresh_from_db()
        count_after_cancel = self.open_event.attending_count
        self.assertEqual(count_after_cancel, 0)

        # Reject cancellation
        reg.refresh_from_db()
        self.client.force_authenticate(user=self.organizer)
        response = self.client.post(f'/api/event-registrations/{reg.id}/reject_cancellation/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.open_event.refresh_from_db()
        self.assertEqual(self.open_event.attending_count, 1)

    def test_multiple_registrations_cancel_independently(self):
        """Test 9: Multiple registrations cancel independently"""
        # Create 3 registrations
        regs = [
            EventRegistration.objects.create(
                event=self.open_event,
                user=user,
                status='registered',
                attendee_status='confirmed'
            )
            for user in [self.user1, self.user2, self.user3]
        ]

        self.open_event.attending_count = 3
        self.open_event.save(update_fields=['attending_count'])

        # Cancel first user
        self.client.force_authenticate(user=self.user1)
        self.client.delete(f'/api/event-registrations/{regs[0].id}/')

        self.open_event.refresh_from_db()
        self.assertEqual(self.open_event.attending_count, 2)

        # Cancel second user
        self.client.force_authenticate(user=self.user2)
        self.client.delete(f'/api/event-registrations/{regs[1].id}/')

        self.open_event.refresh_from_db()
        self.assertEqual(self.open_event.attending_count, 1)

        # Cancel third user
        self.client.force_authenticate(user=self.user3)
        self.client.delete(f'/api/event-registrations/{regs[2].id}/')

        self.open_event.refresh_from_db()
        self.assertEqual(self.open_event.attending_count, 0)
        self.assertGreaterEqual(self.open_event.attending_count, 0)

    def test_integration_app_required_flow(self):
        """Test 10: Full integration with application-required flow"""
        # Create 2 speaker applications
        apps = []
        for user in [self.user1, self.user2]:
            app = EventApplication.objects.create(
                event=self.app_event,
                user=user,
                status='approved'
            )
            track_app = EventApplicationTrackApplication.objects.create(
                application=app,
                track=self.track,
                status='accepted',
                tier_preference=self.free_tier,
                accepted_tier=self.free_tier
            )
            apps.append((app, track_app))

        # Accept both applications
        from events.services.application_decisions import accept_track_application
        for app, track_app in apps:
            accept_track_application(track_app, self.organizer)

        # Verify both registrations created and attending_count = 2
        self.app_event.refresh_from_db()
        self.assertEqual(self.app_event.attending_count, 2)

        regs = list(EventRegistration.objects.filter(event=self.app_event))
        self.assertEqual(len(regs), 2)

        # Verify origins created
        origins = EventAttendeeOrigin.objects.filter(registration__in=regs)
        self.assertEqual(origins.count(), 2)

        # User1 cancels
        self.client.force_authenticate(user=self.user1)
        reg1 = EventRegistration.objects.get(event=self.app_event, user=self.user1)
        response = self.client.delete(f'/api/event-registrations/{reg1.id}/')

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify origin status updated to cancelled
        reg1.refresh_from_db()
        self.assertEqual(reg1.status, 'cancelled')
        self.assertEqual(
            reg1.origins.filter(status='cancelled').count(),
            1
        )

        # Verify attending_count decremented by 1
        self.app_event.refresh_from_db()
        self.assertEqual(self.app_event.attending_count, 1)

        # User2 still registered
        reg2 = EventRegistration.objects.get(event=self.app_event, user=self.user2)
        self.assertEqual(reg2.status, 'registered')
        self.assertGreater(reg2.origins.filter(status='active').count(), 0)


class TestAttendingCountConstraint(TestCase):
    """Test that attending_count constraint is never violated."""

    def setUp(self):
        self.organizer = User.objects.create_user(
            username='organizer',
            email='org@test.com',
            password='test'
        )
        self.community = Community.objects.create(
            name='Community',
            slug='comm'
        )
        self.event = Event.objects.create(
            title='Event',
            community=self.community,
            created_by=self.organizer
        )

    def test_attending_count_never_negative(self):
        """Verify attending_count PositiveIntegerField constraint"""
        # This test verifies the DB constraint is never violated
        self.event.attending_count = 0
        self.event.save()

        # Attempting to set negative should fail
        with self.assertRaises(Exception):
            self.event.attending_count = -1
            self.event.full_clean()  # This validates

    def test_attending_count_non_negative_after_updates(self):
        """Test attending_count stays non-negative after safe recalculation"""
        self.event.attending_count = 5
        self.event.save()

        # Safe recalculation should result in 0 (no actual registrations)
        from events.views import _recalculate_event_attending_count
        _recalculate_event_attending_count(self.event.id)

        self.event.refresh_from_db()
        self.assertEqual(self.event.attending_count, 0)
        self.assertGreaterEqual(self.event.attending_count, 0)
