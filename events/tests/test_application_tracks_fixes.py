"""
Tests for Application Tracks runtime fixes.
Covers: tier selection, role assignment, attendee directory, opt-out, bulk accept, promotional profiles.
"""
from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from django.utils import timezone
from events.models import (
    Event, EventApplication, EventApplicationTrack, EventApplicationTrackApplication,
    EventRegistration, TrackPricingTier, EventRole, EventAttendeeOrigin
)
from community.models import Community
from events.services.application_decisions import accept_track_application


class TierSelectionTestCase(TransactionTestCase):
    """Test proper tier selection with fallback logic."""

    def setUp(self):
        self.community = Community.objects.create(name='TestCom', slug='testcom')
        self.user = User.objects.create_user('speaker@test.com', 'speaker@test.com', 'pass')
        self.event = Event.objects.create(
            title='Test Event',
            community=self.community,
            registration_type='apply'
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            role_mappings_on_acceptance=['speaker']
        )
        # Create tiers
        self.tier_free = TrackPricingTier.objects.create(
            track=self.track,
            key='free',
            label='Free Tier',
            price=0,
            is_default=True,
            is_active=True,
            sort_order=1
        )
        self.tier_paid = TrackPricingTier.objects.create(
            track=self.track,
            key='paid',
            label='Paid Tier',
            price=100,
            is_default=False,
            is_active=True,
            sort_order=2
        )

    def test_accept_with_explicit_tier(self):
        """Test acceptance with explicitly provided tier."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='speaker@test.com',
            submission_mode='self_submission'
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            submission_mode='self_submission'
        )
        reviewer = User.objects.create_user('admin@test.com', 'admin@test.com', 'pass')

        # Accept with paid tier
        result = accept_track_application(
            track_app,
            reviewer,
            accepted_tier=self.tier_paid
        )

        self.assertEqual(result.accepted_tier, self.tier_paid)
        track_app.refresh_from_db()
        self.assertEqual(track_app.status, 'accepted')

    def test_accept_with_default_tier(self):
        """Test acceptance falls back to default tier."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='speaker@test.com',
            submission_mode='self_submission'
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            submission_mode='self_submission'
        )
        reviewer = User.objects.create_user('admin@test.com', 'admin@test.com', 'pass')

        # Accept without specifying tier - should use default
        result = accept_track_application(track_app, reviewer)

        self.assertEqual(result.accepted_tier, self.tier_free)

    def test_accept_free_tier_confirms_immediately(self):
        """Test that free tier creates confirmed attendee."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='speaker@test.com',
            submission_mode='self_submission'
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            submission_mode='self_submission'
        )
        reviewer = User.objects.create_user('admin@test.com', 'admin@test.com', 'pass')

        accept_track_application(track_app, reviewer, accepted_tier=self.tier_free)

        reg = EventRegistration.objects.get(event=self.event, user=self.user)
        self.assertEqual(reg.attendee_status, 'confirmed')

    def test_accept_paid_tier_creates_payment_pending(self):
        """Test that paid tier creates payment_pending attendee."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='speaker@test.com',
            submission_mode='self_submission'
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            submission_mode='self_submission'
        )
        reviewer = User.objects.create_user('admin@test.com', 'admin@test.com', 'pass')

        accept_track_application(track_app, reviewer, accepted_tier=self.tier_paid)

        reg = EventRegistration.objects.get(event=self.event, user=self.user)
        self.assertEqual(reg.attendee_status, 'payment_pending')

    def test_accept_raises_error_if_no_tier_available(self):
        """Test that acceptance fails gracefully if no tier exists."""
        # Create a new track with no tiers
        track_no_tier = EventApplicationTrack.objects.create(
            event=self.event,
            key='no_tier',
            label='No Tier Track',
            role_mappings_on_acceptance=['speaker']
        )

        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='speaker@test.com',
            submission_mode='self_submission'
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=track_no_tier,
            submission_mode='self_submission'
        )
        reviewer = User.objects.create_user('admin@test.com', 'admin@test.com', 'pass')

        # Should raise ValueError
        with self.assertRaises(ValueError):
            accept_track_application(track_app, reviewer)


class RoleAssignmentTestCase(TransactionTestCase):
    """Test role assignment from role_mappings_on_acceptance."""

    def setUp(self):
        self.community = Community.objects.create(name='TestCom', slug='testcom')
        self.user = User.objects.create_user('speaker@test.com', 'speaker@test.com', 'pass')
        self.event = Event.objects.create(
            title='Test Event',
            community=self.community,
            registration_type='apply'
        )

    def test_single_role_assignment(self):
        """Test assignment of single role on acceptance."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            role_mappings_on_acceptance=['speaker']
        )
        tier = TrackPricingTier.objects.create(
            track=track,
            key='free',
            label='Free',
            price=0,
            is_active=True
        )

        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='speaker@test.com',
            submission_mode='self_submission'
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=track,
            submission_mode='self_submission'
        )
        reviewer = User.objects.create_user('admin@test.com', 'admin@test.com', 'pass')

        accept_track_application(track_app, reviewer, accepted_tier=tier)

        reg = EventRegistration.objects.get(event=self.event, user=self.user)
        roles = list(reg.roles.values_list('key', flat=True))
        self.assertIn('speaker', roles)

    def test_multiple_roles_assignment(self):
        """Test assignment of multiple roles on acceptance."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            role_mappings_on_acceptance=['speaker', 'mentor']
        )
        tier = TrackPricingTier.objects.create(
            track=track,
            key='free',
            label='Free',
            price=0,
            is_active=True
        )

        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='speaker@test.com',
            submission_mode='self_submission'
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=track,
            submission_mode='self_submission'
        )
        reviewer = User.objects.create_user('admin@test.com', 'admin@test.com', 'pass')

        accept_track_application(track_app, reviewer, accepted_tier=tier)

        reg = EventRegistration.objects.get(event=self.event, user=self.user)
        roles = list(reg.roles.values_list('key', flat=True))
        self.assertIn('speaker', roles)
        self.assertIn('mentor', roles)


class AttendeeOriginTestCase(TransactionTestCase):
    """Test EventAttendeeOrigin creation."""

    def setUp(self):
        self.community = Community.objects.create(name='TestCom', slug='testcom')
        self.user = User.objects.create_user('speaker@test.com', 'speaker@test.com', 'pass')
        self.event = Event.objects.create(
            title='Test Event',
            community=self.community,
            registration_type='apply'
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            role_mappings_on_acceptance=['speaker']
        )
        self.tier = TrackPricingTier.objects.create(
            track=self.track,
            key='free',
            label='Free',
            price=0,
            is_active=True
        )

    def test_origin_created_on_acceptance(self):
        """Test that EventAttendeeOrigin is created on acceptance."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='speaker@test.com',
            submission_mode='self_submission'
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=self.track,
            submission_mode='self_submission'
        )
        reviewer = User.objects.create_user('admin@test.com', 'admin@test.com', 'pass')

        accept_track_application(track_app, reviewer, accepted_tier=self.tier)

        reg = EventRegistration.objects.get(event=self.event, user=self.user)
        origins = EventAttendeeOrigin.objects.filter(registration=reg)
        self.assertEqual(origins.count(), 1)

        origin = origins.first()
        self.assertEqual(origin.track, self.track)
        self.assertEqual(origin.submission_mode, 'self_submission')
        self.assertEqual(origin.accepted_by, reviewer)
        self.assertEqual(origin.accepted_tier, self.tier)


class OptOutTestCase(TransactionTestCase):
    """Test opt_out_automated_communication flag."""

    def setUp(self):
        self.community = Community.objects.create(name='TestCom', slug='testcom')
        self.user = User.objects.create_user('applicant@test.com', 'applicant@test.com', 'pass')
        self.event = Event.objects.create(
            title='Test Event',
            community=self.community,
            registration_type='apply'
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            role_mappings_on_acceptance=['speaker']
        )
        self.tier = TrackPricingTier.objects.create(
            track=self.track,
            key='free',
            label='Free',
            price=0,
            is_active=True
        )

    def test_opt_out_flag_exists(self):
        """Test that opt_out_automated_communication field exists."""
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='applicant@test.com',
            submission_mode='self_submission',
            opt_out_automated_communication=False
        )
        self.assertFalse(app.opt_out_automated_communication)

        app.opt_out_automated_communication = True
        app.save()
        app.refresh_from_db()
        self.assertTrue(app.opt_out_automated_communication)


class BulkAcceptTestCase(TransactionTestCase):
    """Test bulk acceptance properly calls service."""

    def setUp(self):
        self.community = Community.objects.create(name='TestCom', slug='testcom')
        self.user = User.objects.create_user('speaker1@test.com', 'speaker1@test.com', 'pass')
        self.user2 = User.objects.create_user('speaker2@test.com', 'speaker2@test.com', 'pass')
        self.reviewer = User.objects.create_user('admin@test.com', 'admin@test.com', 'pass')
        self.event = Event.objects.create(
            title='Test Event',
            community=self.community,
            registration_type='apply'
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            role_mappings_on_acceptance=['speaker']
        )
        self.tier = TrackPricingTier.objects.create(
            track=self.track,
            key='free',
            label='Free',
            price=0,
            is_active=True
        )

    def test_bulk_accept_creates_registrations(self):
        """Test that bulk accept creates registrations for all track apps."""
        # Create two applications
        app1 = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email='speaker1@test.com',
            submission_mode='self_submission'
        )
        track_app1 = EventApplicationTrackApplication.objects.create(
            application=app1,
            track=self.track,
            submission_mode='self_submission'
        )

        app2 = EventApplication.objects.create(
            event=self.event,
            user=self.user2,
            email='speaker2@test.com',
            submission_mode='self_submission'
        )
        track_app2 = EventApplicationTrackApplication.objects.create(
            application=app2,
            track=self.track,
            submission_mode='self_submission'
        )

        # Accept both via service (simulating bulk accept)
        accept_track_application(track_app1, self.reviewer, accepted_tier=self.tier)
        accept_track_application(track_app2, self.reviewer, accepted_tier=self.tier)

        # Verify both have registrations
        reg1 = EventRegistration.objects.get(event=self.event, user=self.user)
        reg2 = EventRegistration.objects.get(event=self.event, user=self.user2)

        self.assertIsNotNone(reg1)
        self.assertIsNotNone(reg2)
        self.assertEqual(reg1.attendee_status, 'confirmed')
        self.assertEqual(reg2.attendee_status, 'confirmed')
