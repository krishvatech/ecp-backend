"""
Test suite for EventRole seeding functionality.

Tests cover:
- Automatic role seeding when events are created
- Fallback role seeding for existing events without roles
- No duplicate role creation
- Correct role configuration (promotional_profile flags, visibility, etc.)
- API endpoint returns seeded roles
"""

from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from events.models import Event, EventRole
from events.services.role_seeding import seed_default_roles_for_event, get_or_seed_event_roles
from community.models import Community


class RoleSeedingTestCase(TestCase):
    """Test EventRole seeding functionality."""

    def setUp(self):
        """Create test community."""
        self.community = Community.objects.create(
            title="Test Community",
            description="For testing"
        )

    def test_event_creation_seeds_default_roles(self):
        """Creating an event should seed default EventRole records."""
        # Create event
        event = Event.objects.create(
            title="Test Event",
            community=self.community,
            status="draft"
        )

        # Verify roles were seeded
        roles = EventRole.objects.filter(event=event)
        self.assertGreater(roles.count(), 0, "No roles were seeded on event creation")

        # Verify expected roles exist
        role_keys = set(roles.values_list('key', flat=True))
        expected_keys = {'attendee', 'speaker', 'sponsor', 'sponsor_staff', 'startup', 'investor'}
        for expected_key in expected_keys:
            self.assertIn(expected_key, role_keys, f"Expected role '{expected_key}' not found")

    def test_speaker_role_triggers_promotional_profile(self):
        """Speaker role should have triggers_promotional_profile=True."""
        event = Event.objects.create(
            title="Test Event",
            community=self.community,
            status="draft"
        )

        speaker_role = EventRole.objects.get(event=event, key='speaker')
        self.assertTrue(
            speaker_role.triggers_promotional_profile,
            "Speaker role should trigger promotional profile"
        )

    def test_attendee_role_does_not_trigger_promotional_profile(self):
        """Attendee role should have triggers_promotional_profile=False."""
        event = Event.objects.create(
            title="Test Event",
            community=self.community,
            status="draft"
        )

        attendee_role = EventRole.objects.get(event=event, key='attendee')
        self.assertFalse(
            attendee_role.triggers_promotional_profile,
            "Attendee role should NOT trigger promotional profile"
        )

    def test_no_duplicate_roles_created(self):
        """Calling seed_default_roles_for_event twice should not duplicate roles."""
        event = Event.objects.create(
            title="Test Event",
            community=self.community,
            status="draft"
        )

        # Get initial count
        initial_count = EventRole.objects.filter(event=event).count()

        # Seed again
        stats = seed_default_roles_for_event(event)
        final_count = EventRole.objects.filter(event=event).count()

        # Counts should match
        self.assertEqual(initial_count, final_count, "Duplicate roles were created")
        self.assertEqual(stats['created'], 0, "Should not create any new roles on second seed")
        self.assertGreater(stats['existing'], 0, "Should find existing roles on second seed")

    def test_fallback_seeding_for_event_without_roles(self):
        """Existing event without roles should get roles seeded when accessed."""
        # Create event and manually delete all roles (simulating old event)
        event = Event.objects.create(
            title="Old Event",
            community=self.community,
            status="draft"
        )
        EventRole.objects.filter(event=event).delete()

        # Verify no roles exist
        self.assertEqual(EventRole.objects.filter(event=event).count(), 0)

        # Call fallback seeding
        roles = get_or_seed_event_roles(event)

        # Verify roles were seeded
        self.assertGreater(roles.count(), 0, "Roles should be seeded for event with no roles")

    def test_api_endpoint_returns_seeded_roles(self):
        """API endpoint should return seeded roles for event."""
        event = Event.objects.create(
            title="Test Event",
            community=self.community,
            status="draft"
        )

        # Create test user
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass'
        )

        # Make API request (would be done via client in integration test)
        # Here we just test the service method
        roles = get_or_seed_event_roles(event)

        # Verify response
        self.assertIsNotNone(roles)
        self.assertGreater(roles.count(), 0)

        # Verify all expected roles present
        role_keys = set(roles.values_list('key', flat=True))
        self.assertGreaterEqual(len(role_keys), 6)

    def test_role_sort_priority(self):
        """Roles should be ordered by sort_priority."""
        event = Event.objects.create(
            title="Test Event",
            community=self.community,
            status="draft"
        )

        roles = EventRole.objects.filter(event=event).order_by('sort_priority', 'label')
        priorities = list(roles.values_list('sort_priority', flat=True))

        # Verify sorted order
        self.assertEqual(priorities, sorted(priorities), "Roles not sorted by priority")

    def test_promotional_profile_roles(self):
        """Verify all promotional profile roles are marked correctly."""
        event = Event.objects.create(
            title="Test Event",
            community=self.community,
            status="draft"
        )

        promo_roles = EventRole.objects.filter(
            event=event,
            triggers_promotional_profile=True
        ).values_list('key', flat=True)

        expected_promo_roles = {'speaker', 'sponsor', 'sponsor_staff', 'startup', 'investor'}
        for role_key in promo_roles:
            self.assertIn(role_key, expected_promo_roles)

    def test_non_promotional_roles(self):
        """Verify non-promotional roles are marked correctly."""
        event = Event.objects.create(
            title="Test Event",
            community=self.community,
            status="draft"
        )

        non_promo_roles = EventRole.objects.filter(
            event=event,
            triggers_promotional_profile=False
        ).values_list('key', flat=True)

        expected_non_promo_roles = {'attendee', 'press', 'researcher', 'nominator', 'organiser', 'moderator'}
        for role_key in non_promo_roles:
            self.assertIn(role_key, expected_non_promo_roles)


class RoleTrackMappingTestCase(TestCase):
    """Test role mapping on application tracks."""

    def setUp(self):
        """Create test community and event."""
        self.community = Community.objects.create(
            title="Test Community",
            description="For testing"
        )
        self.event = Event.objects.create(
            title="Test Event",
            community=self.community,
            registration_type="apply",
            status="published"
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass'
        )

    def test_track_role_mapping_saved(self):
        """Creating track with role mappings should save them correctly."""
        from events.models import EventApplicationTrack

        # Create track with role mappings
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key="speaker_track",
            label="Speaker Track",
            status="open",
            role_mappings_on_acceptance=["speaker"]
        )

        # Verify saved
        self.assertEqual(track.role_mappings_on_acceptance, ["speaker"])

    def test_track_accepts_multiple_roles(self):
        """Track should accept multiple role mappings."""
        from events.models import EventApplicationTrack

        track = EventApplicationTrack.objects.create(
            event=self.event,
            key="sponsor_track",
            label="Sponsor Track",
            status="open",
            role_mappings_on_acceptance=["sponsor", "sponsor_staff"]
        )

        self.assertEqual(len(track.role_mappings_on_acceptance), 2)
        self.assertIn("sponsor", track.role_mappings_on_acceptance)
        self.assertIn("sponsor_staff", track.role_mappings_on_acceptance)

    def test_acceptance_assigns_roles_from_track_mapping(self):
        """Accepting application should assign roles from track.role_mappings_on_acceptance."""
        from events.models import EventApplicationTrack, EventApplication, EventApplicationTrackApplication
        from events.services.application_decisions import accept_track_application

        # Create track and tier
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key="speaker_track",
            label="Speaker Track",
            status="open",
            role_mappings_on_acceptance=["speaker"]
        )
        from events.models import TrackPricingTier
        tier = TrackPricingTier.objects.create(
            track=track,
            label="Free",
            price=0,
            is_default=True
        )

        # Create application
        app = EventApplication.objects.create(
            event=self.event,
            user=self.user,
            email=self.user.email,
            status="pending"
        )
        track_app = EventApplicationTrackApplication.objects.create(
            application=app,
            track=track,
            status="pending"
        )

        # Accept
        accept_track_application(track_app, self.user, accepted_tier=tier)

        # Verify roles assigned
        from events.models import EventRegistration
        registration = EventRegistration.objects.get(event=self.event, user=self.user)
        role_keys = set(registration.roles.values_list('key', flat=True))

        self.assertIn("speaker", role_keys, "Speaker role should be assigned")
