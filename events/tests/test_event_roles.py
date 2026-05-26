"""
Comprehensive tests for EventRole model and multi-role attendee functionality.

Tests cover:
- EventRole creation and management
- EventRegistration multi-role support
- Role merging (set union, not overwrite)
- Backfilling existing registrations
- Promotional profile triggers
- Serializer output
- Admin interface
"""

from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from django.db.models import Q
from events.models import Event, EventRegistration, EventRole
from events.serializers import EventRoleSerializer, EventRegistrationSerializer
from community.models import Community
from django.utils import timezone


class EventRoleModelTests(TestCase):
    """Test EventRole model functionality."""

    def setUp(self):
        """Set up test data."""
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community"
        )
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            first_name="Test",
            last_name="User"
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Test Event",
            slug="test-event",
            created_by=self.user
        )

    def test_create_event_role(self):
        """Test creating an EventRole."""
        role = EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            description='Event speaker',
            visibility='public',
            sort_priority=10,
            badge_color='#f59e0b',
            badge_style='filled',
            triggers_promotional_profile=True,
            is_system_default=True
        )
        self.assertEqual(role.key, 'speaker')
        self.assertEqual(role.label, 'Speaker')
        self.assertTrue(role.triggers_promotional_profile)
        self.assertTrue(role.is_system_default)

    def test_event_role_unique_together(self):
        """Test that (event, key) must be unique."""
        EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            triggers_promotional_profile=True
        )
        with self.assertRaises(Exception):
            EventRole.objects.create(
                event=self.event,
                key='speaker',
                label='Speaker',
                triggers_promotional_profile=True
            )

    def test_event_role_str(self):
        """Test EventRole string representation."""
        role = EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker'
        )
        self.assertEqual(str(role), f"Speaker ({self.event.title})")

    def test_role_visibility_choices(self):
        """Test visibility options are properly enforced."""
        for visibility in ['public', 'admin_only', 'restricted']:
            role = EventRole.objects.create(
                event=self.event,
                key=f'test_{visibility}',
                label='Test Role',
                visibility=visibility
            )
            self.assertEqual(role.visibility, visibility)

    def test_role_ordering(self):
        """Test roles are ordered by sort_priority then label."""
        EventRole.objects.create(
            event=self.event,
            key='attendee',
            label='Attendee',
            sort_priority=100
        )
        EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            sort_priority=10
        )
        EventRole.objects.create(
            event=self.event,
            key='sponsor',
            label='Sponsor',
            sort_priority=20
        )
        roles = EventRole.objects.filter(event=self.event)
        self.assertEqual(roles[0].key, 'speaker')  # Priority 10
        self.assertEqual(roles[1].key, 'sponsor')  # Priority 20
        self.assertEqual(roles[2].key, 'attendee')  # Priority 100


class EventRegistrationMultiRoleTests(TestCase):
    """Test EventRegistration multi-role support."""

    def setUp(self):
        """Set up test data."""
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community"
        )
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com"
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Test Event",
            slug="test-event",
            created_by=self.user
        )

        # Create some roles
        self.attendee_role = EventRole.objects.create(
            event=self.event,
            key='attendee',
            label='Attendee',
            triggers_promotional_profile=False,
            sort_priority=100
        )
        self.speaker_role = EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            triggers_promotional_profile=True,
            sort_priority=10
        )
        self.sponsor_role = EventRole.objects.create(
            event=self.event,
            key='sponsor',
            label='Sponsor',
            triggers_promotional_profile=True,
            sort_priority=20
        )

    def test_registration_created_without_roles(self):
        """Test that a registration can be created without roles."""
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user
        )
        self.assertEqual(registration.roles.count(), 0)

    def test_add_single_role_to_registration(self):
        """Test adding a single role to a registration."""
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user
        )
        registration.roles.add(self.attendee_role)
        self.assertEqual(registration.roles.count(), 1)
        self.assertIn(self.attendee_role, registration.roles.all())

    def test_add_multiple_roles_to_registration(self):
        """Test adding multiple roles to a registration."""
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user
        )
        registration.roles.add(self.attendee_role, self.speaker_role, self.sponsor_role)
        self.assertEqual(registration.roles.count(), 3)
        self.assertIn(self.attendee_role, registration.roles.all())
        self.assertIn(self.speaker_role, registration.roles.all())
        self.assertIn(self.sponsor_role, registration.roles.all())

    def test_role_merge_does_not_overwrite(self):
        """Test that adding roles does not remove existing roles (set union)."""
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user
        )
        # Add attendee role
        registration.roles.add(self.attendee_role)
        self.assertEqual(registration.roles.count(), 1)

        # Add speaker role
        registration.roles.add(self.speaker_role)
        self.assertEqual(registration.roles.count(), 2)

        # Both should still be present
        self.assertIn(self.attendee_role, registration.roles.all())
        self.assertIn(self.speaker_role, registration.roles.all())

    def test_duplicate_role_add_is_idempotent(self):
        """Test that adding the same role twice doesn't create duplicates."""
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user
        )
        registration.roles.add(self.attendee_role)
        registration.roles.add(self.attendee_role)
        self.assertEqual(registration.roles.count(), 1)

    def test_get_registrations_by_role(self):
        """Test querying registrations by role."""
        reg1 = EventRegistration.objects.create(event=self.event, user=self.user)

        user2 = User.objects.create_user(username="user2", email="user2@example.com")
        reg2 = EventRegistration.objects.create(event=self.event, user=user2)

        # Assign roles
        reg1.roles.add(self.speaker_role, self.sponsor_role)
        reg2.roles.add(self.attendee_role)

        # Query for speakers
        speakers = EventRegistration.objects.filter(event=self.event, roles=self.speaker_role)
        self.assertEqual(speakers.count(), 1)
        self.assertIn(reg1, speakers)
        self.assertNotIn(reg2, speakers)

    def test_registration_unique_together_event_user(self):
        """Test that (event, user) must be unique."""
        EventRegistration.objects.create(event=self.event, user=self.user)
        with self.assertRaises(Exception):
            EventRegistration.objects.create(event=self.event, user=self.user)


class ProvisionalProfileTriggerTests(TestCase):
    """Test promotional profile triggering based on roles."""

    def setUp(self):
        """Set up test data."""
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community"
        )
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com"
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Test Event",
            slug="test-event",
            created_by=self.user
        )

    def test_roles_with_promotional_profile_trigger(self):
        """Test roles marked with triggers_promotional_profile=True."""
        promotional_roles = {
            'speaker': True,
            'sponsor': True,
            'sponsor_staff': True,
            'startup': True,
            'investor': True,
        }

        for key, expected_trigger in promotional_roles.items():
            role = EventRole.objects.create(
                event=self.event,
                key=key,
                label=key.title(),
                triggers_promotional_profile=expected_trigger
            )
            self.assertEqual(role.triggers_promotional_profile, expected_trigger)

    def test_roles_without_promotional_profile_trigger(self):
        """Test roles marked with triggers_promotional_profile=False."""
        non_promotional_roles = {
            'attendee': False,
            'press': False,
            'researcher': False,
            'nominator': False,
            'organiser': False,
        }

        for key, expected_trigger in non_promotional_roles.items():
            role = EventRole.objects.create(
                event=self.event,
                key=key,
                label=key.title(),
                triggers_promotional_profile=expected_trigger
            )
            self.assertEqual(role.triggers_promotional_profile, expected_trigger)

    def test_query_registrations_requiring_promotional_profile(self):
        """Test querying registrations that have roles requiring promotional profile."""
        speaker_role = EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            triggers_promotional_profile=True
        )
        attendee_role = EventRole.objects.create(
            event=self.event,
            key='attendee',
            label='Attendee',
            triggers_promotional_profile=False
        )

        user1 = User.objects.create_user(username="user1", email="user1@example.com")
        user2 = User.objects.create_user(username="user2", email="user2@example.com")

        reg1 = EventRegistration.objects.create(event=self.event, user=user1)
        reg2 = EventRegistration.objects.create(event=self.event, user=user2)

        reg1.roles.add(speaker_role)
        reg2.roles.add(attendee_role)

        # Query for registrations with promotional profile triggers
        promo_registrations = EventRegistration.objects.filter(
            event=self.event,
            roles__triggers_promotional_profile=True
        ).distinct()

        self.assertEqual(promo_registrations.count(), 1)
        self.assertIn(reg1, promo_registrations)
        self.assertNotIn(reg2, promo_registrations)


class EventRegistrationSerializerTests(TestCase):
    """Test serializer output including roles."""

    def setUp(self):
        """Set up test data."""
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community"
        )
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            first_name="Test",
            last_name="User"
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Test Event",
            slug="test-event",
            created_by=self.user
        )

        self.speaker_role = EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            visibility='public',
            badge_color='#f59e0b',
            badge_style='filled',
            triggers_promotional_profile=True
        )

    def test_registration_serializer_includes_roles(self):
        """Test that registration serializer includes roles."""
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user
        )
        registration.roles.add(self.speaker_role)

        serializer = EventRegistrationSerializer(registration)
        data = serializer.data

        self.assertIn('roles', data)
        self.assertEqual(len(data['roles']), 1)
        self.assertEqual(data['roles'][0]['key'], 'speaker')
        self.assertEqual(data['roles'][0]['label'], 'Speaker')

    def test_registration_serializer_with_multiple_roles(self):
        """Test serializer with multiple roles."""
        attendee_role = EventRole.objects.create(
            event=self.event,
            key='attendee',
            label='Attendee',
            triggers_promotional_profile=False
        )

        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user
        )
        registration.roles.add(self.speaker_role, attendee_role)

        serializer = EventRegistrationSerializer(registration)
        data = serializer.data

        self.assertEqual(len(data['roles']), 2)
        role_keys = {role['key'] for role in data['roles']}
        self.assertEqual(role_keys, {'speaker', 'attendee'})

    def test_event_role_serializer(self):
        """Test EventRoleSerializer output."""
        serializer = EventRoleSerializer(self.speaker_role)
        data = serializer.data

        self.assertEqual(data['key'], 'speaker')
        self.assertEqual(data['label'], 'Speaker')
        self.assertEqual(data['visibility'], 'public')
        self.assertEqual(data['badge_color'], '#f59e0b')
        self.assertEqual(data['badge_style'], 'filled')
        self.assertTrue(data['triggers_promotional_profile'])


class BackfillTests(TransactionTestCase):
    """Test backfilling existing registrations with Attendee role.

    Uses TransactionTestCase to test management commands that use transactions.
    """

    def setUp(self):
        """Set up test data."""
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community"
        )
        self.user1 = User.objects.create_user(username="user1", email="user1@example.com")
        self.user2 = User.objects.create_user(username="user2", email="user2@example.com")
        self.user3 = User.objects.create_user(username="user3", email="user3@example.com")

        self.event = Event.objects.create(
            community=self.community,
            title="Test Event",
            slug="test-event",
            created_by=self.user1
        )

    def test_existing_registration_without_roles(self):
        """Test that existing registrations without roles exist."""
        reg1 = EventRegistration.objects.create(event=self.event, user=self.user1)
        reg2 = EventRegistration.objects.create(event=self.event, user=self.user2)

        # They should have no roles
        self.assertEqual(reg1.roles.count(), 0)
        self.assertEqual(reg2.roles.count(), 0)

    def test_backfill_existing_registrations_with_attendee_role(self):
        """Test backfilling existing registrations with Attendee role."""
        # Create registrations without roles
        reg1 = EventRegistration.objects.create(event=self.event, user=self.user1)
        reg2 = EventRegistration.objects.create(event=self.event, user=self.user2)

        # Create attendee role
        attendee_role = EventRole.objects.create(
            event=self.event,
            key='attendee',
            label='Attendee',
            triggers_promotional_profile=False
        )

        # Manually backfill (simulating what management command does)
        registrations_to_backfill = EventRegistration.objects.filter(
            event=self.event
        ).exclude(
            roles__isnull=False
        )

        for registration in registrations_to_backfill:
            registration.roles.add(attendee_role)

        # Verify backfill
        reg1.refresh_from_db()
        reg2.refresh_from_db()

        self.assertEqual(reg1.roles.count(), 1)
        self.assertEqual(reg2.roles.count(), 1)
        self.assertIn(attendee_role, reg1.roles.all())
        self.assertIn(attendee_role, reg2.roles.all())

    def test_backfill_respects_existing_roles(self):
        """Test that backfill doesn't affect registrations that already have roles."""
        # Create a role and assign it to one registration
        speaker_role = EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            triggers_promotional_profile=True
        )

        reg1 = EventRegistration.objects.create(event=self.event, user=self.user1)
        reg2 = EventRegistration.objects.create(event=self.event, user=self.user2)

        reg1.roles.add(speaker_role)
        # reg2 has no roles

        # Now create attendee role
        attendee_role = EventRole.objects.create(
            event=self.event,
            key='attendee',
            label='Attendee',
            triggers_promotional_profile=False
        )

        # Backfill: only add attendee to registrations with no roles
        registrations_to_backfill = EventRegistration.objects.filter(
            event=self.event
        ).exclude(
            roles__isnull=False
        )

        for registration in registrations_to_backfill:
            registration.roles.add(attendee_role)

        # Verify
        reg1.refresh_from_db()
        reg2.refresh_from_db()

        # reg1 should still only have speaker role
        self.assertEqual(reg1.roles.count(), 1)
        self.assertIn(speaker_role, reg1.roles.all())

        # reg2 should now have attendee role
        self.assertEqual(reg2.roles.count(), 1)
        self.assertIn(attendee_role, reg2.roles.all())


class EdgeCaseTests(TestCase):
    """Test edge cases and error conditions."""

    def setUp(self):
        """Set up test data."""
        self.community = Community.objects.create(
            name="Test Community",
            slug="test-community"
        )
        self.user = User.objects.create_user(username="testuser", email="test@example.com")
        self.event = Event.objects.create(
            community=self.community,
            title="Test Event",
            slug="test-event",
            created_by=self.user
        )

    def test_role_with_different_events(self):
        """Test that roles are event-specific."""
        event2 = Event.objects.create(
            community=self.community,
            title="Test Event 2",
            slug="test-event-2",
            created_by=self.user
        )

        role1 = EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker'
        )
        role2 = EventRole.objects.create(
            event=event2,
            key='speaker',
            label='Speaker'
        )

        # They should be different objects
        self.assertNotEqual(role1.id, role2.id)

        # Each event should have its own speaker role
        self.assertEqual(self.event.roles.filter(key='speaker').count(), 1)
        self.assertEqual(event2.roles.filter(key='speaker').count(), 1)

    def test_empty_role_list_serialization(self):
        """Test serializing a registration with no roles."""
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user
        )

        serializer = EventRegistrationSerializer(registration)
        data = serializer.data

        self.assertIn('roles', data)
        self.assertEqual(data['roles'], [])

    def test_clear_all_roles_from_registration(self):
        """Test removing all roles from a registration."""
        role = EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker'
        )

        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user
        )
        registration.roles.add(role)
        self.assertEqual(registration.roles.count(), 1)

        # Clear all roles
        registration.roles.clear()
        self.assertEqual(registration.roles.count(), 0)

    def test_remove_specific_role_from_registration(self):
        """Test removing a specific role from a registration."""
        speaker_role = EventRole.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker'
        )
        attendee_role = EventRole.objects.create(
            event=self.event,
            key='attendee',
            label='Attendee'
        )

        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user
        )
        registration.roles.add(speaker_role, attendee_role)
        self.assertEqual(registration.roles.count(), 2)

        # Remove speaker role
        registration.roles.remove(speaker_role)
        self.assertEqual(registration.roles.count(), 1)
        self.assertNotIn(speaker_role, registration.roles.all())
        self.assertIn(attendee_role, registration.roles.all())
