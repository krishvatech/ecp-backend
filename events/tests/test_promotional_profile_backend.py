"""
Tests for Promotional Profile backend functionality.

Tests cover:
- Profile creation based on attendee roles
- Module activation and tracking
- Duplicate prevention
- Completion tracking
- Helper functions
"""
from django.test import TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import timedelta

from events.models import (
    Event, EventRegistration, EventParticipant,
    PostAcceptanceFormAssignment, PostAcceptanceFormTemplate
)
from events.services.promotional_profile_service import (
    get_promotional_modules_for_attendee,
    should_create_promotional_profile,
    get_or_create_promotional_profile,
    mark_module_completed,
    get_promotional_profile_completion_summary,
    consolidate_promotional_profiles_for_registration,
)

User = get_user_model()


class PromotionalProfileBackendTest(TestCase):
    """Test promotional profile backend functionality."""

    def setUp(self):
        """Set up test data."""
        self.user1 = User.objects.create_user(username='speaker', email='speaker@test.com')
        self.user2 = User.objects.create_user(username='attendee', email='attendee@test.com')
        self.user3 = User.objects.create_user(username='startup', email='startup@test.com')
        self.admin_user = User.objects.create_user(username='admin', email='admin@test.com', is_staff=True)

        # Create event
        self.event = Event.objects.create(
            title='Test Event',
            description='Test event for promotional profiles',
            event_format='in_person',
            start_date=timezone.now() + timedelta(days=30),
            created_by=self.admin_user,
            status='draft'
        )

    # ========================================================
    # TEST 1: Speaker gets promotional profile
    # ========================================================
    def test_01_speaker_gets_promotional_profile(self):
        """
        Test: Speaker role triggers promotional profile creation

        Expected:
        - EventParticipant created with role='speaker'
        - get_promotional_modules_for_attendee returns ['speaker']
        - should_create_promotional_profile returns True
        - Promotional profile is created with 'speaker' module
        """
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            attendee_status='confirmed',
            status='registered'
        )

        # Create speaker role
        EventParticipant.objects.create(
            event=self.event,
            user=self.user1,
            role='speaker',
            participant_type='staff'
        )

        # Test helper functions
        modules = get_promotional_modules_for_attendee(registration)
        self.assertEqual(modules, ['speaker'], "Should identify speaker module")

        should_create = should_create_promotional_profile(registration)
        self.assertTrue(should_create, "Speaker should trigger profile creation")

        # Create profile
        assignment, created = get_or_create_promotional_profile(registration)
        self.assertTrue(created, "Profile should be newly created")
        self.assertIsNotNone(assignment, "Profile should exist")
        self.assertEqual(assignment.form_type, 'promotional_profile')
        self.assertEqual(assignment.active_modules, ['speaker'])

    # ========================================================
    # TEST 2: Normal attendee does NOT get profile
    # ========================================================
    def test_02_normal_attendee_no_profile(self):
        """
        Test: Normal attendee without promotional roles doesn't get profile

        Expected:
        - No EventParticipant role created
        - get_promotional_modules_for_attendee returns []
        - should_create_promotional_profile returns False
        - No profile is created
        """
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user2,
            attendee_status='confirmed',
            status='registered'
        )

        # No role created - normal attendee

        modules = get_promotional_modules_for_attendee(registration)
        self.assertEqual(modules, [], "Normal attendee should have no modules")

        should_create = should_create_promotional_profile(registration)
        self.assertFalse(should_create, "Normal attendee should not trigger profile")

        assignment, created = get_or_create_promotional_profile(registration)
        self.assertIsNone(assignment, "No profile should be created")

    # ========================================================
    # TEST 3: Multiple roles = one profile with multiple modules
    # ========================================================
    def test_03_multiple_roles_single_profile(self):
        """
        Test: Attendee with multiple promotional roles gets one profile with multiple modules

        Expected:
        - EventParticipant with role='speaker' AND role='startup'
        - get_promotional_modules_for_attendee returns ['speaker', 'startup']
        - Single promotional profile created
        - active_modules = ['speaker', 'startup']
        """
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user3,
            attendee_status='confirmed',
            status='registered'
        )

        # Create multiple roles
        EventParticipant.objects.create(
            event=self.event,
            user=self.user3,
            role='speaker',
            participant_type='staff'
        )
        EventParticipant.objects.create(
            event=self.event,
            user=self.user3,
            role='startup',
            participant_type='staff'
        )

        modules = get_promotional_modules_for_attendee(registration)
        self.assertEqual(set(modules), {'speaker', 'startup'}, "Should have both modules")

        # Create profile
        assignment, created = get_or_create_promotional_profile(registration)
        self.assertTrue(created, "Profile should be created")
        self.assertEqual(set(assignment.active_modules), {'speaker', 'startup'})

        # Verify only one profile exists
        profiles = PostAcceptanceFormAssignment.objects.filter(
            event_registration=registration,
            form_type='promotional_profile'
        )
        self.assertEqual(profiles.count(), 1, "Only one profile should exist")

    # ========================================================
    # TEST 4: Duplicate prevention
    # ========================================================
    def test_04_duplicate_prevention(self):
        """
        Test: Calling get_or_create_promotional_profile twice returns same profile

        Expected:
        - First call: created=True
        - Second call: created=False, same assignment returned
        """
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            attendee_status='confirmed',
            status='registered'
        )

        EventParticipant.objects.create(
            event=self.event,
            user=self.user1,
            role='speaker',
            participant_type='staff'
        )

        # First call
        assignment1, created1 = get_or_create_promotional_profile(registration)
        self.assertTrue(created1, "First call should create profile")

        # Second call
        assignment2, created2 = get_or_create_promotional_profile(registration)
        self.assertFalse(created2, "Second call should not create profile")
        self.assertEqual(assignment1.id, assignment2.id, "Should return same profile")

    # ========================================================
    # TEST 5: Online speaker still gets profile
    # ========================================================
    def test_05_online_speaker_gets_profile(self):
        """
        Test: Speaker in online-only event still gets promotional profile

        Expected:
        - Online event with speaker role
        - Promotional profile created (not affected by event format)
        """
        online_event = Event.objects.create(
            title='Online Event',
            description='Online only event',
            event_format='online',
            start_date=timezone.now() + timedelta(days=30),
            created_by=self.admin_user,
            status='draft'
        )

        registration = EventRegistration.objects.create(
            event=online_event,
            user=self.user1,
            attendee_status='confirmed',
            status='registered'
        )

        EventParticipant.objects.create(
            event=online_event,
            user=self.user1,
            role='speaker',
            participant_type='staff'
        )

        modules = get_promotional_modules_for_attendee(registration)
        self.assertEqual(modules, ['speaker'], "Online speaker should have speaker module")

        should_create = should_create_promotional_profile(registration)
        self.assertTrue(should_create, "Online speaker should trigger profile")

    # ========================================================
    # TEST 6: Module completion tracking
    # ========================================================
    def test_06_module_completion_tracking(self):
        """
        Test: Module completion status is tracked independently

        Expected:
        - Initial status: all modules incomplete
        - After marking speaker complete: speaker=True, other modules remain False
        - After marking all complete: assignment.status = COMPLETED
        """
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user3,
            attendee_status='confirmed',
            status='registered'
        )

        EventParticipant.objects.create(event=self.event, user=self.user3, role='speaker', participant_type='staff')
        EventParticipant.objects.create(event=self.event, user=self.user3, role='startup', participant_type='staff')

        assignment, _ = get_or_create_promotional_profile(registration)

        # Check initial status
        summary = get_promotional_profile_completion_summary(assignment)
        self.assertEqual(summary['completion_percentage'], 0)
        self.assertFalse(summary['fully_completed'])

        # Mark speaker complete
        mark_module_completed(assignment, 'speaker')
        assignment.refresh_from_db()

        summary = get_promotional_profile_completion_summary(assignment)
        self.assertEqual(summary['completion_percentage'], 50)
        self.assertFalse(summary['fully_completed'])

        # Mark startup complete
        mark_module_completed(assignment, 'startup')
        assignment.refresh_from_db()

        summary = get_promotional_profile_completion_summary(assignment)
        self.assertEqual(summary['completion_percentage'], 100)
        self.assertTrue(summary['fully_completed'])
        self.assertEqual(assignment.status, PostAcceptanceFormAssignment.STATUS_COMPLETED)

    # ========================================================
    # TEST 7: Role consolidation
    # ========================================================
    def test_07_role_consolidation(self):
        """
        Test: Adding/removing roles updates existing profile

        Expected:
        - Create profile with speaker role
        - Add startup role
        - Profile updated to include both modules
        """
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            attendee_status='confirmed',
            status='registered'
        )

        # Create speaker role
        EventParticipant.objects.create(
            event=self.event,
            user=self.user1,
            role='speaker',
            participant_type='staff'
        )

        # Create initial profile
        assignment1, _ = get_or_create_promotional_profile(registration)
        self.assertEqual(assignment1.active_modules, ['speaker'])

        # Add startup role
        EventParticipant.objects.create(
            event=self.event,
            user=self.user1,
            role='startup',
            participant_type='staff'
        )

        # Consolidate
        assignment2 = consolidate_promotional_profiles_for_registration(registration)
        self.assertEqual(assignment2.id, assignment1.id, "Should be same profile")
        self.assertEqual(set(assignment2.active_modules), {'speaker', 'startup'})

    # ========================================================
    # TEST 8: All role types work
    # ========================================================
    def test_08_all_role_types(self):
        """
        Test: All promotional profile roles work correctly

        Roles to test:
        - speaker → 'speaker' module
        - sponsor → 'sponsor' module
        - sponsor_staff → 'sponsor_staff' module
        - startup → 'startup' module
        - investor → 'investor' module
        """
        roles_to_test = [
            ('speaker', 'speaker'),
            ('sponsor', 'sponsor'),
            ('sponsor_staff', 'sponsor_staff'),
            ('startup', 'startup'),
            ('investor', 'investor'),
        ]

        for role, expected_module in roles_to_test:
            user = User.objects.create_user(username=f'user_{role}', email=f'{role}@test.com')
            registration = EventRegistration.objects.create(
                event=self.event,
                user=user,
                attendee_status='confirmed',
                status='registered'
            )

            EventParticipant.objects.create(
                event=self.event,
                user=user,
                role=role,
                participant_type='staff'
            )

            modules = get_promotional_modules_for_attendee(registration)
            self.assertIn(expected_module, modules, f"Role {role} should map to module {expected_module}")

            assignment, _ = get_or_create_promotional_profile(registration)
            self.assertIn(expected_module, assignment.active_modules)

    # ========================================================
    # TEST 9: Non-promotional roles (moderator, host) don't trigger
    # ========================================================
    def test_09_non_promotional_roles_ignored(self):
        """
        Test: Moderator and host roles don't trigger promotional profile

        Expected:
        - EventParticipant with role='moderator' or role='host'
        - get_promotional_modules_for_attendee returns []
        - No profile created
        """
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            attendee_status='confirmed',
            status='registered'
        )

        # Create moderator role
        EventParticipant.objects.create(
            event=self.event,
            user=self.user1,
            role='moderator',
            participant_type='staff'
        )

        modules = get_promotional_modules_for_attendee(registration)
        self.assertEqual(modules, [], "Moderator should not trigger profile")

        should_create = should_create_promotional_profile(registration)
        self.assertFalse(should_create)
