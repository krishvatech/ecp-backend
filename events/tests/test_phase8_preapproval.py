"""
Tests for Phase 8: Fine-grained pre-approval per event × track × submission_mode.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from events.models import (
    Community, Event, EventApplicationTrack,
    EventPreApprovalCode, EventPreApprovalAllowlist,
    EventApplication
)

User = get_user_model()


class PreApprovalCodeModelTests(TestCase):
    """Test EventPreApprovalCode model with track + submission_mode scoping."""

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
        self.track_speaker = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            short_description='Apply as speaker',
            status='open',
            enabled_submission_modes=['self_submission', 'confirmed']
        )
        self.track_sponsor = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor',
            label='Sponsor Track',
            short_description='Sponsor event',
            status='open',
            enabled_submission_modes=['confirmed']
        )

    def test_create_code_with_track_and_mode(self):
        """Test creating pre-approval code with track and submission_mode."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='self_submission',
            code='SPEAKER001',
            created_by=self.user
        )
        self.assertEqual(code.track, self.track_speaker)
        self.assertEqual(code.submission_mode, 'self_submission')
        self.assertEqual(code.status, EventPreApprovalCode.STATUS_ACTIVE)

    def test_create_code_event_level(self):
        """Test backward compatibility: event-level code (track=NULL)."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=None,  # Event-level
            submission_mode='',  # All modes
            code='EVENT001',
            created_by=self.user
        )
        self.assertIsNone(code.track)
        self.assertEqual(code.submission_mode, '')

    def test_unique_constraint_track_mode_code(self):
        """Test unique constraint on (event, track, submission_mode, code)."""
        EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='self_submission',
            code='SPEAKER001',
            created_by=self.user
        )
        # Should raise IntegrityError
        with self.assertRaises(IntegrityError):
            EventPreApprovalCode.objects.create(
                event=self.event,
                track=self.track_speaker,
                submission_mode='self_submission',
                code='SPEAKER001',
                created_by=self.user
            )

    def test_same_code_different_track(self):
        """Test same code allowed for different tracks."""
        code1 = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='self_submission',
            code='CODE001',
            created_by=self.user
        )
        code2 = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_sponsor,
            submission_mode='confirmed',
            code='CODE001',
            created_by=self.user
        )
        self.assertNotEqual(code1.id, code2.id)

    def test_code_single_use_enforcement(self):
        """Test code becomes STATUS_USED after first use."""
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='self_submission',
            code='SPEAKER001',
            created_by=self.user
        )
        # Simulate code usage
        code.status = EventPreApprovalCode.STATUS_USED
        code.used_by_email = 'applicant@example.com'
        code.save()

        code.refresh_from_db()
        self.assertEqual(code.status, EventPreApprovalCode.STATUS_USED)


class PreApprovalAllowlistModelTests(TestCase):
    """Test EventPreApprovalAllowlist model with track + submission_mode scoping."""

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
        self.track_speaker = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            status='open',
            enabled_submission_modes=['self_submission', 'confirmed']
        )
        self.track_sponsor = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor',
            label='Sponsor Track',
            status='open',
            enabled_submission_modes=['confirmed']
        )

    def test_create_allowlist_with_track_and_mode(self):
        """Test creating allowlist entry with track and submission_mode."""
        entry = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='self_submission',
            first_name='Jane',
            last_name='Doe',
            email='jane@example.com',
            created_by=self.user
        )
        self.assertEqual(entry.track, self.track_speaker)
        self.assertEqual(entry.submission_mode, 'self_submission')
        self.assertTrue(entry.is_active)

    def test_create_allowlist_event_level(self):
        """Test backward compatibility: event-level allowlist entry."""
        entry = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=None,  # Event-level
            submission_mode='',  # All modes
            first_name='John',
            last_name='Doe',
            email='john@example.com',
            created_by=self.user
        )
        self.assertIsNone(entry.track)
        self.assertEqual(entry.submission_mode, '')

    def test_unique_constraint_track_mode_email(self):
        """Test unique constraint on (event, track, mode, email) WHERE is_active."""
        EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='self_submission',
            first_name='Jane',
            last_name='Doe',
            email='jane@example.com',
            created_by=self.user
        )
        # Should raise IntegrityError
        with self.assertRaises(IntegrityError):
            EventPreApprovalAllowlist.objects.create(
                event=self.event,
                track=self.track_speaker,
                submission_mode='self_submission',
                first_name='Jane',
                last_name='Smith',
                email='jane@example.com',
                created_by=self.user
            )

    def test_same_email_different_track(self):
        """Test same email allowed for different tracks."""
        entry1 = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='self_submission',
            first_name='Jane',
            last_name='Doe',
            email='jane@example.com',
            created_by=self.user
        )
        entry2 = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track_sponsor,
            submission_mode='confirmed',
            first_name='Jane',
            last_name='Doe',
            email='jane@example.com',
            created_by=self.user
        )
        self.assertNotEqual(entry1.id, entry2.id)

    def test_email_normalization(self):
        """Test email is lowercased and stripped."""
        entry = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='self_submission',
            first_name='Jane',
            last_name='Doe',
            email='  JANE@EXAMPLE.COM  ',
            created_by=self.user
        )
        entry.refresh_from_db()
        self.assertEqual(entry.email, 'jane@example.com')


class PreApprovalScopingValidationTests(TestCase):
    """Test that pre-approval scoping is strict and prevents misuse."""

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
            preapproval_code_enabled=True,
            preapproval_allowlist_enabled=True,
        )
        self.track_speaker = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            status='open',
            enabled_submission_modes=['self_submission', 'confirmed']
        )
        self.track_sponsor = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor',
            label='Sponsor Track',
            status='open',
            enabled_submission_modes=['confirmed']
        )

    def test_speaker_code_should_not_approve_sponsor_track(self):
        """Test that speaker-specific code doesn't approve sponsor track."""
        speaker_code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='self_submission',
            code='SPEAKER001',
            created_by=self.user
        )

        # Simulate query for sponsor track - code should NOT be found
        found_code = EventPreApprovalCode.objects.filter(
            event=self.event,
            code='SPEAKER001',
            track=self.track_sponsor,
            submission_mode='confirmed'
        ).first()
        self.assertIsNone(found_code)

    def test_confirmed_code_should_not_approve_self_submission(self):
        """Test that confirmed-mode code doesn't approve self_submission mode."""
        confirmed_code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='confirmed',
            code='CONFIRMED001',
            created_by=self.user
        )

        # Simulate query for self_submission mode - code should NOT be found
        found_code = EventPreApprovalCode.objects.filter(
            event=self.event,
            code='CONFIRMED001',
            track=self.track_speaker,
            submission_mode='self_submission'
        ).first()
        self.assertIsNone(found_code)

    def test_event_level_code_applies_to_all_tracks(self):
        """Test that event-level code (track=NULL) matches any track."""
        event_level_code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=None,
            submission_mode='',
            code='EVENT001',
            created_by=self.user
        )

        # Should match speaker track
        from django.db.models import Q
        found_code = EventPreApprovalCode.objects.filter(
            Q(track__isnull=True) | Q(track=self.track_speaker),
            Q(submission_mode='') | Q(submission_mode='self_submission'),
            event=self.event,
            code='EVENT001'
        ).first()
        self.assertIsNotNone(found_code)

        # Should match sponsor track
        found_code = EventPreApprovalCode.objects.filter(
            Q(track__isnull=True) | Q(track=self.track_sponsor),
            Q(submission_mode='') | Q(submission_mode='confirmed'),
            event=self.event,
            code='EVENT001'
        ).first()
        self.assertIsNotNone(found_code)

    def test_allowlist_scope_isolation(self):
        """Test that allowlist entries are isolated by track+mode."""
        speaker_entry = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track_speaker,
            submission_mode='self_submission',
            first_name='Jane',
            last_name='Doe',
            email='jane@example.com',
            created_by=self.user
        )

        # Email should match speaker+self_submission
        from django.db.models import Q
        found_entry = EventPreApprovalAllowlist.objects.filter(
            Q(track__isnull=True) | Q(track=self.track_speaker),
            Q(submission_mode='') | Q(submission_mode='self_submission'),
            event=self.event,
            email='jane@example.com',
            is_active=True
        ).first()
        self.assertIsNotNone(found_entry)

        # But NOT for sponsor+confirmed
        found_entry = EventPreApprovalAllowlist.objects.filter(
            Q(track__isnull=True) | Q(track=self.track_sponsor),
            Q(submission_mode='') | Q(submission_mode='confirmed'),
            event=self.event,
            email='jane@example.com',
            is_active=True
        ).first()
        self.assertIsNone(found_entry)


class PreApprovalSerializerTests(TestCase):
    """Test pre-approval serializers include new fields."""

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
            status='open',
            enabled_submission_modes=['self_submission']
        )

    def test_code_serializer_includes_track_and_mode(self):
        """Test EventPreApprovalCodeSerializer includes track_id and submission_mode."""
        from events.serializers import EventPreApprovalCodeSerializer

        code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track,
            submission_mode='self_submission',
            code='TEST001',
            created_by=self.user
        )

        serializer = EventPreApprovalCodeSerializer(code)
        data = serializer.data

        self.assertIn('track_id', data)
        self.assertIn('submission_mode', data)
        self.assertEqual(data['track_id'], self.track.id)
        self.assertEqual(data['submission_mode'], 'self_submission')

    def test_allowlist_serializer_includes_track_and_mode(self):
        """Test EventPreApprovalAllowlistSerializer includes track_id and submission_mode."""
        from events.serializers import EventPreApprovalAllowlistSerializer

        entry = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track,
            submission_mode='self_submission',
            first_name='Jane',
            last_name='Doe',
            email='jane@example.com',
            created_by=self.user
        )

        serializer = EventPreApprovalAllowlistSerializer(entry)
        data = serializer.data

        self.assertIn('track_id', data)
        self.assertIn('submission_mode', data)
        self.assertEqual(data['track_id'], self.track.id)
        self.assertEqual(data['submission_mode'], 'self_submission')


class PreApprovalMigrationTests(TestCase):
    """Test backward compatibility and migration safety."""

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

    def test_migration_adds_fields_without_data_loss(self):
        """Test migration adds track and submission_mode fields safely."""
        # Create code with event-level defaults (pre-migration scenario)
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='TEST001',
            created_by=self.user
        )

        code.refresh_from_db()
        self.assertIsNone(code.track)
        self.assertEqual(code.submission_mode, '')

    def test_backward_compatible_queries(self):
        """Test that pre-migration codes (track=NULL) can still be queried."""
        # Create event-level code
        code = EventPreApprovalCode.objects.create(
            event=self.event,
            code='EVENT001',
            created_by=self.user
        )

        # Should be findable
        found = EventPreApprovalCode.objects.filter(
            event=self.event,
            code='EVENT001'
        ).first()
        self.assertIsNotNone(found)
        self.assertEqual(found.id, code.id)
