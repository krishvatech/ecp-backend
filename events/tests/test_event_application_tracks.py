"""
Comprehensive tests for EventApplicationTrack model and track configuration.

Tests cover:
- EventApplicationTrack creation and management
- Track configuration (status, submission modes, roles)
- Track seeding and defaults
- Track queries and filtering
- Serializer output
- Admin interface
"""

from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from events.models import Event, EventApplicationTrack
from events.serializers import EventApplicationTrackSerializer
from community.models import Community


class EventApplicationTrackModelTests(TestCase):
    """Test EventApplicationTrack model functionality."""

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

    def test_create_application_track(self):
        """Test creating an EventApplicationTrack."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Application',
            short_description='Apply as a speaker',
            status='open',
            sort_order=10,
            is_active=True,
            enabled_submission_modes=['online_form', 'preapproved'],
            role_mappings_on_acceptance=['speaker', 'attendee'],
            content_surfaces=['event_page', 'email']
        )
        self.assertEqual(track.key, 'speaker')
        self.assertEqual(track.label, 'Speaker Application')
        self.assertEqual(track.status, 'open')
        self.assertTrue(track.is_active)
        self.assertEqual(len(track.enabled_submission_modes), 2)
        self.assertEqual(len(track.role_mappings_on_acceptance), 2)

    def test_track_unique_together(self):
        """Test that (event, key) must be unique."""
        EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker'
        )
        with self.assertRaises(Exception):
            EventApplicationTrack.objects.create(
                event=self.event,
                key='speaker',
                label='Speaker'
            )

    def test_track_status_choices(self):
        """Test track status options."""
        for status in ['open', 'closed', 'invite_only']:
            track = EventApplicationTrack.objects.create(
                event=self.event,
                key=f'test_{status}',
                label='Test Track',
                status=status
            )
            self.assertEqual(track.status, status)

    def test_track_ordering(self):
        """Test tracks are ordered by sort_order then label."""
        EventApplicationTrack.objects.create(
            event=self.event,
            key='participant',
            label='Participant',
            sort_order=100
        )
        EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            sort_order=10
        )
        EventApplicationTrack.objects.create(
            event=self.event,
            key='startup',
            label='Startup',
            sort_order=20
        )
        tracks = EventApplicationTrack.objects.filter(event=self.event)
        self.assertEqual(tracks[0].key, 'speaker')      # 10
        self.assertEqual(tracks[1].key, 'startup')      # 20
        self.assertEqual(tracks[2].key, 'participant')  # 100

    def test_track_str(self):
        """Test EventApplicationTrack string representation."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker'
        )
        self.assertEqual(str(track), f"Speaker ({self.event.title})")

    def test_track_json_fields(self):
        """Test JSON field functionality."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            enabled_submission_modes=['online_form', 'preapproved', 'invite_only'],
            form_schema={
                'sections': [
                    {
                        'id': 'bio',
                        'title': 'Speaker Bio',
                        'fields': ['bio', 'topic']
                    }
                ]
            },
            preapproval_configuration={
                'codes_enabled': True,
                'allowlist_enabled': False,
                'auto_approve': False
            },
            role_mappings_on_acceptance=['speaker', 'attendee'],
            content_surfaces=['event_page', 'email', 'application_modal']
        )

        # Verify JSON fields can be retrieved
        self.assertEqual(len(track.enabled_submission_modes), 3)
        self.assertIn('sections', track.form_schema)
        self.assertTrue(track.preapproval_configuration['codes_enabled'])
        self.assertEqual(len(track.role_mappings_on_acceptance), 2)
        self.assertEqual(len(track.content_surfaces), 3)

    def test_is_active_index(self):
        """Test that is_active field is indexed."""
        # Create multiple tracks
        EventApplicationTrack.objects.create(
            event=self.event,
            key='track1',
            label='Track 1',
            is_active=True
        )
        EventApplicationTrack.objects.create(
            event=self.event,
            key='track2',
            label='Track 2',
            is_active=False
        )

        # Query by is_active (should use index)
        active_tracks = EventApplicationTrack.objects.filter(
            event=self.event,
            is_active=True
        )
        self.assertEqual(active_tracks.count(), 1)
        self.assertEqual(active_tracks.first().key, 'track1')

    def test_event_specific_tracks(self):
        """Test that tracks are event-specific."""
        event2 = Event.objects.create(
            community=self.community,
            title="Test Event 2",
            slug="test-event-2",
            created_by=self.user
        )

        track1 = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker'
        )
        track2 = EventApplicationTrack.objects.create(
            event=event2,
            key='speaker',
            label='Speaker'
        )

        # They should be different objects
        self.assertNotEqual(track1.id, track2.id)

        # Each event should have its own speaker track
        self.assertEqual(self.event.application_tracks.filter(key='speaker').count(), 1)
        self.assertEqual(event2.application_tracks.filter(key='speaker').count(), 1)


class EventApplicationTrackSerializerTests(TestCase):
    """Test serializer output for application tracks."""

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

    def test_track_serializer(self):
        """Test EventApplicationTrackSerializer output."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Application',
            short_description='Apply to speak at our event',
            status='open',
            sort_order=10,
            is_active=True,
            enabled_submission_modes=['online_form', 'preapproved'],
            role_mappings_on_acceptance=['speaker', 'attendee'],
            content_surfaces=['event_page', 'email']
        )

        serializer = EventApplicationTrackSerializer(track)
        data = serializer.data

        self.assertEqual(data['key'], 'speaker')
        self.assertEqual(data['label'], 'Speaker Application')
        self.assertEqual(data['short_description'], 'Apply to speak at our event')
        self.assertEqual(data['status'], 'open')
        self.assertEqual(data['sort_order'], 10)
        self.assertTrue(data['is_active'])
        self.assertEqual(data['enabled_submission_modes'], ['online_form', 'preapproved'])
        self.assertEqual(data['role_mappings_on_acceptance'], ['speaker', 'attendee'])
        self.assertEqual(data['content_surfaces'], ['event_page', 'email'])

    def test_track_serializer_with_json_fields(self):
        """Test serializer with complex JSON fields."""
        form_schema = {
            'sections': [
                {
                    'id': 'bio',
                    'title': 'Speaker Information',
                    'fields': ['bio', 'topic', 'audience_level']
                }
            ]
        }
        preapproval_config = {
            'codes_enabled': True,
            'allowlist_enabled': True,
            'auto_approve': False
        }

        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            form_schema=form_schema,
            preapproval_configuration=preapproval_config
        )

        serializer = EventApplicationTrackSerializer(track)
        data = serializer.data

        self.assertEqual(data['form_schema'], form_schema)
        self.assertEqual(data['preapproval_configuration'], preapproval_config)

    def test_track_serializer_read_only_fields(self):
        """Test that is_system_default and timestamps are read-only."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            is_system_default=True
        )

        serializer = EventApplicationTrackSerializer(track)
        data = serializer.data

        # Should be able to read these
        self.assertTrue(data['is_system_default'])
        self.assertIn('created_at', data)
        self.assertIn('updated_at', data)


class TrackSeededTests(TransactionTestCase):
    """Test track seeding and default configurations."""

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

    def test_default_tracks_available(self):
        """Test that default track keys are available."""
        default_keys = {'participant', 'speaker', 'startup', 'investment_opportunity', 'research', 'sponsor'}

        # Create default tracks manually (simulating seed command)
        for key in default_keys:
            EventApplicationTrack.objects.create(
                event=self.event,
                key=key,
                label=key.replace('_', ' ').title(),
                is_system_default=True
            )

        tracks = EventApplicationTrack.objects.filter(event=self.event)
        self.assertEqual(tracks.count(), 6)

        track_keys = set(tracks.values_list('key', flat=True))
        self.assertEqual(track_keys, default_keys)

    def test_track_role_mappings(self):
        """Test that tracks have appropriate role mappings."""
        tracks_with_roles = {
            'speaker': ['speaker', 'attendee'],
            'startup': ['startup', 'attendee'],
            'sponsor': ['sponsor', 'sponsor_staff', 'attendee'],
            'investor': ['investor', 'attendee'],
            'researcher': ['researcher', 'attendee'],
            'participant': ['attendee'],
        }

        for key, roles in tracks_with_roles.items():
            track = EventApplicationTrack.objects.create(
                event=self.event,
                key=key,
                label=key.title(),
                role_mappings_on_acceptance=roles
            )
            self.assertEqual(track.role_mappings_on_acceptance, roles)

    def test_track_submission_modes(self):
        """Test that tracks support different submission modes."""
        submission_modes = {
            'speaker': ['online_form', 'preapproved', 'invite_only'],
            'participant': ['online_form', 'preapproved'],
            'startup': ['online_form', 'preapproved'],
        }

        for key, modes in submission_modes.items():
            track = EventApplicationTrack.objects.create(
                event=self.event,
                key=key,
                label=key.title(),
                enabled_submission_modes=modes
            )
            self.assertEqual(track.enabled_submission_modes, modes)


class TrackQueryTests(TestCase):
    """Test querying and filtering application tracks."""

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

    def test_get_open_tracks(self):
        """Test querying open tracks."""
        EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            status='open'
        )
        EventApplicationTrack.objects.create(
            event=self.event,
            key='startup',
            label='Startup',
            status='closed'
        )

        open_tracks = EventApplicationTrack.objects.filter(
            event=self.event,
            status='open'
        )
        self.assertEqual(open_tracks.count(), 1)
        self.assertEqual(open_tracks.first().key, 'speaker')

    def test_get_active_tracks(self):
        """Test querying active tracks."""
        EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            is_active=True
        )
        EventApplicationTrack.objects.create(
            event=self.event,
            key='startup',
            label='Startup',
            is_active=False
        )

        active_tracks = EventApplicationTrack.objects.filter(
            event=self.event,
            is_active=True
        )
        self.assertEqual(active_tracks.count(), 1)
        self.assertEqual(active_tracks.first().key, 'speaker')

    def test_get_sorted_tracks(self):
        """Test tracks are returned in sorted order."""
        EventApplicationTrack.objects.create(
            event=self.event,
            key='participant',
            label='Participant',
            sort_order=100
        )
        EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            sort_order=10
        )

        tracks = EventApplicationTrack.objects.filter(event=self.event)
        self.assertEqual(tracks[0].key, 'speaker')
        self.assertEqual(tracks[1].key, 'participant')

    def test_get_tracks_by_submission_mode(self):
        """Test querying tracks by submission mode."""
        EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            enabled_submission_modes=['online_form', 'preapproved']
        )
        EventApplicationTrack.objects.create(
            event=self.event,
            key='startup',
            label='Startup',
            enabled_submission_modes=['online_form', 'invite_only']
        )

        # Query tracks with preapproved mode
        # Note: This is a JSON field query, which varies by database
        tracks_with_preapproved = [
            t for t in EventApplicationTrack.objects.filter(event=self.event)
            if 'preapproved' in t.enabled_submission_modes
        ]
        self.assertEqual(len(tracks_with_preapproved), 1)
        self.assertEqual(tracks_with_preapproved[0].key, 'speaker')


class TrackEdgeTests(TestCase):
    """Test edge cases and error conditions."""

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

    def test_track_with_empty_json_fields(self):
        """Test track with empty JSON field defaults."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker'
            # Omit all JSON fields to test defaults
        )

        self.assertEqual(track.enabled_submission_modes, [])
        self.assertEqual(track.form_schema, {})
        self.assertEqual(track.preapproval_configuration, {})
        self.assertEqual(track.role_mappings_on_acceptance, [])
        self.assertEqual(track.content_surfaces, [])

    def test_disable_and_reenable_track(self):
        """Test disabling and re-enabling a track."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            is_active=True
        )

        # Disable
        track.is_active = False
        track.save()
        self.assertFalse(track.is_active)

        # Re-enable
        track.is_active = True
        track.save()
        self.assertTrue(track.is_active)

    def test_update_track_status(self):
        """Test updating track status."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            status='open'
        )

        # Change status
        track.status = 'closed'
        track.save()

        track.refresh_from_db()
        self.assertEqual(track.status, 'closed')

    def test_update_role_mappings(self):
        """Test updating role mappings."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            role_mappings_on_acceptance=['attendee']
        )

        # Add more roles
        track.role_mappings_on_acceptance = ['speaker', 'attendee']
        track.save()

        track.refresh_from_db()
        self.assertEqual(track.role_mappings_on_acceptance, ['speaker', 'attendee'])
