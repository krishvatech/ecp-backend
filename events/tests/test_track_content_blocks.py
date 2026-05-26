"""
Tests for Phase 6: Per-track content surfaces.

Tests cover:
1. Content block model fields and persistence
2. Serializer output with markdown content
3. Admin interface for editing content blocks
4. Management command for seeding default content
5. Content block retrieval and filtering
"""

from django.test import TestCase
from django.contrib.auth.models import User
from events.models import Event, EventApplicationTrack
from events.serializers import EventApplicationTrackSerializer
from community.models import Community


class TrackContentBlocksModelTests(TestCase):
    """Tests for content block fields on EventApplicationTrack."""

    def setUp(self):
        self.community = Community.objects.create(
            name='Test Community',
            slug='test-community'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.user
        )

    def test_create_track_with_content_blocks(self):
        """Test creating a track with content blocks."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            landing_page_content='# Welcome Speakers',
            form_header_notice='Please fill out all fields',
            confirmation_page_content='Thank you for applying!'
        )
        self.assertEqual(track.landing_page_content, '# Welcome Speakers')
        self.assertEqual(track.form_header_notice, 'Please fill out all fields')
        self.assertEqual(track.confirmation_page_content, 'Thank you for applying!')

    def test_content_blocks_blank_by_default(self):
        """Test that content blocks are blank by default."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track'
        )
        self.assertEqual(track.landing_page_content, '')
        self.assertEqual(track.form_header_notice, '')
        self.assertEqual(track.confirmation_page_content, '')

    def test_content_blocks_support_markdown(self):
        """Test that content blocks can store markdown."""
        markdown_content = '''# Header
## Subheader

This is **bold** and this is *italic*.

- List item 1
- List item 2

[Link](https://example.com)
'''
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            landing_page_content=markdown_content,
            form_header_notice=markdown_content,
            confirmation_page_content=markdown_content
        )
        # Verify markdown is preserved exactly as provided
        self.assertEqual(track.landing_page_content, markdown_content)
        self.assertEqual(track.form_header_notice, markdown_content)
        self.assertEqual(track.confirmation_page_content, markdown_content)

    def test_content_blocks_support_long_text(self):
        """Test that content blocks can store long text."""
        long_content = 'A' * 5000  # 5000 characters
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            landing_page_content=long_content
        )
        self.assertEqual(len(track.landing_page_content), 5000)

    def test_update_content_blocks(self):
        """Test updating content blocks."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            landing_page_content='Original content'
        )
        track.landing_page_content = 'Updated content'
        track.save()

        # Reload from DB
        track.refresh_from_db()
        self.assertEqual(track.landing_page_content, 'Updated content')

    def test_content_blocks_per_track(self):
        """Test that different tracks have different content."""
        track1 = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            landing_page_content='Speaker content'
        )
        track2 = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor',
            label='Sponsor Track',
            landing_page_content='Sponsor content'
        )
        self.assertEqual(track1.landing_page_content, 'Speaker content')
        self.assertEqual(track2.landing_page_content, 'Sponsor content')


class TrackContentBlocksSerializerTests(TestCase):
    """Tests for content blocks in serializer output."""

    def setUp(self):
        self.community = Community.objects.create(
            name='Test Community',
            slug='test-community'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.user
        )

    def test_serializer_includes_content_blocks(self):
        """Test that serializer includes content block fields."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            landing_page_content='# Welcome',
            form_header_notice='Fill fields',
            confirmation_page_content='Thank you'
        )
        serializer = EventApplicationTrackSerializer(track)
        data = serializer.data

        self.assertEqual(data['landing_page_content'], '# Welcome')
        self.assertEqual(data['form_header_notice'], 'Fill fields')
        self.assertEqual(data['confirmation_page_content'], 'Thank you')

    def test_serializer_includes_markdown(self):
        """Test that serializer preserves markdown in content blocks."""
        markdown = '# Header\n\n**Bold text**\n\n[Link](url)'
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            landing_page_content=markdown
        )
        serializer = EventApplicationTrackSerializer(track)
        self.assertEqual(serializer.data['landing_page_content'], markdown)

    def test_serializer_blank_content_blocks(self):
        """Test that serializer handles blank content blocks."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track'
        )
        serializer = EventApplicationTrackSerializer(track)
        self.assertEqual(serializer.data['landing_page_content'], '')
        self.assertEqual(serializer.data['form_header_notice'], '')
        self.assertEqual(serializer.data['confirmation_page_content'], '')

    def test_serializer_writable_content_blocks(self):
        """Test that serializer allows writing content blocks."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track'
        )
        serializer = EventApplicationTrackSerializer(
            track,
            data={
                'event_id': self.event.id,
                'key': 'speaker',
                'label': 'Speaker Track',
                'landing_page_content': 'New landing content',
                'form_header_notice': 'New form notice',
                'confirmation_page_content': 'New confirmation'
            },
            partial=True
        )
        self.assertTrue(serializer.is_valid())
        updated_track = serializer.save()
        self.assertEqual(updated_track.landing_page_content, 'New landing content')
        self.assertEqual(updated_track.form_header_notice, 'New form notice')
        self.assertEqual(updated_track.confirmation_page_content, 'New confirmation')


class TrackContentBlocksRetrieval(TestCase):
    """Tests for retrieving tracks with content blocks."""

    def setUp(self):
        self.community = Community.objects.create(
            name='Test Community',
            slug='test-community'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.user
        )

    def test_retrieve_track_by_id(self):
        """Test retrieving track with content by ID."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            landing_page_content='Speaker landing page'
        )
        retrieved = EventApplicationTrack.objects.get(id=track.id)
        self.assertEqual(retrieved.landing_page_content, 'Speaker landing page')

    def test_retrieve_track_by_key(self):
        """Test retrieving track with content by key."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            form_header_notice='Speaker form notice'
        )
        retrieved = EventApplicationTrack.objects.get(event=self.event, key='speaker')
        self.assertEqual(retrieved.form_header_notice, 'Speaker form notice')

    def test_filter_tracks_by_event(self):
        """Test filtering tracks with content by event."""
        track1 = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            landing_page_content='Speaker content'
        )
        track2 = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor',
            label='Sponsor Track',
            landing_page_content='Sponsor content'
        )
        tracks = list(EventApplicationTrack.objects.filter(event=self.event))
        self.assertEqual(len(tracks), 2)
        self.assertIn(track1, tracks)
        self.assertIn(track2, tracks)

    def test_tracks_with_empty_content(self):
        """Test retrieving tracks that have empty content blocks."""
        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track'
        )
        retrieved = EventApplicationTrack.objects.get(id=track.id)
        self.assertEqual(retrieved.landing_page_content, '')


class TrackContentBlocksManagementCommand(TestCase):
    """Tests for seeding default content blocks."""

    def setUp(self):
        self.community = Community.objects.create(
            name='Test Community',
            slug='test-community'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.user
        )

    def test_seed_speaker_content(self):
        """Test seeding default speaker content."""
        from django.core.management import call_command
        from io import StringIO

        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track'
        )

        out = StringIO()
        call_command('seed_track_content_blocks', '--track-id', str(track.id), stdout=out)

        track.refresh_from_db()
        self.assertTrue(len(track.landing_page_content) > 0)
        self.assertTrue(len(track.form_header_notice) > 0)
        self.assertTrue(len(track.confirmation_page_content) > 0)
        self.assertIn('# Become a Speaker', track.landing_page_content)

    def test_seed_sponsor_content(self):
        """Test seeding default sponsor content."""
        from django.core.management import call_command
        from io import StringIO

        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor',
            label='Sponsor Track'
        )

        out = StringIO()
        call_command('seed_track_content_blocks', '--track-id', str(track.id), stdout=out)

        track.refresh_from_db()
        self.assertIn('# Become a Sponsor', track.landing_page_content)

    def test_seed_attendee_content(self):
        """Test seeding default attendee content."""
        from django.core.management import call_command
        from io import StringIO

        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='attendee',
            label='Attendee Track'
        )

        out = StringIO()
        call_command('seed_track_content_blocks', '--track-id', str(track.id), stdout=out)

        track.refresh_from_db()
        self.assertIn('# Register to Attend', track.landing_page_content)

    def test_seed_skip_unknown_track_key(self):
        """Test seeding skips tracks with unknown keys."""
        from django.core.management import call_command
        from io import StringIO

        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='unknown_key',
            label='Unknown Track'
        )

        out = StringIO()
        call_command('seed_track_content_blocks', '--track-id', str(track.id), stdout=out)

        track.refresh_from_db()
        self.assertEqual(track.landing_page_content, '')

    def test_seed_skip_existing_content(self):
        """Test seeding skips tracks that already have content."""
        from django.core.management import call_command
        from io import StringIO

        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track',
            landing_page_content='Existing content'
        )

        original_content = track.landing_page_content

        out = StringIO()
        call_command('seed_track_content_blocks', '--track-id', str(track.id), stdout=out)

        track.refresh_from_db()
        # Content should not change
        self.assertEqual(track.landing_page_content, original_content)

    def test_seed_by_track_key(self):
        """Test seeding by track key."""
        from django.core.management import call_command
        from io import StringIO

        track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track'
        )

        out = StringIO()
        call_command('seed_track_content_blocks', '--track-key', 'speaker', stdout=out)

        track.refresh_from_db()
        self.assertTrue(len(track.landing_page_content) > 0)

    def test_seed_all_tracks(self):
        """Test seeding all tracks at once."""
        from django.core.management import call_command
        from io import StringIO

        track1 = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track'
        )
        track2 = EventApplicationTrack.objects.create(
            event=self.event,
            key='sponsor',
            label='Sponsor Track'
        )

        out = StringIO()
        call_command('seed_track_content_blocks', stdout=out)

        track1.refresh_from_db()
        track2.refresh_from_db()
        self.assertTrue(len(track1.landing_page_content) > 0)
        self.assertTrue(len(track2.landing_page_content) > 0)
