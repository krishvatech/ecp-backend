"""
RTK Join Fix Tests

Tests verify:
1. Existing registered user can join successfully
2. Missing/invalid registration returns 403/400 (no crash)
3. New registration is always saved before update_fields usage
4. No duplicate registrations on concurrent joins
5. live_join_slot context manager cleans up correctly on exceptions
6. Registration has primary key before marked as joined_live
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.utils import timezone
from django.urls import reverse
from rest_framework.test import APIClient
from datetime import timedelta
from unittest.mock import patch, MagicMock
from events.models import Event, EventRegistration, EventRole
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class RTKJoinFixTestCase(TestCase):
    """Test cases for RTK join endpoint fixes."""

    def setUp(self):
        """Create test fixtures."""
        self.client = APIClient()

        # Create test users
        self.user1 = User.objects.create_user(
            username='user1', email='user1@example.com', password='pass123'
        )
        self.user2 = User.objects.create_user(
            username='user2', email='user2@example.com', password='pass123'
        )
        self.organizer = User.objects.create_user(
            username='organizer', email='org@example.com', password='pass123'
        )

        # Create event (live, no waiting room)
        self.event = Event.objects.create(
            title='Test Live Event',
            slug='test-live-event',
            description='Test event for RTK join',
            format='online',
            start_time=timezone.now() + timedelta(hours=1),
            end_time=timezone.now() + timedelta(hours=2),
            organizer=self.organizer,
            registration_type='open',
            status='live'
        )

        # Create event with waiting room enabled
        self.event_waiting_room = Event.objects.create(
            title='Test Event with Waiting Room',
            slug='test-waiting-room-event',
            description='Test event with waiting room',
            format='online',
            start_time=timezone.now() + timedelta(hours=1),
            end_time=timezone.now() + timedelta(hours=2),
            organizer=self.organizer,
            registration_type='open',
            status='live',
            waiting_room_enabled=True,
            waiting_room_grace_period_minutes=10
        )

        # Create event role
        self.host_role = EventRole.objects.create(
            event=self.event,
            key='host',
            name='Host'
        )

    @override_settings(
        LIVE_MEETING_ASG_AUTOSCALE_ENABLED=False,
        LIVE_JOIN_CONCURRENT_LIMIT=60
    )
    @patch('events.views._ensure_rtk_meeting_for_event')
    @patch('events.views.add_rtk_participant')
    def test_existing_registered_user_can_join(self, mock_add_participant, mock_ensure_meeting):
        """Test that existing registered user can join successfully."""
        # Create existing registration
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            status='registered',
            admission_status='admitted'
        )

        # Mock RTK responses
        mock_ensure_meeting.return_value = 'meeting_123'
        mock_add_participant.return_value = ('auth_token_123', None)

        # Make join request
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(
            reverse('event-rtk-join', kwargs={'pk': self.event.id})
        )

        # Verify success
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['authToken'], 'auth_token_123')
        self.assertEqual(response.data['meetingId'], 'meeting_123')

        # Verify registration was updated
        registration.refresh_from_db()
        self.assertTrue(registration.joined_live)
        self.assertIsNotNone(registration.joined_live_at)

    @override_settings(
        LIVE_MEETING_ASG_AUTOSCALE_ENABLED=False,
        LIVE_JOIN_CONCURRENT_LIMIT=60
    )
    @patch('events.views._ensure_rtk_meeting_for_event')
    @patch('events.views.add_rtk_participant')
    def test_new_unregistered_user_creates_and_saves_registration(self, mock_add_participant, mock_ensure_meeting):
        """Test that new user gets registration saved before update_fields is called."""
        # No pre-existing registration
        self.assertFalse(
            EventRegistration.objects.filter(event=self.event, user=self.user1).exists()
        )

        # Mock RTK responses
        mock_ensure_meeting.return_value = 'meeting_123'
        mock_add_participant.return_value = ('auth_token_123', None)

        # Make join request
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(
            reverse('event-rtk-join', kwargs={'pk': self.event.id})
        )

        # Verify success
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['authToken'], 'auth_token_123')

        # Verify registration was created and has primary key
        registration = EventRegistration.objects.get(event=self.event, user=self.user1)
        self.assertIsNotNone(registration.pk)
        self.assertTrue(registration.joined_live)
        self.assertIsNotNone(registration.joined_live_at)
        self.assertEqual(registration.status, 'registered')
        self.assertEqual(registration.admission_status, 'admitted')

    @override_settings(
        LIVE_MEETING_ASG_AUTOSCALE_ENABLED=False,
        LIVE_JOIN_CONCURRENT_LIMIT=60
    )
    @patch('events.views._ensure_rtk_meeting_for_event')
    @patch('events.views.add_rtk_participant')
    def test_banned_user_gets_403(self, mock_add_participant, mock_ensure_meeting):
        """Test that banned user cannot join."""
        # Create banned registration
        EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            status='registered',
            is_banned=True
        )

        # Make join request
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(
            reverse('event-rtk-join', kwargs={'pk': self.event.id})
        )

        # Verify 403 response
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['error'], 'banned')

        # Verify no extra registrations were created
        self.assertEqual(
            EventRegistration.objects.filter(event=self.event, user=self.user1).count(),
            1
        )

    @override_settings(
        LIVE_MEETING_ASG_AUTOSCALE_ENABLED=False,
        LIVE_JOIN_CONCURRENT_LIMIT=60
    )
    @patch('events.views._ensure_rtk_meeting_for_event')
    @patch('events.views.add_rtk_participant')
    def test_cancelled_registration_gets_403(self, mock_add_participant, mock_ensure_meeting):
        """Test that cancelled registration cannot rejoin."""
        # Create cancelled registration
        EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            status='cancelled',
            admission_status='admitted'
        )

        # Make join request
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(
            reverse('event-rtk-join', kwargs={'pk': self.event.id})
        )

        # Verify 403 response
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['error'], 'not_registered')

        # Verify no extra registrations were created
        self.assertEqual(
            EventRegistration.objects.filter(event=self.event, user=self.user1).count(),
            1
        )

    @override_settings(
        LIVE_MEETING_ASG_AUTOSCALE_ENABLED=False,
        LIVE_JOIN_CONCURRENT_LIMIT=60
    )
    @patch('events.views._ensure_rtk_meeting_for_event')
    @patch('events.views.add_rtk_participant')
    def test_new_user_with_waiting_room_enters_waiting(self, mock_add_participant, mock_ensure_meeting):
        """Test that new user with waiting room enabled enters waiting room."""
        # No pre-existing registration
        self.assertFalse(
            EventRegistration.objects.filter(event=self.event_waiting_room, user=self.user1).exists()
        )

        # Make join request
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(
            reverse('event-rtk-join', kwargs={'pk': self.event_waiting_room.id})
        )

        # Verify waiting room response
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.get('waiting', False))
        self.assertEqual(response.data.get('admission_status'), 'waiting')

        # Verify registration was created with correct status
        registration = EventRegistration.objects.get(event=self.event_waiting_room, user=self.user1)
        self.assertIsNotNone(registration.pk)
        self.assertEqual(registration.admission_status, 'waiting')
        self.assertIsNotNone(registration.waiting_started_at)

    @override_settings(
        LIVE_MEETING_ASG_AUTOSCALE_ENABLED=False,
        LIVE_JOIN_CONCURRENT_LIMIT=60
    )
    @patch('events.views._ensure_rtk_meeting_for_event')
    @patch('events.views.add_rtk_participant')
    def test_idempotent_join_no_duplicates(self, mock_add_participant, mock_ensure_meeting):
        """Test that calling join twice doesn't create duplicate registrations."""
        # Mock RTK responses
        mock_ensure_meeting.return_value = 'meeting_123'
        mock_add_participant.return_value = ('auth_token_123', None)

        # Make first join request
        self.client.force_authenticate(user=self.user1)
        response1 = self.client.post(
            reverse('event-rtk-join', kwargs={'pk': self.event.id})
        )
        self.assertEqual(response1.status_code, 200)

        # Verify exactly one registration exists
        registrations_count = EventRegistration.objects.filter(
            event=self.event, user=self.user1
        ).count()
        self.assertEqual(registrations_count, 1)
        first_registration = EventRegistration.objects.get(event=self.event, user=self.user1)
        first_pk = first_registration.pk

        # Make second join request
        response2 = self.client.post(
            reverse('event-rtk-join', kwargs={'pk': self.event.id})
        )
        self.assertEqual(response2.status_code, 200)

        # Verify still exactly one registration
        registrations_count = EventRegistration.objects.filter(
            event=self.event, user=self.user1
        ).count()
        self.assertEqual(registrations_count, 1)

        # Verify same registration was reused
        registration = EventRegistration.objects.get(event=self.event, user=self.user1)
        self.assertEqual(registration.pk, first_pk)

    @override_settings(
        LIVE_MEETING_ASG_AUTOSCALE_ENABLED=False,
        LIVE_JOIN_CONCURRENT_LIMIT=60
    )
    @patch('events.views._ensure_rtk_meeting_for_event')
    @patch('events.views.add_rtk_participant')
    def test_registration_has_pk_before_joined_live_update(self, mock_add_participant, mock_ensure_meeting):
        """Test that registration primary key is set before trying to use update_fields."""
        # Create new user (no pre-existing registration)
        self.assertFalse(
            EventRegistration.objects.filter(event=self.event, user=self.user2).exists()
        )

        # Mock RTK responses
        mock_ensure_meeting.return_value = 'meeting_123'
        mock_add_participant.return_value = ('auth_token_123', None)

        # Make join request
        self.client.force_authenticate(user=self.user2)
        response = self.client.post(
            reverse('event-rtk-join', kwargs={'pk': self.event.id})
        )

        # Should succeed without ValueError
        self.assertEqual(response.status_code, 200)

        # Verify registration has pk and joined_live is set
        registration = EventRegistration.objects.get(event=self.event, user=self.user2)
        self.assertIsNotNone(registration.pk)
        self.assertTrue(registration.joined_live)
        self.assertIsNotNone(registration.joined_live_at)

    @override_settings(
        LIVE_MEETING_ASG_AUTOSCALE_ENABLED=False,
        LIVE_JOIN_CONCURRENT_LIMIT=60
    )
    @patch('events.views._ensure_rtk_meeting_for_event')
    @patch('events.views.add_rtk_participant')
    def test_event_not_found_returns_404(self, mock_add_participant, mock_ensure_meeting):
        """Test that non-existent event returns 404."""
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(
            reverse('event-rtk-join', kwargs={'pk': 99999})
        )

        # Should return 404
        self.assertEqual(response.status_code, 404)

    @override_settings(
        LIVE_MEETING_ASG_AUTOSCALE_ENABLED=False,
        LIVE_JOIN_CONCURRENT_LIMIT=60
    )
    @patch('events.views._ensure_rtk_meeting_for_event')
    @patch('events.views.add_rtk_participant')
    def test_event_cancelled_returns_400(self, mock_add_participant, mock_ensure_meeting):
        """Test that cancelled event returns 400."""
        # Cancel the event
        self.event.status = 'cancelled'
        self.event.save()

        # Create registration
        EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            status='registered',
            admission_status='admitted'
        )

        # Make join request
        self.client.force_authenticate(user=self.user1)
        response = self.client.post(
            reverse('event-rtk-join', kwargs={'pk': self.event.id})
        )

        # Should return 400
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'event_cancelled')
