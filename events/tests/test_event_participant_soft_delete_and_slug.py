from datetime import timedelta
from types import SimpleNamespace

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from rest_framework import serializers
from rest_framework.test import APIRequestFactory, force_authenticate

from community.models import Community
from events.models import Event, EventParticipant
from events.serializers import EventSerializer
from events.views import EventViewSet


class EventParticipantSoftDeleteAndSlugTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.owner = User.objects.create_superuser(
            username="event-owner-soft-delete",
            email="event-owner-soft-delete@example.com",
            password="pass1234",
        )
        self.speaker = User.objects.create_user(
            username="event-speaker-soft-delete",
            email="event-speaker-soft-delete@example.com",
            password="pass1234",
        )
        self.host = User.objects.create_user(
            username="event-host-soft-delete",
            email="event-host-soft-delete@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(
            name="Participant Soft Delete Community",
            owner=self.owner,
        )
        now = timezone.now()
        self.event = Event.objects.create(
            community=self.community,
            created_by=self.owner,
            title="Reserved Slug Event",
            slug="reserved-event",
            status="draft",
            start_time=now + timedelta(days=1),
            end_time=now + timedelta(days=1, hours=2),
        )

    def test_removed_participant_is_hidden_but_database_row_is_preserved(self):
        removed = EventParticipant.objects.create(
            event=self.event,
            participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
            role=EventParticipant.ROLE_SPEAKER,
            user=self.speaker,
            display_order=0,
        )
        retained = EventParticipant.objects.create(
            event=self.event,
            participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
            role=EventParticipant.ROLE_HOST,
            user=self.host,
            display_order=1,
        )

        serializer = EventSerializer(
            instance=self.event,
            context={"request": SimpleNamespace(user=self.owner)},
        )
        serializer._update_participants(
            self.event,
            [
                {
                    "type": "staff",
                    "user_id": self.host.id,
                    "role": "host",
                    "display_order": 0,
                }
            ],
        )

        self.assertFalse(EventParticipant.objects.filter(pk=removed.pk).exists())
        stored = EventParticipant.all_objects.get(pk=removed.pk)
        self.assertTrue(stored.is_deleted)
        self.assertIsNotNone(stored.deleted_at)
        self.assertEqual(stored.deleted_by, self.owner)
        self.assertEqual(stored.deletion_reason, "Removed from the event participant list.")

        retained.refresh_from_db()
        self.assertFalse(retained.is_deleted)
        self.assertEqual(retained.display_order, 0)

    def test_restore_makes_participant_visible_again(self):
        participant = EventParticipant.objects.create(
            event=self.event,
            participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
            role=EventParticipant.ROLE_SPEAKER,
            user=self.speaker,
        )
        participant.soft_delete(user=self.owner, reason="Programme changed")
        self.assertFalse(EventParticipant.objects.filter(pk=participant.pk).exists())

        stored = EventParticipant.all_objects.get(pk=participant.pk)
        stored.restore()

        self.assertTrue(EventParticipant.objects.filter(pk=participant.pk).exists())
        restored = EventParticipant.objects.get(pk=participant.pk)
        self.assertIsNone(restored.deleted_at)
        self.assertIsNone(restored.deleted_by)
        self.assertEqual(restored.deletion_reason, "")

    def test_create_slug_uses_next_available_suffix_including_archived_events(self):
        Event.objects.create(
            community=self.community,
            created_by=self.owner,
            title="Reserved Slug Event 2",
            slug="reserved-event-2",
            status="archived",
            is_hidden=True,
            start_time=self.event.start_time,
            end_time=self.event.end_time,
        )

        self.assertEqual(Event.next_available_slug("reserved-event"), "reserved-event-3")
        serializer = EventSerializer()
        self.assertEqual(serializer.validate_slug("reserved-event"), "reserved-event-3")

    def test_edit_slug_remains_strict(self):
        other = Event.objects.create(
            community=self.community,
            created_by=self.owner,
            title="Other Event",
            slug="other-event",
            status="draft",
            start_time=self.event.start_time,
            end_time=self.event.end_time,
        )
        serializer = EventSerializer(instance=self.event)

        with self.assertRaises(serializers.ValidationError):
            serializer.validate_slug(other.slug)

    def test_slug_availability_returns_non_blocking_suggestion(self):
        view = EventViewSet.as_view({"get": "slug_availability"})
        request = self.factory.get(
            "/api/events/slug-availability/",
            {"slug": "reserved-event"},
        )
        force_authenticate(request, user=self.owner)
        response = view(request)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["available"])
        self.assertEqual(response.data["suggested_slug"], "reserved-event-2")
