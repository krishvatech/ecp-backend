from io import StringIO
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from community.models import Community
from events.models import Event, EventPlatform, EventPublication
from events.views import EventViewSet


@override_settings(
    SALEOR_ENABLED=False,
    LIVE_MEETING_ASG_AUTOSCALE_ENABLED=False,
    EVENT_PLATFORM_SYNC_TRIGGER_ON_COMMIT=False,
)
class ArchivedEventLiveGuardTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.owner = User.objects.create_superuser(
            username="archive-live-owner",
            email="archive-live-owner@example.com",
            password="test-pass",
        )
        self.community = Community.objects.create(
            name="Archived Live Guard Community",
            owner=self.owner,
        )
        self.imma, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect",
            defaults={"name": "IMAA Connect", "is_active": True},
        )

    def make_event(self, **overrides):
        defaults = {
            "community": self.community,
            "created_by": self.owner,
            "title": "Archived Live Guard Event",
            "description": "Regression test",
            "status": "archived",
            "start_time": timezone.now() + timezone.timedelta(days=1),
            "end_time": timezone.now() + timezone.timedelta(days=1, hours=1),
            "archived_at": timezone.now(),
            "is_hidden": True,
            "is_live": False,
            "is_free": True,
        }
        defaults.update(overrides)
        event = Event(**defaults)
        event.skip_saleor_sync = True
        event.save()
        EventPublication.objects.get_or_create(
            event=event,
            platform=self.imma,
            defaults={"is_enabled": True},
        )
        return event

    def call_action(self, event, action, data=None):
        view = EventViewSet.as_view({"post": action})
        request = self.factory.post(
            f"/api/events/{event.pk}/{action}/",
            data or {},
            format="json",
        )
        force_authenticate(request, user=self.owner)
        return view(request, pk=str(event.pk))

    def test_archived_event_cannot_start_or_end_via_live_status(self):
        event = self.make_event()

        start_response = self.call_action(event, "live_status", {"action": "start"})
        end_response = self.call_action(event, "live_status", {"action": "end"})

        self.assertEqual(start_response.status_code, 409)
        self.assertEqual(end_response.status_code, 409)
        event.refresh_from_db()
        self.assertEqual(event.status, "archived")
        self.assertFalse(event.is_live)
        self.assertTrue(event.is_hidden)

    def test_end_meeting_cannot_overwrite_archived_status(self):
        event = self.make_event()

        response = self.call_action(event, "end_meeting")

        self.assertEqual(response.status_code, 409)
        event.refresh_from_db()
        self.assertEqual(event.status, "archived")
        self.assertFalse(event.is_live)
        self.assertTrue(event.is_hidden)

    @patch("events.views._ensure_rtk_meeting_for_event")
    def test_archived_event_rtk_join_is_rejected_before_rtk_creation(self, ensure_meeting):
        event = self.make_event()

        response = self.call_action(event, "rtk_join", {"role": "publisher"})

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data.get("error"), "event_archived")
        ensure_meeting.assert_not_called()

    def test_archived_event_cannot_confirm_live_attendance(self):
        event = self.make_event()

        response = self.call_action(
            event,
            "rtk_confirm_joined",
            {"room_type": "main_room"},
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data.get("error"), "event_archived")

    def test_active_archive_marker_blocks_stale_live_status(self):
        event = self.make_event(status="live", is_live=True)

        response = self.call_action(event, "live_status", {"action": "start"})

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data.get("error"), "event_archived")
        event.refresh_from_db()
        # Guard does not silently rewrite history; the explicit repair command does.
        self.assertEqual(event.status, "live")

    def test_repair_command_restores_corrupted_archived_event_state(self):
        event = self.make_event(status="ended", is_live=True, is_hidden=True)
        stdout = StringIO()

        call_command(
            "repair_archived_event_lifecycle",
            "--event-id",
            str(event.id),
            "--apply",
            stdout=stdout,
        )

        event.refresh_from_db()
        self.assertEqual(event.status, "archived")
        self.assertFalse(event.is_live)
        self.assertFalse(event.is_on_break)
        self.assertTrue(event.is_hidden)
        self.assertIn("Repaired 1 event", stdout.getvalue())
