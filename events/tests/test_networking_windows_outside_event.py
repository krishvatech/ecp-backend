"""Pre-event / post-event 1:1 networking windows.

Admins may configure networking windows on any date — before the event starts,
during it, crossing its end time, or after it ends — and attendees can book
1:1 slots in those windows. Windows are no longer clamped to event start/end.

Side effects (notifications, emails) are raised via transaction.on_commit, which
does not fire inside Django's TestCase, so nothing is sent during these tests.
"""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from community.models import Community
from events.models import (
    Event, EventPlatform, EventPublication, EventRegistration,
    EventNetworkingSettings, NetworkingTable, NetworkingMeeting,
)


def client_for(user):
    c = APIClient()
    c.force_authenticate(user)
    return c


class NetworkingWindowsOutsideEventTests(TestCase):
    def setUp(self):
        User = get_user_model()
        now = timezone.now()
        # Event runs 09:00-17:00 UTC two days from now.
        self.start = (now + timedelta(days=2)).replace(hour=9, minute=0, second=0, microsecond=0)
        self.end = self.start.replace(hour=17)

        self.owner = User.objects.create_user(username="nwo-owner", password="pass")
        self.requester = User.objects.create_user(username="nwo-req", email="nwo-req@example.com")
        self.recipient = User.objects.create_user(username="nwo-rec", email="nwo-rec@example.com")
        self.community = Community.objects.create(name="nwo community", owner=self.owner)
        self.platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect", defaults={"name": "IMAA Connect", "is_active": True})

        self.event = Event(
            title="Windows summit", community=self.community, created_by=self.owner,
            format="in_person", status="published", timezone="UTC",
            start_time=self.start, end_time=self.end)
        self.event.skip_saleor_sync = True
        self.event.save()
        EventPublication.objects.get_or_create(
            event=self.event, platform=self.platform, defaults={"is_enabled": True})

        self.requester_reg = EventRegistration.objects.create(
            event=self.event, user=self.requester, status="registered")
        self.recipient_reg = EventRegistration.objects.create(
            event=self.event, user=self.recipient, status="registered")

        self.settings = EventNetworkingSettings.objects.create(
            event=self.event, enabled=True, duration_options_minutes=[15], allowed_windows=[])
        NetworkingTable.objects.create(event=self.event, table_number=1, is_active=True)

        self.pre_day = (self.start - timedelta(days=1)).date().isoformat()
        self.event_day = self.start.date().isoformat()
        self.post_day = (self.end + timedelta(days=1)).date().isoformat()

    # ---- helpers ----

    def patch_windows(self, windows):
        return client_for(self.owner).patch(
            f"/api/events/{self.event.id}/networking-settings/",
            {"allowed_windows": windows}, format="json")

    def set_windows(self, windows):
        EventNetworkingSettings.objects.filter(pk=self.settings.pk).update(allowed_windows=windows)

    def availability(self):
        res = client_for(self.requester).get(
            f"/api/events/{self.event.id}/networking-meetings/availability/",
            {"recipient_registration_id": self.recipient_reg.id, "duration_minutes": 15})
        self.assertEqual(res.status_code, 200, res.data)
        return res.data["available_slots"]

    # ---- Admin can save windows outside the event ----

    def test_admin_can_save_pre_event_window(self):
        res = self.patch_windows([{"date": self.pre_day, "start": "09:00", "end": "10:00"}])
        self.assertEqual(res.status_code, 200, res.data)

    def test_admin_can_save_post_event_window(self):
        res = self.patch_windows([{"date": self.post_day, "start": "14:00", "end": "15:00"}])
        self.assertEqual(res.status_code, 200, res.data)

    def test_admin_can_save_window_crossing_event_end(self):
        res = self.patch_windows([{"date": self.event_day, "start": "16:30", "end": "18:00"}])
        self.assertEqual(res.status_code, 200, res.data)

    def test_end_before_start_still_rejected(self):
        res = self.patch_windows([{"date": self.post_day, "start": "15:00", "end": "14:00"}])
        self.assertEqual(res.status_code, 400)
        self.assertIn("allowed_windows", res.data)

    def test_invalid_date_format_still_rejected(self):
        res = self.patch_windows([{"date": "10/11/2026", "start": "09:00", "end": "10:00"}])
        self.assertEqual(res.status_code, 400)

    # ---- Attendees see slots outside the event ----

    def test_slots_offered_before_during_and_after_event(self):
        self.set_windows([
            {"date": self.pre_day, "start": "09:00", "end": "10:00"},
            {"date": self.event_day, "start": "16:30", "end": "18:00"},
            {"date": self.post_day, "start": "14:00", "end": "15:00"},
        ])
        starts = [s["start_time"] for s in self.availability()]

        self.assertEqual(sum(s.startswith(self.pre_day) for s in starts), 4)
        self.assertEqual(sum(s.startswith(self.post_day) for s in starts), 4)
        # Crossing window: 16:30-18:00 = 6 slots, including ones after the 17:00 event end.
        event_day_starts = [s for s in starts if s.startswith(self.event_day)]
        self.assertEqual(len(event_day_starts), 6)
        self.assertIn(f"{self.event_day}T17:30:00+00:00", event_day_starts)

    def test_post_event_meeting_can_be_created_and_accepted(self):
        self.set_windows([{"date": self.post_day, "start": "14:00", "end": "15:00"}])
        slot = self.availability()[0]

        created = client_for(self.requester).post(
            f"/api/events/{self.event.id}/networking-meetings/",
            {"recipient_registration_id": self.recipient_reg.id, "duration_minutes": 15,
             "start_time": slot["start_time"]},
            format="json")
        self.assertEqual(created.status_code, 201, created.data)

        accepted = client_for(self.recipient).post(
            f"/api/networking-meetings/{created.data['id']}/accept/", {}, format="json")
        self.assertEqual(accepted.status_code, 200, accepted.data)

        meeting = NetworkingMeeting.objects.get(id=created.data["id"])
        self.assertEqual(meeting.status, "accepted")
        self.assertIsNotNone(meeting.table_id)
        self.assertGreater(meeting.start_time, self.event.end_time)
        meeting.full_clean()  # model validation no longer rejects post-event meetings

    def test_booking_still_open_after_event_has_ended(self):
        now = timezone.now()
        Event.objects.filter(pk=self.event.pk).update(
            start_time=now - timedelta(days=2), end_time=now - timedelta(days=2) + timedelta(hours=8))
        tomorrow = (now + timedelta(days=1)).date().isoformat()
        self.set_windows([{"date": tomorrow, "start": "10:00", "end": "11:00"}])

        slots = self.availability()
        self.assertEqual(len(slots), 4)

        created = client_for(self.requester).post(
            f"/api/events/{self.event.id}/networking-meetings/",
            {"recipient_registration_id": self.recipient_reg.id, "duration_minutes": 15,
             "start_time": slots[0]["start_time"]},
            format="json")
        self.assertEqual(created.status_code, 201, created.data)

    # ---- Existing rules are unchanged ----

    def test_past_window_offers_no_slots(self):
        yesterday = (timezone.now() - timedelta(days=1)).date().isoformat()
        self.set_windows([{"date": yesterday, "start": "10:00", "end": "11:00"}])
        self.assertEqual(self.availability(), [])

    def test_slot_outside_any_window_is_rejected(self):
        self.set_windows([{"date": self.post_day, "start": "14:00", "end": "15:00"}])
        res = client_for(self.requester).post(
            f"/api/events/{self.event.id}/networking-meetings/",
            {"recipient_registration_id": self.recipient_reg.id, "duration_minutes": 15,
             "start_time": f"{self.post_day}T16:00:00+00:00"},
            format="json")
        self.assertEqual(res.status_code, 409)
