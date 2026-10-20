"""IPDT-769: pre-event Companion Directory + 1:1 Networking for eligible participants.

Covers the access matrix (who may view the directory / use networking before the
event starts) and the security requirement that networking endpoints must never
silently create an EventRegistration for a non-participant.

Side effects (notifications, emails) are raised via transaction.on_commit, which
does not fire inside Django's TestCase (each test runs in a rolled-back
transaction), so no emails/notifications are sent during these tests.
"""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from community.models import Community
from events.models import (
    Event, EventPlatform, EventPublication, EventRegistration,
    EventApplication, EventNetworkingSettings, NetworkingTable, NetworkingMeeting,
)


class CompanionPreEventAccessTests(TestCase):
    @classmethod
    def _future_event(cls, title, **kw):
        defaults = dict(
            community=cls.community, created_by=cls.owner, format="in_person",
            status="published", timezone="UTC",
            start_time=cls.start, end_time=cls.end,
        )
        defaults.update(kw)
        ev = Event(title=title, **defaults)
        ev.skip_saleor_sync = True
        ev.save()
        EventPublication.objects.get_or_create(
            event=ev, platform=cls.platform, defaults={"is_enabled": True})
        return ev

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        now = timezone.now()
        # Event starts two days from now (pre-event window) and runs 09:00-17:00 UTC.
        cls.start = (now + timedelta(days=2)).replace(hour=9, minute=0, second=0, microsecond=0)
        cls.end = cls.start.replace(hour=17)

        cls.owner = User.objects.create_user(username="769-owner", password="pass")
        cls.registered = User.objects.create_user(username="769-registered", email="reg@example.com")
        cls.approved = User.objects.create_user(username="769-approved", email="appr@example.com")
        cls.approved_no_reg = User.objects.create_user(username="769-approved-noreg", email="anr@example.com")
        cls.pending = User.objects.create_user(username="769-pending", email="pend@example.com")
        cls.declined = User.objects.create_user(username="769-declined", email="decl@example.com")
        cls.stranger = User.objects.create_user(username="769-stranger", email="stranger@example.com")
        cls.other_event_user = User.objects.create_user(username="769-other", email="other@example.com")
        cls.recipient = User.objects.create_user(username="769-recipient", email="recip@example.com")

        cls.community = Community.objects.create(name="769 community", owner=cls.owner)
        cls.platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect", defaults={"name": "IMAA Connect", "is_active": True})

        cls.event = cls._future_event("Pre-event summit", registration_type="apply")
        cls.another_event = cls._future_event("Unrelated summit")

        # Accepted participants (registered). Acceptance normally creates a
        # registration, so the primary eligible user is "registered".
        cls.registered_reg = EventRegistration.objects.create(
            event=cls.event, user=cls.registered, status="registered")
        cls.recipient_reg = EventRegistration.objects.create(
            event=cls.event, user=cls.recipient, status="registered")

        # Approved application WITH its registration (the normal accepted state).
        # EventApplication is unique per (event, email), so each fixture sets its
        # applicant email explicitly.
        EventApplication.objects.create(
            event=cls.event, user=cls.approved, email=cls.approved.email, status="approved")
        cls.approved_reg = EventRegistration.objects.create(
            event=cls.event, user=cls.approved, status="registered")

        # Approved application WITHOUT a registration (legacy/edge): may view the
        # directory but cannot network (no registration to hang a meeting on).
        EventApplication.objects.create(
            event=cls.event, user=cls.approved_no_reg, email=cls.approved_no_reg.email, status="approved")

        # Pending / declined applicants (no registration).
        EventApplication.objects.create(
            event=cls.event, user=cls.pending, email=cls.pending.email, status="pending")
        EventApplication.objects.create(
            event=cls.event, user=cls.declined, email=cls.declined.email, status="declined")

        # A user registered only for a DIFFERENT event.
        EventRegistration.objects.create(
            event=cls.another_event, user=cls.other_event_user, status="registered")

    def client_for(self, user=None):
        c = APIClient()
        if user is not None:
            c.force_authenticate(user)
        return c

    def directory(self, user):
        return self.client_for(user).get(f"/api/events/{self.event.id}/companion-directory/")

    # ---- Directory access matrix (event has NOT started) ----

    def test_registered_participant_can_view_directory_before_start(self):
        res = self.directory(self.registered)
        self.assertEqual(res.status_code, 200)
        # Regression: the old pre-event block must be gone.
        self.assertNotIn("code", res.data)

    def test_approved_applicant_can_view_directory_before_start(self):
        self.assertEqual(self.directory(self.approved).status_code, 200)

    def test_approved_without_registration_can_view_directory(self):
        self.assertEqual(self.directory(self.approved_no_reg).status_code, 200)

    def test_event_manager_can_preview_directory_before_start(self):
        self.assertEqual(self.directory(self.owner).status_code, 200)

    def test_pending_applicant_denied(self):
        self.assertEqual(self.directory(self.pending).status_code, 403)

    def test_declined_applicant_denied(self):
        self.assertEqual(self.directory(self.declined).status_code, 403)

    def test_unregistered_user_denied(self):
        self.assertEqual(self.directory(self.stranger).status_code, 403)

    def test_registration_for_another_event_does_not_authorize(self):
        self.assertEqual(self.directory(self.other_event_user).status_code, 403)

    def test_anonymous_denied(self):
        res = self.client_for().get(f"/api/events/{self.event.id}/companion-directory/")
        self.assertIn(res.status_code, (401, 403))

    def test_directory_still_accessible_after_start(self):
        Event.objects.filter(pk=self.event.pk).update(
            start_time=timezone.now() - timedelta(hours=1))
        self.assertEqual(self.directory(self.registered).status_code, 200)

    # ---- Networking authorization / anti-auto-registration (security) ----

    def test_availability_does_not_auto_register_non_participant(self):
        before = EventRegistration.objects.filter(event=self.event, user=self.stranger).count()
        res = self.client_for(self.stranger).get(
            f"/api/events/{self.event.id}/networking-meetings/availability/",
            {"recipient_registration_id": self.recipient_reg.id, "duration_minutes": 15})
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.data.get("code"), "NOT_NETWORKING_ELIGIBLE")
        after = EventRegistration.objects.filter(event=self.event, user=self.stranger).count()
        self.assertEqual(before, after)
        self.assertEqual(after, 0)

    def test_create_does_not_auto_register_non_participant(self):
        res = self.client_for(self.stranger).post(
            f"/api/events/{self.event.id}/networking-meetings/",
            {"recipient_registration_id": self.recipient_reg.id, "duration_minutes": 15,
             "start_time": (self.start + timedelta(minutes=30)).isoformat()},
            format="json")
        self.assertEqual(res.status_code, 403)
        self.assertFalse(
            EventRegistration.objects.filter(event=self.event, user=self.stranger).exists())

    def test_my_meetings_does_not_auto_register_and_is_empty(self):
        res = self.client_for(self.stranger).get(
            f"/api/events/{self.event.id}/networking-meetings/my/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(list(res.data), [])
        self.assertFalse(
            EventRegistration.objects.filter(event=self.event, user=self.stranger).exists())

    def test_approved_without_registration_cannot_network(self):
        # Documents the limitation: viewing the directory != being able to book.
        res = self.client_for(self.approved_no_reg).get(
            f"/api/events/{self.event.id}/networking-meetings/availability/",
            {"recipient_registration_id": self.recipient_reg.id, "duration_minutes": 15})
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.data.get("code"), "NOT_NETWORKING_ELIGIBLE")

    # ---- Recipient eligibility ----

    def test_cancelled_recipient_not_bookable(self):
        cancelled = EventRegistration.objects.create(
            event=self.event, user=self.declined, status="cancelled")
        res = self.client_for(self.registered).get(
            f"/api/events/{self.event.id}/networking-meetings/availability/",
            {"recipient_registration_id": cancelled.id, "duration_minutes": 15})
        self.assertEqual(res.status_code, 400)


class CompanionPreEventNetworkingHappyPathTests(TestCase):
    """Eligible participants can plan (query/create/accept) meetings before start."""

    def setUp(self):
        User = get_user_model()
        now = timezone.now()
        self.start = (now + timedelta(days=2)).replace(hour=9, minute=0, second=0, microsecond=0)
        self.end = self.start.replace(hour=17)

        self.owner = User.objects.create_user(username="769hp-owner", password="pass")
        self.requester = User.objects.create_user(username="769hp-req", email="req@example.com")
        self.recipient = User.objects.create_user(username="769hp-rec", email="rec@example.com")
        self.community = Community.objects.create(name="769hp community", owner=self.owner)
        self.platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect", defaults={"name": "IMAA Connect", "is_active": True})

        self.event = Event(
            title="HP summit", community=self.community, created_by=self.owner,
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

        # Networking enabled, one window during the event, 15-minute meetings.
        window_date = self.start.date().isoformat()
        EventNetworkingSettings.objects.create(
            event=self.event, enabled=True, duration_options_minutes=[15],
            allowed_windows=[{"date": window_date, "start": "10:00", "end": "11:00"}])
        NetworkingTable.objects.create(event=self.event, table_number=1, is_active=True)

    def test_eligible_participant_sees_pre_event_slots(self):
        res = APIClient_force(self.requester).get(
            f"/api/events/{self.event.id}/networking-meetings/availability/",
            {"recipient_registration_id": self.recipient_reg.id, "duration_minutes": 15})
        self.assertEqual(res.status_code, 200)
        slots = res.data["available_slots"]
        self.assertTrue(len(slots) > 0, "expected bookable slots before event start")

    def test_eligible_participant_can_create_and_accept_advance_meeting(self):
        req_client = APIClient_force(self.requester)
        slots = req_client.get(
            f"/api/events/{self.event.id}/networking-meetings/availability/",
            {"recipient_registration_id": self.recipient_reg.id, "duration_minutes": 15},
        ).data["available_slots"]
        self.assertTrue(slots)

        created = req_client.post(
            f"/api/events/{self.event.id}/networking-meetings/",
            {"recipient_registration_id": self.recipient_reg.id, "duration_minutes": 15,
             "start_time": slots[0]["start_time"]},
            format="json")
        self.assertEqual(created.status_code, 201)
        meeting_id = created.data["id"]
        self.assertEqual(
            NetworkingMeeting.objects.get(id=meeting_id).status, "pending")

        # Duplicate request is still rejected.
        dup = req_client.post(
            f"/api/events/{self.event.id}/networking-meetings/",
            {"recipient_registration_id": self.recipient_reg.id, "duration_minutes": 15,
             "start_time": slots[0]["start_time"]},
            format="json")
        self.assertEqual(dup.status_code, 409)

        # Recipient accepts before the event starts.
        accepted = APIClient_force(self.recipient).post(
            f"/api/networking-meetings/{meeting_id}/accept/", {}, format="json")
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(
            NetworkingMeeting.objects.get(id=meeting_id).status, "accepted")


def APIClient_force(user):
    c = APIClient()
    c.force_authenticate(user)
    return c
