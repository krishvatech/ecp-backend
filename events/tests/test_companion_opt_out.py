"""Per-event Event Companion opt-out (EventRegistration.hide_from_companion)."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event, EventPlatform, EventPublication, EventRegistration


class CompanionOptOutTests(TestCase):
    def setUp(self):
        User = get_user_model()
        now = timezone.now()
        self.owner = User.objects.create_user(username="optout-owner", password="pass")
        self.member = User.objects.create_user(username="optout-member", email="member@example.com")
        self.other = User.objects.create_user(username="optout-other", email="other@example.com")
        self.community = Community.objects.create(name="Opt-out community", owner=self.owner)
        platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect", defaults={"name": "IMAA Connect", "is_active": True},
        )

        def event(title, **kw):
            defaults = dict(
                community=self.community, created_by=self.owner, format="in_person",
                status="published", start_time=now - timedelta(hours=1),
                end_time=now + timedelta(hours=5),
            )
            defaults.update(kw)
            ev = Event(title=title, **defaults)
            ev.skip_saleor_sync = True
            ev.save()
            # Non-admin event lookups require an enabled IMAA Connect publication.
            EventPublication.objects.get_or_create(event=ev, platform=platform, defaults={"is_enabled": True})
            return ev

        self.event = event("In-person summit")
        self.second = event("Second in-person summit", start_time=now + timedelta(days=30),
                            end_time=now + timedelta(days=31))
        self.virtual = event("Virtual webinar", format="virtual")
        self.ended = event("Past summit", start_time=now - timedelta(days=3),
                           end_time=now - timedelta(days=2), status="ended")
        self.draft = event("Draft summit", status="draft")

        self.reg = EventRegistration.objects.create(event=self.event, user=self.member, status="registered")
        self.second_reg = EventRegistration.objects.create(event=self.second, user=self.member, status="registered")
        for ev in (self.virtual, self.ended, self.draft):
            EventRegistration.objects.create(event=ev, user=self.member, status="registered")
        self.other_reg = EventRegistration.objects.create(event=self.event, user=self.other, status="registered")

        self.client = APIClient()
        self.client.force_authenticate(self.member)

    def set_hidden(self, reg, value, client=None):
        return (client or self.client).post(
            f"/api/event-registrations/{reg.id}/companion-visibility/",
            {"hide_from_companion": value}, format="json",
        )

    def test_list_only_current_in_person_registrations(self):
        response = self.client.get("/api/event-registrations/companion-visibility/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [row["registration_id"] for row in response.data],
            [self.reg.id, self.second_reg.id],
        )
        self.assertFalse(response.data[0]["hide_from_companion"])
        self.assertEqual(response.data[0]["event"]["slug"], self.event.slug)

    def test_opt_out_is_per_event(self):
        response = self.set_hidden(self.reg, True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["hide_from_companion"])
        self.reg.refresh_from_db()
        self.second_reg.refresh_from_db()
        self.assertTrue(self.reg.hide_from_companion)
        self.assertFalse(self.second_reg.hide_from_companion)

        self.assertEqual(self.set_hidden(self.reg, False).status_code, 200)
        self.reg.refresh_from_db()
        self.assertFalse(self.reg.hide_from_companion)

    def test_cannot_change_someone_elses_or_ineligible_registration(self):
        self.assertEqual(self.set_hidden(self.other_reg, True).status_code, 404)
        virtual_reg = EventRegistration.objects.get(event=self.virtual, user=self.member)
        self.assertEqual(self.set_hidden(virtual_reg, True).status_code, 404)
        self.other_reg.refresh_from_db()
        self.assertFalse(self.other_reg.hide_from_companion)

    def test_rejects_non_boolean_value(self):
        self.assertEqual(self.set_hidden(self.reg, "yes").status_code, 400)

    def test_hidden_participant_not_in_companion_directory_but_keeps_access(self):
        self.set_hidden(self.reg, True)
        other_client = APIClient()
        other_client.force_authenticate(self.other)
        listed = other_client.get(f"/api/events/{self.event.id}/companion-directory/")
        self.assertEqual(listed.status_code, 200)
        user_ids = {p["user_id"] for p in listed.data["participants"]}
        self.assertNotIn(self.member.id, user_ids)
        self.assertIn(self.other.id, user_ids)

        # The hidden member can still open the Companion and sees their own
        # card, flagged as hidden.
        own = self.client.get(f"/api/events/{self.event.id}/companion-directory/")
        self.assertEqual(own.status_code, 200)
        mine = [p for p in own.data["participants"] if p["user_id"] == self.member.id]
        self.assertEqual(len(mine), 1)
        self.assertTrue(mine[0]["hidden_from_companion"])
        other_row = next(p for p in own.data["participants"] if p["user_id"] == self.other.id)
        self.assertFalse(other_row["hidden_from_companion"])

    def test_hidden_participant_cannot_be_booked_for_meetings(self):
        self.set_hidden(self.reg, True)
        other_client = APIClient()
        other_client.force_authenticate(self.other)
        create = other_client.post(
            f"/api/events/{self.event.id}/networking-meetings/",
            {
                "recipient_registration_id": self.reg.id,
                "duration_minutes": 15,
                "start_time": (timezone.now() + timedelta(hours=1)).isoformat(),
            },
            format="json",
        )
        self.assertEqual(create.status_code, 404)
        slots = other_client.get(
            f"/api/events/{self.event.id}/networking-meetings/availability/",
            {"recipient_registration_id": self.reg.id, "duration_minutes": 15},
        )
        self.assertEqual(slots.status_code, 400)

    def test_owner_roster_shows_opt_out_flag(self):
        self.set_hidden(self.reg, True)
        owner_client = APIClient()
        owner_client.force_authenticate(self.owner)
        response = owner_client.get(f"/api/events/{self.event.id}/companion-roster/")
        self.assertEqual(response.status_code, 200)
        row = next(r for r in response.data["results"] if r.get("registration_id") == self.reg.id)
        self.assertTrue(row["hide_from_companion"])
