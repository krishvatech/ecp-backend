"""Regression coverage for public/Companion participation without registration writes."""
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from community.models import Community
from events.models import (
    Event, EventApplication, EventApplicationTrack, EventApplicationTrackApplication,
    EventRegistration, GuestAttendee, TrackPricingTier,
)
from events.services.participant_roster import (
    extra_participant_rows, public_participant_count,
)
from events.serializers import EventListSerializer


class ParticipantRosterCountTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user(username="roster-owner", password="pass", is_staff=True)
        self.community = Community.objects.create(name="Roster community")
        self.event = Event.objects.create(
            title="Roster event", community=self.community, created_by=self.owner,
            registration_type="apply", show_public_hosts=True,
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event, label="Delegate", short_description="Participant",
        )
        self.free = TrackPricingTier.objects.create(track=self.track, label="Free", price=0)
        self.paid = TrackPricingTier.objects.create(track=self.track, label="Paid", price=90)

    def application(self, email, *, tier=None, linked_user=None, status="accepted", parent_status="pending"):
        app = EventApplication.objects.create(
            event=self.event, email=email, first_name="Applicant", last_name="Example",
            user=linked_user, status=parent_status,
        )
        ta = EventApplicationTrackApplication.objects.create(
            application=app, track=self.track, status=status,
            accepted_tier=tier or self.free,
        )
        return app, ta

    def test_free_accepted_guest_without_account_counts_but_does_not_register(self):
        self.application("guest@example.com")
        self.assertEqual(public_participant_count(self.event), 1)
        self.assertEqual(EventRegistration.objects.filter(event=self.event).count(), 0)
        self.assertEqual(extra_participant_rows(self.event)[0]["source"], "accepted_application")
        self.assertEqual(EventListSerializer(self.event).data["public_participant_count"], 1)

    def test_paid_pending_and_nonaccepted_guest_do_not_count(self):
        self.application("unpaid@example.com", tier=self.paid)
        self.application("pending@example.com", status="pending")
        self.assertEqual(public_participant_count(self.event), 0)

    def test_duplicate_applications_and_registered_member_count_once(self):
        User = get_user_model()
        member = User.objects.create_user(username="registered", email="member@example.com")
        EventRegistration.objects.create(event=self.event, user=member, status="registered")
        self.application("member@example.com")
        self.application("guest@example.com")
        self.application("GUEST@EXAMPLE.COM")
        self.assertEqual(public_participant_count(self.event), 2)
        self.assertEqual(len(extra_participant_rows(self.event)), 1)

    def test_cancelled_registration_or_parent_application_does_not_resurrect(self):
        User = get_user_model()
        member = User.objects.create_user(username="cancelled", email="cancelled@example.com")
        EventRegistration.objects.create(event=self.event, user=member, status="cancelled", attendee_status="cancelled")
        self.application("cancelled@example.com")
        self.application("withdrawn@example.com", parent_status="cancelled")
        self.assertEqual(public_participant_count(self.event), 0)

    def test_superuser_guest_match_is_not_publicly_counted(self):
        User = get_user_model()
        User.objects.create_superuser(username="admin-guest", email="admin@example.com", password="pw")
        self.application("ADMIN@example.com")
        self.assertEqual(public_participant_count(self.event), 0)
        self.assertEqual(len(extra_participant_rows(self.event, include_superusers=True)), 1)

    def test_verified_guest_and_application_are_deduplicated(self):
        self.application("guest@example.com")
        GuestAttendee.objects.create(
            event=self.event, email="guest@example.com", first_name="Guest",
            last_name="Example", email_verified=True,
        )
        self.assertEqual(public_participant_count(self.event), 1)

    def test_companion_roster_owner_only_and_nonassignable_guest_rows(self):
        self.application("guest@example.com")
        client = APIClient()
        outsider = get_user_model().objects.create_user(username="outsider-roster")
        client.force_authenticate(outsider)
        denied = client.get(f"/events/{self.event.id}/companion-roster/")
        self.assertEqual(denied.status_code, 403)
        client.force_authenticate(self.owner)
        result = client.get(f"/events/{self.event.id}/companion-roster/")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data["count"], 1)
        self.assertIsNone(result.data["results"][0]["registration_id"])
        self.assertFalse(result.data["results"][0]["can_assign_labels"])
        self.assertEqual(result.data["public_participant_count"], 1)

    def test_public_popup_paginates_full_eligible_roster_without_private_guest_data(self):
        User = get_user_model()
        member = User.objects.create_user(username="pop-member", email="member@example.com")
        EventRegistration.objects.create(event=self.event, user=member, status="registered")
        for n in range(18):
            self.application(f"guest{n:02d}@example.com")
        self.application("guest00@EXAMPLE.com")  # same identity, different casing
        self.application("paid@example.com", tier=self.paid)
        client = APIClient()
        client.force_authenticate(member)
        first = client.get(f"/events/{self.event.id}/participants/?limit=10&offset=0")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.data["public_participant_count"], 19)
        self.assertEqual(first.data["directory_row_count"], 19)
        self.assertEqual(len(first.data["participants"]), 10)
        self.assertEqual(first.data["next_offset"], 10)
        second = client.get(f"/events/{self.event.id}/participants/?limit=10&offset=10")
        self.assertEqual(second.status_code, 200)
        self.assertEqual(len(second.data["participants"]), 9)
        self.assertFalse(second.data["has_next"])
        all_rows = first.data["participants"] + second.data["participants"]
        self.assertEqual(len({p["participant_key"] for p in all_rows}), 19)
        guest_rows = [p for p in all_rows if p["source"] == "accepted_application"]
        self.assertEqual(len(guest_rows), 18)
        for row in guest_rows:
            self.assertEqual(row["email"], "")
            self.assertIsNone(row["profile_url"])
            self.assertIsNone(row["user_id"])
            self.assertIsNone(row["registration_id"])
            self.assertFalse(row["is_profile_clickable"])
            self.assertNotIn("guest00@example.com", str(row))
        self.assertFalse(EventRegistration.objects.filter(event=self.event, user__email__icontains="guest").exists())

    def test_popup_respects_existing_event_visibility(self):
        self.application("guest@example.com")
        from django.utils import timezone
        from datetime import timedelta
        self.event.start_time = timezone.now() + timedelta(days=10)
        self.event.show_participants_before_event = False
        self.event.save(update_fields=["start_time", "show_participants_before_event"])
        viewer = get_user_model().objects.create_user(username="popup-viewer")
        client = APIClient()
        client.force_authenticate(viewer)
        denied = client.get(f"/events/{self.event.id}/participants/")
        self.assertEqual(denied.status_code, 403)
        client.force_authenticate(self.owner)
        allowed = client.get(f"/events/{self.event.id}/participants/")
        self.assertEqual(allowed.status_code, 200)

    def test_companion_directory_includes_names_without_guest_meeting_credentials(self):
        self.application("guest@example.com")
        self.application("unpaid@example.com", tier=self.paid)
        member = get_user_model().objects.create_user(username="directory-member", email="member@example.com")
        EventRegistration.objects.create(event=self.event, user=member, status="registered")
        client = APIClient()
        outsider = get_user_model().objects.create_user(username="directory-outsider")
        client.force_authenticate(outsider)
        denied = client.get(f"/events/{self.event.id}/companion-directory/")
        self.assertEqual(denied.status_code, 403)
        client.force_authenticate(member)
        response = client.get(f"/events/{self.event.id}/companion-directory/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["public_participant_count"], 2)
        self.assertEqual(response.data["count"], 2)
        self.assertEqual(response.data["networking_profile_count"], 1)
        guests = [p for p in response.data["participants"] if p["source"] == "accepted_application"]
        self.assertEqual(len(guests), 1)
        guest = guests[0]
        self.assertEqual(guest["display_name"], "Applicant Example")
        self.assertIsNone(guest["user_id"])
        self.assertIsNone(guest["registration_id"])
        self.assertIsNone(guest["profile_url"])
        self.assertFalse(guest["is_networking_eligible"])
        self.assertNotIn("email", guest)
        found = client.get(f"/events/{self.event.id}/companion-directory/?q=Applicant")
        self.assertEqual(found.data["count"], 1)

    def test_unnamed_applicant_never_exposes_email_as_display_name(self):
        app, _ = self.application("unnamed@example.com")
        app.first_name = ""
        app.last_name = ""
        app.save(update_fields=["first_name", "last_name"])
        from events.services.participant_roster import public_directory_extra_rows
        rows = public_directory_extra_rows(self.event)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["display_name"], "Event participant")
        self.assertEqual(rows[0]["email"], "")
