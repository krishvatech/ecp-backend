"""Event Companion directory loads its data in bulk, without changing what it returns."""
from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from community.models import Community
from events.models import (
    Event,
    EventApplication,
    EventApplicationTrack,
    EventApplicationTrackApplication,
    EventParticipant,
    EventPlatform,
    EventPublication,
    EventRegistration,
    GuestAttendee,
    TrackPricingTier,
)
from users.models import Experience, UserProfile

EXPERIENCE_ORDER = ("-currently_work_here", "-end_date", "-start_date", "-id")


class CompanionDirectoryTestBase(TestCase):
    def setUp(self):
        self.User = get_user_model()
        now = timezone.now()
        owner = self.User.objects.create_user(username="dir-owner", password="pass")
        community = Community.objects.create(name="Directory community", owner=owner)
        platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect", defaults={"name": "IMAA Connect", "is_active": True},
        )
        self.event = Event(
            title="Directory summit", community=community, created_by=owner, format="in_person",
            status="published", start_time=now + timedelta(days=1), end_time=now + timedelta(days=2),
        )
        self.event.skip_saleor_sync = True
        self.event.save()
        # Non-admin event lookups require an enabled IMAA Connect publication.
        EventPublication.objects.get_or_create(event=self.event, platform=platform, defaults={"is_enabled": True})

        self.viewer = self.add_attendee("viewer", job_title="Viewer title", company="Viewer co")
        self.client = APIClient()
        self.client.force_authenticate(self.viewer)
        self.url = f"/api/events/{self.event.id}/companion-directory/"

    def add_attendee(self, name, job_title="", company=""):
        user = self.User.objects.create_user(
            username=f"dir-{name}", email=f"{name}@example.com", first_name=name.title(), last_name="Attendee",
        )
        UserProfile.objects.update_or_create(user=user, defaults={"job_title": job_title, "company": company})
        EventRegistration.objects.create(event=self.event, user=user, status="registered")
        return user

    def add_experience(self, user, position, company, start=date(2020, 1, 1), end=None, current=False):
        return Experience.objects.create(
            user=user, position=position, community_name=company,
            start_date=start, end_date=end, currently_work_here=current,
        )

    def add_speaker(self, user, order=0):
        # bulk_create: the participant post_save signal isn't relevant to this view.
        EventParticipant.objects.bulk_create([EventParticipant(
            event=self.event, user=user, participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
            role="speaker", display_order=order,
        )])

    def add_accepted_application(self, email, first_name="Applicant", last_name="Person"):
        track, _ = EventApplicationTrack.objects.get_or_create(
            event=self.event, key="delegates", defaults={"label": "Delegates", "status": "open"},
        )
        tier, _ = TrackPricingTier.objects.get_or_create(
            track=track, key="delegates",
            defaults={"label": "Delegates", "price": 0, "currency": "USD", "visibility": "public"},
        )
        application = EventApplication.objects.create(
            event=self.event, first_name=first_name, last_name=last_name, email=email,
        )
        EventApplicationTrackApplication.objects.create(
            application=application, track=track, status="accepted", accepted_tier=tier,
        )

    def add_guest(self, email):
        GuestAttendee.objects.create(
            event=self.event, email=email, first_name="Guest", last_name="Person", email_verified=True,
            token_jti=f"jti-{email}", expires_at=timezone.now() + timedelta(days=30),
        )

    def directory(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.content[:300])
        return response.data

    def row_for(self, user):
        return next(row for row in self.directory()["participants"] if row["user_id"] == user.id)


class CompanionDirectoryQueryCountTests(CompanionDirectoryTestBase):
    def add_batch(self, start, count):
        for i in range(start, start + count):
            user = self.add_attendee(f"person{i}")
            self.add_experience(user, f"Role {i}", f"Firm {i}", current=True)
            self.add_experience(user, "Old role", "Old firm", start=date(2015, 1, 1), end=date(2019, 1, 1))
            self.add_speaker(user, order=i)

    def query_count(self):
        with CaptureQueriesContext(connection) as queries:
            self.directory()
        return len(queries)

    def test_query_count_does_not_grow_with_attendees_or_speakers(self):
        self.add_accepted_application("applicant@example.com")
        self.add_guest("guest@example.com")
        self.add_batch(0, 2)
        # The first request also fills process-wide caches, so measure from the second.
        self.directory()
        small = self.query_count()

        self.add_batch(2, 12)
        large = self.query_count()

        self.assertEqual(self.directory()["networking_profile_count"], 15)
        self.assertEqual(large, small, f"{small} queries for 3 attendees, {large} for 15")

    def test_query_count_stays_small(self):
        self.add_accepted_application("applicant@example.com")
        self.add_batch(0, 5)
        self.assertLessEqual(self.query_count(), 25)


class CompanionDirectoryOutputTests(CompanionDirectoryTestBase):
    def test_profile_details_win_over_experience(self):
        user = self.add_attendee("complete", job_title="Profile title", company="Profile co")
        self.add_experience(user, "Experience title", "Experience co", current=True)
        row = self.row_for(user)
        self.assertEqual((row["job_title"], row["company"]), ("Profile title", "Profile co"))

    def test_only_the_missing_detail_comes_from_experience(self):
        no_company = self.add_attendee("nocompany", job_title="Profile title")
        self.add_experience(no_company, "Experience title", "Experience co", current=True)
        row = self.row_for(no_company)
        self.assertEqual((row["job_title"], row["company"]), ("Profile title", "Experience co"))

        no_title = self.add_attendee("notitle", company="Profile co")
        self.add_experience(no_title, "Experience title", "Experience co", current=True)
        row = self.row_for(no_title)
        self.assertEqual((row["job_title"], row["company"]), ("Experience title", "Profile co"))

    def test_no_details_and_no_experience_stay_blank(self):
        row = self.row_for(self.add_attendee("blank"))
        self.assertEqual((row["job_title"], row["company"]), ("", ""))

    def test_experience_choice_matches_the_one_at_a_time_lookup(self):
        """Includes end_date NULL on a past role, which sorts first under descending order on PostgreSQL."""
        cases = {
            "current": [
                ("Old", date(2015, 1, 1), date(2019, 1, 1), False),
                ("Current", date(2021, 1, 1), None, True),
                ("Newest past", date(2022, 1, 1), date(2024, 1, 1), False),
            ],
            "newestend": [
                ("Earlier end", date(2015, 1, 1), date(2018, 1, 1), False),
                ("Later end", date(2014, 1, 1), date(2023, 1, 1), False),
            ],
            "nullend": [
                ("Has end", date(2015, 1, 1), date(2023, 1, 1), False),
                ("No end", date(2010, 1, 1), None, False),
            ],
            "tie": [
                ("First", date(2020, 1, 1), date(2021, 1, 1), False),
                ("Second", date(2020, 1, 1), date(2021, 1, 1), False),
            ],
        }
        users = {}
        for name, experiences in cases.items():
            users[name] = self.add_attendee(name)
            for position, start, end, current in experiences:
                self.add_experience(users[name], position, f"{position} co", start=start, end=end, current=current)

        rows = {row["user_id"]: row for row in self.directory()["participants"]}
        expected = {"current": "Current", "newestend": "Later end", "nullend": "No end", "tie": "Second"}
        for name, user in users.items():
            one_at_a_time = Experience.objects.filter(user=user).order_by(*EXPERIENCE_ORDER).first()
            self.assertEqual(rows[user.id]["job_title"], one_at_a_time.position, name)
            self.assertEqual(rows[user.id]["company"], one_at_a_time.community_name, name)
            self.assertEqual(rows[user.id]["job_title"], expected[name], name)

    def test_user_without_a_profile_is_still_listed(self):
        user = self.add_attendee("noprofile")
        self.add_experience(user, "Experience title", "Experience co", current=True)
        UserProfile.objects.filter(user=user).delete()
        row = self.row_for(user)
        self.assertEqual(row["display_name"], "Noprofile Attendee")
        self.assertEqual((row["job_title"], row["company"]), ("Experience title", "Experience co"))

    def test_display_name_falls_back_to_profile_then_username(self):
        from_profile = self.User.objects.create_user(username="dir-p", email="p@example.com")
        UserProfile.objects.update_or_create(user=from_profile, defaults={"full_name": "Profile Name"})
        EventRegistration.objects.create(event=self.event, user=from_profile, status="registered")
        self.assertEqual(self.row_for(from_profile)["display_name"], "Profile Name")

        from_username = self.User.objects.create_user(username="dir-u", email="u@example.com")
        EventRegistration.objects.create(event=self.event, user=from_username, status="registered")
        self.assertEqual(self.row_for(from_username)["display_name"], "dir-u")

    def test_speaker_role_is_resolved(self):
        user = self.add_attendee("speaker")
        self.add_speaker(user)
        row = self.row_for(user)
        self.assertEqual(row["badge_key"], "speaker")
        self.assertEqual(row["roles"], ["speaker"])

    def test_extra_rows_and_counts(self):
        self.add_attendee("member")
        self.add_accepted_application("applicant@example.com")
        self.add_guest("guest@example.com")
        # A registered user's own application must not add a second row or count.
        self.add_accepted_application("member@example.com", first_name="Member", last_name="Attendee")

        data = self.directory()
        sources = sorted(row["source"] for row in data["participants"])
        self.assertEqual(sources, ["accepted_application", "registration", "registration", "verified_guest"])
        self.assertEqual(data["count"], 4)
        self.assertEqual(data["networking_profile_count"], 2)
        self.assertEqual(data["public_participant_count"], 4)
