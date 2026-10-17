"""
IPDT-771: Event application track selector must allow only ONE track.

Covers the new-submission API guard (guest + registered single-track success,
multi-track / duplicate / mixed-payload rejection, legacy single-track
compatibility) and verifies that historical multi-track applications created
before the restriction remain readable, reviewable, and decidable.

The guard lives only at the POST /apply/ new-submission boundary; these tests
also assert rejected submissions create no parent/child/registration rows.
"""
from unittest.mock import patch

from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

from community.models import Community
from events.models import (
    Event,
    EventApplication,
    EventApplicationTrack,
    EventApplicationTrackApplication,
    EventRegistration,
    EventPlatform,
    EventPublication,
    TrackPricingTier,
)

User = get_user_model()


def _grant_imaa_visibility(event):
    """Non-admin API requests only see events published to imaa_connect
    (EventViewSet.get_queryset), so the apply endpoint 404s without this."""
    platform, _ = EventPlatform.objects.update_or_create(
        slug="imaa_connect",
        defaults={"name": "IMAA Connect", "is_active": True},
    )
    EventPublication.objects.get_or_create(
        event=event,
        platform=platform,
        defaults={"is_enabled": True},
    )


class SingleTrackSubmissionTests(TestCase):
    """New submissions: one track allowed, more than one rejected."""

    def setUp(self):
        self.client = APIClient()
        self.owner = User.objects.create_user(
            username="owner-771", email="owner771@example.com", password="pass123"
        )
        self.community = Community.objects.create(
            name="IPDT771 Community", slug="ipdt771-community", owner=self.owner
        )
        self.event = Event.objects.create(
            community=self.community,
            title="IPDT771 Event",
            slug="ipdt771-event",
            registration_type="apply",
            status="published",
            created_by=self.owner,
            allow_guest_applications=True,
        )
        _grant_imaa_visibility(self.event)
        self.track_a = EventApplicationTrack.objects.create(
            event=self.event, key="track-a", label="Track A",
            status="open", is_active=True,
            enabled_submission_modes=["self_submission"],
        )
        self.track_b = EventApplicationTrack.objects.create(
            event=self.event, key="track-b", label="Track B",
            status="open", is_active=True,
            enabled_submission_modes=["self_submission"],
        )
        self.base_payload = {
            "first_name": "Pat",
            "last_name": "Applicant",
            "email": "pat@example.com",
            "job_title": "Analyst",
            "company_name": "Example Ltd",
        }

    # ---- success paths -------------------------------------------------

    def test_guest_single_track_succeeds(self):
        payload = {**self.base_payload, "track_applications": [{"track_id": self.track_a.id}]}
        resp = self.client.post(f"/api/events/{self.event.id}/apply/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(email="pat@example.com")
        self.assertIsNone(app.user_id)  # guest
        self.assertEqual(app.track_applications.count(), 1)
        self.assertEqual(app.track_applications.first().track, self.track_a)

    def test_registered_single_track_succeeds(self):
        user = User.objects.create_user(
            username="member-771", email="member771@example.com",
            password="pass123", first_name="Mem", last_name="Ber",
        )
        self.client.force_authenticate(user=user)
        payload = {**self.base_payload, "email": user.email,
                   "track_applications": [{"track_id": self.track_a.id}]}
        with patch(
            "events.views.EventViewSet._get_missing_lead_gen_fields",
            return_value=(True, {}),
        ):
            resp = self.client.post(f"/api/events/{self.event.id}/apply/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        app = EventApplication.objects.get(email=user.email)
        self.assertEqual(app.user_id, user.id)
        self.assertEqual(app.track_applications.count(), 1)

    def test_legacy_track_id_single_track_succeeds(self):
        payload = {**self.base_payload, "track_id": self.track_a.id,
                   "submission_mode": "self_submission"}
        resp = self.client.post(f"/api/events/{self.event.id}/apply/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            EventApplication.objects.get(email="pat@example.com").track_applications.count(), 1
        )

    def test_legacy_track_key_single_track_succeeds(self):
        payload = {**self.base_payload, "track_key": self.track_a.key,
                   "submission_mode": "self_submission"}
        resp = self.client.post(f"/api/events/{self.event.id}/apply/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            EventApplication.objects.get(email="pat@example.com").track_applications.count(), 1
        )

    # ---- rejection paths (no side effects) -----------------------------

    def _assert_no_records(self):
        self.assertFalse(EventApplication.objects.filter(email="pat@example.com").exists())
        self.assertFalse(
            EventApplicationTrackApplication.objects.filter(
                application__email="pat@example.com"
            ).exists()
        )
        self.assertFalse(
            EventRegistration.objects.filter(event=self.event, user=self.owner).exists()
        )

    def test_guest_multiple_tracks_rejected(self):
        payload = {**self.base_payload, "track_applications": [
            {"track_id": self.track_a.id}, {"track_id": self.track_b.id}]}
        resp = self.client.post(f"/api/events/{self.event.id}/apply/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("one application track", resp.data["detail"].lower())
        self._assert_no_records()

    def test_registered_multiple_tracks_rejected(self):
        user = User.objects.create_user(
            username="member2-771", email="member2771@example.com",
            password="pass123", first_name="Mem", last_name="Two",
        )
        self.client.force_authenticate(user=user)
        payload = {**self.base_payload, "email": user.email, "track_applications": [
            {"track_id": self.track_a.id}, {"track_id": self.track_b.id}]}
        with patch(
            "events.views.EventViewSet._get_missing_lead_gen_fields",
            return_value=(True, {}),
        ):
            resp = self.client.post(f"/api/events/{self.event.id}/apply/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(EventApplication.objects.filter(email=user.email).exists())

    def test_duplicate_track_id_rejected(self):
        payload = {**self.base_payload, "track_applications": [
            {"track_id": self.track_a.id}, {"track_id": self.track_a.id}]}
        resp = self.client.post(f"/api/events/{self.event.id}/apply/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self._assert_no_records()

    def test_mixed_legacy_and_modern_payload_rejected(self):
        payload = {**self.base_payload, "track_id": self.track_a.id,
                   "track_applications": [{"track_id": self.track_b.id}]}
        resp = self.client.post(f"/api/events/{self.event.id}/apply/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("one selection format", resp.data["detail"].lower())
        self._assert_no_records()

    def test_no_track_selected_still_rejected(self):
        # Two open tracks, nothing selected -> existing "please select" 400.
        resp = self.client.post(
            f"/api/events/{self.event.id}/apply/", dict(self.base_payload), format="json"
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self._assert_no_records()

    def test_invalid_track_id_rejected(self):
        payload = {**self.base_payload, "track_applications": [{"track_id": 999999}]}
        resp = self.client.post(f"/api/events/{self.event.id}/apply/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self._assert_no_records()


class HistoricalMultiTrackCompatibilityTests(TestCase):
    """A multi-track application created before the restriction must remain
    retrievable, listed in the review queue, and decidable per track."""

    def setUp(self):
        self.client = APIClient()
        self.manager = User.objects.create_user(
            username="mgr-771", email="mgr771@example.com",
            password="pass123", is_staff=True, is_superuser=True,
        )
        self.community = Community.objects.create(
            name="IPDT771 Hist Community", slug="ipdt771-hist", owner=self.manager
        )
        self.event = Event.objects.create(
            community=self.community,
            title="IPDT771 Hist Event",
            slug="ipdt771-hist-event",
            registration_type="apply",
            status="published",
            created_by=self.manager,
        )
        _grant_imaa_visibility(self.event)
        self.track1 = EventApplicationTrack.objects.create(
            event=self.event, key="hist-1", label="Hist Track 1",
            status="open", is_active=True,
            enabled_submission_modes=["self_submission"],
        )
        self.track2 = EventApplicationTrack.objects.create(
            event=self.event, key="hist-2", label="Hist Track 2",
            status="open", is_active=True,
            enabled_submission_modes=["self_submission"],
        )
        # Acceptance requires an active pricing tier on the track.
        self.tier1 = TrackPricingTier.objects.create(
            track=self.track1, key="tier-free", label="Free",
            price=0, is_active=True, is_default=True,
        )
        # Simulate a legacy two-track application (created directly, as before
        # the restriction existed). This is exactly what historical rows look like.
        self.app = EventApplication.objects.create(
            event=self.event,
            first_name="Old", last_name="Applicant",
            email="old@example.com",
            selected_tracks=[self.track1.id, self.track2.id],
        )
        self.ta1 = EventApplicationTrackApplication.objects.create(
            application=self.app, track=self.track1,
            submission_mode="self_submission", status="pending",
            form_answers={"q1": "answer-one"},
        )
        self.ta2 = EventApplicationTrackApplication.objects.create(
            application=self.app, track=self.track2,
            submission_mode="self_submission", status="pending",
            form_answers={"q2": "answer-two"},
        )

    def test_historical_application_retains_both_tracks(self):
        self.assertEqual(self.app.track_applications.count(), 2)

    def test_review_queue_lists_both_tracks(self):
        self.client.force_authenticate(user=self.manager)
        resp = self.client.get(f"/api/events/{self.event.id}/review-queue/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        results = resp.data.get("results", resp.data)
        track_ids = {row["track_id"] for row in results}
        self.assertIn(self.track1.id, track_ids)
        self.assertIn(self.track2.id, track_ids)

    def test_each_historical_track_can_be_decided_independently(self):
        self.client.force_authenticate(user=self.manager)
        accept = self.client.post(
            f"/api/events/{self.event.id}/applications/{self.app.id}/"
            f"track-applications/{self.ta1.id}/accept/",
            {}, format="json",
        )
        self.assertIn(accept.status_code, (status.HTTP_200_OK, status.HTTP_201_CREATED))
        decline = self.client.post(
            f"/api/events/{self.event.id}/applications/{self.app.id}/"
            f"track-applications/{self.ta2.id}/decline/",
            {}, format="json",
        )
        self.assertIn(decline.status_code, (status.HTTP_200_OK, status.HTTP_201_CREATED))
        self.ta1.refresh_from_db()
        self.ta2.refresh_from_db()
        self.assertEqual(self.ta1.status, "accepted")
        self.assertEqual(self.ta2.status, "declined")
        # Answers preserved on both child rows.
        self.assertEqual(self.ta1.form_answers, {"q1": "answer-one"})
        self.assertEqual(self.ta2.form_answers, {"q2": "answer-two"})
