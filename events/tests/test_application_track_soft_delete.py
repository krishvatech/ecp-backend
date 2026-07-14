from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

from community.models import Community
from events.models import (
    Event,
    EventApplication,
    EventApplicationTrack,
    EventApplicationTrackApplication,
    TrackPricingTier,
)


class ApplicationTrackSoftDeleteTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="track-owner",
            email="track-owner@example.com",
            password="Password123!",
        )
        self.other_user = User.objects.create_user(
            username="other-user",
            email="other@example.com",
            password="Password123!",
        )
        self.community = Community.objects.create(
            name="Track Test Community",
            slug="track-test-community",
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Application Track Test Event",
            slug="application-track-test-event",
            created_by=self.owner,
            registration_type="apply",
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key="speaker",
            label="Speaker Application",
            status="open",
            is_active=True,
            enabled_submission_modes=["self_submission"],
            role_mappings_on_acceptance=["speaker"],
        )
        self.tier = TrackPricingTier.objects.create(
            track=self.track,
            key="standard",
            label="Standard",
            price="100.00",
            currency="USD",
            is_default=True,
            is_active=True,
        )
        self.application = EventApplication.objects.create(
            event=self.event,
            user=self.other_user,
            first_name="Other",
            last_name="User",
            email="other@example.com",
            application_track=self.track,
        )
        self.track_application = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track,
            tier_preference=self.tier,
            accepted_tier=self.tier,
            status=EventApplicationTrackApplication.STATUS_ACCEPTED,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.owner)

    def test_delete_track_deactivates_and_preserves_history(self):
        response = self.client.delete(
            f"/api/events/{self.event.id}/application-tracks/{self.track.id}/",
            {"reason": "Created with the wrong configuration"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["code"], "application_track_soft_deleted")

        self.track.refresh_from_db()
        self.assertFalse(self.track.is_active)
        self.assertEqual(self.track.status, "closed")
        self.assertEqual(self.track.status_before_deactivation, "open")
        self.assertEqual(self.track.deactivated_by_id, self.owner.id)
        self.assertIsNotNone(self.track.deactivated_at)

        self.assertTrue(EventApplication.objects.filter(pk=self.application.pk).exists())
        self.assertTrue(
            EventApplicationTrackApplication.objects.filter(pk=self.track_application.pk).exists()
        )
        self.assertTrue(TrackPricingTier.objects.filter(pk=self.tier.pk).exists())

        list_response = self.client.get(
            f"/api/events/{self.event.id}/application-tracks/"
        )
        self.assertEqual(list_response.status_code, 200)
        self.assertNotIn(self.track.id, [item["id"] for item in list_response.data])

    def test_non_manager_cannot_delete_track(self):
        self.client.force_authenticate(self.other_user)
        response = self.client.delete(
            f"/api/events/{self.event.id}/application-tracks/{self.track.id}/"
        )
        self.assertEqual(response.status_code, 403)
        self.track.refresh_from_db()
        self.assertTrue(self.track.is_active)

    def test_delete_tier_deactivates_and_preserves_application_links(self):
        response = self.client.delete(
            f"/api/events/{self.event.id}/application-tracks/{self.track.id}/pricing-tiers/{self.tier.id}/",
            {"reason": "No longer offered"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["code"], "pricing_tier_soft_deleted")

        self.tier.refresh_from_db()
        self.assertFalse(self.tier.is_active)
        self.assertFalse(self.tier.is_default)
        self.assertTrue(self.tier.was_default_before_deactivation)
        self.assertEqual(self.tier.deactivated_by_id, self.owner.id)
        self.assertIsNotNone(self.tier.deactivated_at)

        self.track_application.refresh_from_db()
        self.assertEqual(self.track_application.tier_preference_id, self.tier.id)
        self.assertEqual(self.track_application.accepted_tier_id, self.tier.id)

        list_response = self.client.get(
            f"/api/events/{self.event.id}/application-tracks/{self.track.id}/pricing-tiers/"
        )
        self.assertEqual(list_response.status_code, 200)
        self.assertNotIn(self.tier.id, [item["id"] for item in list_response.data])
