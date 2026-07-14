from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

from community.models import Community
from events.models import (
    Event,
    EventApplicationTrack,
    EventPreApprovalAllowlist,
    EventPreApprovalCode,
)


class PreApprovalSoftDeleteTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="preapproval-owner",
            email="preapproval-owner@example.com",
            password="Password123!",
        )
        self.community = Community.objects.create(
            name="Preapproval Test Community",
            slug="preapproval-test-community",
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Preapproval Soft Delete Event",
            slug="preapproval-soft-delete-event",
            created_by=self.owner,
            registration_type="apply",
            preapproval_code_enabled=True,
            preapproval_allowlist_enabled=True,
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key="speaker",
            label="Speaker",
            status="open",
            is_active=True,
            enabled_submission_modes=["self_submission"],
            role_mappings_on_acceptance=["speaker"],
        )
        self.code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.track,
            submission_mode="self_submission",
            code="SPEAKER123",
            created_by=self.owner,
        )
        self.allowlist_entry = EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.track,
            submission_mode="self_submission",
            first_name="Mittal",
            last_name="Gamit",
            email="gamitmittal9@gmail.com",
            created_by=self.owner,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.owner)

    def test_revoke_code_preserves_row_and_disables_validation(self):
        response = self.client.post(
            f"/api/events/{self.event.id}/preapproval/codes/{self.code.id}/revoke/",
            {},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["soft_deleted"])
        self.assertEqual(response.data["deletion_type"], "soft")

        self.code.refresh_from_db()
        self.assertEqual(self.code.status, EventPreApprovalCode.STATUS_REVOKED)
        self.assertEqual(self.code.revoked_by_id, self.owner.id)
        self.assertIsNotNone(self.code.revoked_at)
        self.assertTrue(EventPreApprovalCode.objects.filter(pk=self.code.pk).exists())

        check_response = self.client.post(
            f"/api/events/{self.event.id}/preapproval/check-code/",
            {
                "code": self.code.code,
                "track_id": self.track.id,
                "submission_mode": "self_submission",
            },
            format="json",
        )
        self.assertEqual(check_response.status_code, 200)
        self.assertFalse(check_response.data["preapproved"])
        self.assertEqual(check_response.data["reason"], "revoked")

    def test_used_code_cannot_have_usage_history_overwritten(self):
        self.code.status = EventPreApprovalCode.STATUS_USED
        self.code.used_by_email = "used@example.com"
        self.code.save(update_fields=["status", "used_by_email"])

        response = self.client.post(
            f"/api/events/{self.event.id}/preapproval/codes/{self.code.id}/revoke/",
            {},
            format="json",
        )

        self.assertEqual(response.status_code, 409)
        self.code.refresh_from_db()
        self.assertEqual(self.code.status, EventPreApprovalCode.STATUS_USED)
        self.assertEqual(self.code.used_by_email, "used@example.com")

    def test_remove_allowlist_preserves_row_and_stops_preapproval(self):
        response = self.client.delete(
            f"/api/events/{self.event.id}/preapproval/allowlist/{self.allowlist_entry.id}/"
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["soft_deleted"])
        self.assertEqual(response.data["deletion_type"], "soft")

        self.allowlist_entry.refresh_from_db()
        self.assertFalse(self.allowlist_entry.is_active)
        self.assertEqual(self.allowlist_entry.removed_by_id, self.owner.id)
        self.assertIsNotNone(self.allowlist_entry.removed_at)
        self.assertTrue(
            EventPreApprovalAllowlist.objects.filter(pk=self.allowlist_entry.pk).exists()
        )

        check_response = self.client.post(
            f"/api/events/{self.event.id}/preapproval/check-email/",
            {
                "email": self.allowlist_entry.email,
                "track_id": self.track.id,
                "submission_mode": "self_submission",
            },
            format="json",
        )
        self.assertEqual(check_response.status_code, 200)
        self.assertFalse(check_response.data["preapproved"])
        self.assertEqual(check_response.data["reason"], "not_found")

    def test_readding_removed_email_restores_same_row(self):
        self.allowlist_entry.is_active = False
        self.allowlist_entry.removed_by = self.owner
        self.allowlist_entry.save(update_fields=["is_active", "removed_by"])

        response = self.client.post(
            f"/api/events/{self.event.id}/preapproval/allowlist/",
            {
                "first_name": "Updated",
                "last_name": "Name",
                "email": self.allowlist_entry.email,
                "track_id": self.track.id,
                "submission_mode": "self_submission",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["restored"])
        self.assertEqual(response.data["id"], self.allowlist_entry.id)
        self.assertEqual(
            EventPreApprovalAllowlist.objects.filter(
                event=self.event,
                track=self.track,
                submission_mode="self_submission",
                email=self.allowlist_entry.email,
            ).count(),
            1,
        )

        self.allowlist_entry.refresh_from_db()
        self.assertTrue(self.allowlist_entry.is_active)
        self.assertIsNone(self.allowlist_entry.removed_by_id)
        self.assertIsNone(self.allowlist_entry.removed_at)
        self.assertEqual(self.allowlist_entry.first_name, "Updated")
