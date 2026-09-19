from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.models import MauticIdentityAuditLog, MauticUserConnection


User = get_user_model()


class MarketingAuditAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("newsletter-admin-marketing-audit")
        MauticIdentityAuditLog.objects.all().delete()
        self.mapped_superuser = User.objects.create_superuser(
            username="mapped-admin",
            email="mapped@example.test",
            password="pass",
        )
        self.unmapped_superuser = User.objects.create_superuser(
            username="unmapped-admin",
            email="unmapped@example.test",
            password="pass",
        )
        self.staff = User.objects.create_user(
            username="staff-user",
            email="staff@example.test",
            password="pass",
            is_staff=True,
        )
        self.normal = User.objects.create_user(
            username="normal-user",
            email="normal@example.test",
            password="pass",
        )
        self.inactive = User.objects.create_superuser(
            username="inactive-admin",
            email="inactive@example.test",
            password="pass",
        )
        self.inactive.is_active = False
        self.inactive.save(update_fields=["is_active"])

        MauticUserConnection.objects.create(
            user=self.mapped_superuser,
            mautic_user_id=6,
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
        )

        now = timezone.now()
        self.success = self._audit(
            actor=self.mapped_superuser,
            mautic_user_id=6,
            action="segment.update",
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            auth_mode="asserted_user",
            correlation_id="corr-segment-success",
            assertion_jti="jti-segment-success",
            created_at=now - timezone.timedelta(minutes=5),
        )
        self.denied = self._audit(
            actor=self.unmapped_superuser,
            mautic_user_id=7,
            action="stage.create",
            status=MauticIdentityAuditLog.Status.DENIED,
            auth_mode="asserted_user",
            correlation_id="corr-stage-denied",
            assertion_jti="jti-stage-denied",
            error_code="mautic_permission_denied",
            detail="MauticBridgeRejectedError",
            created_at=now - timezone.timedelta(minutes=3),
        )
        self.failed = self._audit(
            actor=None,
            mautic_user_id=None,
            action="newsletter.test_send",
            status=MauticIdentityAuditLog.Status.FAILED,
            auth_mode="service_account",
            correlation_id="corr-send-failed",
            assertion_jti="",
            error_code="mautic_unavailable",
            detail="TemporaryMauticError",
            created_at=now - timezone.timedelta(minutes=1),
        )
        self.unknown = self._audit(
            actor=self.mapped_superuser,
            mautic_user_id=None,
            action="future.operation",
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            auth_mode="service_account",
            correlation_id="corr-future",
            created_at=now,
        )

    def _audit(self, *, actor, created_at, **fields):
        entry = MauticIdentityAuditLog.objects.create(
            ecp_user=actor,
            ecp_user_label=actor.get_username() if actor else "system",
            resource="segment",
            resource_id="22",
            **fields,
        )
        MauticIdentityAuditLog.objects.filter(pk=entry.pk).update(created_at=created_at)
        entry.refresh_from_db()
        return entry

    def _get(self, user=None, params=None):
        self.client.force_authenticate(user=user)
        return self.client.get(self.url, params or {})

    def test_mapped_active_superuser_can_list_audit(self):
        response = self._get(self.mapped_superuser)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 4)

    def test_unmapped_active_superuser_can_list_audit(self):
        response = self._get(self.unmapped_superuser)
        self.assertEqual(response.status_code, 200)

    def test_staff_normal_anonymous_and_inactive_users_are_denied(self):
        for user in (self.staff, self.normal, self.inactive):
            response = self._get(user)
            self.assertEqual(response.status_code, 403)

        self.client.force_authenticate(user=None)
        response = self.client.get(self.url)
        self.assertIn(response.status_code, (401, 403))

    def test_pagination_and_newest_first_ordering(self):
        response = self._get(self.mapped_superuser, {"page_size": 2})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 4)
        self.assertEqual(response.data["page_size"], 2)
        self.assertEqual(response.data["results"][0]["id"], self.unknown.id)
        self.assertEqual(response.data["results"][1]["id"], self.failed.id)

    def test_filters(self):
        cases = [
            ({"ecp_user_id": self.mapped_superuser.id}, {self.success.id, self.unknown.id}),
            ({"mautic_user_id": 7}, {self.denied.id}),
            ({"action": "segment.update"}, {self.success.id}),
            ({"auth_mode": "service_account"}, {self.failed.id, self.unknown.id}),
            ({"status": "denied"}, {self.denied.id}),
            ({"domain": "segments"}, {self.success.id}),
            ({"search": "corr-stage"}, {self.denied.id}),
            ({"search": "jti-segment-success"}, {self.success.id}),
            ({"search": "unmapped-admin"}, {self.denied.id}),
        ]
        for params, expected_ids in cases:
            response = self._get(self.mapped_superuser, params)
            self.assertEqual(response.status_code, 200, params)
            self.assertEqual(
                {row["id"] for row in response.data["results"]},
                expected_ids,
                params,
            )

    def test_date_filters(self):
        after_success = (self.success.created_at + timezone.timedelta(seconds=1)).isoformat()
        response = self._get(self.mapped_superuser, {"date_from": after_success})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.success.id, {row["id"] for row in response.data["results"]})

        before_failed = (self.failed.created_at - timezone.timedelta(seconds=1)).isoformat()
        response = self._get(self.mapped_superuser, {"date_to": before_failed})
        self.assertEqual(response.status_code, 200)
        self.assertEqual({row["id"] for row in response.data["results"]}, {self.success.id, self.denied.id})

    def test_summary_counts_reflect_full_filtered_dataset_not_page(self):
        response = self._get(self.mapped_superuser, {"page_size": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["summary"]["actions"], 4)
        self.assertEqual(response.data["summary"]["succeeded"], 2)
        self.assertEqual(response.data["summary"]["denied"], 1)
        self.assertEqual(response.data["summary"]["failed"], 1)
        self.assertEqual(response.data["summary"]["asserted_user"], 2)
        self.assertEqual(response.data["summary"]["service_account"], 2)
        self.assertEqual(len(response.data["results"]), 1)

    def test_serializes_nulls_denied_failed_unknown_and_no_secrets(self):
        response = self._get(self.mapped_superuser, {"page_size": 10})
        self.assertEqual(response.status_code, 200)
        rows = {row["id"]: row for row in response.data["results"]}

        self.assertEqual(rows[self.failed.id]["mautic_user"], None)
        self.assertEqual(rows[self.failed.id]["assertion_jti"], "")
        self.assertEqual(rows[self.failed.id]["error_code"], "mautic_unavailable")
        self.assertEqual(rows[self.denied.id]["status"], "denied")
        self.assertEqual(rows[self.unknown.id]["domain"], "Other")

        payload = str(response.data).lower()
        for secret_word in ["authorization", "bearer", "private_key", "password", "raw assertion"]:
            self.assertNotIn(secret_word, payload)

    def test_deleted_actor_does_not_break_list(self):
        deleted_id = self.unmapped_superuser.id
        self.unmapped_superuser.delete()

        response = self._get(self.mapped_superuser, {"search": "unmapped-admin"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        actor = response.data["results"][0]["ecp_user"]
        self.assertTrue(actor["is_deleted"])
        self.assertIsNone(actor["id"])
        self.assertEqual(actor["label"], "unmapped-admin")

    def test_invalid_filters_return_400(self):
        for params in [
            {"status": "pending"},
            {"action": "nope"},
            {"auth_mode": "magic"},
            {"domain": "unknown"},
            {"ecp_user_id": "abc"},
            {"date_from": "not-a-date"},
        ]:
            response = self._get(self.mapped_superuser, params)
            self.assertEqual(response.status_code, 400, params)
