from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

from users.models import UserEmailAlias, UserProfile


class AccountLoginStatusTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="blocked-member",
            email="blocked@example.com",
            password="ValidPassword123!",
            is_active=False,
        )
        profile = self.user.profile
        profile.profile_status = UserProfile.PROFILE_STATUS_DELETED
        profile.profile_status_reason = "Deactivated by admin"
        profile.save(update_fields=["profile_status", "profile_status_reason"])

    def test_deactivated_email_returns_specific_terminal_message(self):
        response = self.client.post(
            "/api/auth/login-status/",
            {"identifier": "BLOCKED@example.com"},
            format="json",
        )

        self.assertEqual(response.status_code, 403, response.content)
        self.assertFalse(response.data["can_login"])
        self.assertEqual(response.data["code"], "account_deleted")
        self.assertIn("deactivated by an administrator", response.data["detail"])
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_verified_alias_also_resolves_blocked_user(self):
        UserEmailAlias.objects.create(
            user=self.user,
            email="alias@example.com",
            verified=True,
        )

        response = self.client.post(
            "/api/auth/login-status/",
            {"identifier": "alias@example.com"},
            format="json",
        )

        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(response.data["code"], "account_deleted")

    def test_active_and_unknown_identifiers_have_same_public_result(self):
        User.objects.create_user(
            username="active-member",
            email="active@example.com",
            password="ValidPassword123!",
            is_active=True,
        )

        active = self.client.post(
            "/api/auth/login-status/",
            {"identifier": "active@example.com"},
            format="json",
        )
        unknown = self.client.post(
            "/api/auth/login-status/",
            {"identifier": "unknown@example.com"},
            format="json",
        )

        self.assertEqual(active.status_code, 200)
        self.assertEqual(unknown.status_code, 200)
        self.assertEqual(active.data, {"can_login": True})
        self.assertEqual(unknown.data, {"can_login": True})
