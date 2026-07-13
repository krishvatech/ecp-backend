from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIClient

from users.models import UserProfile
from users.serializers import EmailTokenObtainPairSerializer


@override_settings(COGNITO_REGION="", COGNITO_USER_POOL_ID="", COGNITO_CLIENT_ID="")
class DeactivatedLoginFeedbackTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="deactivated-member",
            email="deactivated@example.com",
            password="ValidPassword123!",
            is_active=False,
        )
        self.profile = self.user.profile
        self.profile.profile_status = UserProfile.PROFILE_STATUS_DELETED
        self.profile.profile_status_reason = "Deactivated from admin UI"
        self.profile.save(
            update_fields=["profile_status", "profile_status_reason"]
        )

    def test_email_token_serializer_returns_specific_admin_deactivation_error(self):
        serializer = EmailTokenObtainPairSerializer(
            data={
                "email": self.user.email,
                "password": "ValidPassword123!",
            }
        )

        with self.assertRaises(AuthenticationFailed) as raised:
            serializer.is_valid(raise_exception=True)

        detail = raised.exception.detail
        self.assertEqual(str(detail["code"]), "account_deleted")
        self.assertEqual(str(detail["profile_status"]), "deleted")
        self.assertIn("deactivated by an administrator", str(detail["detail"]))

    @patch("users.wordpress_webhook.set_cognito_user_password")
    @patch("users.wordpress_webhook.get_cognito_tokens_admin")
    @patch("users.wordpress_webhook.get_profile_sync_service")
    def test_wordpress_fallback_returns_403_without_issuing_tokens(
        self,
        get_sync_service,
        get_cognito_tokens,
        set_cognito_password,
    ):
        wp_client = SimpleNamespace(
            authenticate_user=Mock(
                return_value={
                    "id": 501,
                    "email": self.user.email,
                    "slug": self.user.username,
                    "name": "Deactivated Member",
                }
            ),
            get_user_by_email=Mock(return_value=None),
        )
        sync_service = SimpleNamespace(
            wp_client=wp_client,
            sync_user_from_wordpress=Mock(return_value=(self.user, False)),
        )
        get_sync_service.return_value = sync_service

        response = APIClient().post(
            "/api/auth/wordpress/sync/",
            {
                "email": self.user.email,
                "password": "ValidPassword123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(response.data["code"], "account_deleted")
        self.assertEqual(response.data["profile_status"], "deleted")
        self.assertIn("deactivated by an administrator", response.data["detail"])
        self.assertNotIn("access_token", response.data)
        get_cognito_tokens.assert_not_called()
        set_cognito_password.assert_not_called()
