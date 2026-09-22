from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient


@override_settings(
    COGNITO_REGION="eu-central-1",
    COGNITO_USER_POOL_ID="eu-central-1_test",
    COGNITO_CLIENT_ID="test-client",
    WP_IMAA_ALLOW_EMAIL_ONLY_SYNC=False,
)
class SecureSessionWordPressCompatibilityTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="wp-secure-member",
            email="wp-secure@example.com",
            password="OldPassword123!",
            is_active=True,
        )

    def _sync_service(self):
        wp_payload = {
            "id": 701,
            "email": self.user.email,
            "slug": self.user.username,
            "username": self.user.username,
            "name": "Secure Member",
        }
        return SimpleNamespace(
            wp_client=SimpleNamespace(
                authenticate_user=Mock(return_value=wp_payload),
                get_user_by_email=Mock(return_value=None),
            ),
            sync_user_from_wordpress=Mock(return_value=(self.user, False)),
        )

    @override_settings(SECURE_AUTH_SESSION_ENABLED=True)
    @patch("users.wordpress_webhook.update_cognito_user_email")
    @patch("users.wordpress_webhook.set_cognito_user_password", return_value=False)
    @patch("users.wordpress_webhook.get_cognito_tokens_admin", return_value={})
    @patch("users.wordpress_webhook.get_profile_sync_service")
    def test_secure_mode_never_downgrades_wordpress_login_to_simplejwt(
        self,
        get_sync_service,
        get_cognito_tokens,
        _set_cognito_password,
        _update_cognito_email,
    ):
        get_sync_service.return_value = self._sync_service()

        response = APIClient().post(
            "/api/auth/wordpress/sync/",
            {"email": self.user.email, "password": "ValidPassword123!"},
            format="json",
        )

        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(response.data["code"], "cognito_session_unavailable")
        self.assertNotIn("access_token", response.data)
        self.assertNotIn("refresh_token", response.data)
        get_cognito_tokens.assert_called_once_with(self.user.username)

    @override_settings(SECURE_AUTH_SESSION_ENABLED=False)
    @patch("users.wordpress_webhook.update_cognito_user_email")
    @patch("users.wordpress_webhook.set_cognito_user_password", return_value=False)
    @patch("users.wordpress_webhook.get_cognito_tokens_admin", return_value={})
    @patch("users.wordpress_webhook.get_profile_sync_service")
    def test_legacy_mode_keeps_existing_simplejwt_fallback(
        self,
        get_sync_service,
        get_cognito_tokens,
        _set_cognito_password,
        _update_cognito_email,
    ):
        get_sync_service.return_value = self._sync_service()

        response = APIClient().post(
            "/api/auth/wordpress/sync/",
            {"email": self.user.email, "password": "ValidPassword123!"},
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.data.get("access_token"))
        self.assertTrue(response.data.get("id_token"))
        self.assertTrue(response.data.get("refresh_token"))
        get_cognito_tokens.assert_called_once_with(self.user.username)
