"""IPDT-772: /auth/check-email/ must detect accounts that exist in Cognito
even when the Django user row has not been created yet (users are created
lazily on first authenticated login). A result that cannot be confirmed against
Cognito must report `indeterminate` rather than a false "new account".
"""
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import override_settings
from rest_framework.test import APITestCase


class CheckEmailCognitoTests(APITestCase):
    URL = "/api/auth/check-email/"

    def test_requires_email_param(self):
        resp = self.client.get(self.URL)
        self.assertEqual(resp.status_code, 400)

    def test_django_user_exists_short_circuits(self):
        User.objects.create_user(username="u1", email="member@example.com", password="x")
        # Even if Cognito would error, a Django match is authoritative.
        with patch(
            "users.views.CheckEmailExistsView._cognito_has_email",
            return_value=None,
        ) as mock_cog:
            resp = self.client.get(self.URL, {"email": "MEMBER@example.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data["exists"])
        self.assertFalse(resp.data["indeterminate"])
        mock_cog.assert_not_called()

    def test_cognito_only_account_is_detected(self):
        with patch(
            "users.views.CheckEmailExistsView._cognito_has_email",
            return_value=True,
        ):
            resp = self.client.get(self.URL, {"email": "cognito-only@example.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data["exists"])
        self.assertFalse(resp.data["indeterminate"])

    def test_genuinely_new_email(self):
        with patch(
            "users.views.CheckEmailExistsView._cognito_has_email",
            return_value=False,
        ):
            resp = self.client.get(self.URL, {"email": "brand-new@example.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.data["exists"])
        self.assertFalse(resp.data["indeterminate"])

    def test_cognito_unavailable_is_indeterminate_not_new(self):
        with patch(
            "users.views.CheckEmailExistsView._cognito_has_email",
            return_value=None,
        ):
            resp = self.client.get(self.URL, {"email": "unknown@example.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.data["exists"])
        self.assertTrue(resp.data["indeterminate"])

    @override_settings(COGNITO_REGION="", COGNITO_USER_POOL_ID="")
    def test_cognito_lookup_returns_none_when_unconfigured(self):
        # Exercises the real helper: no region/pool -> cannot confirm -> None,
        # so the endpoint fails closed with indeterminate=True (not "new").
        resp = self.client.get(self.URL, {"email": "noconfig@example.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.data["exists"])
        self.assertTrue(resp.data["indeterminate"])

    def test_quote_in_email_is_not_sent_to_cognito_filter(self):
        # Filter-injection guard: a quote yields a safe False from the helper.
        from users.views import CheckEmailExistsView
        with override_settings(COGNITO_REGION="eu-central-1", COGNITO_USER_POOL_ID="pool"):
            self.assertFalse(CheckEmailExistsView()._cognito_has_email('a"b@example.com'))
