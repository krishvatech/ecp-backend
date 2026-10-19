"""IPDT-773 — IssueSignupProofView is inert unless the prototype flag is on."""
from unittest.mock import patch

from django.test import override_settings
from rest_framework.test import APITestCase

from users.captcha import TurnstileResult


class SignupProofEndpointTests(APITestCase):
    URL = "/api/auth/signup-proof/"

    @override_settings(CAPTCHA_PROTOTYPE_ENABLED=False)
    def test_disabled_by_default_returns_404(self):
        resp = self.client.post(self.URL, {"token": "t", "email": "a@example.com"}, format="json")
        self.assertEqual(resp.status_code, 404)

    @override_settings(CAPTCHA_PROTOTYPE_ENABLED=True, TURNSTILE_SECRET="s", SIGNUP_PROOF_SECRET="k")
    def test_enabled_issues_proof_on_valid_captcha(self):
        with patch("users.captcha.verify_turnstile", return_value=TurnstileResult(True, hostname="localhost")):
            resp = self.client.post(self.URL, {"token": "good", "email": "a@example.com"}, format="json")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("proof", resp.data)

    @override_settings(CAPTCHA_PROTOTYPE_ENABLED=True, TURNSTILE_SECRET="s", SIGNUP_PROOF_SECRET="k")
    def test_enabled_rejects_bad_captcha(self):
        with patch("users.captcha.verify_turnstile", return_value=TurnstileResult(False, reason="rejected")):
            resp = self.client.post(self.URL, {"token": "bad", "email": "a@example.com"}, format="json")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data.get("detail"), "captcha_failed")

    @override_settings(CAPTCHA_PROTOTYPE_ENABLED=True)
    def test_enabled_requires_email(self):
        resp = self.client.post(self.URL, {"token": "good"}, format="json")
        self.assertEqual(resp.status_code, 400)

    @override_settings(CAPTCHA_PROTOTYPE_ENABLED=True, TURNSTILE_SECRET="s", SIGNUP_PROOF_SECRET="")
    def test_enabled_without_proof_secret_fails_closed(self):
        # Valid CAPTCHA but no dedicated signing secret -> 503, never an insecure proof.
        with patch("users.captcha.verify_turnstile", return_value=TurnstileResult(True)):
            resp = self.client.post(self.URL, {"token": "good", "email": "a@example.com"}, format="json")
        self.assertEqual(resp.status_code, 503)
        self.assertNotIn("proof", resp.data)
