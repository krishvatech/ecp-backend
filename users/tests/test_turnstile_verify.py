"""IPDT-773 — tests for the Turnstile Siteverify helper (mocked HTTP)."""
from unittest.mock import patch

from django.test import TestCase, override_settings

from users.captcha import verify_turnstile


class _FakeResp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("HTTP error")

    def json(self):
        return self._payload


@override_settings(TURNSTILE_SECRET="test-secret")
class TurnstileVerifyTests(TestCase):
    def test_valid_token_accepted(self):
        with patch("users.captcha.requests.post", return_value=_FakeResp({"success": True, "hostname": "localhost"})):
            r = verify_turnstile("good-token")
        self.assertTrue(r.success)

    def test_missing_token_rejected(self):
        r = verify_turnstile("")
        self.assertFalse(r.success)
        self.assertEqual(r.reason, "missing_token")

    def test_invalid_token_rejected(self):
        with patch("users.captcha.requests.post",
                   return_value=_FakeResp({"success": False, "error-codes": ["invalid-input-response"]})):
            r = verify_turnstile("bad-token")
        self.assertFalse(r.success)
        self.assertEqual(r.reason, "rejected")

    def test_provider_timeout_fails_closed(self):
        with patch("users.captcha.requests.post", side_effect=Exception("timeout")):
            r = verify_turnstile("whatever")
        self.assertFalse(r.success)
        self.assertEqual(r.reason, "provider_error")

    def test_hostname_mismatch_rejected(self):
        with override_settings(TURNSTILE_EXPECTED_HOSTNAME="connect.example.org"):
            with patch("users.captcha.requests.post",
                       return_value=_FakeResp({"success": True, "hostname": "evil.test"})):
                r = verify_turnstile("good-token")
        self.assertFalse(r.success)
        self.assertEqual(r.reason, "hostname_mismatch")

    @override_settings(TURNSTILE_SECRET="")
    def test_unconfigured_fails_closed(self):
        r = verify_turnstile("good-token")
        self.assertFalse(r.success)
        self.assertEqual(r.reason, "not_configured")

    def test_secret_and_token_never_logged(self):
        # The helper must not emit the raw token, any token substring (prefix
        # or suffix), or the secret at WARNING/INFO.
        token = "ABCDwxyz0123456789TOKENvalue"
        with patch("users.captcha.requests.post", side_effect=Exception("boom")):
            with self.assertLogs("users.captcha", level="INFO") as cm:
                verify_turnstile(token)
        joined = "\n".join(cm.output)
        self.assertNotIn(token, joined)
        self.assertNotIn(token[:4], joined)   # no prefix
        self.assertNotIn(token[-4:], joined)  # no suffix
        self.assertNotIn("test-secret", joined)

    def test_rejected_log_contains_no_token_substring(self):
        token = "PREFIXmiddleSUFFIX1234567890"
        with patch("users.captcha.requests.post",
                   return_value=_FakeResp({"success": False, "error-codes": ["x"]})):
            with self.assertLogs("users.captcha", level="INFO") as cm:
                verify_turnstile(token)
        joined = "\n".join(cm.output)
        self.assertNotIn(token[:4], joined)
        self.assertNotIn(token[-4:], joined)
