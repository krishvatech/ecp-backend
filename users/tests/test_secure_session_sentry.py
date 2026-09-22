"""
Sentry redaction tests for secure-session credentials.

Nothing here reaches the real Sentry service: the unit tests call the sanitizer
directly, and the end-to-end tests initialize a client whose transport only
records envelopes in memory (and the previous client is restored afterwards).
"""

import copy
import json
from unittest import mock

import sentry_sdk
from django.test import SimpleTestCase
from rest_framework.test import APIClient
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.transport import Transport

from ecp_backend.sentry_scrubbing import (
    REDACTED,
    SensitiveValues,
    before_send,
    before_send_transaction,
    protect_current_request,
    sanitize_event,
)
from users import secure_session as svc
from users.models import CognitoSecureSession
from users.tests.test_secure_session import (
    COOKIE,
    ESTABLISH,
    REFRESH,
    SecureSessionTestBase,
    make_cognito_token,
)

SECRET = "TEST_REFRESH_TOKEN_DO_NOT_LEAK_12345"
LONG_SECRET = SECRET + "-" + "q" * 200  # longer than Sentry's frame-var repr trimming


def _event_with_secret(secret):
    return {
        "request": {
            "headers": {
                "Authorization": f"Bearer {secret}",
                "Cookie": f"{COOKIE}={secret}; other=1",
                "X-CSRFToken": "csrf-value",
                "User-Agent": "tests",
            },
            "cookies": {COOKIE: secret, "unrelated": "keep-me"},
            "data": {
                "refresh_token": secret,
                "email": "member@example.com",
                "nested": {"auth": {"refresh_token": secret}, "list": [{"idToken": secret}]},
            },
            "query_string": f"refresh_token={secret}&page=2",
        },
        "exception": {
            "values": [
                {
                    "type": "RuntimeError",
                    "value": f"failed with {secret}",
                    "stacktrace": {
                        "frames": [
                            {
                                "function": "post",
                                "vars": {
                                    "refresh_token": f"'{secret}'",
                                    "params": {"REFRESH_TOKEN": f"'{secret}'"},
                                    "body": f"'{{\"AuthParameters\": {{\"REFRESH_TOKEN\": \"{secret}\"}}}}'",
                                    "truncated": f"'{secret[:40]}...'",
                                    "count": "3",
                                },
                            }
                        ]
                    },
                }
            ]
        },
        "breadcrumbs": {"values": [{"message": f"payload {{\"refresh_token\": \"{secret}\"}}"}]},
        "extra": {"raw": f"Bearer {secret}", "handle": secret},
    }


class SentrySanitizerUnitTests(SimpleTestCase):
    def test_registered_secret_never_survives_anywhere(self):
        sensitive = SensitiveValues()
        sensitive.add(LONG_SECRET)
        event = before_send(_event_with_secret(LONG_SECRET), {"_ecp_sensitive_values": sensitive})
        dumped = json.dumps(event)
        self.assertNotIn(SECRET, dumped)
        self.assertNotIn(LONG_SECRET[:24], dumped)
        self.assertIn(REDACTED, dumped)

    def test_keyed_and_patterned_secrets_redacted_without_registration(self):
        event = before_send(_event_with_secret(SECRET), {})
        request = event["request"]
        self.assertEqual(request["data"]["refresh_token"], REDACTED)
        self.assertEqual(request["data"]["nested"]["auth"]["refresh_token"], REDACTED)
        self.assertEqual(request["data"]["nested"]["list"][0]["idToken"], REDACTED)
        self.assertEqual(request["cookies"][COOKIE], REDACTED)
        self.assertNotIn(SECRET, request["query_string"])
        frame_vars = event["exception"]["values"][0]["stacktrace"]["frames"][0]["vars"]
        self.assertEqual(frame_vars["refresh_token"], REDACTED)
        self.assertEqual(frame_vars["params"]["REFRESH_TOKEN"], REDACTED)
        self.assertNotIn(SECRET, event["breadcrumbs"]["values"][0]["message"])
        self.assertNotIn(SECRET, event["extra"]["raw"])
        self.assertEqual(event["extra"]["handle"], REDACTED)

    def test_existing_header_filtering_preserved(self):
        event = before_send(_event_with_secret(SECRET), {})
        headers = event["request"]["headers"]
        self.assertEqual(headers["Authorization"], "[Filtered]")
        self.assertEqual(headers["Cookie"], "[Filtered]")
        self.assertEqual(headers["X-CSRFToken"], "[Filtered]")
        self.assertEqual(headers["User-Agent"], "tests")

    def test_unrelated_data_untouched(self):
        event = before_send(_event_with_secret(SECRET), {})
        self.assertEqual(event["request"]["data"]["email"], "member@example.com")
        self.assertEqual(event["request"]["cookies"]["unrelated"], "keep-me")
        self.assertIn("page=2", event["request"]["query_string"])
        self.assertEqual(event["exception"]["values"][0]["stacktrace"]["frames"][0]["vars"]["count"], "3")
        plain = {"message": "user 5 updated profile", "extra": {"status": "ok"}}
        self.assertEqual(sanitize_event(copy.deepcopy(plain)), plain)

    def test_transaction_events_are_sanitized(self):
        sensitive = SensitiveValues()
        sensitive.add(LONG_SECRET)
        transaction = {
            "type": "transaction",
            "request": {"data": {"refresh_token": LONG_SECRET}, "headers": {"Authorization": f"Bearer {LONG_SECRET}"}},
            "spans": [{"description": f"POST refresh_token={LONG_SECRET}"}],
        }
        dumped = json.dumps(before_send_transaction(transaction, {"_ecp_sensitive_values": sensitive}))
        self.assertNotIn(SECRET, dumped)

    def test_refresh_result_repr_hides_tokens(self):
        result = svc.RefreshResult(id_token=LONG_SECRET, rotated_refresh_token=LONG_SECRET)
        self.assertNotIn(SECRET, repr(result))
        self.assertNotIn(SECRET, str(result))

    def test_protection_is_inert_without_active_sentry_client(self):
        with mock.patch.object(sentry_sdk, "get_isolation_scope") as get_scope:
            with mock.patch.object(sentry_sdk, "get_client") as get_client:
                get_client.return_value.is_active.return_value = False
                protect_current_request()
        get_scope.assert_not_called()


class _MemoryTransport(Transport):
    def __init__(self):
        super().__init__(options=None)
        self.envelopes = []

    def capture_envelope(self, envelope):
        self.envelopes.append(envelope)


class SentryEndToEndRedactionTests(SecureSessionTestBase):
    """Unhandled exceptions inside the views, captured by the real Django integration."""

    def setUp(self):
        super().setUp()
        self.refresh_token = LONG_SECRET
        self.transport = _MemoryTransport()
        previous_client = sentry_sdk.get_client()
        sentry_sdk.init(
            dsn="https://public@o0.ingest.invalid/0",
            transport=self.transport,
            default_integrations=False,
            integrations=[DjangoIntegration()],
            before_send=before_send,
            before_send_transaction=before_send_transaction,
            send_default_pii=False,
        )

        def restore():
            sentry_sdk.get_client().close()
            sentry_sdk.get_global_scope().set_client(previous_client if previous_client.is_active() else None)

        self.addCleanup(restore)
        self.client = APIClient(raise_request_exception=False)

    def captured_bytes(self):
        sentry_sdk.flush()
        return b"".join(envelope.serialize() for envelope in self.transport.envelopes)

    def assert_event_captured_without(self, *secrets):
        data = self.captured_bytes()
        self.assertTrue(self.transport.envelopes, "expected Sentry to capture the unhandled exception")
        self.assertIn(b"RuntimeError", data)
        for secret in secrets:
            self.assertNotIn(secret.encode(), data)
            self.assertNotIn(secret[:24].encode(), data)
        self.assertNotIn(SECRET.encode(), data)

    def test_establish_crash_does_not_leak_refresh_token_bearer_or_handle(self):
        bearer = make_cognito_token(self.sub)
        handles = []
        real_new_handle = svc.new_session_handle

        def record_handle():
            handle = real_new_handle()
            handles.append(handle)
            return handle

        with sentry_sdk.isolation_scope(), \
                mock.patch("users.secure_session.new_session_handle", side_effect=record_handle), \
                mock.patch.object(CognitoSecureSession.objects, "create", side_effect=RuntimeError("database down")):
            response = self.establish(bearer=bearer)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(len(handles), 1)
        self.assert_event_captured_without(LONG_SECRET, bearer, self.new_id_token, handles[0])

    def test_refresh_crash_does_not_leak_decrypted_token_or_cookie(self):
        handle = "cookie-handle-" + "h" * 40
        self.make_session(handle=handle)
        with sentry_sdk.isolation_scope(), \
                mock.patch("users.secure_session_views.svc.verify_id_token", side_effect=RuntimeError("jwks exploded")):
            response = self.client.post(REFRESH, **self.headers())

        self.assertEqual(response.status_code, 500)
        self.assert_event_captured_without(LONG_SECRET, handle, self.new_id_token)
