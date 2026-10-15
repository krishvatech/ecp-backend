"""B15: webhook registration verification and delivery evidence in the
Marketing Hub diagnostics response. Read-only: nothing here may change
Mautic's webhook registration, and the secret is never returned."""

import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.tests import mautic_webhook_fixtures as fx
from newsletter.tests.marketing_actors import grant_marketing_access


User = get_user_model()
SECRET = "b15-diagnostics-secret"
RECEIVER = "https://ecp.example.test/api/newsletter/webhooks/mautic/"
ALL_EVENTS = [
    "mautic.email_on_open",
    "mautic.email_on_send",
    "mautic.lead_channel_subscription_changed",
    "mautic.page_on_hit",
]
SETTINGS = {
    "MAUTIC_SYNC_ENABLED": True,
    "MAUTIC_BASE_URL": "https://mautic.example.test",
    "MAUTIC_USERNAME": "api-user",
    "MAUTIC_PASSWORD": "api-password",
    "MAUTIC_WEBHOOK_SECRET": SECRET,
    "MAUTIC_REQUEST_TIMEOUT": 3,
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "b15-diag"}},
}


def hook(url=RECEIVER, *, published=True, secret=SECRET, events=ALL_EVENTS, hook_id=1):
    # Shape of GET /api/hooks entries in Mautic 7.1.3.
    return {
        "id": hook_id,
        "name": "ECP",
        "isPublished": published,
        "webhookUrl": url,
        "secret": secret,
        "eventsOrderbyDir": "",
        "triggers": list(events),
    }


@override_settings(**SETTINGS)
class MauticWebhookDiagnosticsTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="b15-diag-staff", email="b15-diag@example.test", password="pw",
            is_staff=True, is_superuser=True,
        )
        grant_marketing_access(self.staff)
        self.client.force_authenticate(self.staff)
        self.url = reverse("newsletter-admin-mautic-diagnostics")

    def diagnostics(self, client_cls, hooks=None, *, error=None):
        client = client_cls.return_value
        client.health_check.return_value = True
        client.get_marketing_bridge_capabilities.return_value = {"capabilities": []}
        client.get_campaign_builder_capabilities.return_value = {
            "actions": [], "conditions": [], "decisions": [], "connectionRestrictions": {},
        }
        if error is not None:
            client.list_webhooks.side_effect = error
        else:
            client.list_webhooks.return_value = hooks if hooks is not None else []
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        return response

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_registered_hook_with_matching_secret_and_all_events(self, client_cls):
        response = self.diagnostics(client_cls, [hook()])

        webhook = response.data["webhook"]
        self.assertEqual(webhook["registration"], "Registered")
        self.assertIs(webhook["secret_matches"], True)
        self.assertEqual(webhook["registered_events"], ALL_EVENTS)
        self.assertEqual(webhook["missing_events"], [])
        self.assertEqual(webhook["delivery_host"], "ecp.example.test")
        self.assertIs(webhook["delivery_host_private"], False)
        self.assertEqual(webhook["matching_hooks"], 1)
        warnings = " ".join(response.data["diagnostics"]["warnings"])
        for text in ("Not Registered", "Disabled in Mautic", "secret", "not subscribed", "private address"):
            self.assertNotIn(text, warnings)

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_secret_mismatch_is_reported_and_no_secret_is_returned(self, client_cls):
        response = self.diagnostics(client_cls, [hook(secret="mautic-side-secret")])

        self.assertIs(response.data["webhook"]["secret_matches"], False)
        self.assertTrue(any("secret does not match" in w for w in response.data["diagnostics"]["warnings"]))
        body = json.dumps(response.data, default=str)
        self.assertNotIn(SECRET, body)
        self.assertNotIn("mautic-side-secret", body)

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_hooks_for_other_receivers_mean_not_registered(self, client_cls):
        response = self.diagnostics(client_cls, [hook("https://crm.example.test/hooks/in")])

        self.assertEqual(response.data["webhook"]["registration"], "Not Registered")
        self.assertIsNone(response.data["webhook"]["secret_matches"])
        self.assertIn("Mautic webhook: Not Registered.", response.data["diagnostics"]["warnings"])

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_unpublished_hook_is_disabled_in_mautic(self, client_cls):
        response = self.diagnostics(client_cls, [hook(published=False)])

        self.assertEqual(response.data["webhook"]["registration"], "Disabled in Mautic")
        self.assertIn("unpublishes", response.data["webhook"]["registration_detail"])
        self.assertIn("Mautic webhook: Disabled in Mautic.", response.data["diagnostics"]["warnings"])

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_published_hook_wins_over_an_unpublished_duplicate(self, client_cls):
        response = self.diagnostics(client_cls, [
            hook(published=False, hook_id=1), hook(published=True, hook_id=2), "junk",
        ])

        self.assertEqual(response.data["webhook"]["registration"], "Registered")
        self.assertEqual(response.data["webhook"]["matching_hooks"], 2)

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_missing_events_are_listed(self, client_cls):
        response = self.diagnostics(client_cls, [hook(events=["mautic.email_on_send"])])

        webhook = response.data["webhook"]
        self.assertEqual(webhook["registered_events"], ["mautic.email_on_send"])
        self.assertIn("mautic.email_on_open", webhook["missing_events"])
        self.assertTrue(any("not subscribed to every" in w for w in response.data["diagnostics"]["warnings"]))

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_private_delivery_address_is_flagged(self, client_cls):
        response = self.diagnostics(client_cls, [hook("http://172.19.0.1:8000/api/newsletter/webhooks/mautic/")])

        self.assertIs(response.data["webhook"]["delivery_host_private"], True)
        self.assertTrue(any("private address" in w for w in response.data["diagnostics"]["warnings"]))

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_unreadable_webhook_list_is_not_verifiable(self, client_cls):
        cases = (
            (PermanentMauticError("HTTP 403"), "does not allow"),
            (TemporaryMauticError("timeout"), "could not be read"),
        )
        for error, detail in cases:
            with self.subTest(error=error):
                webhook = self.diagnostics(client_cls, error=error).data["webhook"]
                self.assertEqual(webhook["registration"], "Not Verifiable")
                self.assertIn(detail, webhook["registration_detail"])
                self.assertIsNone(webhook["secret_matches"])

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_unreachable_mautic_does_not_query_webhooks(self, client_cls):
        client = client_cls.return_value
        client.health_check.return_value = False
        client.get_marketing_bridge_capabilities.side_effect = TemporaryMauticError("down")
        client.get_campaign_builder_capabilities.side_effect = TemporaryMauticError("down")

        webhook = self.client.get(self.url).data["webhook"]

        self.assertEqual(webhook["registration"], "Not Verifiable")
        client.list_webhooks.assert_not_called()

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_delivery_evidence_reflects_received_deliveries(self, client_cls):
        body = fx.encode(fx.email_on_send())
        self.client.post(
            reverse("newsletter-mautic-webhook"), data=body, content_type="application/json",
            HTTP_WEBHOOK_SIGNATURE=fx.sign(body, SECRET),
        )
        self.client.post(
            reverse("newsletter-mautic-webhook"), data=body, content_type="application/json",
            HTTP_WEBHOOK_SIGNATURE="forged",
        )

        deliveries = self.diagnostics(client_cls, [hook()]).data["webhook"]["deliveries"]

        self.assertTrue(deliveries["observed"])
        self.assertEqual(deliveries["last_accepted"]["ignored"], 1)
        self.assertEqual(deliveries["last_rejected"]["reason"], "invalid_signature")
        self.assertIsNone(deliveries["last_failed"])

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_diagnostics_never_writes_to_mautic(self, client_cls):
        self.diagnostics(client_cls, [hook(published=False)])

        called = {name for name, _args, _kwargs in client_cls.return_value.method_calls}
        self.assertFalse({c for c in called if c.startswith(("create", "update", "edit", "delete", "publish"))})
