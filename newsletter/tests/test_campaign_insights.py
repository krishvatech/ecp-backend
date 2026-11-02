"""Campaign contacts and per-step statistics (read-only bridge endpoints)."""

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError
from newsletter.mautic.client import MauticClient
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import MAUTIC_SETTINGS, response

User = get_user_model()

STATS = {
    "campaignId": 31,
    "contacts": {"current": 9, "removed": 1},
    "events": [
        {"id": 6, "name": "Send", "type": "email.send", "eventType": "action", "parentId": None, "decisionPath": None,
         "deleted": False, "processed": 4, "pending": 6, "yes": 10, "no": 0, "failed": 1, "properties": {"secret": 1}},
    ],
}


@override_settings(**MAUTIC_SETTINGS)
class InsightsClientTests(SimpleTestCase):
    def test_routes_and_params(self):
        session = Mock()
        session.request.side_effect = [response(200, {"contacts": [], "total": 0}), response(200, STATS)]
        client = MauticClient(session=session)
        client.get_campaign_contacts(31, start=25, limit=25, search="ann")
        client.get_campaign_stats(31)
        calls = session.request.call_args_list
        self.assertEqual([(c.args[0], c.args[1].split("/api/")[1]) for c in calls],
                         [("GET", "ecp/campaigns/31/contacts"), ("GET", "ecp/campaigns/31/stats")])
        self.assertEqual(calls[0].kwargs["params"], {"start": 25, "limit": 25, "search": "ann"})


class InsightsApiTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        admin = User.objects.create_superuser(username="insights-admin", email="insights-admin@example.test", password="x")
        grant_marketing_access(admin, mautic_user_id=6)
        self.api.force_authenticate(admin)
        self.client_mock = Mock()
        patcher = patch("newsletter.native_campaign_views.MauticClient", return_value=self.client_mock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_contacts_are_paged_minimal_and_never_cached(self):
        self.client_mock.get_campaign_contacts.return_value = {"total": 30, "contacts": [
            {"id": 70, "email": "a@x.test", "firstname": "Ann", "lastname": "Lee", "dateAdded": "2026-11-01 10:00:00",
             "manuallyAdded": True, "rotation": 1, "lastActivity": None}]}
        result = self.api.get(reverse("newsletter-admin-mautic-campaign-contacts", args=["31"]), {"page": 2, "page_size": 500, "search": " ann "})
        self.assertEqual(result.status_code, 200)
        self.client_mock.get_campaign_contacts.assert_called_once_with("31", start=100, limit=100, search="ann", timeout=20)
        body = result.json()
        self.assertEqual((body["count"], body["num_pages"], body["results"][0]["name"]), (30, 1, "Ann Lee"))
        self.assertEqual(result["Cache-Control"], "no-store, private")

    def test_stats_pass_through_only_the_counts(self):
        self.client_mock.get_campaign_stats.return_value = STATS
        body = self.api.get(reverse("newsletter-admin-mautic-campaign-stats", args=["31"])).json()
        self.assertEqual(body["contacts"], {"current": 9, "removed": 1})
        self.assertEqual((body["events"][0]["processed"], body["events"][0]["pending"], body["events"][0]["failed"]), (4, 6, 1))
        self.assertNotIn("properties", body["events"][0])

    def test_missing_campaign_and_access(self):
        self.client_mock.get_campaign_stats.side_effect = PermanentMauticError("Mautic API request failed (HTTP 404): Campaign not found.")
        self.assertEqual(self.api.get(reverse("newsletter-admin-mautic-campaign-stats", args=["31"])).status_code, 404)
        other = APIClient()
        other.force_authenticate(User.objects.create_user(username="insights-normal", email="in@example.test", password="x"))
        for name in ("newsletter-admin-mautic-campaign-stats", "newsletter-admin-mautic-campaign-contacts"):
            self.assertEqual(other.get(reverse(name, args=["31"])).status_code, 403)
