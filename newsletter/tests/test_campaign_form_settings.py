"""Batch 2 (3): campaign settings (category, restart, publish window) and Form
settings (category, publish window, kiosk mode, no-index, progressive profiling)."""

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.form_views import FormPolicyError, parse_form_settings
from newsletter.mautic import MauticClient
from newsletter.mautic_publish_window import PublishWindowError, parse_window, to_mautic
from newsletter.models import MauticIdentityAuditLog
from newsletter.native_campaign_views import parse_campaign_settings
from newsletter.tests.marketing_actors import grant_marketing_access

User = get_user_model()
CATEGORIES = {"categories": {
    "1": {"id": 1, "title": "Onboarding", "alias": "onboarding", "bundle": "campaign"},
    "2": {"id": 2, "title": "Lead forms", "alias": "lead-forms", "bundle": "form"},
    "3": {"id": 3, "title": "Everything", "alias": "everything", "bundle": "global"},
}}
OVERVIEW = {"usage": {}, "published": {1: True, 2: True, 3: True}}


def category_client():
    client = Mock(name="mautic")
    client._uses_asserted_user.return_value = False
    client.list_categories.return_value = CATEGORIES
    client.get_category_overview.return_value = OVERVIEW
    return client


class PublishWindowTests(SimpleTestCase):
    def test_moments_become_mautic_utc_text(self):
        self.assertEqual(to_mautic("2026-12-01T10:00:00+01:00", field="publishUp"), "2026-12-01 09:00")
        self.assertEqual(to_mautic("2026-12-01T09:30:00Z", field="publishUp"), "2026-12-01 09:30")
        self.assertIsNone(to_mautic("", field="publishUp"))
        for bad in ("2026-12-01 10:00", "tomorrow", "2026-13-01T00:00:00Z"):
            with self.subTest(bad=bad), self.assertRaises(PublishWindowError):
                to_mautic(bad, field="publishUp")

    def test_the_end_must_follow_the_start_even_when_only_one_changes(self):
        with self.assertRaises(PublishWindowError):
            parse_window({"publishUp": "2026-12-05T00:00:00Z", "publishDown": "2026-12-04T00:00:00Z"})
        with self.assertRaises(PublishWindowError):
            parse_window({"publishDown": "2026-12-01T00:00:00Z"}, {"publishUp": "2026-12-02T00:00:00+00:00"})
        self.assertEqual(parse_window({"publishUp": None}, {"publishUp": "2026-12-02T00:00:00+00:00"}), {"publishUp": None})


class CampaignSettingsParseTests(SimpleTestCase):
    def setUp(self):
        cache.clear()
        self.client = category_client()
        patcher = patch("newsletter.mautic_category_services.MauticClient", return_value=self.client)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_settings_rules(self):
        self.assertEqual(parse_campaign_settings({"category": 1, "allowRestart": "true", "publishUp": "2026-12-01T10:00:00+01:00"}, {}),
                         {"category": 1, "allowRestart": True, "publishUp": "2026-12-01 09:00"})
        self.assertEqual(parse_campaign_settings({"category": 3}, {})["category"], 3)
        self.assertEqual(parse_campaign_settings({"category": None, "publishDown": ""}, {}), {"category": None, "publishDown": None})
        for data in ({"category": 2}, {"name": "x"}, {}, {"publishUp": "2026-12-01"}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_campaign_settings(data, {})


@override_settings(ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False)
class CampaignSettingsApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="camp-settings", email="camp-settings@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api.force_authenticate(self.admin)
        self.client = category_client()
        self.client.get_campaign.return_value = {"id": 7, "name": "Welcome", "publishUp": None, "publishDown": None}
        self.client.update_campaign_settings.return_value = {"id": 7, "name": "Welcome", "allowRestart": True,
                                                             "category": {"id": 1, "title": "Onboarding"}}
        for target in ("newsletter.native_campaign_views.MauticClient", "newsletter.mautic_category_services.MauticClient"):
            patcher = patch(target, return_value=self.client)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.url = reverse("newsletter-admin-mautic-campaign-settings", args=["7"])

    def test_only_settings_are_sent_and_the_change_is_audited(self):
        response = self.api.patch(self.url, {"category": 1, "allowRestart": True}, format="json")
        self.assertEqual(response.status_code, 200, response.json())
        self.client.update_campaign_settings.assert_called_once_with("7", {"category": 1, "allowRestart": True})
        self.client.update_campaign.assert_not_called()
        self.assertEqual((response.json()["category"]["id"], response.json()["allowRestart"]), (1, True))
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual((entry.resource_id, entry.status, entry.detail), ("7", "succeeded", "settings: allowRestart, category"))

    def test_refusals_never_write(self):
        for data in ({"category": 2}, {"events": []}, {}, {"publishUp": "2026-12-05T00:00:00Z", "publishDown": "2026-12-04T00:00:00Z"}):
            with self.subTest(data=data):
                self.assertEqual(self.api.patch(self.url, data, format="json").status_code, 400)
        self.client.update_campaign_settings.assert_not_called()

    def test_a_clear_travels_as_json_null(self):
        client = MauticClient.__new__(MauticClient)
        client._uses_asserted_user = lambda: False
        client._request = Mock(return_value=Mock(status_code=200, json=lambda: {"campaign": {"id": 7}}))
        client._json_object = lambda response, context: response.json()
        MauticClient.update_campaign_settings(client, "7", {"category": None})
        self.assertEqual(client._request.call_args.kwargs, {"json": {"category": None}})


class FormSettingsParseTests(SimpleTestCase):
    def setUp(self):
        cache.clear()
        self.client = category_client()
        patcher = patch("newsletter.mautic_category_services.MauticClient", return_value=self.client)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.current = {"name": "Inquiry", "postAction": "message", "postActionProperty": "Thanks", "category": {"id": 2},
                        "inKioskMode": False, "noIndex": False, "progressiveProfilingLimit": 3,
                        "publishUp": "2026-12-01T09:00:00+00:00", "publishDown": None}

    def test_only_changed_settings_are_sent(self):
        self.assertEqual(parse_form_settings({"category": 2, "progressiveProfilingLimit": 3, "inKioskMode": False,
                                              "publishUp": "2026-12-01T10:00:00+01:00"}, current=self.current), {})
        self.assertEqual(parse_form_settings({"category": None, "progressiveProfilingLimit": None, "noIndex": True, "publishUp": None},
                                             current=self.current),
                         {"category": None, "progressiveProfilingLimit": None, "noIndex": True, "publishUp": None})
        created = parse_form_settings({"name": "New", "postAction": "message", "postActionProperty": "Hi", "category": 3, "inKioskMode": True})
        self.assertEqual((created["category"], created["inKioskMode"]), (3, True))

    def test_refusals(self):
        for data in ({"category": 1}, {"progressiveProfilingLimit": 0.5}, {"progressiveProfilingLimit": 101},
                     {"publishDown": "2026-11-30T00:00:00Z"}):
            with self.subTest(data=data), self.assertRaises(FormPolicyError):
                parse_form_settings(data, current=self.current)

    def test_the_client_sends_a_clear_as_blank(self):
        self.assertEqual(MauticClient._form_clears({"category": None, "noIndex": False, "name": "x"}), {"category": "", "noIndex": False, "name": "x"})
