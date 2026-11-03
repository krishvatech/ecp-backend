"""Batch 2 (4): BCC, excluded segments (broadcasts only) and the template publish window."""

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.email_delivery_options import DeliveryOptionsError, options_match, parse_delivery_options
from newsletter.mautic import MauticClient
from newsletter.models import NewsletterCampaign
from newsletter.template_views import _parse_template_payload
from newsletter.tests.marketing_actors import grant_marketing_access

User = get_user_model()
PUBLISHED = {"5": True, "6": True, "7": False}


class ExtrasRuleTests(SimpleTestCase):
    def test_bcc_is_one_valid_address(self):
        self.assertEqual(parse_delivery_options({"bccAddress": " archive@imaa.test "}), {"bccAddress": "archive@imaa.test"})
        self.assertEqual(parse_delivery_options({"bccAddress": ""}), {"bccAddress": ""})
        for bad in ("a@b.test, c@d.test", "nope", 5):
            with self.subTest(bad=bad), self.assertRaises(DeliveryOptionsError):
                parse_delivery_options({"bccAddress": bad})

    def test_excluded_segments_rules(self):
        exclusions = {"published": PUBLISHED, "targets": ["9"]}
        self.assertEqual(parse_delivery_options({"excludedLists": ["5", 6, "5"]}, exclusions=exclusions), {"excludedLists": ["5", "6"]})
        self.assertEqual(parse_delivery_options({"excludedLists": []}, exclusions=exclusions), {"excludedLists": []})
        for value, message in ((["7"], "unpublished"), (["8"], "unpublished"), (["9"], "sent to"), (["x"], "chosen from"),
                               ([str(n) for n in range(1, 22)], "up to 20")):
            with self.subTest(value=value), self.assertRaisesRegex(DeliveryOptionsError, message):
                parse_delivery_options({"excludedLists": value}, exclusions=exclusions)
        with self.assertRaisesRegex(DeliveryOptionsError, "broadcasts only"):
            parse_delivery_options({"excludedLists": ["5"]})

    def test_read_back_checks_bcc_and_exclusions(self):
        stored = {"bccAddress": "a@imaa.test", "excludedLists": [{"id": 5, "name": "Staff"}]}
        self.assertEqual(options_match(stored, {"bccAddress": "a@imaa.test", "excludedLists": ["5"]}), [])
        self.assertEqual(options_match(stored, {"bccAddress": "", "excludedLists": []}), ["BCC", "excluded segments"])

    def test_clearing_exclusions_or_a_category_travels_as_json(self):
        self.assertEqual(MauticClient._email_body({"excludedLists": [], "emailType": "list"}), {"json": {"excludedLists": [], "emailType": "list"}})
        self.assertIn("data", MauticClient._email_body({"excludedLists": ["5"]}))
        self.assertEqual(MauticClient._email_body({"category": "", "name": "T"}), {"json": {"category": None, "name": "T"}})
        self.assertIn("data", MauticClient._email_body({"category": 4}))

    def test_templates_take_bcc_and_a_window_but_not_exclusions(self):
        payload = _parse_template_payload({"bccAddress": "a@imaa.test", "publishUp": "2026-12-01T10:00:00+01:00", "publishDown": None},
                                          partial=True)
        self.assertEqual(payload, {"bccAddress": "a@imaa.test", "publishUp": "2026-12-01 09:00", "publishDown": ""})
        for data in ({"excludedLists": ["5"]}, {"publishUp": "2026-12-02T00:00:00Z", "publishDown": "2026-12-01T00:00:00Z"}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                _parse_template_payload(data, partial=True)


@override_settings(ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False)
class BroadcastExclusionApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="extras-admin", email="extras-admin@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api.force_authenticate(self.admin)
        self.campaign = NewsletterCampaign.objects.create(name="News", status=NewsletterCampaign.Status.DRAFT, mautic_email_id="80")
        self.url = reverse("newsletter-admin-campaign-delivery-options", args=[self.campaign.uuid])
        self.client_mock = Mock()
        self.client_mock._uses_asserted_user.return_value = False
        self.client_mock.list_segments.return_value = {"total": 3, "lists": [
            {"id": 5, "isPublished": True}, {"id": 7, "isPublished": False}, {"id": 9, "isPublished": True}]}
        self.stored = {"id": 80, "lists": [{"id": 9}], "excludedLists": [{"id": 5, "name": "Staff"}], "bccAddress": "",
                       "variantChildren": [{"id": 81}]}
        self.client_mock.get_email.return_value = self.stored
        # Mautic's email API omits exclusions; the plugin reports them.
        self.client_mock.get_email_excluded_segments.return_value = [{"id": 5, "name": "Staff"}]
        for target in ("newsletter.email_delivery_views.MauticClient", "newsletter.mautic_identity_execution.MauticClient"):
            patcher = patch(target, return_value=self.client_mock)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_exclusions_reach_every_version(self):
        response = self.api.patch(self.url, {"excludedLists": ["5"]}, format="json")
        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual([call.args for call in self.client_mock.update_email.call_args_list],
                         [("80", {"excludedLists": ["5"], "emailType": "list"}), ("81", {"excludedLists": ["5"], "emailType": "list"})])
        self.assertEqual(response.json()["excludedLists"], [{"id": "5", "name": "Staff"}])

    def test_its_own_segment_or_an_unpublished_one_is_refused(self):
        for value in (["9"], ["7"]):
            with self.subTest(value=value):
                self.assertEqual(self.api.patch(self.url, {"excludedLists": value}, format="json").status_code, 400)
        self.client_mock.update_email.assert_not_called()
