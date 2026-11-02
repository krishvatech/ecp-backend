"""Email delivery options (Reply-To, UTM tags, attachments) and per-link clicks."""

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter import email_delivery_views as views
from newsletter.email_delivery_options import DeliveryOptionsError, normalize_delivery_options, parse_delivery_options
from newsletter.mautic.client import MauticClient
from newsletter.models import NewsletterCampaign
from newsletter.template_views import _normalize_template, _parse_template_payload
from newsletter.tests.marketing_actors import grant_marketing_access

User = get_user_model()


class DeliveryOptionRuleTests(SimpleTestCase):
    def test_valid_options_become_native_settings(self):
        native = parse_delivery_options({"replyToAddress": " team@imaa.org ",
                                         "utmTags": {"utmSource": "imaa", "utmCampaign": "nov-2026 {subject}"},
                                         "assetAttachments": ["5", 5, {"id": "6"}]}, known_assets={"5", "6"})
        self.assertEqual(native, {"replyToAddress": "team@imaa.org",
                                  "utmTags": {"utmSource": "imaa", "utmMedium": "", "utmCampaign": "nov-2026 {subject}", "utmContent": ""},
                                  "assetAttachments": ["5", "6"]})
        self.assertEqual(parse_delivery_options({"replyToAddress": "", "assetAttachments": []}), {"replyToAddress": "", "assetAttachments": []})

    def test_invalid_options_are_refused(self):
        for data in ({"replyToAddress": "not-an-email"}, {"replyToAddress": "a@x.test, b@x.test"},
                     {"utmTags": {"utm_source": "x"}}, {"utmTags": {"utmSource": 'x" onclick'}}, {"utmTags": {"utmSource": "a&b=c"}},
                     {"utmTags": {"utmSource": "x" * 101}}, {"utmTags": "imaa"},
                     {"assetAttachments": ["9"]}, {"assetAttachments": ["x"]}, {"assetAttachments": [str(i) for i in range(1, 12)]}):
            with self.subTest(data=data), self.assertRaises(DeliveryOptionsError):
                parse_delivery_options(data, known_assets={str(i) for i in range(1, 12)} - {"9"})

    def test_mautic_shapes_are_normalized(self):
        self.assertEqual(normalize_delivery_options({"utmTags": [], "assetAttachments": {"0": {"id": 5, "title": "Brochure"}}}),
                         {"replyToAddress": "", "utmTags": {"utmSource": "", "utmMedium": "", "utmCampaign": "", "utmContent": ""},
                          "assetAttachments": [{"id": "5", "title": "Brochure"}]})

    def test_form_encoding_nests_utm_tags_and_clearing_attachments_uses_json(self):
        encoded = MauticClient._email_form_data({"utmTags": {"utmSource": "imaa", "utmMedium": ""}, "lists": [1, 2]})
        self.assertEqual(encoded, [("utmTags[utmSource]", "imaa"), ("utmTags[utmMedium]", ""), ("lists[]", 1), ("lists[]", 2)])
        self.assertEqual(MauticClient._email_body({"assetAttachments": ["5"]}), {"data": [("assetAttachments[]", "5")]})
        # A form cannot carry an empty list (Mautic refuses "" as a choice).
        self.assertEqual(MauticClient._email_body({"assetAttachments": [], "replyToAddress": ""}),
                         {"json": {"assetAttachments": [], "replyToAddress": ""}})

    def test_templates_carry_the_options(self):
        payload = _parse_template_payload({"name": "T", "replyToAddress": "team@imaa.org", "utmTags": {"utmSource": "imaa"}}, partial=True)
        self.assertEqual((payload["replyToAddress"], payload["utmTags"]["utmSource"]), ("team@imaa.org", "imaa"))
        with self.assertRaises(ValueError):
            _parse_template_payload({"replyToAddress": "bad"}, partial=True)
        normalized = _normalize_template({"id": 4, "name": "T", "replyToAddress": "team@imaa.org", "assetAttachments": [{"id": 5, "title": "B"}]})
        self.assertEqual((normalized["replyToAddress"], normalized["assetAttachments"]), ("team@imaa.org", [{"id": "5", "title": "B"}]))


class LinkClickTests(SimpleTestCase):
    def test_clicks_are_summed_per_address_across_the_family(self):
        client = Mock()
        client.list_stat_rows.side_effect = [
            ([{"channel_id": "40", "redirect_id": "1", "hits": "5", "unique_hits": "3"},
              {"channel_id": "41", "redirect_id": "2", "hits": "2", "unique_hits": "2"},
              {"channel_id": "41", "redirect_id": "3", "hits": "9", "unique_hits": "4"}], 3),
            ([{"id": "1", "url": "https://imaa.org/a"}, {"id": "2", "url": "https://imaa.org/a"}, {"id": "3", "url": "https://imaa.org/b"}], 3),
        ]
        data = views.email_link_clicks(client, ["40", "41"], {"40": "Main", "41": "Variant B"})
        self.assertEqual(data["totalClicks"], 16)
        self.assertEqual([(link["url"], link["clicks"], link["uniqueClicks"]) for link in data["links"]],
                         [("https://imaa.org/b", 9, 4), ("https://imaa.org/a", 7, 5)])
        self.assertEqual([(v["name"], v["clicks"]) for v in data["links"][1]["byEmail"]], [("Main", 5), ("Variant B", 2)])
        self.assertEqual(client.list_stat_rows.call_args_list[0].args[1], [("channel", "eq", "email"), ("channel_id", "in", "40,41")])
        self.assertEqual(views.family_email_ids({"id": 40, "variantChildren": [{"id": 41}], "translationChildren": {"0": {"id": 42}}}),
                         ["40", "41", "42"])


def run_with(client):
    return lambda request, **kwargs: (kwargs["mutate"](client), None)


class BroadcastDeliveryOptionTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        admin = User.objects.create_superuser(username="delivery-admin", email="delivery-admin@example.test", password="x")
        grant_marketing_access(admin, mautic_user_id=6)
        self.api.force_authenticate(admin)
        self.campaign = NewsletterCampaign.objects.create(name="B", status=NewsletterCampaign.Status.DRAFT, mautic_email_id="80")
        self.url = reverse("newsletter-admin-campaign-delivery-options", args=[self.campaign.uuid])
        self.client_mock = Mock()
        self.client_mock.list_assets.return_value = {"total": 1, "assets": [{"id": 5}]}
        patcher = patch("newsletter.email_delivery_views.MauticClient", return_value=self.client_mock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_options_are_set_on_every_version_and_verified(self):
        saved = {"id": 80, "replyToAddress": "team@imaa.org", "utmTags": {"utmSource": "imaa"}, "assetAttachments": [{"id": 5, "title": "B"}],
                 "variantChildren": [{"id": 81}], "translationChildren": []}
        self.client_mock.get_email.side_effect = [{"id": 80, "variantChildren": [{"id": 81}], "translationChildren": []}, saved]
        with patch("newsletter.email_delivery_views.run_interactive_mutation", side_effect=run_with(self.client_mock)):
            result = self.api.patch(self.url, {"replyToAddress": "team@imaa.org", "utmTags": {"utmSource": "imaa"}, "assetAttachments": ["5"]},
                                    format="json")
        self.assertEqual(result.status_code, 200, result.json())
        self.assertEqual([c.args[0] for c in self.client_mock.update_email.call_args_list], ["80", "81"])
        self.assertEqual(self.client_mock.update_email.call_args_list[0].args[1]["emailType"], "list")
        self.assertEqual(result.json()["assetAttachments"], [{"id": "5", "title": "B"}])

    def test_guards(self):
        self.assertEqual(self.api.patch(self.url, {"subject": "x"}, format="json").status_code, 400)
        self.assertEqual(self.api.patch(self.url, {"assetAttachments": ["9"]}, format="json").status_code, 400)
        unsynced = NewsletterCampaign.objects.create(name="U", status=NewsletterCampaign.Status.DRAFT)
        url = reverse("newsletter-admin-campaign-delivery-options", args=[unsynced.uuid])
        self.assertEqual(self.api.get(url).json(), {"available": False, "editable": False})
        self.assertEqual(self.api.patch(url, {"replyToAddress": ""}, format="json").json()["code"], "broadcast_not_synced")
        self.campaign.status = NewsletterCampaign.Status.SENT
        self.campaign.save(update_fields=["status"])
        self.assertEqual(self.api.patch(self.url, {"replyToAddress": ""}, format="json").json()["code"], "broadcast_not_draft")
        self.client_mock.update_email.assert_not_called()

    def test_a_mismatched_read_back_is_not_success(self):
        self.client_mock.get_email.side_effect = [{"id": 80}, {"id": 80, "replyToAddress": ""}]
        with patch("newsletter.email_delivery_views.run_interactive_mutation", side_effect=run_with(self.client_mock)):
            result = self.api.patch(self.url, {"replyToAddress": "team@imaa.org"}, format="json")
        self.assertEqual((result.status_code, result.json()["code"]), (409, "delivery_options_mismatch"))
