from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter import broadcast_family_views as views
from newsletter.analytics_services import _mautic_stats_summary
from newsletter.broadcast_delivery_inspection import _read_provider
from newsletter.campaign_services import delete_draft_campaign, sync_family_shared_fields
from newsletter.mautic import PermanentMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.operations import (
    ASSERTABLE_OPERATIONS,
    EMAIL_TRANSLATION_CREATE,
    EMAIL_VARIANT_CREATE,
    EMAIL_VARIANT_UPDATE,
)
from newsletter.models import NewsletterCampaign, NewsletterCampaignSendEvent, NewsletterEmailDesign
from newsletter.send_outcome_resolution import classify
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import response
from newsletter.webhooks import _attributable_campaign

User = get_user_model()
LOCMEM = {"CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "broadcast-family-tests"}}}


def email(eid, **extra):
    return {"id": eid, "name": f"E{eid}", "subject": "Hi", "emailType": "list", "customHtml": f"<p>{eid}</p>", "language": "en",
            "isPublished": True, "variantParent": None, "translationParent": None, "variantChildren": [], "translationChildren": [],
            "sentCount": 0, **extra}


def run_with(client):
    return lambda request, **kwargs: (kwargs["mutate"](client), None)


class FamilyRulesTests(TestCase):
    def test_only_a_draft_without_a_send_request_is_editable(self):
        draft = NewsletterCampaign.objects.create(name="D", status=NewsletterCampaign.Status.DRAFT)
        self.assertTrue(views.is_family_editable(draft))
        for state in (NewsletterCampaign.Status.SCHEDULED, NewsletterCampaign.Status.SENT):
            self.assertFalse(views.is_family_editable(NewsletterCampaign.objects.create(name=state, status=state)))
        NewsletterCampaignSendEvent.objects.create(campaign=draft)
        self.assertFalse(views.is_family_editable(draft))

    def test_variants_share_sender_and_segments_translations_share_sender(self):
        client = Mock()
        client.get_email.return_value = email(80, variantChildren=[email(81)], translationChildren=[email(82, language="fr")])
        sync_family_shared_fields(client, "80", {"fromName": "IMAA", "fromAddress": "news@x.test", "lists": [7], "subject": "S"})
        self.assertEqual([c.args for c in client.update_email.call_args_list], [
            ("81", {"fromName": "IMAA", "fromAddress": "news@x.test", "emailType": "list", "lists": [7]}),
            ("82", {"fromName": "IMAA", "fromAddress": "news@x.test", "emailType": "list"}),
        ])

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    def test_deleting_a_draft_deletes_its_versions_first(self):
        draft = NewsletterCampaign.objects.create(name="D", status=NewsletterCampaign.Status.DRAFT, mautic_email_id="80")
        NewsletterEmailDesign.objects.create(mautic_email_id="81", design_json={}, mjml="", html_sha256="x" * 64)
        client = Mock()
        client.get_email_family_ids.return_value = ["81", "82"]
        delete_draft_campaign(draft, client=client)
        self.assertEqual([c.args[0] for c in client.delete_email.call_args_list], ["81", "82", "80"])
        self.assertFalse(NewsletterEmailDesign.objects.filter(mautic_email_id="81").exists())
        self.assertFalse(NewsletterCampaign.objects.filter(pk=draft.pk).exists())


class FamilyResultsTests(TestCase):
    def test_send_outcome_accepts_only_family_aggregated_evidence(self):
        campaign = NewsletterCampaign.objects.create(name="S", status=NewsletterCampaign.Status.SENDING, mautic_email_id="80")
        event = Mock(provider_send_started_at=timezone.now() - timezone.timedelta(hours=1), status="processing", last_error="uncertain")
        evidence = {"email": {"id": 80, "email_type": "list", "related_email_ids": [81], "sent_count": 4},
                    "stats": {"total": 4, "before_since": 0, "since": 4}, "pending": 0, "queued": 0}
        with patch("newsletter.send_outcome_resolution.is_unresolved_send", return_value=True):
            self.assertEqual(classify(campaign, event, evidence)["reason"], "related_emails")
            self.assertEqual(classify(campaign, event, {**evidence, "family_aggregated": True})["classification"], "confirmed_sent")

    def test_analytics_add_up_the_family(self):
        stats = {"80": [{"is_read": 1, "lead_id": 1}, {"is_read": 0, "lead_id": 2}], "81": [{"is_read": 1, "lead_id": 3}]}
        client = Mock()
        client.get_email_family_ids.return_value = ["81"]
        client.get_email_stats.side_effect = lambda eid: {"total": len(stats[eid]), "stats": stats[eid]}
        campaign = NewsletterCampaign(name="S", mautic_email_id="80")
        with patch("newsletter.analytics_services.MauticClient", return_value=client):
            opens, summary, metadata = _mautic_stats_summary(campaign, include_send_summary=True)
        self.assertEqual((opens["opened_count"], summary["sent_count"], metadata["mautic_stats_count"]), (2, 3, 3))
        self.assertEqual(metadata["mautic_family_email_ids"], ["80", "81"])

    def test_delivery_inspection_counts_the_family(self):
        client = Mock()
        client.get_email.return_value = email(80, sentCount=2, variantChildren=[email(81, sentCount=2)], translationChildren=[email(82, sentCount=1)])
        client.count_email_stats.side_effect = lambda eid, **kw: 0 if kw else {"80": 2, "81": 2, "82": 1}[eid]
        client.get_latest_email_send.side_effect = lambda eid: {"date_sent": {"80": "2026-10-29 09:00:01", "81": "2026-10-29 09:00:03", "82": None}[eid]}
        evidence = _read_provider(client, "80")
        self.assertEqual((evidence["sent_count"], evidence["stats"]["recorded"], evidence["stats"]["last_sent_at"]), (5, 5, "2026-10-29 09:00:03"))

    @override_settings(**LOCMEM)
    def test_webhook_events_on_a_version_count_for_its_broadcast(self):
        cache.clear()
        campaign = NewsletterCampaign.objects.create(name="S", status=NewsletterCampaign.Status.SENT, mautic_email_id="80")
        client = Mock()
        client.get_email.return_value = email(81, variantParent={"id": 80})
        with patch("newsletter.mautic.MauticClient", return_value=client):
            self.assertEqual(_attributable_campaign("81"), campaign)
            self.assertEqual(_attributable_campaign("81"), campaign)
        client.get_email.assert_called_once_with("81")  # cached
        other = Mock()
        other.get_email.return_value = email(90, emailType="template")
        with patch("newsletter.mautic.MauticClient", return_value=other):
            self.assertIsNone(_attributable_campaign("90"))


class FamilyClientTests(SimpleTestCase):
    def test_writes_use_the_broadcast_bridge_with_their_operation(self):
        session = Mock()
        session.request.side_effect = [response(200, {"email": email(81)}), response(200, {"email": {"id": 81}}), response(200, {"email": email(82)})]
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)
        client.create_broadcast_variant(80, weight=50, winner_criteria="email.openrate")
        client.update_broadcast_variant(81, weight=40)
        client.create_broadcast_translation(80, language="de")
        self.assertEqual([c.args[1].split("/api/")[1] for c in session.request.call_args_list], [
            "ecp/bridge/emails/80/variants/new", "ecp/bridge/emails/81/variant/edit", "ecp/bridge/emails/80/translations/new"])
        self.assertEqual([c.args[0] for c in provider.call_args_list], [EMAIL_VARIANT_CREATE, EMAIL_VARIANT_UPDATE, EMAIL_TRANSLATION_CREATE])
        for operation in (EMAIL_VARIANT_CREATE, EMAIL_VARIANT_UPDATE, EMAIL_TRANSLATION_CREATE):
            self.assertIn(operation, ASSERTABLE_OPERATIONS)

    def test_family_ids(self):
        session = Mock()
        session.request.return_value = response(200, {"email": email(80, variantChildren=[email(81)], translationChildren=[email(82)])})
        self.assertEqual(MauticClient(session=session).get_email_family_ids(80), ["81", "82"])


@override_settings(**LOCMEM)
class FamilyApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="bfam-admin", email="bf@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api = APIClient()
        self.api.force_authenticate(self.admin)
        self.draft = NewsletterCampaign.objects.create(name="Summit", status=NewsletterCampaign.Status.DRAFT, mautic_email_id="80",
                                                       html_content="<p>80</p>")
        self.sent = NewsletterCampaign.objects.create(name="Old", status=NewsletterCampaign.Status.SENT, mautic_email_id="70")
        self.emails = {"80": email(80, variantChildren=[email(81, variantParent={"id": 80})],
                                   translationChildren=[email(82, translationParent={"id": 80}, language="fr")]),
                       "81": email(81, variantParent={"id": 80}), "82": email(82, translationParent={"id": 80}, language="fr"),
                       "70": email(70), "99": email(99, variantParent={"id": 70})}
        self.client_mock = Mock()
        self.client_mock.get_email.side_effect = lambda eid: self.emails[str(eid)]
        self.client_mock.get_broadcast_abtest.return_value = {"parentId": 80, "criteria": "email.openrate", "versions": [
            {"id": 80, "isMain": True, "isPublished": True, "weight": 50, "sent": 2}, {"id": 81, "isPublished": True, "weight": 50, "sent": 2}]}
        patcher = patch("newsletter.broadcast_family_views.MauticClient", return_value=self.client_mock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def url(self, name, campaign=None, *extra):
        return reverse(f"newsletter-admin-campaign-{name}", args=[(campaign or self.draft).uuid, *extra])

    def test_family_lists_versions_and_results(self):
        body = self.api.get(self.url("family")).json()
        self.assertEqual((body["editable"], [v["id"] for v in body["variants"]], [t["language"] for t in body["translations"]]), (True, ["81"], ["fr"]))
        self.assertEqual([(v["id"], v["weight"], v["sent"]) for v in body["abTest"]["versions"]], [("80", 50, 2), ("81", 50, 2)])
        self.assertFalse(self.api.get(self.url("family", self.sent)).json()["editable"])

    def test_changes_are_refused_unless_the_broadcast_is_a_draft(self):
        for method, url, data in (("post", self.url("variants", self.sent), {"weight": 50, "winnerCriteria": "email.openrate"}),
                                  ("post", self.url("translations", self.sent), {"language": "de"}),
                                  ("patch", self.url("version", self.sent, "99"), {"subject": "x"}),
                                  ("delete", self.url("version", self.sent, "99"), None),
                                  ("patch", self.url("abtest", self.sent), {"winnerCriteria": "email.openrate"})):
            with self.subTest(url=url):
                r = getattr(self.api, method)(url, data, format="json")
                self.assertEqual((r.status_code, r.json()["code"]), (409, "broadcast_not_draft"))

    def test_create_variant_syncs_the_draft_then_copies_it(self):
        created = email(83, variantParent={"id": 80}, customHtml="<p>83</p>")
        self.client_mock.create_broadcast_variant.return_value = created
        self.emails["83"] = created
        with patch("newsletter.broadcast_family_views.run_interactive_mutation", side_effect=run_with(self.client_mock)) as run, \
                patch("newsletter.broadcast_family_views.sync_campaign_draft_to_mautic", return_value=self.draft) as sync, \
                patch("newsletter.broadcast_family_views.copy_campaign_design_to_email", return_value=object()) as copy:
            r = self.api.post(self.url("variants"), {"weight": 50, "winnerCriteria": "email.clickthrough"}, format="json")
        self.assertEqual((r.status_code, r.json()["id"], r.json()["role"], r.json()["designCopied"]), (201, "83", "variant", True))
        sync.assert_called_once()
        self.client_mock.create_broadcast_variant.assert_called_once_with("80", weight=50, winner_criteria="email.clickthrough", name=None)
        self.assertEqual(run.call_args.kwargs["action"], EMAIL_VARIANT_CREATE)
        self.assertEqual(copy.call_args.args[1:], ("83", "<p>83</p>"))
        r = self.api.post(self.url("variants"), {"weight": 0, "winnerCriteria": "email.openrate"}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_a_version_must_belong_to_this_broadcast(self):
        self.assertEqual(self.api.get(self.url("version", None, "81")).json()["role"], "variant")
        r = self.api.get(self.url("version", None, "99"))
        self.assertEqual((r.status_code, r.json()["code"]), (404, "version_not_found"))
        self.assertEqual(self.api.get(self.url("version", None, "80")).status_code, 404)

    def test_editing_a_version(self):
        with patch("newsletter.broadcast_family_views.run_interactive_mutation", side_effect=run_with(self.client_mock)):
            r = self.api.patch(self.url("version", None, "81"), {"subject": "B subject", "customHtml": "<p>b</p>"}, format="json")
            self.assertEqual(r.status_code, 200)
            self.client_mock.update_email.assert_called_once_with("81", {"subject": "B subject", "customHtml": "<p>b</p>", "emailType": "list"})
            r = self.api.patch(self.url("version", None, "82"), {"language": "en_GB"}, format="json")
            self.assertEqual((r.status_code, r.json()["code"]), (409, "broadcast_language_taken"))
            r = self.api.patch(self.url("version", None, "81"), {"language": "de"}, format="json")
            self.assertEqual(r.status_code, 400)
            r = self.api.patch(self.url("version", None, "81"), {"publishUp": "2026-11-01"}, format="json")
            self.assertEqual(r.status_code, 400)

    def test_removing_a_version_and_its_design(self):
        NewsletterEmailDesign.objects.create(mautic_email_id="81", design_json={}, mjml="", html_sha256="x" * 64)
        with patch("newsletter.broadcast_family_views.run_interactive_mutation", side_effect=run_with(self.client_mock)):
            self.assertEqual(self.api.delete(self.url("version", None, "81")).status_code, 204)
        self.client_mock.delete_email.assert_called_once_with("81")
        self.assertFalse(NewsletterEmailDesign.objects.filter(mautic_email_id="81").exists())

    def test_abtest_changes(self):
        with patch("newsletter.broadcast_family_views.run_interactive_mutation", side_effect=run_with(self.client_mock)):
            self.assertEqual(self.api.patch(self.url("abtest"), {"emailId": "81", "weight": 30}, format="json").status_code, 200)
            self.client_mock.update_broadcast_variant.assert_called_with("81", weight=30, winner_criteria=None)
            self.assertEqual(self.api.patch(self.url("abtest"), {"winnerCriteria": "email.clickthrough"}, format="json").status_code, 200)
            self.client_mock.update_broadcast_variant.assert_called_with("80", weight=None, winner_criteria="email.clickthrough")
            self.assertEqual(self.api.patch(self.url("abtest"), {"weight": 30}, format="json").status_code, 400)
            self.assertEqual(self.api.patch(self.url("abtest"), {"emailId": "99", "weight": 30}, format="json").status_code, 404)

    def test_plugin_refusals_are_conflicts(self):
        with patch("newsletter.broadcast_family_views.run_interactive_mutation",
                   side_effect=PermanentMauticError("Mautic request failed (HTTP 409): The main broadcast is already in en.")), \
                patch("newsletter.broadcast_family_views.sync_campaign_draft_to_mautic"):
            r = self.api.post(self.url("translations"), {"language": "en_GB"}, format="json")
        self.assertEqual((r.status_code, r.json()["detail"]), (409, "The main broadcast is already in en."))
