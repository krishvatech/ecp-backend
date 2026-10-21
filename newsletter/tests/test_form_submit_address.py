"""Forms submit to Mautic's trusted public address (site_url), whatever address
ECP uses to reach Mautic's API, and ECP says so when they differ."""

import json
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from newsletter.form_views import submit_address_status, validate_public_url
from newsletter.models import NewsletterCategory
from newsletter.tests.test_admin_forms_api import PER_USER_ON, _FormsApiBase, native_form

PUBLIC = "https://mautic.example.org"


def rendered(base, form_id=31):
    return (f'<form autocomplete="false" role="form" method="post" action="{base}/form/submit?formId={form_id}" '
            'id="mauticform_x"><button type="submit">Send</button></form>')


def _cached(name, parts, build, ttl):
    return build()


class PublicUrlRuleTests(SimpleTestCase):
    @override_settings(DEBUG=False)
    def test_deployed_public_url_must_be_https_except_loopback(self):
        self.assertEqual(validate_public_url("https://mautic.example.org"), "https://mautic.example.org")
        self.assertIsNone(validate_public_url("http://mautic.example.org"))
        self.assertEqual(validate_public_url("http://localhost:8088"), "http://localhost:8088")
        self.assertEqual(validate_public_url("http://127.0.0.1:8088"), "http://127.0.0.1:8088")

    @override_settings(DEBUG=True)
    def test_local_development_accepts_http(self):
        self.assertEqual(validate_public_url("http://mautic.local:8080"), "http://mautic.local:8080")

    def test_explicit_rule_overrides_debug(self):
        self.assertIsNone(validate_public_url("http://mautic.local", require_https=True))
        self.assertEqual(validate_public_url("http://mautic.local", require_https=False), "http://mautic.local")


@patch("newsletter.form_views.marketing_cache.cached_value", side_effect=_cached)
class SubmitAddressStatusTests(SimpleTestCase):
    def status(self, html, public=PUBLIC):
        with patch("newsletter.form_views.MauticClient") as client:
            client.return_value.get_marketing_bridge_capabilities.return_value = {"publicUrl": public}
            return submit_address_status({"id": 31, "cachedHtml": html})

    def test_same_address_in_another_spelling_matches(self, _):
        self.assertEqual(self.status(rendered("https://MAUTIC.example.org:443"))["status"], "match")
        self.assertEqual(self.status(rendered("http://localhost:8088"), public="http://localhost:8088/")["status"], "match")

    def test_internal_or_other_host_is_a_mismatch(self, _):
        for base in ("http://mautic:80", "http://127.0.0.1:8088", "https://mautic.example.org:8443", "http://mautic.example.org"):
            with self.subTest(base=base):
                status = self.status(rendered(base))
                self.assertEqual((status["status"], status["stored"], status["expected"]), ("mismatch", base, PUBLIC))

    def test_other_forms_actions_and_missing_html_are_not_matched(self, _):
        self.assertEqual(self.status(rendered(PUBLIC, form_id=32))["status"], "missing")
        self.assertEqual(self.status("")["status"], "missing")

    def test_untrusted_or_missing_public_url_cannot_be_checked(self, _):
        for public in (None, "javascript:alert(1)", 'https://x.example/"><script>'):
            with self.subTest(public=public):
                self.assertEqual(self.status(rendered(PUBLIC), public=public)["status"], "public_url_unavailable")


@override_settings(**PER_USER_ON)
class SubmitAddressApiTests(_FormsApiBase):
    def setUp(self):
        super().setUp()
        self.service.get_marketing_bridge_capabilities.return_value = {"capabilities": [], "publicUrl": PUBLIC}
        cache = patch("newsletter.form_views.marketing_cache.cached_value", side_effect=_cached)
        cache.start()
        self.addCleanup(cache.stop)

    def test_details_report_the_submit_address(self):
        self.service.get_form.return_value = native_form(cachedHtml=rendered("http://mautic:80"))
        body = self.api.get(self.detail_url).json()
        self.assertEqual(body["submitAddress"]["status"], "mismatch")
        self.assertEqual(body["submitAddress"]["stored"], "http://mautic:80")

    def test_a_write_that_leaves_a_published_form_on_the_wrong_address_is_an_explicit_error(self):
        self.service.get_form.side_effect = [native_form(), native_form(isPublished=True, cachedHtml=rendered("http://mautic:80"))]
        response = self.api.post(self.publish_url)
        body = response.json()
        self.assertEqual((response.status_code, body["code"], body["saved"]), (409, "form_submit_address_mismatch", True))
        self.assertTrue(body["form"]["isPublished"])
        self.assertIn("http://mautic:80", body["detail"])

    def test_a_write_on_the_public_address_succeeds(self):
        self.service.get_form.side_effect = [native_form(), native_form(isPublished=True, cachedHtml=rendered(PUBLIC))]
        response = self.api.post(self.publish_url)
        self.assertEqual((response.status_code, response.json()["submitAddress"]["status"]), (200, "match"))

    def test_unpublished_form_reports_the_mismatch_without_failing(self):
        self.service.get_form.side_effect = [native_form(isPublished=True), native_form(cachedHtml=rendered("http://mautic:80"))]
        response = self.api.post(self.unpublish_url)
        self.assertEqual((response.status_code, response.json()["submitAddress"]["status"]), (200, "mismatch"))

    def test_settings_edit_preserves_structure_and_checks_the_address(self):
        before = native_form(isPublished=True, cachedHtml=rendered(PUBLIC))
        self.service.get_form.side_effect = [before, {**before, "description": "New", "cachedHtml": rendered("http://mautic:80")}]
        response = self.api.patch(self.detail_url, {"description": "New"}, format="json")
        self.assertEqual((response.status_code, response.json()["code"]), (409, "form_submit_address_mismatch"))
        self.asserted.update_form.assert_called_once()

    def test_request_host_headers_never_change_the_public_address(self):
        self.service.get_form.return_value = native_form(isPublished=True, cachedHtml=rendered(PUBLIC))
        url = reverse("newsletter-admin-form-embed", args=["31"])
        body = self.api.get(url, HTTP_HOST="localhost", HTTP_X_FORWARDED_HOST="attacker.example",
                            HTTP_X_FORWARDED_PROTO="http").json()
        self.assertEqual(body["publicUrl"], PUBLIC)
        self.assertNotIn("attacker.example", json.dumps(body))
        self.assertEqual(body["submitAddress"]["status"], "match")


class AuditCommandTests(TestCase):
    def test_reports_mismatched_forms_and_unsafe_form_campaigns_read_only(self):
        NewsletterCategory.objects.create(name="Updates", slug="updates", mautic_segment_id="61", is_active=True)
        with patch("newsletter.management.commands.audit_form_submission_safety.MauticClient") as client_cls, \
                patch("newsletter.form_views.MauticClient") as caps_cls, \
                patch("newsletter.form_views.marketing_cache.cached_value", side_effect=_cached):
            caps_cls.return_value.get_marketing_bridge_capabilities.return_value = {"publicUrl": PUBLIC}
            client = client_cls.return_value
            client.list_forms.return_value = {"total": 2, "forms": [{"id": 31}, {"id": 32}]}
            client.get_form.side_effect = lambda form_id: native_form(
                id=int(form_id), isPublished=True, cachedHtml=rendered(PUBLIC if form_id == "31" else "http://mautic:80", int(form_id)))
            client.list_campaigns.return_value = {"total": 2, "campaigns": [{"id": 5}, {"id": 6}]}
            client.get_campaign.side_effect = lambda cid: {
                "id": int(cid), "name": f"C{cid}", "isPublished": True,
                "forms": [{"id": 31}] if cid == "5" else [], "lists": [],
                "events": [{"id": 9, "type": "email.send", "eventType": "action", "name": "Mail",
                            "properties": {"email": 1, "email_type": "marketing"}, "parent": None}],
            }
            client.get_campaign_event_states.return_value = {"activeEventIds": [9]}
            out = StringIO()
            call_command("audit_form_submission_safety", "--json", stdout=out)
        report = json.loads(out.getvalue())
        self.assertEqual(report["mode"], "read-only")
        self.assertEqual(report["summary"]["forms_mismatched"], ["32"])
        self.assertEqual(report["summary"]["campaigns_with_unsafe_email"], ["5"])
        written = [name for name, *_ in client.method_calls
                   if name.split(".")[0].startswith(("update", "create", "set_", "delete", "publish"))]
        self.assertEqual(written, [])
