from datetime import timedelta
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.form_views import embed_snippets, native_submit_base, preview_document, validate_public_url
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.models import MauticIdentityAuditLog
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_admin_forms_api import PER_USER_ON, native_form

User = get_user_model()

CACHED_HTML = (
    '<style type="text/css">.mauticform_wrapper{max-width:600px}</style>'
    '<div id="mauticform_wrapper_inquiry"><form autocomplete="false" role="form" method="post" '
    'action="https://mautic.example.org/form/submit?formId=31" id="mauticforminquiry">'
    '<label class="mauticform-label">Email</label><span class="mauticform-required">*</span>'
    '<select name="mauticform[interest]"><option value="valuation">Valuation</option></select>'
    '<script>alert("never runs")</script><button type="submit">Send</button></form></div>'
)


class PreviewEmbedRuleTests(SimpleTestCase):
    def test_public_url_must_be_a_plain_web_address(self):
        self.assertEqual(validate_public_url("https://mautic.example.org/"), "https://mautic.example.org")
        self.assertEqual(validate_public_url("https://example.org/mautic"), "https://example.org/mautic")
        for value in (None, "", "javascript:alert(1)", "ftp://x.example", "https://u:p@x.example", "https://x.example?a=1",
                      'https://x.example/"><script>', "https://x.example/a b", "https://x.example:99999", "//x.example"):
            with self.subTest(value=value):
                self.assertIsNone(validate_public_url(value))

    def test_preview_document_is_inert(self):
        document = preview_document(CACHED_HTML)
        self.assertNotIn("<script", document)
        self.assertIn("Content-Security-Policy", document)
        self.assertIn("default-src 'none'", document)
        self.assertIn("form-action 'none'", document)
        self.assertIn('class="mauticform-required"', document)

    def test_embed_codes_match_mautics_own_formats(self):
        codes = {item["method"]: item["code"] for item in embed_snippets("https://mautic.example.org", "31")}
        self.assertEqual(codes["javascript"], '<script type="text/javascript" src="https://mautic.example.org/form/generate.js?id=31"></script>')
        self.assertEqual(codes["iframe"], '<iframe src="https://mautic.example.org/form/31" width="300" height="300" '
                                          'title="Embedded form"><p>Your browser does not support iframes.</p></iframe>')

    def test_native_submit_base_is_read_only_for_this_form(self):
        self.assertEqual(native_submit_base(CACHED_HTML, "31"), "https://mautic.example.org")
        self.assertIsNone(native_submit_base(CACHED_HTML, "32"))
        self.assertIsNone(native_submit_base("<p>no form</p>", "31"))


@override_settings(**PER_USER_ON)
class PreviewEmbedApiTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="preview-admin", email="preview-admin@example.test", password="x")
        grant_marketing_access(self.admin, mautic_user_id=6)
        self.api.force_authenticate(self.admin)
        self.service = Mock(name="service")
        self.service._uses_asserted_user.return_value = False
        self.service.get_marketing_bridge_capabilities.return_value = {"capabilities": [], "publicUrl": "https://mautic.example.org"}
        self.service.list_tags.return_value = {"tags": []}
        patcher = patch("newsletter.form_views.MauticClient", return_value=self.service)
        patcher.start()
        self.addCleanup(patcher.stop)
        cache = patch("newsletter.form_views.marketing_cache.cached_value", side_effect=lambda name, parts, build, ttl: build())
        cache.start()
        self.addCleanup(cache.stop)
        self.preview_url = reverse("newsletter-admin-form-preview", args=["31"])
        self.embed_url = reverse("newsletter-admin-form-embed", args=["31"])

    def form(self, **overrides):
        return native_form(**{"cachedHtml": CACHED_HTML, "publishUp": None, "publishDown": None, **overrides})

    def test_draft_preview_is_rendered_from_the_saved_native_html_without_a_public_url(self):
        self.service.get_form.return_value = self.form(isPublished=False)
        response = self.api.get(self.preview_url)
        body = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual((body["isPublished"], body["isLive"], body["liveUrl"]), (False, False, None))
        self.assertNotIn("<script", body["document"])
        self.assertIn("last saved version", body["note"])
        self.assertEqual(response["Cache-Control"], "no-store, private")
        self.service.set_form_published.assert_not_called()

    def test_published_preview_offers_the_live_public_page(self):
        self.service.get_form.return_value = self.form(isPublished=True)
        body = self.api.get(self.preview_url).json()
        self.assertEqual((body["isLive"], body["liveUrl"]), (True, "https://mautic.example.org/form/31"))

    def test_publish_window_decides_liveness(self):
        future = (timezone.now() + timedelta(days=1)).isoformat()
        past = (timezone.now() - timedelta(days=1)).isoformat()
        self.service.get_form.return_value = self.form(isPublished=True, publishUp=future)
        self.assertFalse(self.api.get(self.preview_url).json()["isLive"])
        self.service.get_form.return_value = self.form(isPublished=True, publishDown=past)
        self.assertFalse(self.api.get(self.preview_url).json()["isLive"])
        self.service.get_form.return_value = self.form(isPublished=True, publishUp="2026-01-01 00:00:00")  # naive = UTC
        self.assertTrue(self.api.get(self.preview_url).json()["isLive"])

    def test_preview_needs_rendered_html(self):
        self.service.get_form.return_value = native_form(cachedHtml="")
        response = self.api.get(self.preview_url)
        self.assertEqual((response.status_code, response.json()["code"]), (409, "form_preview_unavailable"))

    def test_embed_codes_use_mautics_public_url_and_warn(self):
        self.service.get_form.return_value = self.form(isPublished=False, cachedHtml=CACHED_HTML.replace("https://mautic.example.org", "http://mautic-internal:8080"))
        body = self.api.get(self.embed_url).json()
        self.assertEqual(body["publicUrl"], "https://mautic.example.org")
        self.assertIn('src="https://mautic.example.org/form/generate.js?id=31"', body["methods"][0]["code"])
        self.assertEqual(body["submitBase"], "http://mautic-internal:8080")
        self.assertEqual(len(body["warnings"]), 2)  # not published + submit address mismatch
        self.service.set_form_published.assert_not_called()
        self.assertFalse(MauticIdentityAuditLog.objects.exists())

    def test_embed_codes_never_carry_credentials_or_assertions(self):
        self.service.get_form.return_value = self.form(isPublished=True)
        content = self.api.get(self.embed_url).content.decode()
        for secret in ("api-user", "secret", "X-ECP-Identity", "Bearer", "sessionid"):
            self.assertNotIn(secret, content)

    def test_unsafe_or_missing_public_url_refuses_embed_codes(self):
        self.service.get_form.return_value = self.form(isPublished=True)
        for value in (None, "javascript:alert(1)", 'https://x.example/"><script>'):
            with self.subTest(value=value):
                self.service.get_marketing_bridge_capabilities.return_value = {"capabilities": [], "publicUrl": value}
                response = self.api.get(self.embed_url)
                self.assertEqual((response.status_code, response.json()["code"]), (503, "form_public_url_unavailable"))
        self.service.get_marketing_bridge_capabilities.side_effect = TemporaryMauticError("down")
        self.assertEqual(self.api.get(self.embed_url).status_code, 503)

    def test_errors_and_access(self):
        self.assertEqual(self.api.get(reverse("newsletter-admin-form-preview", args=["x"])).status_code, 400)
        self.service.get_form.side_effect = PermanentMauticError("Mautic API request failed (HTTP 404)")
        self.assertEqual(self.api.get(self.embed_url).status_code, 404)
        other = APIClient()
        other.force_authenticate(User.objects.create_user(username="preview-normal", email="pn@example.test", password="x"))
        for client in (other, APIClient()):
            for url in (self.preview_url, self.embed_url):
                self.assertIn(client.get(url).status_code, (401, 403))
