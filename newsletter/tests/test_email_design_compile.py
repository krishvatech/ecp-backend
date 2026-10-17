from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from rest_framework import serializers
from rest_framework.test import APIClient

from newsletter.email_design_services import (
    MAX_MJML_BYTES,
    EmailDesignCompileError,
    compile_marketing_mjml,
)
from newsletter.models import MauticIdentityAuditLog
from newsletter.tests.marketing_actors import grant_marketing_access


User = get_user_model()

# Shaped like @templatical/renderer output: tokens in text, links and buttons.
DESIGN_MJML = """<mjml lang="en">
  <mj-head><mj-attributes><mj-all font-family="Arial, sans-serif" /></mj-attributes></mj-head>
  <mj-body width="600px">
    <mj-section>
      <mj-column>
        <mj-text>Hello {contactfield=firstname} from {companyfield=companyname} &amp; team</mj-text>
        <mj-button href="{webview_url}">View in browser</mj-button>
        <mj-image src="https://cdn.example.com/hero.png" alt="Hero" href="https://imaa.example.com" />
        <mj-text><a href="{unsubscribe_url}">Unsubscribe</a></mj-text>
      </mj-column>
    </mj-section>
  </mj-body>
</mjml>"""


class CompileMarketingMjmlTests(SimpleTestCase):
    """Runs the real CMS compiler (mrml, or the mjml CLI fallback)."""

    def test_compiles_html_and_preserves_every_mautic_token(self):
        result = compile_marketing_mjml(DESIGN_MJML)

        html = result["html"]
        self.assertIn("<html", html.lower())
        self.assertIn("Hello {contactfield=firstname} from {companyfield=companyname}", html)
        self.assertIn('href="{webview_url}"', html)
        self.assertIn('href="{unsubscribe_url}"', html)
        self.assertIn('src="https://cdn.example.com/hero.png"', html)
        self.assertNotIn("data-merge-tag", html)
        self.assertEqual(
            result["tokens"],
            [
                "{companyfield=companyname}",
                "{contactfield=firstname}",
                "{unsubscribe_url}",
                "{webview_url}",
            ],
        )

    def test_rejects_missing_or_non_mjml_input(self):
        for value in (None, "", "   ", 42, ["<mjml/>"], "<html><body>x</body></html>"):
            with self.subTest(value=value), self.assertRaises(EmailDesignCompileError):
                compile_marketing_mjml(value)

    def test_rejects_oversized_input_before_compiling(self):
        oversized = "<mjml><mj-body>" + ("x" * MAX_MJML_BYTES) + "</mj-body></mjml>"
        with patch("newsletter.email_design_services.compile_mjml") as compiler:
            with self.assertRaisesMessage(EmailDesignCompileError, "cannot exceed"):
                compile_marketing_mjml(oversized)
        compiler.assert_not_called()

    def test_rejects_mj_include_so_server_files_are_never_read(self):
        mjml = '<mjml><mj-body><mj-include path="/etc/passwd" /></mj-body></mjml>'
        with patch("newsletter.email_design_services.compile_mjml") as compiler:
            with self.assertRaisesMessage(EmailDesignCompileError, "<mj-include> is not allowed"):
                compile_marketing_mjml(mjml)
        compiler.assert_not_called()

    def test_malformed_mjml_returns_the_compiler_error(self):
        with self.assertRaisesMessage(EmailDesignCompileError, "MJML compilation failed"):
            compile_marketing_mjml("<mjml><mj-body><mj-section>")

    def test_missing_compiler_is_reported_not_raised_as_server_error(self):
        error = serializers.ValidationError({"mjml_body": "MJML compiler is not installed."})
        with patch("newsletter.email_design_services.compile_mjml", side_effect=error):
            with self.assertRaisesMessage(EmailDesignCompileError, "MJML compiler is not installed."):
                compile_marketing_mjml(DESIGN_MJML)

    def test_rejects_script_urls_and_script_tags(self):
        script_link = (
            '<mjml><mj-body><mj-section><mj-column>'
            '<mj-button href="javascript:alert(1)">Go</mj-button>'
            "</mj-column></mj-section></mj-body></mjml>"
        )
        script_tag = (
            "<mjml><mj-body><mj-raw><script>alert(1)</script></mj-raw></mj-body></mjml>"
        )
        for mjml in (script_link, script_tag):
            with self.subTest(mjml=mjml), self.assertRaisesMessage(
                EmailDesignCompileError, "Scripts are not allowed"
            ):
                compile_marketing_mjml(mjml)

    def test_a_token_lost_in_compilation_is_an_error(self):
        compiled = "<html><body>Hello {contactfield=firstname}</body></html>"
        with patch("newsletter.email_design_services.compile_mjml", return_value=compiled):
            with self.assertRaisesMessage(
                EmailDesignCompileError, "{unsubscribe_url}, {webview_url}"
            ):
                compile_marketing_mjml(DESIGN_MJML.replace("{companyfield=companyname}", ""))

    def test_empty_compiler_output_is_an_error(self):
        with patch("newsletter.email_design_services.compile_mjml", return_value="  "):
            with self.assertRaisesMessage(EmailDesignCompileError, "produced no HTML"):
                compile_marketing_mjml(DESIGN_MJML)


class EmailDesignCompileAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("newsletter-admin-email-design-compile")
        self.marketer = User.objects.create_user(
            username="design-marketer",
            email="design-marketer@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        grant_marketing_access(self.marketer)

    def test_marketing_user_gets_compiled_html_without_any_mautic_call(self):
        self.client.force_authenticate(user=self.marketer)
        with patch("newsletter.mautic.client.MauticClient._request") as provider:
            response = self.client.post(self.url, {"mjml": DESIGN_MJML}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertIn('href="{unsubscribe_url}"', response.data["html"])
        self.assertIn("{contactfield=firstname}", response.data["tokens"])
        provider.assert_not_called()
        self.assertFalse(MauticIdentityAuditLog.objects.exists())

    def test_invalid_mjml_is_a_400_with_detail(self):
        self.client.force_authenticate(user=self.marketer)

        for body in ({"mjml": "<p>not mjml</p>"}, {}, ["<mjml></mjml>"]):
            with self.subTest(body=body):
                response = self.client.post(self.url, body, format="json")
                self.assertEqual(response.status_code, 400)
                self.assertIn("detail", response.data)

    def test_users_without_marketing_access_are_refused(self):
        staff_only = User.objects.create_user(
            username="design-staff",
            email="design-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        superuser_without_mapping = User.objects.create_user(
            username="design-super",
            email="design-super@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )

        anonymous = self.client.post(self.url, {"mjml": DESIGN_MJML}, format="json")
        self.assertIn(anonymous.status_code, (401, 403))

        for user in (staff_only, superuser_without_mapping):
            with self.subTest(user=user.username):
                self.client.force_authenticate(user=user)
                response = self.client.post(self.url, {"mjml": DESIGN_MJML}, format="json")
                self.assertEqual(response.status_code, 403)

    def test_get_is_not_allowed(self):
        self.client.force_authenticate(user=self.marketer)
        self.assertEqual(self.client.get(self.url).status_code, 405)
