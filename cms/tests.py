from django.test import TestCase
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from unittest.mock import patch

from cms.models import EmailTemplate, TEMPLATE_KEY_CHOICES
from django.template import Template, Context


class EmailTemplateTests(TestCase):
    def test_template_creation(self):
        """Test creating an email template."""
        tmpl = EmailTemplate.objects.create(
            template_key="test_simple",
            subject="Test Subject {{ app_name }}",
            html_body="<p>Hello {{ first_name }}</p>",
            text_body="Hello {{ first_name }}",
            is_active=True,
        )
        self.assertEqual(tmpl.template_key, "test_simple")
        self.assertTrue(tmpl.is_active)

    def test_validation_invalid_syntax(self):
        """Test that invalid Django syntax is caught."""
        tmpl = EmailTemplate(
            template_key="test_invalid",
            subject="Test",
            html_body="{% invalid %}",
            text_body="Test",
        )
        with self.assertRaises(ValidationError) as cm:
            tmpl.full_clean()
        self.assertIn("html_body", cm.exception.error_dict)

    def test_validation_missing_placeholder(self):
        """Test that missing required placeholders are caught."""
        tmpl = EmailTemplate(
            template_key="event_invite",
            subject="Test",
            html_body="<p>Join {{ event_title }}</p>",  # Missing {{ invite_url }}
            text_body="Test",
        )
        with self.assertRaises(ValidationError) as cm:
            tmpl.full_clean()
        self.assertIn("html_body", cm.exception.error_dict)
        self.assertIn("{{ invite_url }}", str(cm.exception))

    def test_template_rendering(self):
        """Test rendering a template with context."""
        event_invite = EmailTemplate.objects.create(
            template_key="event_invite",
            subject="You're invited to {{ event_title }}",
            html_body="<p>{{ inviter_name }} invited you to {{ event_title }}: {{ invite_url }}</p>",
            text_body="Join {{ event_title }} at {{ invite_url }}",
        )
        ctx = Context({
            "app_name": "IMAA Connect",
            "inviter_name": "John Doe",
            "event_title": "M&A Summit",
            "invite_url": "https://example.com/invite",
            "support_email": "support@example.com",
        })
        
        subject = Template(event_invite.subject).render(ctx)
        self.assertIn("M&A Summit", subject)
        
        html = Template(event_invite.html_body).render(ctx)
        self.assertIn("John Doe", html)
        self.assertIn("https://example.com/invite", html)

    def test_str_representation(self):
        """Test string representation of template."""
        tmpl = EmailTemplate.objects.create(
            template_key="test_str",
            subject="Test",
            html_body="<p>Test</p>",
            text_body="Test",
            is_active=True,
        )
        self.assertEqual(str(tmpl), "Test Str (active)")

        tmpl.is_active = False
        tmpl.save()
        self.assertEqual(str(tmpl), "Test Str (inactive)")

    def test_template_key_choices_include_expected_templates(self):
        """Test that the CMS exposes the current global template keys."""
        keys = {key for key, _label in TEMPLATE_KEY_CHOICES}
        self.assertIn("welcome", keys)
        self.assertIn("networking_meeting_reminder", keys)
        self.assertEqual(len(keys), len(TEMPLATE_KEY_CHOICES))


class EmailTemplateApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin = User.objects.create_superuser(
            username="admin",
            email="admin@example.com",
            password="pass123",
        )
        self.client.force_authenticate(self.admin)

    def test_list_returns_all_template_keys(self):
        response = self.client.get("/api/cms/email-templates/")
        self.assertEqual(response.status_code, 200)
        returned_keys = {item["template_key"] for item in response.data}
        expected_keys = {key for key, _label in TEMPLATE_KEY_CHOICES}
        self.assertEqual(returned_keys, expected_keys)
        self.assertEqual(len(response.data), len(TEMPLATE_KEY_CHOICES))

    @patch("cms.api.compile_mjml")
    def test_patch_saves_editor_json_mjml_and_html(self, mock_compile_mjml):
        mock_compile_mjml.return_value = "<p>Hello {{ first_name }} from {{ app_name }}</p>"
        response = self.client.patch(
            "/api/cms/email-templates/welcome/",
            {
                "subject": "Hi {{ first_name }}",
                "mjml_body": "<mjml><mj-body>{{ first_name }} {{ app_name }}</mj-body></mjml>",
                "text_body": "Hello {{ first_name }} from {{ app_name }}",
                "editor_json": {"blocks": [{"type": "text"}]},
            },
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.data)
        template = EmailTemplate.objects.get(template_key="welcome")
        self.assertEqual(template.editor_json["blocks"][0]["type"], "text")
        self.assertIn("{{ first_name }}", template.mjml_body)
        self.assertIn("{{ app_name }}", template.html_body)
        self.assertEqual(template.updated_by, self.admin)

    def test_preview_renders_variables(self):
        EmailTemplate.objects.create(
            template_key="welcome",
            subject="Welcome {{ first_name }}",
            html_body="<p>Hello {{ first_name }} from {{ app_name }}</p>",
            text_body="Hello {{ first_name }} from {{ app_name }}",
        )
        response = self.client.post("/api/cms/email-templates/welcome/preview/", {}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["rendered_subject"], "Welcome Alex")
        self.assertIn("IMAA Connect", response.data["rendered_html"])

    def test_required_placeholder_validation_works(self):
        response = self.client.patch(
            "/api/cms/email-templates/welcome/",
            {
                "subject": "Welcome",
                "html_body": "<p>Hello only</p>",
                "text_body": "Hello",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("{{ first_name }}", str(response.data))

    def test_reset_restores_file_default(self):
        EmailTemplate.objects.create(
            template_key="welcome",
            subject="Changed {{ first_name }}",
            html_body="<p>Changed {{ first_name }} {{ app_name }}</p>",
            text_body="Changed",
            editor_json={"changed": True},
            mjml_body="<mjml></mjml>",
            is_active=False,
        )
        response = self.client.post("/api/cms/email-templates/welcome/reset/", {}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        template = EmailTemplate.objects.get(template_key="welcome")
        self.assertTrue(template.is_active)
        self.assertIsNone(template.editor_json)
        self.assertEqual(template.mjml_body, "")
        self.assertEqual(template.subject, "Welcome to {{ app_name }}")
        self.assertIn("{{ first_name }}", template.html_body)
