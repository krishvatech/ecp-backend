from django.test import TestCase
from django.core.exceptions import ValidationError
from cms.models import EmailTemplate
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
        event_invite = EmailTemplate.objects.get(template_key="event_invite")
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

    def test_all_17_templates_exist(self):
        """Test that all 17 templates are in the database."""
        count = EmailTemplate.objects.count()
        self.assertEqual(count, 17, f"Expected 17 templates, found {count}")
        
        # Verify specific templates
        expected_keys = [
            "welcome", "password_changed", "speaker_credentials",
            "admin_credentials", "event_confirmation", "event_cancelled",
            "event_invite", "group_invite", "replay_no_show", "replay_partial",
            "kyc_approved", "kyc_failed", "name_change_approved",
            "name_change_manual_review", "name_change_verification_failed",
            "name_change_rejected", "admin_name_change_review",
        ]
        for key in expected_keys:
            exists = EmailTemplate.objects.filter(template_key=key).exists()
            self.assertTrue(exists, f"Template '{key}' not found")
