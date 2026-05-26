from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase

from cms.models import EmailTemplate
from community.models import Community
from events.email_template_api import (
    get_event_email_template_payload,
    render_event_email_payload,
)
from events.models import Event, EventEmailTemplate
from users.email_utils import send_template_email


class EventEmailTemplateTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="owner",
            email="owner@example.com",
            password="pass123",
            first_name="Owner",
        )
        self.community = Community.objects.create(name="Email Community", created_by=self.owner)
        self.event = Event.objects.create(
            community=self.community,
            title="Event Override Summit",
            created_by=self.owner,
            timezone="Asia/Kolkata",
        )

    def test_event_specific_payload_overrides_global_template(self):
        EmailTemplate.objects.create(
            template_key="event_join_confirmation",
            subject="Global {{ event_title }}",
            html_body="<p>Global {{ first_name }} {{ event_title }} {{ event_url }}</p>",
            text_body="Global {{ first_name }} {{ event_title }} {{ event_url }}",
            is_active=True,
        )
        EventEmailTemplate.objects.create(
            event=self.event,
            template_key="event_join_confirmation",
            subject="Event {{ event_title }}",
            html_body="<p>Event {{ first_name }} {{ event_title }} {{ event_url }}</p>",
            text_body="Event {{ first_name }} {{ event_title }} {{ event_url }}",
            is_active=True,
        )

        payload = get_event_email_template_payload(self.event, "event_join_confirmation")

        self.assertEqual(payload["source"], "event_specific")
        self.assertEqual(payload["subject"], "Event {{ event_title }}")

    def test_reset_falls_back_to_global_template(self):
        global_template = EmailTemplate.objects.create(
            template_key="event_join_confirmation",
            subject="Global {{ event_title }}",
            html_body="<p>Global {{ first_name }} {{ event_title }} {{ event_url }}</p>",
            text_body="Global {{ first_name }} {{ event_title }} {{ event_url }}",
            is_active=True,
        )
        EventEmailTemplate.objects.create(
            event=self.event,
            template_key="event_join_confirmation",
            subject="Event {{ event_title }}",
            html_body="<p>Event {{ first_name }} {{ event_title }} {{ event_url }}</p>",
            text_body="Event {{ first_name }} {{ event_title }} {{ event_url }}",
            is_active=True,
        )

        EventEmailTemplate.objects.filter(event=self.event, template_key="event_join_confirmation").delete()
        payload = get_event_email_template_payload(self.event, "event_join_confirmation")

        self.assertEqual(payload["source"], "global_default")
        self.assertEqual(payload["subject"], global_template.subject)

    def test_preview_uses_actual_event_data(self):
        payload = {
            "subject": "Preview {{ event_title }}",
            "html_body": "<p>{{ event_title }} {{ event_url }}</p>",
            "text_body": "{{ event_title }} {{ event_url }}",
            "mjml_body": "",
        }

        rendered = render_event_email_payload(
            self.event,
            "event_join_confirmation",
            payload,
            user=self.owner,
        )

        self.assertIn("Event Override Summit", rendered["rendered_subject"])
        self.assertIn("Event Override Summit", rendered["rendered_html"])
        self.assertIn(str(self.event.slug or self.event.id), rendered["rendered_html"])

    @patch("users.email_utils.send_platform_email")
    def test_send_template_email_uses_event_specific_template(self, mock_send_platform_email):
        mock_send_platform_email.return_value = 1
        EventEmailTemplate.objects.create(
            event=self.event,
            template_key="event_join_confirmation",
            subject="Event subject {{ event_title }}",
            html_body="<p>Event body {{ first_name }} {{ event_title }} {{ event_url }}</p>",
            text_body="Event body {{ first_name }} {{ event_title }} {{ event_url }}",
            is_active=True,
        )

        sent = send_template_email(
            template_key="event_join_confirmation",
            to_email="alex@example.com",
            context={
                "first_name": "Alex",
                "event_title": self.event.title,
                "event_url": "/events/test/",
            },
            event=self.event,
        )

        self.assertTrue(sent)
        kwargs = mock_send_platform_email.call_args.kwargs
        self.assertEqual(kwargs["subject"], "Event subject Event Override Summit")
        self.assertIn("Event body Alex Event Override Summit", kwargs["html_message"])
