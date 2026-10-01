from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.exceptions import MauticBridgeRejectedError
from newsletter.models import MauticIdentityAuditLog, MauticUserConnection
from newsletter.mautic.operations import (
    NEWSLETTER_TEST_SEND,
    TEMPLATE_CREATE,
    TEMPLATE_DELETE,
    TEMPLATE_DUPLICATE,
    TEMPLATE_UPDATE,
)
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_user_identity import IDENTITY_SETTINGS


User = get_user_model()


@override_settings(ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False)
class NewsletterAdminTemplatesAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="templates-staff",
            email="templates-staff@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        grant_marketing_access(self.staff)
        self.normal_user = User.objects.create_user(
            username="templates-normal",
            email="templates-normal@example.test",
            password="test-password",
        )
        self.list_url = reverse("newsletter-admin-template-list")
        self.detail_url = reverse(
            "newsletter-admin-template-detail",
            args=["18"],
        )
        self.duplicate_url = reverse(
            "newsletter-admin-template-duplicate",
            args=["18"],
        )
        self.preview_url = reverse(
            "newsletter-admin-template-preview",
            args=["18"],
        )
        self.test_send_url = reverse(
            "newsletter-admin-template-test-send",
            args=["18"],
        )
        self.usage_url = reverse(
            "newsletter-admin-template-usage",
            args=["18"],
        )

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    @staticmethod
    def _template(**overrides):
        data = {
            "id": 18,
            "name": "Reusable Newsletter",
            "subject": "Monthly update",
            "preheaderText": "What changed this month",
            "fromName": "IMAA Connect",
            "fromAddress": "eventncommunity@gmail.com",
            "plainText": "Plain content",
            "customHtml": "<h1>HTML content</h1>",
            "emailType": "template",
            "category": {"id": 4, "title": "Email Updates"},
            "template": "blank",
            "isPublished": False,
            "dateAdded": "2026-09-09T06:00:00+00:00",
            "dateModified": "2026-09-09T06:10:00+00:00",
            "sentCount": 0,
            "readCount": 0,
        }
        data.update(overrides)
        return data

    def test_guest_and_normal_user_are_denied(self):
        for url in (self.list_url, self.detail_url):
            response = self.client.get(url)
            self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        for url in (self.list_url, self.detail_url):
            self.assertEqual(self.client.get(url).status_code, 403)

    @patch("newsletter.template_views.MauticClient")
    def test_list_forwards_search_pagination_and_normalizes(self, client_cls):
        client = client_cls.return_value
        client.list_email_templates.return_value = {
            "total": 1,
            "start": 25,
            "limit": 25,
            "emails": [self._template()],
        }
        self._authenticate(self.staff)

        response = self.client.get(
            self.list_url,
            {
                "page": 2,
                "page_size": 25,
                "search": "Reusable",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["page"], 2)
        self.assertEqual(response.data["page_size"], 25)
        self.assertEqual(response.data["results"][0]["id"], "18")
        self.assertEqual(
            response.data["results"][0]["emailType"],
            "template",
        )
        client.list_email_templates.assert_called_once_with(
            start=25,
            limit=25,
            search="Reusable",
        )

    @patch("newsletter.template_views.MauticClient")
    def test_list_accepts_empty_provider_result(self, client_cls):
        client_cls.return_value.list_email_templates.return_value = {
            "total": 0,
            "start": 0,
            "limit": 25,
            "emails": [],
        }
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 0)
        self.assertEqual(response.data["num_pages"], 0)
        self.assertEqual(response.data["results"], [])

    @patch("newsletter.template_views.MauticClient")
    def test_create_validates_and_normalizes_payload(self, client_cls):
        client = client_cls.return_value
        client.create_email_template.return_value = self._template()
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {
                "name": " Reusable Newsletter ",
                "subject": " Monthly update ",
                "preheaderText": "What changed this month",
                "fromName": " IMAA Connect ",
                "fromAddress": " eventncommunity@gmail.com ",
                "plainText": "Plain content",
                "customHtml": "<h1>HTML content</h1>",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["id"], "18")
        client.create_email_template.assert_called_once_with(
            {
                "name": "Reusable Newsletter",
                "subject": "Monthly update",
                "preheaderText": "What changed this month",
                "fromName": "IMAA Connect",
                "fromAddress": "eventncommunity@gmail.com",
                "plainText": "Plain content",
                "customHtml": "<h1>HTML content</h1>",
                "isPublished": False,
            }
        )

    @patch("newsletter.template_views.MauticClient")
    def test_create_supports_explicit_publish_state(self, client_cls):
        client = client_cls.return_value
        client.create_email_template.return_value = self._template(
            isPublished=True
        )
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {
                "name": "Published Template",
                "isPublished": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        client.create_email_template.assert_called_once_with(
            {
                "name": "Published Template",
                "isPublished": True,
            }
        )

    @patch("newsletter.template_views.run_interactive_mutation")
    def test_create_uses_template_create_identity_operation(self, helper):
        helper.return_value = (self._template(), None)
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {"name": "Reusable Newsletter"},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(helper.call_args.kwargs["action"], TEMPLATE_CREATE)
        self.assertEqual(helper.call_args.kwargs["resource"], "template")
        self.assertNotIn("resource_id", helper.call_args.kwargs)

    @patch("newsletter.template_views.MauticClient")
    def test_create_rejects_invalid_payloads(self, client_cls):
        self._authenticate(self.staff)
        invalid_payloads = (
            {"name": ""},
            {"name": "A", "unknown": 1},
            {"name": "A", "description": "Not supported by Mautic Email API"},
            {"name": "A", "isPublished": "maybe"},
            {"name": "A", "fromAddress": "not-an-email"},
            {"name": "A" * 191},
            {"name": "A", "subject": "S" * 191},
        )

        for payload in invalid_payloads:
            response = self.client.post(
                self.list_url,
                payload,
                format="json",
            )
            self.assertEqual(response.status_code, 400)

        client_cls.return_value.create_email_template.assert_not_called()

    @patch("newsletter.template_views.MauticClient")
    def test_detail_get_returns_template(self, client_cls):
        client = client_cls.return_value
        client.get_email_template.return_value = self._template()
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["id"], "18")
        self.assertEqual(response.data["name"], "Reusable Newsletter")
        self.assertFalse(response.data["isPublished"])
        self.assertEqual(response.data["category"]["id"], "4")
        self.assertEqual(response.data["template"], "blank")
        client.get_email_template.assert_called_once_with("18")

    @patch("newsletter.template_views.MauticClient")
    def test_patch_updates_only_supplied_fields(self, client_cls):
        client = client_cls.return_value
        client.update_email_template.return_value = self._template(
            name="Updated Newsletter",
            isPublished=True,
        )
        self._authenticate(self.staff)

        response = self.client.patch(
            self.detail_url,
            {
                "name": " Updated Newsletter ",
                "isPublished": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["name"], "Updated Newsletter")
        self.assertTrue(response.data["isPublished"])
        client.update_email_template.assert_called_once_with(
            "18",
            {
                "name": "Updated Newsletter",
                "isPublished": True,
            },
        )

    @patch("newsletter.template_views.run_interactive_mutation")
    def test_patch_uses_template_update_identity_operation(self, helper):
        helper.return_value = (self._template(name="Updated Newsletter"), None)
        self._authenticate(self.staff)

        response = self.client.patch(
            self.detail_url,
            {"name": "Updated Newsletter"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(helper.call_args.kwargs["action"], TEMPLATE_UPDATE)
        self.assertEqual(helper.call_args.kwargs["resource"], "template")
        self.assertEqual(helper.call_args.kwargs["resource_id"], "18")

    @patch("newsletter.template_views.MauticClient")
    def test_patch_rejects_empty_or_unsupported_payload(self, client_cls):
        self._authenticate(self.staff)

        response = self.client.patch(
            self.detail_url,
            {},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.patch(
            self.detail_url,
            {"emailType": "list"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        client_cls.return_value.update_email_template.assert_not_called()

    @patch("newsletter.template_views.MauticClient")
    def test_delete_removes_provider_template(self, client_cls):
        client = client_cls.return_value
        self._authenticate(self.staff)

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 204)
        client.delete_email_template.assert_called_once_with("18")

    @patch("newsletter.template_views.run_interactive_mutation")
    def test_delete_uses_template_delete_identity_operation(self, helper):
        helper.return_value = ({}, None)
        self._authenticate(self.staff)

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 204)
        self.assertEqual(helper.call_args.kwargs["action"], TEMPLATE_DELETE)
        self.assertEqual(helper.call_args.kwargs["resource"], "template")
        self.assertEqual(helper.call_args.kwargs["resource_id"], "18")

    @patch("newsletter.template_views.MauticClient")
    def test_duplicate_creates_provider_draft_copy(self, client_cls):
        client = client_cls.return_value
        client.duplicate_email_template.return_value = self._template(
            id=22,
            name="Reusable Newsletter Copy",
        )
        self._authenticate(self.staff)

        response = self.client.post(self.duplicate_url, {}, format="json")

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["id"], "22")
        client.duplicate_email_template.assert_called_once_with("18", name=None)

    @patch("newsletter.template_views.run_interactive_mutation")
    def test_duplicate_uses_template_duplicate_identity_operation(self, helper):
        helper.return_value = (
            self._template(id=22, name="Reusable Newsletter Copy"),
            None,
        )
        self._authenticate(self.staff)

        response = self.client.post(self.duplicate_url, {}, format="json")

        self.assertEqual(response.status_code, 201)
        self.assertEqual(helper.call_args.kwargs["action"], TEMPLATE_DUPLICATE)
        self.assertEqual(helper.call_args.kwargs["resource"], "template")
        self.assertEqual(helper.call_args.kwargs["resource_id"], "18")

    @patch("newsletter.template_views.MauticClient")
    def test_preview_returns_raw_html_preview_contract(self, client_cls):
        client_cls.return_value.get_email_template.return_value = self._template()
        self._authenticate(self.staff)

        response = self.client.get(self.preview_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["type"], "raw_html")
        self.assertEqual(response.data["tokenResolution"], "placeholders_only")
        self.assertEqual(response.data["html"], "<h1>HTML content</h1>")

    def _stub_test_send(self, client_cls, *, existing_contact=None):
        client = client_cls.return_value
        client.get_email_template.return_value = self._template()
        client.create_email.return_value = {"id": 901, "emailType": "template"}
        client.find_contact_by_email.return_value = existing_contact
        client.create_disposable_contact.return_value = ({"id": 77}, True)
        client.send_email_to_contact.return_value = {"success": True}
        return client

    def _post_test_send(self, email="admin@example.test"):
        return self.client.post(self.test_send_url, {"email": email}, format="json")

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_delivers_a_temporary_copy_to_a_temporary_contact(self, client_cls):
        client = self._stub_test_send(client_cls)
        self._authenticate(self.staff)

        response = self._post_test_send(" Admin@Example.TEST ")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data,
            {"success": True, "recipient_email": "admin@example.test"},
        )
        client.get_email_template.assert_called_once_with("18")
        payload = client.create_email.call_args.args[0]
        self.assertEqual(payload["name"], "Reusable Newsletter - Test")
        self.assertEqual(payload["subject"], "Monthly update")
        self.assertEqual(payload["preheaderText"], "What changed this month")
        self.assertEqual(payload["fromName"], "IMAA Connect")
        self.assertEqual(payload["fromAddress"], "eventncommunity@gmail.com")
        self.assertEqual(payload["customHtml"], "<h1>HTML content</h1>")
        self.assertEqual(payload["plainText"], "Plain content")
        self.assertEqual(payload["template"], "blank")
        self.assertEqual(payload["emailType"], "template")
        self.assertIs(payload["isPublished"], True)
        client.find_contact_by_email.assert_called_once_with("admin@example.test")
        client.create_disposable_contact.assert_called_once_with("admin@example.test")
        # The copy is sent, never the real Template, so its stats stay untouched.
        client.send_email_to_contact.assert_called_once_with("901", "77")
        client.delete_email.assert_called_once_with("901")
        client.delete_contact.assert_called_once_with("77")
        # The real Template is only read.
        client.update_email_template.assert_not_called()
        client.delete_email_template.assert_not_called()

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_reuses_and_keeps_an_existing_contact(self, client_cls):
        client = self._stub_test_send(client_cls, existing_contact={"id": 55})
        self._authenticate(self.staff)

        response = self._post_test_send("known@example.test")

        self.assertEqual(response.status_code, 200)
        client.create_disposable_contact.assert_not_called()
        client.send_email_to_contact.assert_called_once_with("901", "55")
        client.delete_email.assert_called_once_with("901")
        client.delete_contact.assert_not_called()

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_keeps_a_contact_mautic_matched_to_an_existing_record(self, client_cls):
        # Our lookup found nothing, but Mautic's create matched an existing
        # contact (HTTP 200): ownership is not proven, so it is never deleted.
        client = self._stub_test_send(client_cls)
        client.create_disposable_contact.return_value = ({"id": 88}, False)
        self._authenticate(self.staff)

        with self.assertLogs("newsletter.campaign_services", level="WARNING") as logs:
            response = self._post_test_send("raced@example.test")

        self.assertEqual(response.status_code, 200)
        client.send_email_to_contact.assert_called_once_with("901", "88")
        client.delete_email.assert_called_once_with("901")
        client.delete_contact.assert_not_called()
        self.assertIn("template test recipient to existing contact id=88", "\n".join(logs.output))

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_rejects_invalid_recipients_before_contacting_mautic(self, client_cls):
        self._authenticate(self.staff)

        for payload in ({}, {"email": ""}, {"email": "   "}, {"email": "not-an-email"}):
            response = self.client.post(self.test_send_url, payload, format="json")
            self.assertEqual(response.status_code, 400, payload)
            self.assertIn("recipient", response.data["detail"])

        client_cls.assert_not_called()

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_of_a_missing_template_is_not_found(self, client_cls):
        client = self._stub_test_send(client_cls)
        client.get_email_template.side_effect = PermanentMauticError(
            "Mautic email lookup failed with HTTP 404"
        )
        self._authenticate(self.staff)

        response = self._post_test_send()

        self.assertEqual(response.status_code, 404)
        client.create_email.assert_not_called()
        client.send_email_to_contact.assert_not_called()

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_of_a_non_template_email_is_not_found(self, client_cls):
        client = self._stub_test_send(client_cls)
        client.get_email_template.side_effect = PermanentMauticError(
            "Mautic email is not a Mautic template email"
        )
        self._authenticate(self.staff)

        response = self._post_test_send()

        self.assertEqual(response.status_code, 404)
        client.create_email.assert_not_called()

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_requires_a_subject_and_content(self, client_cls):
        client = self._stub_test_send(client_cls)
        self._authenticate(self.staff)

        client.get_email_template.return_value = self._template(subject="")
        response = self._post_test_send()
        self.assertEqual(response.status_code, 400)
        self.assertIn("subject", response.data["detail"])

        client.get_email_template.return_value = self._template(
            customHtml="   ",
            plainText="",
        )
        response = self._post_test_send()
        self.assertEqual(response.status_code, 400)
        self.assertIn("content", response.data["detail"])

        client.create_email.assert_not_called()
        client.create_disposable_contact.assert_not_called()
        client.send_email_to_contact.assert_not_called()

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_failure_removes_the_temporary_copy_and_contact(self, client_cls):
        client = self._stub_test_send(client_cls)
        client.send_email_to_contact.side_effect = TemporaryMauticError(
            "Mautic single-contact email send returned an unsuccessful response"
        )
        self._authenticate(self.staff)

        response = self._post_test_send()

        self.assertEqual(response.status_code, 502)
        client.delete_email.assert_called_once_with("901")
        client.delete_contact.assert_called_once_with("77")

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_provider_rejection_returns_400_and_cleans_up(self, client_cls):
        client = self._stub_test_send(client_cls)
        client.send_email_to_contact.side_effect = PermanentMauticError(
            "Mautic request failed with HTTP 422"
        )
        self._authenticate(self.staff)

        response = self._post_test_send()

        self.assertEqual(response.status_code, 400)
        client.delete_email.assert_called_once_with("901")
        client.delete_contact.assert_called_once_with("77")

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_contact_creation_failure_still_removes_the_copy(self, client_cls):
        client = self._stub_test_send(client_cls)
        client.create_disposable_contact.side_effect = TemporaryMauticError("Mautic is down")
        self._authenticate(self.staff)

        response = self._post_test_send()

        self.assertEqual(response.status_code, 502)
        client.send_email_to_contact.assert_not_called()
        client.delete_email.assert_called_once_with("901")
        client.delete_contact.assert_not_called()

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_success_survives_cleanup_failures(self, client_cls):
        client = self._stub_test_send(client_cls)
        client.delete_email.side_effect = TemporaryMauticError("Mautic is down")
        client.delete_contact.side_effect = PermanentMauticError("HTTP 500")
        self._authenticate(self.staff)

        with self.assertLogs("newsletter.campaign_services", level="WARNING") as logs:
            response = self._post_test_send()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])
        messages = "\n".join(logs.output)
        self.assertIn("temporary Mautic template test email id=901", messages)
        self.assertIn("temporary Mautic template test contact id=77", messages)
        # Credentials never reach the log line.
        self.assertNotIn("password", messages.lower())

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_failure_is_not_masked_by_cleanup_failure(self, client_cls):
        client = self._stub_test_send(client_cls)
        client.send_email_to_contact.side_effect = TemporaryMauticError("send failed")
        client.delete_email.side_effect = TemporaryMauticError("cleanup failed")
        self._authenticate(self.staff)

        with self.assertLogs("newsletter.campaign_services", level="WARNING"):
            response = self._post_test_send()

        self.assertEqual(response.status_code, 502)
        self.assertIn("send failed", response.data["detail"])
        client.delete_contact.assert_called_once_with("77")

    @patch("newsletter.template_views.run_interactive_mutation")
    def test_test_send_uses_the_newsletter_test_send_operation(self, helper):
        helper.return_value = (
            {"recipient_email": "admin@example.test", "contact_id": "77", "temporary_contact": True},
            None,
        )
        self._authenticate(self.staff)

        response = self._post_test_send()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(helper.call_args.kwargs["action"], NEWSLETTER_TEST_SEND)
        self.assertEqual(helper.call_args.kwargs["resource"], "template")
        self.assertEqual(helper.call_args.kwargs["resource_id"], "18")
        # Internal provider IDs are not echoed to the browser.
        self.assertEqual(
            response.data,
            {"success": True, "recipient_email": "admin@example.test"},
        )

    @patch("newsletter.template_views.MauticClient")
    def test_test_send_is_denied_without_marketing_access(self, client_cls):
        unmapped_superuser = User.objects.create_superuser(
            username="templates-unmapped",
            email="templates-unmapped@example.test",
            password="test-password",
        )

        self.assertIn(self._post_test_send().status_code, (401, 403))
        for user in (self.normal_user, unmapped_superuser):
            self._authenticate(user)
            self.assertEqual(self._post_test_send().status_code, 403)

        client_cls.assert_not_called()

    @patch("newsletter.template_views.MauticClient")
    def test_usage_reports_dependency_gap_and_provider_guard(self, client_cls):
        client_cls.return_value.get_email_template.return_value = self._template()
        self._authenticate(self.staff)

        response = self.client.get(self.usage_url)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["available"])
        self.assertEqual(response.data["deletePolicy"], "provider_enforced")
        self.assertEqual(response.data["template"]["id"], "18")

    @patch("newsletter.template_views.MauticClient")
    def test_tokens_are_generated_from_mautic_fields(self, client_cls):
        client = client_cls.return_value
        client.list_fields.side_effect = [
            {"fields": [{"alias": "firstname", "label": "First Name"}]},
            {"fields": [{"alias": "companyname", "label": "Company Name"}]},
        ]
        self._authenticate(self.staff)

        response = self.client.get(reverse("newsletter-admin-template-tokens"))

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "{contactfield=firstname}",
            [token["token"] for token in response.data["results"]],
        )
        self.assertIn(
            "{companyfield=companyname}",
            [token["token"] for token in response.data["results"]],
        )

    @patch("newsletter.template_views.MauticClient")
    def test_categories_filters_email_bundle(self, client_cls):
        client_cls.return_value.list_categories.return_value = {
            "categories": [
                {"id": 4, "title": "Email", "bundle": "email"},
                {"id": 5, "title": "Assets", "bundle": "asset"},
            ]
        }
        self._authenticate(self.staff)

        response = self.client.get(reverse("newsletter-admin-template-categories"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["id"], "4")

    @patch("newsletter.template_views.MauticClient")
    def test_themes_filters_email_compatible_themes(self, client_cls):
        client_cls.return_value.list_themes.return_value = {
            "themes": {
                "blank": {
                    "key": "blank",
                    "name": "Blank",
                    "config": {"features": ["email"]},
                },
                "page": {
                    "key": "page",
                    "name": "Page",
                    "config": {"features": ["page"]},
                },
            }
        }
        self._authenticate(self.staff)

        response = self.client.get(reverse("newsletter-admin-template-themes"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["key"], "blank")

    @patch("newsletter.template_views.MauticClient")
    def test_non_template_email_is_hidden_as_not_found(self, client_cls):
        client_cls.return_value.get_email_template.side_effect = (
            PermanentMauticError(
                "Mautic email is not a Mautic template email"
            )
        )
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.template_views.MauticClient")
    def test_provider_404_is_not_found(self, client_cls):
        client_cls.return_value.get_email_template.side_effect = (
            PermanentMauticError(
                "Mautic API request failed (HTTP 404)"
            )
        )
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.template_views.MauticClient")
    def test_provider_validation_failure_returns_400(self, client_cls):
        client_cls.return_value.create_email_template.side_effect = (
            PermanentMauticError(
                "Mautic API request failed (HTTP 422): Invalid template"
            )
        )
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {"name": "Rejected"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)

    @patch("newsletter.template_views.MauticClient")
    def test_provider_temporary_failure_returns_502(self, client_cls):
        client_cls.return_value.list_email_templates.side_effect = (
            TemporaryMauticError(
                "Mautic API request failed (HTTP 503)"
            )
        )
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 502)


PER_USER_ON = {**IDENTITY_SETTINGS, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": True}


@override_settings(**PER_USER_ON)
class NewsletterAdminTemplateTestSendIdentityTests(TestCase):
    """Who executes each step of a Template test send, with the flag on and off.

    Building the temporary copy and contact is provisioning and always runs as
    the service account (as for a Broadcast test email); the send itself runs
    through the interactive client, which carries the mapped user's assertion
    when per-user execution is on.
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_superuser(
            username="templates-identity",
            email="templates-identity@example.test",
            password="test-password",
        )
        MauticUserConnection.objects.create(
            user=self.user,
            mautic_user_id=6,
            mautic_display_name="Ecp DevProof",
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
            connected_at=timezone.now(),
        )
        self.client.force_authenticate(user=self.user)
        self.url = reverse("newsletter-admin-template-test-send", args=["18"])

        self.service = Mock(name="service-client")
        self.service.get_email_template.return_value = (
            NewsletterAdminTemplatesAPITests._template()
        )
        self.service.create_email.return_value = {"id": 901}
        self.service.find_contact_by_email.return_value = None
        self.service.create_disposable_contact.return_value = ({"id": 77}, True)
        self.service.send_email_to_contact.return_value = {"success": True}
        self.asserted = Mock(name="asserted-client")
        self.asserted.send_email_to_contact.return_value = {"success": True}

        def factory(*args, **kwargs):
            if kwargs.get("assertion_provider") is not None:
                self.asserted.execution_identity = kwargs["execution_identity"]
                return self.asserted
            if "execution_identity" in kwargs:
                self.service.execution_identity = kwargs["execution_identity"]
            return self.service

        patcher = patch("newsletter.template_views.MauticClient", side_effect=factory)
        patcher.start()
        self.addCleanup(patcher.stop)

    def post(self):
        return self.client.post(self.url, {"email": "admin@example.test"}, format="json")

    def test_asserted_user_sends_and_service_account_provisions(self):
        response = self.post()

        self.assertEqual(response.status_code, 200)
        self.asserted.send_email_to_contact.assert_called_once_with("901", "77")
        self.service.send_email_to_contact.assert_not_called()
        self.service.create_email.assert_called_once()
        self.service.create_disposable_contact.assert_called_once()
        self.service.delete_email.assert_called_once_with("901")
        self.service.delete_contact.assert_called_once_with("77")
        self.asserted.create_email.assert_not_called()
        self.asserted.create_disposable_contact.assert_not_called()

        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.action, NEWSLETTER_TEST_SEND)
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.SUCCEEDED)
        self.assertEqual(entry.ecp_user_id, self.user.pk)
        self.assertEqual(entry.mautic_user_id, 6)
        self.assertEqual(entry.auth_mode, "asserted_user")
        self.assertEqual(entry.resource, "template")
        self.assertEqual(entry.resource_id, "18")
        self.assertTrue(entry.correlation_id)

    def test_bridge_denial_is_audited_and_cleaned_up_without_fallback(self):
        self.asserted.send_email_to_contact.side_effect = MauticBridgeRejectedError(
            "Access denied. (HTTP 403)"
        )

        response = self.post()

        self.assertGreaterEqual(response.status_code, 400)
        # Never retried as the service account.
        self.service.send_email_to_contact.assert_not_called()
        self.service.delete_email.assert_called_once_with("901")
        self.service.delete_contact.assert_called_once_with("77")
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.action, NEWSLETTER_TEST_SEND)
        self.assertIn(
            entry.status,
            {MauticIdentityAuditLog.Status.DENIED, MauticIdentityAuditLog.Status.FAILED},
        )
        self.assertEqual(entry.auth_mode, "asserted_user")

    def test_provider_failure_is_audited_as_failed(self):
        self.asserted.send_email_to_contact.side_effect = TemporaryMauticError(
            "Mautic single-contact email send returned an unsuccessful response"
        )

        response = self.post()

        self.assertEqual(response.status_code, 502)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.FAILED)
        # Only the exception type is stored, never provider text.
        self.assertEqual(entry.detail, "TemporaryMauticError")

    def test_invalid_recipient_never_reaches_the_identity_layer(self):
        response = self.client.post(self.url, {"email": "nope"}, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertFalse(MauticIdentityAuditLog.objects.exists())
        self.service.create_email.assert_not_called()
        self.asserted.send_email_to_contact.assert_not_called()

    @override_settings(**{**PER_USER_ON, "ECP_MAUTIC_IDENTITY_PRIVATE_KEY": ""})
    def test_missing_signing_config_fails_closed(self):
        response = self.post()

        self.assertGreaterEqual(response.status_code, 400)
        self.service.create_email.assert_not_called()
        self.service.send_email_to_contact.assert_not_called()
        self.asserted.send_email_to_contact.assert_not_called()

    @override_settings(**{**PER_USER_ON, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": False})
    def test_flag_off_sends_as_the_service_account(self):
        response = self.post()

        self.assertEqual(response.status_code, 200)
        self.service.send_email_to_contact.assert_called_once_with("901", "77")
        self.asserted.send_email_to_contact.assert_not_called()
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.action, NEWSLETTER_TEST_SEND)
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.SUCCEEDED)
        self.assertEqual(entry.auth_mode, "service_account")
