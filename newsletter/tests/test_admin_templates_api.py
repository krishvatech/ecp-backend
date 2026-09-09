from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError


User = get_user_model()


class NewsletterAdminTemplatesAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="templates-staff",
            email="templates-staff@example.test",
            password="test-password",
            is_staff=True,
        )
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
