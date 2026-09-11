"""Dynamic custom-field values on contacts and companies.

These cover the rule that a partial save must never rewrite Mautic values the admin did
not touch, for both objects.
"""

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.tests.test_admin_companies_api import (
    COMPANY_FIELD_METADATA,
    company_payload,
)


User = get_user_model()


CONTACT_PAYLOAD = {
    "id": 2,
    "fields": {
        "core": {
            "email": {"alias": "email", "value": "ravi@example.test"},
            "firstname": {"alias": "firstname", "value": "Ravi"},
        },
        "professional": {
            "persona": {"alias": "persona", "value": "buyer"},
            "legacy_code": {"alias": "legacy_code", "value": "keep-me"},
        },
    },
}


class ContactDynamicFieldValueTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="dyn-staff",
            email="dyn-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.list_url = reverse("newsletter-admin-contact-list")
        self.detail_url = reverse("newsletter-admin-contact-detail", args=["2"])

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_update_sends_only_the_supplied_custom_field(self, client_cls):
        client = MagicMock()
        client.get_contact.return_value = CONTACT_PAYLOAD
        client.update_contact.return_value = CONTACT_PAYLOAD
        client_cls.return_value = client

        response = self.client.patch(
            self.detail_url,
            {"custom_fields": {"persona": "champion"}},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        _, payload = client.update_contact.call_args[0]
        self.assertEqual(payload, {"persona": "champion"})
        # An untouched custom field is absent, so Mautic keeps its stored value.
        self.assertNotIn("legacy_code", payload)

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_create_forwards_custom_fields(self, client_cls):
        client = MagicMock()
        client.create_contact.return_value = {"id": 2}
        client.get_contact.return_value = CONTACT_PAYLOAD
        client_cls.return_value = client

        response = self.client.post(
            self.list_url,
            {"email": "ravi@example.test", "custom_fields": {"persona": "buyer"}},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        payload = client.create_contact.call_args[0][0]
        self.assertEqual(payload["email"], "ravi@example.test")
        self.assertEqual(payload["persona"], "buyer")

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_custom_fields_must_be_an_object(self, client_cls):
        client_cls.return_value = MagicMock()

        response = self.client.patch(
            self.detail_url,
            {"custom_fields": "persona"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)


class CompanyDynamicFieldValueTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="dyn-company-staff",
            email="dyn-company-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.detail_url = reverse("newsletter-admin-company-detail", args=["1"])

    @patch("newsletter.field_services.MauticClient")
    @patch("newsletter.company_services.MauticClient")
    def test_company_update_sends_only_the_supplied_alias(self, company_cls, field_cls):
        field_client = MagicMock()
        field_client.list_fields.return_value = COMPANY_FIELD_METADATA
        field_cls.return_value = field_client

        client = MagicMock()
        client.get_company.return_value = company_payload()
        company_cls.return_value = client

        response = self.client.patch(
            self.detail_url,
            {"segment_tier": "platinum"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        _, payload = client.update_company.call_args[0]
        self.assertEqual(payload, {"segment_tier": "platinum"})
        # Core identity values the admin did not edit are not resent.
        self.assertNotIn("companyname", payload)
        self.assertNotIn("companyemail", payload)

    @patch("newsletter.field_services.MauticClient")
    @patch("newsletter.company_services.MauticClient")
    def test_company_custom_field_is_writable_without_code_change(
        self, company_cls, field_cls
    ):
        """A company field defined only in Mautic is accepted purely from metadata."""
        field_client = MagicMock()
        field_client.list_fields.return_value = COMPANY_FIELD_METADATA
        field_cls.return_value = field_client

        client = MagicMock()
        client.get_company.return_value = company_payload()
        company_cls.return_value = client

        response = self.client.patch(
            self.detail_url, {"segment_tier": "gold"}, format="json"
        )

        self.assertEqual(response.status_code, 200)
        field_client.list_fields.assert_called_once_with("company", limit=500)
