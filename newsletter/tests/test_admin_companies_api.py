from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.models import MauticContactMapping


User = get_user_model()


COMPANY_FIELD_METADATA = {
    "fields": {
        "29": {
            "id": 29,
            "label": "Company Name",
            "alias": "companyname",
            "type": "text",
            "group": "core",
            "object": "company",
            "order": 9,
            "isPublished": True,
            "isRequired": True,
            "isFixed": True,
            "properties": {},
        },
        "31": {
            "id": 31,
            "label": "Company Email",
            "alias": "companyemail",
            "type": "email",
            "group": "core",
            "object": "company",
            "order": 3,
            "isPublished": True,
            "isFixed": True,
            "properties": {},
        },
        "40": {
            "id": 40,
            "label": "Segment Tier",
            "alias": "segment_tier",
            "type": "select",
            "group": "professional",
            "object": "company",
            "order": 20,
            "isPublished": True,
            "isFixed": False,
            "properties": {"list": [{"label": "Gold", "value": "gold"}]},
        },
    }
}


def company_payload(company_id=1, name="Acme Inc", email="hello@acme.test"):
    return {
        "id": company_id,
        "score": 0,
        "dateAdded": "2026-01-05T10:00:00+00:00",
        "dateModified": "2026-02-05T10:00:00+00:00",
        "fields": {
            "core": {
                "companyname": {"alias": "companyname", "value": name},
                "companyemail": {"alias": "companyemail", "value": email},
                "companycity": {"alias": "companycity", "value": "Austin"},
            },
            "professional": {
                "segment_tier": {"alias": "segment_tier", "value": "gold"},
            },
        },
    }


class NewsletterAdminCompaniesAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="company-staff",
            email="company-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="company-normal",
            email="company-normal@example.test",
            password="test-password",
        )
        self.list_url = reverse("newsletter-admin-company-list")
        self.detail_url = reverse("newsletter-admin-company-detail", args=["1"])
        self.contacts_url = reverse("newsletter-admin-company-contact-list", args=["1"])
        self.contact_detail_url = reverse(
            "newsletter-admin-company-contact-detail",
            args=["1", "7"],
        )

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def _field_client(self, client_cls):
        """Wire the company field metadata used to validate writable aliases."""
        client = MagicMock()
        client.list_fields.return_value = COMPANY_FIELD_METADATA
        client_cls.return_value = client
        return client

    # ------------------------------------------------------------------ auth

    def test_company_list_requires_authentication(self):
        response = self.client.get(self.list_url)
        self.assertIn(response.status_code, (401, 403))

    def test_company_list_rejects_non_staff(self):
        self._authenticate(self.normal_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 403)

    def test_company_detail_rejects_non_staff(self):
        self._authenticate(self.normal_user)
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, 403)

    def test_company_contacts_rejects_non_staff(self):
        self._authenticate(self.normal_user)
        response = self.client.get(self.contacts_url)
        self.assertEqual(response.status_code, 403)

    # ------------------------------------------------------------------ list

    @patch("newsletter.company_services.MauticClient")
    def test_company_list_normalizes_grouped_fields(self, client_cls):
        client = MagicMock()
        client.list_companies.return_value = {
            "total": 1,
            "companies": {"1": company_payload()},
        }
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        company = response.data["results"][0]
        self.assertEqual(company["id"], "1")
        self.assertEqual(company["name"], "Acme Inc")
        self.assertEqual(company["email"], "hello@acme.test")
        self.assertEqual(company["city"], "Austin")
        # Custom company values stay available under `values`.
        self.assertEqual(company["values"]["segment_tier"], "gold")

    @patch("newsletter.company_services.MauticClient")
    def test_company_list_forwards_search_and_paging(self, client_cls):
        client = MagicMock()
        client.list_companies.return_value = {"total": 0, "companies": {}}
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.get(self.list_url, {"search": "acme", "page": 2, "page_size": 10})

        self.assertEqual(response.status_code, 200)
        client.list_companies.assert_called_once_with(start=10, limit=10, search="acme")

    @patch("newsletter.company_services.MauticClient")
    def test_company_list_surfaces_provider_failure(self, client_cls):
        client = MagicMock()
        client.list_companies.side_effect = TemporaryMauticError("Mautic API request failed")
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("detail", response.data)

    # ---------------------------------------------------------------- detail

    @patch("newsletter.company_services.MauticClient")
    def test_company_detail_returns_metadata(self, client_cls):
        client = MagicMock()
        client.get_company.return_value = company_payload()
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["name"], "Acme Inc")
        self.assertEqual(response.data["date_added"], "2026-01-05T10:00:00+00:00")
        self.assertIn("core", response.data["field_groups"])

    @patch("newsletter.company_services.MauticClient")
    def test_company_detail_missing_company_returns_404(self, client_cls):
        client = MagicMock()
        client.get_company.side_effect = PermanentMauticError(
            "Mautic company lookup (HTTP 404)"
        )
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 404)

    # ---------------------------------------------------------------- create

    @patch("newsletter.field_services.MauticClient")
    @patch("newsletter.company_services.MauticClient")
    def test_create_company_uses_only_mautic(self, company_cls, field_cls):
        self._field_client(field_cls)
        client = MagicMock()
        client.create_company.return_value = {"id": 1}
        client.get_company.return_value = company_payload()
        company_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.post(
            self.list_url,
            {"companyname": "Acme Inc", "companyemail": "hello@acme.test"},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        client.create_company.assert_called_once_with(
            {"companyname": "Acme Inc", "companyemail": "hello@acme.test"}
        )
        # Creating a Mautic company must never create ECP state.
        self.assertEqual(User.objects.filter(username="company-created").count(), 0)
        self.assertEqual(MauticContactMapping.objects.count(), 0)

    @patch("newsletter.field_services.MauticClient")
    @patch("newsletter.company_services.MauticClient")
    def test_create_company_requires_name(self, company_cls, field_cls):
        self._field_client(field_cls)
        company_cls.return_value = MagicMock()

        self._authenticate(self.staff)
        response = self.client.post(
            self.list_url,
            {"companyemail": "hello@acme.test"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("companyname", response.data["detail"])

    @patch("newsletter.field_services.MauticClient")
    @patch("newsletter.company_services.MauticClient")
    def test_create_company_rejects_unknown_alias(self, company_cls, field_cls):
        self._field_client(field_cls)
        company_cls.return_value = MagicMock()

        self._authenticate(self.staff)
        response = self.client.post(
            self.list_url,
            {"companyname": "Acme", "not_a_mautic_field": "x"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("not_a_mautic_field", response.data["detail"])

    # ---------------------------------------------------------------- update

    @patch("newsletter.field_services.MauticClient")
    @patch("newsletter.company_services.MauticClient")
    def test_update_company_sends_only_changed_aliases(self, company_cls, field_cls):
        self._field_client(field_cls)
        client = MagicMock()
        client.get_company.return_value = company_payload(name="Acme Group")
        company_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.patch(
            self.detail_url,
            {"companyname": "Acme Group"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        # Untouched company values are not part of the PATCH payload.
        client.update_company.assert_called_once_with("1", {"companyname": "Acme Group"})

    # ---------------------------------------------------------------- delete

    @patch("newsletter.company_services.MauticClient")
    def test_delete_company(self, client_cls):
        client = MagicMock()
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["deleted"])
        client.delete_company.assert_called_once_with("1")

    @patch("newsletter.company_services.MauticClient")
    def test_delete_company_surfaces_provider_rejection(self, client_cls):
        client = MagicMock()
        client.delete_company.side_effect = PermanentMauticError(
            "Mautic company deletion (HTTP 409): in use"
        )
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 400)

    # --------------------------------------------------------- relationships

    @patch("newsletter.company_services.list_admin_contacts")
    def test_company_contacts_use_native_company_id_search(self, list_contacts):
        list_contacts.return_value = {
            "count": 1,
            "page": 1,
            "page_size": 25,
            "num_pages": 1,
            "results": [{"mautic_contact_id": "7", "email": "a@b.test"}],
        }

        self._authenticate(self.staff)
        response = self.client.get(self.contacts_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["company_id"], "1")
        list_contacts.assert_called_once_with(page=1, page_size=25, search="company_id:1")

    @patch("newsletter.company_services.list_admin_contacts")
    def test_company_contacts_combine_company_filter_with_search(self, list_contacts):
        list_contacts.return_value = {
            "count": 0,
            "page": 1,
            "page_size": 25,
            "num_pages": 1,
            "results": [],
        }

        self._authenticate(self.staff)
        response = self.client.get(self.contacts_url, {"search": "ravi"})

        self.assertEqual(response.status_code, 200)
        list_contacts.assert_called_once_with(
            page=1, page_size=25, search="company_id:1 ravi"
        )

    @patch("newsletter.company_services.MauticClient")
    def test_add_contact_to_company_creates_no_django_record(self, client_cls):
        client = MagicMock()
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.post(self.contacts_url, {"contact_id": "7"}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["associated"])
        client.add_contact_to_company.assert_called_once_with("1", "7")
        # The relationship lives in Mautic only.
        self.assertEqual(MauticContactMapping.objects.count(), 0)

    @patch("newsletter.company_services.MauticClient")
    def test_add_contact_requires_contact_id(self, client_cls):
        client_cls.return_value = MagicMock()

        self._authenticate(self.staff)
        response = self.client.post(self.contacts_url, {}, format="json")

        self.assertEqual(response.status_code, 400)

    @patch("newsletter.company_services.MauticClient")
    def test_remove_contact_from_company(self, client_cls):
        client = MagicMock()
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.delete(self.contact_detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["associated"])
        client.remove_contact_from_company.assert_called_once_with("1", "7")
        self.assertEqual(MauticContactMapping.objects.count(), 0)
