from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError


User = get_user_model()


SYSTEM_FIELD = {
    "id": 2,
    "label": "First Name",
    "alias": "firstname",
    "type": "text",
    "group": "core",
    "object": "lead",
    "order": 2,
    "isPublished": True,
    "isRequired": False,
    # Mautic's own protection flag for built-in fields.
    "isFixed": True,
    "properties": {},
    "charLengthLimit": 64,
}

CUSTOM_FIELD = {
    "id": 44,
    "label": "Persona",
    "alias": "persona",
    "type": "select",
    "group": "professional",
    "object": "lead",
    "order": 30,
    "isPublished": True,
    "isRequired": False,
    "isFixed": False,
    "properties": {
        "list": [
            {"label": "Buyer", "value": "buyer"},
            {"label": "Champion", "value": "champion"},
        ]
    },
}

UNPUBLISHED_FIELD = {
    "id": 45,
    "label": "Legacy Code",
    "alias": "legacy_code",
    "type": "text",
    "group": "professional",
    "object": "lead",
    "order": 31,
    "isPublished": False,
    "isFixed": False,
    "properties": {},
}

FIELD_TYPES = {
    "total": 3,
    "types": [
        {"type": "text", "label": "Text", "hasOptionList": False, "requiredProperties": []},
        {
            "type": "select",
            "label": "Select",
            "hasOptionList": True,
            "requiredProperties": ["list"],
        },
        {"type": "country", "label": "Country", "hasOptionList": True, "requiredProperties": []},
    ],
    "listTypes": ["select", "country"],
}


class NewsletterAdminCustomFieldsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="field-staff",
            email="field-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="field-normal",
            email="field-normal@example.test",
            password="test-password",
        )
        self.contact_url = reverse("newsletter-admin-field-list", args=["contact"])
        self.company_url = reverse("newsletter-admin-field-list", args=["company"])
        self.types_url = reverse("newsletter-admin-field-types")
        self.custom_detail_url = reverse(
            "newsletter-admin-field-detail", args=["contact", "44"]
        )
        self.system_detail_url = reverse(
            "newsletter-admin-field-detail", args=["contact", "2"]
        )

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def _client(self, client_cls, fields=None):
        client = MagicMock()
        client.list_fields.return_value = {
            "fields": {str(field["id"]): field for field in (fields or [SYSTEM_FIELD, CUSTOM_FIELD])}
        }
        client.get_field_type_capabilities.return_value = FIELD_TYPES
        client_cls.return_value = client
        return client

    # ------------------------------------------------------------------ auth

    def test_field_list_requires_authentication(self):
        response = self.client.get(self.contact_url)
        self.assertIn(response.status_code, (401, 403))

    def test_field_list_rejects_non_staff(self):
        self._authenticate(self.normal_user)
        response = self.client.get(self.contact_url)
        self.assertEqual(response.status_code, 403)

    def test_field_types_rejects_non_staff(self):
        self._authenticate(self.normal_user)
        response = self.client.get(self.types_url)
        self.assertEqual(response.status_code, 403)

    def test_field_delete_rejects_non_staff(self):
        self._authenticate(self.normal_user)
        response = self.client.delete(self.custom_detail_url)
        self.assertEqual(response.status_code, 403)

    # ------------------------------------------------------------------ list

    @patch("newsletter.field_services.MauticClient")
    def test_contact_field_list_exposes_system_flag_and_options(self, client_cls):
        self._client(client_cls)

        self._authenticate(self.staff)
        response = self.client.get(self.contact_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["object"], "contact")
        by_alias = {field["alias"]: field for field in response.data["results"]}

        self.assertTrue(by_alias["firstname"]["is_system"])
        self.assertFalse(by_alias["firstname"]["can_delete"])
        self.assertFalse(by_alias["persona"]["is_system"])
        self.assertTrue(by_alias["persona"]["can_delete"])
        # `object` is normalized from Mautic's internal "lead" name.
        self.assertEqual(by_alias["persona"]["object"], "contact")
        self.assertEqual(
            by_alias["persona"]["options"],
            [
                {"label": "Buyer", "value": "buyer"},
                {"label": "Champion", "value": "champion"},
            ],
        )

    @patch("newsletter.field_services.MauticClient")
    def test_company_field_list_requests_company_object(self, client_cls):
        client = self._client(client_cls, fields=[])

        self._authenticate(self.staff)
        response = self.client.get(self.company_url)

        self.assertEqual(response.status_code, 200)
        client.list_fields.assert_called_once_with("company", limit=200)

    @patch("newsletter.field_services.MauticClient")
    def test_published_only_filter(self, client_cls):
        self._client(client_cls, fields=[CUSTOM_FIELD, UNPUBLISHED_FIELD])

        self._authenticate(self.staff)
        response = self.client.get(self.contact_url, {"published_only": "true"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual([f["alias"] for f in response.data["results"]], ["persona"])

    def test_invalid_field_object_is_rejected(self):
        self._authenticate(self.staff)
        response = self.client.get(
            reverse("newsletter-admin-field-list", args=["invoice"])
        )
        self.assertEqual(response.status_code, 400)

    @patch("newsletter.field_services.MauticClient")
    def test_field_list_surfaces_provider_failure(self, client_cls):
        client = MagicMock()
        client.list_fields.side_effect = TemporaryMauticError("Mautic API request failed")
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.get(self.contact_url)

        self.assertEqual(response.status_code, 502)

    # ----------------------------------------------------------------- types

    @patch("newsletter.field_services.MauticClient")
    def test_field_types_come_from_mautic_registry(self, client_cls):
        self._client(client_cls)

        self._authenticate(self.staff)
        response = self.client.get(self.types_url)

        self.assertEqual(response.status_code, 200)
        by_type = {entry["type"]: entry for entry in response.data["results"]}
        self.assertEqual(set(by_type), {"text", "select", "country"})
        self.assertTrue(by_type["select"]["has_option_list"])
        self.assertEqual(by_type["select"]["required_properties"], ["list"])
        self.assertFalse(by_type["text"]["has_option_list"])

    # ---------------------------------------------------------------- create

    @patch("newsletter.field_services.MauticClient")
    def test_create_field_maps_payload_to_mautic_keys(self, client_cls):
        client = self._client(client_cls)
        client.create_field.return_value = CUSTOM_FIELD

        self._authenticate(self.staff)
        response = self.client.post(
            self.contact_url,
            {
                "label": "Persona",
                "type": "select",
                "group": "professional",
                "is_published": True,
                "is_required": False,
                "options": [{"label": "Buyer", "value": "buyer"}],
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        called_object, payload = client.create_field.call_args[0]
        self.assertEqual(called_object, "contact")
        self.assertEqual(payload["label"], "Persona")
        self.assertEqual(payload["type"], "select")
        self.assertEqual(payload["isPublished"], 1)
        self.assertEqual(payload["isRequired"], 0)
        self.assertEqual(
            payload["properties"], {"list": [{"label": "Buyer", "value": "buyer"}]}
        )

    @patch("newsletter.field_services.MauticClient")
    def test_create_field_requires_label(self, client_cls):
        self._client(client_cls)

        self._authenticate(self.staff)
        response = self.client.post(self.contact_url, {"type": "text"}, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertIn("label", response.data["detail"])

    @patch("newsletter.field_services.MauticClient")
    def test_create_field_rejects_type_mautic_does_not_support(self, client_cls):
        """The supported type list comes from Mautic, never from a hardcoded guess."""
        self._client(client_cls)

        self._authenticate(self.staff)
        response = self.client.post(
            self.contact_url,
            {"label": "Weird", "type": "quantum"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("quantum", response.data["detail"])

    # ---------------------------------------------------------------- update

    @patch("newsletter.field_services.MauticClient")
    def test_update_field_publishes_without_touching_options(self, client_cls):
        client = self._client(client_cls)
        client.get_field.return_value = CUSTOM_FIELD
        client.update_field.return_value = dict(CUSTOM_FIELD, isPublished=False)

        self._authenticate(self.staff)
        response = self.client.patch(
            self.custom_detail_url, {"is_published": False}, format="json"
        )

        self.assertEqual(response.status_code, 200)
        _, _, payload = client.update_field.call_args[0]
        self.assertEqual(payload, {"isPublished": 0})
        # Omitting `properties` is what preserves the existing option list in Mautic.
        self.assertNotIn("properties", payload)

    @patch("newsletter.field_services.MauticClient")
    def test_update_field_rejects_alias_and_type_changes(self, client_cls):
        # Mautic locks alias and type once a field exists.
        self._client(client_cls)

        self._authenticate(self.staff)
        response = self.client.patch(
            self.custom_detail_url,
            {"alias": "renamed", "type": "text"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("alias", response.data["detail"])

    @patch("newsletter.field_services.MauticClient")
    def test_update_preserves_options_when_explicitly_resent(self, client_cls):
        client = self._client(client_cls)
        client.get_field.return_value = CUSTOM_FIELD
        client.update_field.return_value = CUSTOM_FIELD

        self._authenticate(self.staff)
        response = self.client.patch(
            self.custom_detail_url,
            {
                "label": "Persona",
                "options": [
                    {"label": "Buyer", "value": "buyer"},
                    {"label": "Champion", "value": "champion"},
                    {"label": "Blocker", "value": "blocker"},
                ],
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        _, _, payload = client.update_field.call_args[0]
        # Ordering is preserved exactly as submitted.
        self.assertEqual(
            [option["value"] for option in payload["properties"]["list"]],
            ["buyer", "champion", "blocker"],
        )

    @patch("newsletter.field_services.MauticClient")
    def test_system_field_group_cannot_be_changed(self, client_cls):
        client = self._client(client_cls)
        client.get_field.return_value = SYSTEM_FIELD

        self._authenticate(self.staff)
        response = self.client.patch(
            self.system_detail_url, {"group": "professional"}, format="json"
        )

        self.assertEqual(response.status_code, 409)
        client.update_field.assert_not_called()

    @patch("newsletter.field_services.MauticClient")
    def test_system_field_label_can_still_be_edited(self, client_cls):
        client = self._client(client_cls)
        client.get_field.return_value = SYSTEM_FIELD
        client.update_field.return_value = dict(SYSTEM_FIELD, label="Given Name")

        self._authenticate(self.staff)
        response = self.client.patch(
            self.system_detail_url, {"label": "Given Name"}, format="json"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["label"], "Given Name")

    # ---------------------------------------------------------------- delete

    @patch("newsletter.field_services.MauticClient")
    def test_protected_system_field_cannot_be_deleted(self, client_cls):
        client = self._client(client_cls)
        client.get_field.return_value = SYSTEM_FIELD

        self._authenticate(self.staff)
        response = self.client.delete(self.system_detail_url)

        self.assertEqual(response.status_code, 409)
        client.delete_field.assert_not_called()

    @patch("newsletter.field_services.MauticClient")
    def test_custom_field_can_be_deleted(self, client_cls):
        client = self._client(client_cls)
        client.get_field.return_value = CUSTOM_FIELD

        self._authenticate(self.staff)
        response = self.client.delete(self.custom_detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["deleted"])
        client.delete_field.assert_called_once_with("contact", "44")

    @patch("newsletter.field_services.MauticClient")
    def test_missing_field_returns_404(self, client_cls):
        client = self._client(client_cls)
        client.get_field.side_effect = PermanentMauticError(
            "Mautic field lookup (HTTP 404)"
        )

        self._authenticate(self.staff)
        response = self.client.delete(self.custom_detail_url)

        self.assertEqual(response.status_code, 404)


class NewsletterAdminFieldChoicesAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="choice-staff",
            email="choice-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="choice-normal",
            email="choice-normal@example.test",
            password="test-password",
        )
        self.url = reverse("newsletter-admin-field-choices", args=["country"])

    def test_requires_staff(self):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, (401, 403))

        self.client.force_authenticate(user=self.normal_user)
        self.assertEqual(self.client.get(self.url).status_code, 403)

    @patch("newsletter.field_services.MauticClient")
    def test_country_choices_come_from_mautic(self, client_cls):
        client = MagicMock()
        client.get_field_type_choices.return_value = {
            "type": "country",
            "choices": [
                {"label": "India", "value": "India"},
                {"label": "United States", "value": "United States"},
            ],
        }
        client_cls.return_value = client

        self.client.force_authenticate(user=self.staff)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 2)
        client.get_field_type_choices.assert_called_once_with("country")

    def test_unsupported_choice_type_is_rejected(self):
        self.client.force_authenticate(user=self.staff)
        response = self.client.get(
            reverse("newsletter-admin-field-choices", args=["text"])
        )
        self.assertEqual(response.status_code, 400)
