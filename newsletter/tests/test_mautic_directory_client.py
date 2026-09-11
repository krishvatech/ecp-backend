"""Client coverage for the Mautic company, tag, and field endpoints.

Endpoint paths here were verified against the Mautic 7.1.3 LeadBundle routing config
(`mautic_api_companiesstandard`, `mautic_api_tagsstandard`, `mautic_api_fieldsstandard`).
"""

from unittest.mock import Mock

from django.test import SimpleTestCase, override_settings

from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import PermanentMauticError, TemporaryMauticError


MAUTIC_SETTINGS = {
    "MAUTIC_BASE_URL": "http://mautic.local",
    "MAUTIC_USERNAME": "api-user",
    "MAUTIC_PASSWORD": "secret",
    "MAUTIC_REQUEST_TIMEOUT": 12,
}


def response(status_code=200, payload=None):
    result = Mock()
    result.status_code = status_code
    result.json.return_value = {} if payload is None else payload
    return result


@override_settings(**MAUTIC_SETTINGS)
class MauticCompanyClientTests(SimpleTestCase):
    def make_client(self, result=None):
        session = Mock()
        if result is not None:
            session.request.return_value = result
        return MauticClient(session=session), session

    def test_get_company_uses_expected_endpoint(self):
        client, session = self.make_client(response(200, {"company": {"id": 1}}))

        company = client.get_company("1")

        self.assertEqual(company["id"], 1)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/companies/1"),
        )

    def test_create_company_posts_to_new(self):
        client, session = self.make_client(response(201, {"company": {"id": 5}}))

        client.create_company({"companyname": "Acme"})

        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/companies/new"),
        )
        self.assertEqual(session.request.call_args.kwargs["data"], {"companyname": "Acme"})

    def test_update_company_patches_edit(self):
        client, session = self.make_client(response(200, {"company": {"id": 5}}))

        client.update_company("5", {"companycity": "Austin"})

        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/companies/5/edit"),
        )

    def test_delete_company_allows_missing_id_in_response(self):
        client, session = self.make_client(
            response(200, {"company": {"id": None, "companyname": "Acme"}})
        )

        result = client.delete_company("5")

        self.assertEqual(result["companyname"], "Acme")
        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/companies/5/delete"),
        )

    def test_company_id_is_required(self):
        client, _ = self.make_client()
        with self.assertRaises(PermanentMauticError):
            client.get_company("")

    def test_invalid_company_response_is_temporary(self):
        client, _ = self.make_client(response(200, {"company": "nope"}))
        with self.assertRaises(TemporaryMauticError):
            client.get_company("1")


@override_settings(**MAUTIC_SETTINGS)
class MauticTagClientTests(SimpleTestCase):
    def make_client(self, result=None):
        session = Mock()
        if result is not None:
            session.request.return_value = result
        return MauticClient(session=session), session

    def test_create_tag(self):
        client, session = self.make_client(response(201, {"tag": {"id": 3, "tag": "vip"}}))

        tag = client.create_tag({"tag": "vip"})

        self.assertEqual(tag["tag"], "vip")
        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/tags/new"),
        )

    def test_update_tag(self):
        client, session = self.make_client(response(200, {"tag": {"id": 3, "tag": "VIP"}}))

        client.update_tag("3", {"tag": "VIP"})

        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/tags/3/edit"),
        )

    def test_delete_tag_allows_missing_id_in_response(self):
        client, session = self.make_client(response(200, {"tag": {"id": None, "tag": "vip"}}))

        client.delete_tag("3")

        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/tags/3/delete"),
        )

    def test_tag_id_is_required(self):
        client, _ = self.make_client()
        with self.assertRaises(PermanentMauticError):
            client.delete_tag("")


@override_settings(**MAUTIC_SETTINGS)
class MauticFieldClientTests(SimpleTestCase):
    def make_client(self, result=None):
        session = Mock()
        if result is not None:
            session.request.return_value = result
        return MauticClient(session=session), session

    def test_list_fields_defaults_to_contact_object(self):
        client, session = self.make_client(response(200, {"fields": {}}))

        client.list_fields()

        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/fields/contact"),
        )

    def test_list_fields_supports_company_object(self):
        client, session = self.make_client(response(200, {"fields": {}}))

        client.list_fields("company", limit=50)

        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/fields/company"),
        )
        self.assertEqual(session.request.call_args.kwargs["params"], {"limit": 50})

    def test_lead_object_is_normalized_to_contact(self):
        client, session = self.make_client(response(200, {"fields": {}}))

        client.list_fields("lead")

        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/fields/contact"),
        )

    def test_unsupported_field_object_is_rejected(self):
        client, _ = self.make_client()
        with self.assertRaises(PermanentMauticError):
            client.list_fields("invoice")

    def test_create_field(self):
        client, session = self.make_client(response(201, {"field": {"id": 44}}))

        client.create_field("contact", {"label": "Persona", "type": "select"})

        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/fields/contact/new"),
        )

    def test_update_field(self):
        client, session = self.make_client(response(200, {"field": {"id": 44}}))

        client.update_field("company", "44", {"isPublished": 0})

        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/fields/company/44/edit"),
        )

    def test_delete_field(self):
        client, session = self.make_client(response(200, {"field": {"id": None}}))

        client.delete_field("contact", "44")

        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/fields/contact/44/delete"),
        )

    def test_field_creation_accepts_queued_202_response(self):
        """Mautic returns 202 when the column build is queued; that is a success."""
        client, _ = self.make_client(response(202, {"field": {"id": 44}}))

        field = client.create_field("contact", {"label": "Persona"})

        self.assertEqual(field["id"], 44)


@override_settings(**MAUTIC_SETTINGS)
class MauticFieldCapabilityClientTests(SimpleTestCase):
    def make_client(self, result=None):
        session = Mock()
        if result is not None:
            session.request.return_value = result
        return MauticClient(session=session), session

    def test_field_types_use_the_bridge_endpoint(self):
        client, session = self.make_client(
            response(200, {"types": [{"type": "text", "label": "Text"}]})
        )

        data = client.get_field_type_capabilities()

        self.assertEqual(data["types"][0]["type"], "text")
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/ecp/fields/types"),
        )

    def test_invalid_field_type_capability_response_is_temporary(self):
        client, _ = self.make_client(response(200, {"types": "nope"}))
        with self.assertRaises(TemporaryMauticError):
            client.get_field_type_capabilities()

    def test_reference_choices_use_the_bridge_endpoint(self):
        client, session = self.make_client(response(200, {"choices": []}))

        client.get_field_type_choices("country")

        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/ecp/fields/choices/country"),
        )

    def test_reference_choices_reject_unsupported_type(self):
        client, _ = self.make_client()
        with self.assertRaises(PermanentMauticError):
            client.get_field_type_choices("text")
