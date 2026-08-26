from types import SimpleNamespace

from django.test import SimpleTestCase

from crm_integrations.providers.base import CRMProvider
from crm_integrations.services import build_user_contact_payload


class UserContactPayloadTests(SimpleTestCase):
    def test_builds_and_normalizes_user_and_profile_fields(self):
        user = SimpleNamespace(
            pk=42,
            first_name="  Jane ",
            last_name=" Doe  ",
            email=" JANE@EXAMPLE.COM ",
            is_active=True,
            profile=SimpleNamespace(
                company="  Acme Capital ",
                job_title=" Director ",
                location_country=" Switzerland ",
                location_country_code=" ch ",
                profile_status="active",
            ),
        )

        self.assertEqual(
            build_user_contact_payload(user),
            {
                "ecp_user_id": "42",
                "first_name": "Jane",
                "last_name": "Doe",
                "email": "jane@example.com",
                "company": "Acme Capital",
                "job_title": "Director",
                "country": "Switzerland",
                "country_code": "CH",
                "is_active": True,
                "profile_status": "active",
            },
        )

    def test_missing_profile_produces_safe_defaults(self):
        user = SimpleNamespace(
            pk=9,
            first_name="John",
            last_name="Smith",
            email="john@example.com",
            is_active=False,
        )

        payload = build_user_contact_payload(user)

        self.assertEqual(payload["company"], "")
        self.assertEqual(payload["country_code"], "")
        self.assertEqual(payload["profile_status"], "active")
        self.assertFalse(payload["is_active"])

    def test_provider_contract_cannot_be_instantiated_directly(self):
        with self.assertRaises(TypeError):
            CRMProvider()
