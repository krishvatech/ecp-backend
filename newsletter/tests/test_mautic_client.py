from unittest.mock import Mock

import requests
from django.test import SimpleTestCase, override_settings

from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import (
    PermanentMauticError,
    TemporaryMauticError,
)


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
class MauticClientTests(SimpleTestCase):
    def make_mautic_client(self, result=None):
        session = Mock()
        if result is not None:
            session.request.return_value = result
        return MauticClient(session=session), session

    def test_health_check_uses_basic_auth_and_timeout(self):
        client, session = self.make_mautic_client(response(200, {"contacts": {}}))

        self.assertTrue(client.health_check())

        session.request.assert_called_once()
        args, kwargs = session.request.call_args
        self.assertEqual(args[:2], ("GET", "http://mautic.local/api/contacts"))
        self.assertEqual(kwargs["params"], {"limit": 1})
        self.assertEqual(kwargs["timeout"], 12)
        self.assertEqual(kwargs["auth"].username, "api-user")
        self.assertEqual(kwargs["auth"].password, "secret")

    def test_find_contact_by_email_matches_nested_mautic_fields(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "contacts": {
                        "42": {
                            "id": 42,
                            "fields": {
                                "core": {
                                    "email": {
                                        "value": "member@example.com",
                                    }
                                }
                            },
                        }
                    }
                },
            )
        )

        found = client.find_contact_by_email(" MEMBER@EXAMPLE.COM ")

        self.assertEqual(found["id"], 42)
        self.assertEqual(
            session.request.call_args.kwargs["params"],
            {"search": "email:member@example.com", "limit": 20},
        )

    def test_find_contact_by_email_returns_none_when_no_exact_match(self):
        client, _ = self.make_mautic_client(
            response(
                200,
                {
                    "contacts": {
                        "9": {
                            "id": 9,
                            "email": "other@example.com",
                        }
                    }
                },
            )
        )

        self.assertIsNone(client.find_contact_by_email("member@example.com"))

    def test_create_contact_requires_email_and_returns_contact(self):
        client, session = self.make_mautic_client(
            response(201, {"contact": {"id": 51, "email": "member@example.com"}})
        )

        created = client.create_contact(
            {
                "email": "member@example.com",
                "firstname": "Member",
            }
        )

        self.assertEqual(created["id"], 51)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/contacts/new"),
        )

    def test_update_contact_calls_edit_endpoint(self):
        client, session = self.make_mautic_client(
            response(200, {"contact": {"id": 51, "firstname": "Updated"}})
        )

        updated = client.update_contact(51, {"firstname": "Updated"})

        self.assertEqual(updated["id"], 51)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/contacts/51/edit"),
        )

    def test_delete_contact_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(response(200, {"contact": {"id": None}}))

        client.delete_contact(51)

        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/contacts/51/delete"),
        )

    def test_delete_contact_requires_contact_id(self):
        client, session = self.make_mautic_client()

        with self.assertRaises(PermanentMauticError):
            client.delete_contact("")

        session.request.assert_not_called()

    def test_add_contact_to_segment_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(response(200, {"success": 1}))

        client.add_contact_to_segment(3, 51)

        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/segments/3/contact/51/add"),
        )

    def test_remove_contact_from_segment_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(response(200, {"success": 1}))

        client.remove_contact_from_segment(3, 51)

        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/segments/3/contact/51/remove"),
        )

    def test_timeout_is_retryable(self):
        client, session = self.make_mautic_client()
        session.request.side_effect = requests.Timeout("secret transport detail")

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "Mautic API request failed",
        ):
            client.health_check()

    def test_server_error_is_retryable(self):
        client, _ = self.make_mautic_client(
            response(503, {"errors": [{"message": "Service unavailable"}]})
        )

        with self.assertRaises(TemporaryMauticError):
            client.health_check()

    def test_validation_error_is_permanent(self):
        client, _ = self.make_mautic_client(
            response(400, {"errors": [{"message": "Invalid contact data"}]})
        )

        with self.assertRaisesRegex(
            PermanentMauticError,
            "Invalid contact data",
        ):
            client.create_contact({"email": "member@example.com"})

    @override_settings(MAUTIC_BASE_URL="")
    def test_missing_base_url_is_rejected_before_network_request(self):
        with self.assertRaisesRegex(
            PermanentMauticError,
            "base URL is not configured",
        ):
            MauticClient(session=Mock())

    @override_settings(MAUTIC_PASSWORD="")
    def test_missing_credentials_are_rejected_before_network_request(self):
        with self.assertRaisesRegex(
            PermanentMauticError,
            "credentials are not configured",
        ):
            MauticClient(session=Mock())
