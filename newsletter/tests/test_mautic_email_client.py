from unittest.mock import Mock

import requests
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
class MauticEmailClientTests(SimpleTestCase):
    def make_client(self, result=None):
        session = Mock()
        if result is not None:
            session.request.return_value = result
        return MauticClient(session=session), session

    def test_get_email_uses_expected_route(self):
        client, session = self.make_client(
            response(200, {"email": {"id": 41, "subject": "Draft"}})
        )

        email = client.get_email(41)

        self.assertEqual(email["id"], 41)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/emails/41"),
        )

    def test_create_email_posts_payload_and_returns_email(self):
        payload = {
            "name": "Draft",
            "subject": "Draft subject",
            "emailType": "list",
            "lists": [1],
            "isPublished": False,
        }
        client, session = self.make_client(
            response(201, {"email": {"id": 42, **payload}})
        )

        email = client.create_email(payload)

        self.assertEqual(email["id"], 42)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/emails/new"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["data"],
            [
                ("name", "Draft"),
                ("subject", "Draft subject"),
                ("emailType", "list"),
                ("lists[]", 1),
                ("isPublished", "0"),
            ],
        )

    def test_update_email_patches_same_email(self):
        payload = {"subject": "Updated"}
        client, session = self.make_client(
            response(200, {"email": {"id": 42, "subject": "Updated"}})
        )

        email = client.update_email(42, payload)

        self.assertEqual(email["id"], 42)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/emails/42/edit"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["data"],
            [("subject", "Updated")],
        )

    def test_email_form_data_repeats_multiple_list_values(self):
        encoded = MauticClient._email_form_data(
            {
                "lists": [1, 2],
                "excludedLists": [3],
                "isPublished": True,
            }
        )

        self.assertEqual(
            encoded,
            [
                ("lists[]", 1),
                ("lists[]", 2),
                ("excludedLists[]", 3),
                ("isPublished", "1"),
            ],
        )

    def test_delete_email_uses_expected_route_and_accepts_null_deleted_id(self):
        client, session = self.make_client(response(200, {"email": {"id": None}}))

        deleted = client.delete_email(42)

        self.assertIsNone(deleted["id"])
        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/emails/42/delete"),
        )

    def test_send_email_to_contact_uses_single_contact_route(self):
        client, session = self.make_client(response(200, {"success": True}))

        result = client.send_email_to_contact(42, 51)

        self.assertTrue(result["success"])
        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/emails/42/contact/51/send"),
        )
        self.assertNotIn("data", session.request.call_args.kwargs)

    def test_send_email_to_contact_rejects_missing_ids(self):
        client, session = self.make_client()

        for email_id, contact_id in (("", 51), (42, "")):
            with self.subTest(email_id=email_id, contact_id=contact_id):
                with self.assertRaises(PermanentMauticError):
                    client.send_email_to_contact(email_id, contact_id)

        session.request.assert_not_called()

    def test_send_email_to_contact_requires_success_response(self):
        client, _ = self.make_client(response(200, {"success": False}))

        with self.assertRaises(TemporaryMauticError):
            client.send_email_to_contact(42, 51)

    def test_send_email_to_segments_uses_broadcast_route_and_list_encoding(self):
        client, session = self.make_client(
            response(
                200,
                {
                    "success": 1,
                    "sentCount": 3,
                    "failedRecipients": [],
                },
            )
        )

        result = client.send_email_to_segments(42, [7, "22"])

        self.assertEqual(result["sentCount"], 3)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/emails/42/send"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["data"],
            [("lists[]", "7"), ("lists[]", "22")],
        )

    def test_send_email_to_segments_rejects_missing_email_or_segments(self):
        client, session = self.make_client()

        for email_id, segment_ids in (
            ("", [7]),
            (42, []),
            (42, ["", "  "]),
        ):
            with self.subTest(email_id=email_id, segment_ids=segment_ids):
                with self.assertRaises(PermanentMauticError):
                    client.send_email_to_segments(email_id, segment_ids)

        session.request.assert_not_called()

    def test_send_email_to_segments_requires_success_response(self):
        client, _ = self.make_client(
            response(
                200,
                {
                    "success": 0,
                    "sentCount": 0,
                    "failedRecipients": [],
                },
            )
        )

        with self.assertRaises(TemporaryMauticError):
            client.send_email_to_segments(42, [7])

    def test_missing_email_id_is_rejected(self):
        client, session = self.make_client()

        for method in (client.get_email, client.delete_email):
            with self.subTest(method=method.__name__):
                with self.assertRaises(PermanentMauticError):
                    method("")

        with self.assertRaises(PermanentMauticError):
            client.update_email("", {})

        session.request.assert_not_called()

    def test_auth_errors_are_permanent(self):
        for status_code in (401, 403):
            with self.subTest(status_code=status_code):
                client, _ = self.make_client(
                    response(status_code, {"errors": [{"message": "Unauthorized"}]})
                )
                with self.assertRaises(PermanentMauticError):
                    client.get_email(42)

    def test_rate_limit_and_server_errors_are_temporary(self):
        for status_code in (429, 500, 503):
            with self.subTest(status_code=status_code):
                client, _ = self.make_client(
                    response(status_code, {"errors": [{"message": "Unavailable"}]})
                )
                with self.assertRaises(TemporaryMauticError):
                    client.get_email(42)

    def test_transport_errors_are_temporary(self):
        for error in (
            requests.Timeout("timeout"),
            requests.ConnectionError("connection"),
        ):
            with self.subTest(error=type(error).__name__):
                client, session = self.make_client()
                session.request.side_effect = error
                with self.assertRaises(TemporaryMauticError):
                    client.get_email(42)

    def test_invalid_email_response_is_temporary(self):
        result = response(200)
        result.json.side_effect = ValueError("invalid JSON")
        client, _ = self.make_client(result)

        with self.assertRaises(TemporaryMauticError):
            client.get_email(42)

    def test_missing_email_envelope_is_temporary(self):
        client, _ = self.make_client(response(200, {"email": {}}))

        with self.assertRaises(TemporaryMauticError):
            client.get_email(42)
