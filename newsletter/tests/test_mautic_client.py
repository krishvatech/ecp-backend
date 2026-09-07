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

    def test_get_contact_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(
            response(200, {"contact": {"id": 2, "points": 0}})
        )

        contact = client.get_contact("2")

        self.assertEqual(contact["id"], 2)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/contacts/2"),
        )

    def test_get_contact_requires_contact_id(self):
        client, _ = self.make_mautic_client()

        with self.assertRaisesRegex(
            PermanentMauticError,
            "contact id is required",
        ):
            client.get_contact("")

    def test_get_contact_rejects_malformed_response(self):
        client, _ = self.make_mautic_client(response(200, {"contact": []}))

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "contact detail returned an invalid response",
        ):
            client.get_contact("2")

    def test_get_contact_activity_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "events": [],
                    "total": 0,
                    "page": 1,
                    "limit": 25,
                    "maxPages": 1.0,
                },
            )
        )

        data = client.get_contact_activity("2", page=1, limit=25)

        self.assertEqual(data["total"], 0)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/contacts/2/activity"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["params"],
            {"page": 1, "limit": 25},
        )

    def test_get_contact_activity_requires_contact_id(self):
        client, _ = self.make_mautic_client()

        with self.assertRaisesRegex(
            PermanentMauticError,
            "contact id is required",
        ):
            client.get_contact_activity("")

    def test_get_contact_activity_rejects_malformed_response(self):
        client, _ = self.make_mautic_client(
            response(200, {"events": None})
        )

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "activity returned invalid events",
        ):
            client.get_contact_activity("2")

    def test_list_contacts_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "total": 1,
                    "contacts": {
                        "2": {
                            "id": 2,
                            "fields": {
                                "core": {
                                    "email": {"value": "ravi@example.com"},
                                }
                            },
                        }
                    },
                },
            )
        )

        data = client.list_contacts(start=0, limit=25, search="Ravi")

        self.assertEqual(data["total"], 1)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/contacts"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["params"],
            {"start": 0, "limit": 25, "search": "Ravi"},
        )

    def test_list_contacts_rejects_malformed_response(self):
        client, _ = self.make_mautic_client(response(200, {"total": 0}))

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "contact list returned an invalid response",
        ):
            client.list_contacts()

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

    def test_get_email_stats_returns_raw_stats_response(self):
        payload = {
            "total": 1,
            "data": [
                {
                    "id": 101,
                    "email_id": 77,
                    "email_address": "member@example.com",
                    "is_read": True,
                    "is_failed": False,
                }
            ],
        }
        client, session = self.make_mautic_client(response(200, payload))

        stats = client.get_email_stats(" 77 ")

        self.assertEqual(stats, payload)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/stats/email_stats"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["params"],
            {
                "where[0][col]": "email_id",
                "where[0][expr]": "eq",
                "where[0][val]": "77",
            },
        )

    def test_get_email_stats_allows_empty_response(self):
        payload = {"total": 0, "data": []}
        client, _ = self.make_mautic_client(response(200, payload))

        self.assertEqual(client.get_email_stats(77), payload)

    def test_get_email_stats_requires_email_id(self):
        client, session = self.make_mautic_client()

        with self.assertRaisesRegex(PermanentMauticError, "email ID is required"):
            client.get_email_stats("")

        session.request.assert_not_called()

    def test_get_email_stats_temporary_failure(self):
        client, _ = self.make_mautic_client(
            response(503, {"errors": [{"message": "Stats unavailable"}]})
        )

        with self.assertRaises(TemporaryMauticError):
            client.get_email_stats(77)

    def test_get_email_stats_permanent_failure(self):
        client, _ = self.make_mautic_client(
            response(403, {"errors": [{"message": "Access denied"}]})
        )

        with self.assertRaisesRegex(PermanentMauticError, "Access denied"):
            client.get_email_stats(77)

    def test_get_email_stats_rejects_unexpected_response(self):
        client, _ = self.make_mautic_client(response(200, {"email": {"id": 77}}))

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "email statistics lookup returned an invalid response",
        ):
            client.get_email_stats(77)

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

    def test_list_segments_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(
            response(200, {"lists": {"3": {"id": 3, "alias": "imaa-events"}}})
        )

        data = client.list_segments(search="alias:imaa-events", limit=20)

        self.assertEqual(data["lists"]["3"]["id"], 3)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/segments"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["params"],
            {"search": "alias:imaa-events", "limit": 20},
        )

    def test_list_segments_rejects_malformed_response(self):
        client, _ = self.make_mautic_client(response(200, {}))

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "segment list returned an invalid response",
        ):
            client.list_segments()

    def test_get_segment_returns_mautic_list_payload(self):
        client, session = self.make_mautic_client(
            response(200, {"list": {"id": 3, "name": "IMAA Events"}})
        )

        segment = client.get_segment(" 3 ")

        self.assertEqual(segment["id"], 3)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/segments/3"),
        )

    def test_create_segment_calls_new_endpoint(self):
        client, session = self.make_mautic_client(
            response(201, {"list": {"id": 4, "alias": "new-list"}})
        )

        segment = client.create_segment({"name": "New List", "filters": []})

        self.assertEqual(segment["id"], 4)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/segments/new"),
        )

    def test_update_segment_calls_edit_endpoint(self):
        client, session = self.make_mautic_client(
            response(200, {"list": {"id": 4, "name": "Updated"}})
        )

        segment = client.update_segment(4, {"name": "Updated"})

        self.assertEqual(segment["id"], 4)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/segments/4/edit"),
        )

    def test_delete_segment_calls_delete_endpoint(self):
        client, session = self.make_mautic_client(
            response(200, {"list": {"id": 4, "name": "Deleted"}})
        )

        client.delete_segment(4)

        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/segments/4/delete"),
        )

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
