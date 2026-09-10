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

    def test_list_point_actions_calls_expected_endpoint_and_accepts_empty_list(self):
        client, session = self.make_mautic_client(
            response(200, {"total": 0, "points": []})
        )

        data = client.list_point_actions(start=0, limit=100)

        self.assertEqual(data, {"total": 0, "points": []})
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/points"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["params"],
            {"start": 0, "limit": 100},
        )

    def test_list_point_actions_rejects_malformed_response(self):
        client, _ = self.make_mautic_client(response(200, {"total": 0}))

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "point action list returned an invalid response",
        ):
            client.list_point_actions()

    def test_list_point_action_types_returns_provider_types(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "pointActionTypes": {
                        "email.open": "Opens an email",
                        "url.hit": "Visits specific URL",
                    }
                },
            )
        )

        action_types = client.list_point_action_types()

        self.assertEqual(
            action_types,
            {
                "email.open": "Opens an email",
                "url.hit": "Visits specific URL",
            },
        )
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/points/actions/types"),
        )

    def test_get_point_action_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "point": {
                        "id": 8,
                        "name": "Newsletter open",
                        "type": "email.open",
                        "delta": 2,
                    }
                },
            )
        )

        point = client.get_point_action(" 8 ")

        self.assertEqual(point["id"], 8)
        self.assertEqual(point["delta"], 2)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/points/8"),
        )

    def test_create_and_update_point_action_use_standard_endpoints(self):
        payload = {
            "name": "Newsletter open",
            "type": "email.open",
            "delta": 2,
            "repeatable": True,
            "properties": {},
            "isPublished": True,
        }
        client, session = self.make_mautic_client(
            response(
                201,
                {
                    "point": {
                        "id": 8,
                        **payload,
                    }
                },
            )
        )

        created = client.create_point_action(payload)

        self.assertEqual(created["id"], 8)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/points/new"),
        )
        self.assertEqual(session.request.call_args.kwargs["data"], payload)

        session.reset_mock()
        session.request.return_value = response(
            200,
            {
                "point": {
                    "id": 8,
                    **payload,
                    "delta": 5,
                }
            },
        )

        updated = client.update_point_action(8, {"delta": 5})

        self.assertEqual(updated["delta"], 5)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/points/8/edit"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["data"],
            {"delta": 5},
        )

    def test_create_point_action_persists_type_specific_properties_in_second_step(self):
        client, session = self.make_mautic_client()
        session.request.side_effect = [
            response(
                201,
                {
                    "point": {
                        "id": 9,
                        "name": "Important URL",
                        "type": "url.hit",
                        "delta": 3,
                        "properties": [],
                    }
                },
            ),
            response(
                200,
                {
                    "point": {
                        "id": 9,
                        "name": "Important URL",
                        "type": "url.hit",
                        "delta": 3,
                        "properties": {
                            "page_url": "https://example.com/important",
                            "page_hits": 1,
                        },
                    }
                },
            ),
            response(
                200,
                {
                    "point": {
                        "id": 9,
                        "name": "Important URL",
                        "type": "url.hit",
                        "delta": 3,
                        "properties": {
                            "page_url": "https://example.com/important",
                            "page_hits": 1,
                        },
                    }
                },
            ),
        ]

        payload = {
            "name": "Important URL",
            "type": "url.hit",
            "delta": 3,
            "repeatable": True,
            "isPublished": True,
            "properties[page_url]": "https://example.com/important",
            "properties[page_hits]": 1,
        }

        created = client.create_point_action(payload)

        self.assertEqual(created["id"], 9)
        self.assertEqual(
            created["properties"]["page_url"],
            "https://example.com/important",
        )
        self.assertEqual(session.request.call_count, 3)

        create_call, patch_call, fetch_call = session.request.call_args_list
        self.assertEqual(
            create_call.args[:2],
            ("POST", "http://mautic.local/api/points/new"),
        )
        self.assertNotIn(
            "properties[page_url]",
            create_call.kwargs["data"],
        )
        self.assertNotIn(
            "properties[page_hits]",
            create_call.kwargs["data"],
        )

        self.assertEqual(
            patch_call.args[:2],
            ("PATCH", "http://mautic.local/api/points/9/edit"),
        )
        self.assertEqual(
            patch_call.kwargs["data"],
            {
                "properties[page_url]": "https://example.com/important",
                "properties[page_hits]": 1,
                "type": "url.hit",
            },
        )

        self.assertEqual(
            fetch_call.args[:2],
            ("GET", "http://mautic.local/api/points/9"),
        )

    def test_create_point_action_cleans_up_partial_entity_when_properties_fail(self):
        client, session = self.make_mautic_client()
        session.request.side_effect = [
            response(
                201,
                {
                    "point": {
                        "id": 10,
                        "name": "Broken URL",
                        "type": "url.hit",
                        "delta": 3,
                        "properties": [],
                    }
                },
            ),
            response(
                422,
                {
                    "errors": [
                        {"message": "Invalid Point Action properties"}
                    ]
                },
            ),
            response(
                200,
                {
                    "point": {
                        "id": None,
                        "name": "Broken URL",
                    }
                },
            ),
        ]

        with self.assertRaisesRegex(
            PermanentMauticError,
            "Invalid Point Action properties",
        ):
            client.create_point_action(
                {
                    "name": "Broken URL",
                    "type": "url.hit",
                    "delta": 3,
                    "properties[page_url]": "not-a-valid-url",
                }
            )

        self.assertEqual(session.request.call_count, 3)
        cleanup_call = session.request.call_args_list[2]
        self.assertEqual(
            cleanup_call.args[:2],
            ("DELETE", "http://mautic.local/api/points/10/delete"),
        )

    def test_create_point_action_cleans_up_when_provider_does_not_persist_properties(self):
        client, session = self.make_mautic_client()
        session.request.side_effect = [
            response(
                201,
                {
                    "point": {
                        "id": 11,
                        "name": "URL action",
                        "type": "url.hit",
                        "delta": 3,
                        "properties": [],
                    }
                },
            ),
            response(
                200,
                {
                    "point": {
                        "id": 11,
                        "name": "URL action",
                        "type": "url.hit",
                        "delta": 3,
                        "properties": [],
                    }
                },
            ),
            response(
                200,
                {
                    "point": {
                        "id": 11,
                        "name": "URL action",
                        "type": "url.hit",
                        "delta": 3,
                        "properties": [],
                    }
                },
            ),
            response(
                200,
                {
                    "point": {
                        "id": None,
                        "name": "URL action",
                    }
                },
            ),
        ]

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "properties were not persisted",
        ):
            client.create_point_action(
                {
                    "name": "URL action",
                    "type": "url.hit",
                    "delta": 3,
                    "properties[page_url]": "https://example.com/action",
                }
            )

        cleanup_call = session.request.call_args_list[-1]
        self.assertEqual(
            cleanup_call.args[:2],
            ("DELETE", "http://mautic.local/api/points/11/delete"),
        )

    def test_delete_point_action_accepts_response_without_id(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "point": {
                        "id": None,
                        "name": "Newsletter open",
                    }
                },
            )
        )

        deleted = client.delete_point_action(8)

        self.assertIsNone(deleted["id"])
        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/points/8/delete"),
        )

    def test_point_action_methods_require_id(self):
        client, session = self.make_mautic_client()

        with self.assertRaisesRegex(
            PermanentMauticError,
            "point action ID is required",
        ):
            client.get_point_action("")
        with self.assertRaisesRegex(
            PermanentMauticError,
            "point action ID is required",
        ):
            client.update_point_action("", {"delta": 2})
        with self.assertRaisesRegex(
            PermanentMauticError,
            "point action ID is required",
        ):
            client.delete_point_action("")

        session.request.assert_not_called()

    def test_list_point_groups_calls_expected_endpoint_and_accepts_empty_list(self):
        client, session = self.make_mautic_client(
            response(200, {"total": 0, "pointGroups": []})
        )

        data = client.list_point_groups(start=0, limit=100)

        self.assertEqual(data, {"total": 0, "pointGroups": []})
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/points/groups"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["params"],
            {"start": 0, "limit": 100},
        )

    def test_list_point_groups_rejects_malformed_response(self):
        client, _ = self.make_mautic_client(response(200, {"total": 0}))

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "point group list returned an invalid response",
        ):
            client.list_point_groups()

    def test_point_group_crud_uses_standard_endpoints(self):
        payload = {
            "name": "Engagement",
            "description": "Newsletter engagement score",
            "isPublished": False,
        }
        client, session = self.make_mautic_client(
            response(
                201,
                {
                    "pointGroup": {
                        "id": 4,
                        **payload,
                    }
                },
            )
        )

        created = client.create_point_group(payload)
        self.assertEqual(created["id"], 4)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/points/groups/new"),
        )
        self.assertEqual(session.request.call_args.kwargs["data"], payload)

        session.reset_mock()
        session.request.return_value = response(
            200,
            {"pointGroup": {"id": 4, **payload}},
        )
        fetched = client.get_point_group(" 4 ")
        self.assertEqual(fetched["name"], "Engagement")
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/points/groups/4"),
        )

        session.reset_mock()
        session.request.return_value = response(
            200,
            {
                "pointGroup": {
                    "id": 4,
                    **payload,
                    "name": "Engagement Updated",
                }
            },
        )
        updated = client.update_point_group(
            4,
            {"name": "Engagement Updated"},
        )
        self.assertEqual(updated["name"], "Engagement Updated")
        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/points/groups/4/edit"),
        )

        session.reset_mock()
        session.request.return_value = response(
            200,
            {
                "pointGroup": {
                    "id": None,
                    "name": "Engagement Updated",
                }
            },
        )
        deleted = client.delete_point_group(4)
        self.assertIsNone(deleted["id"])
        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/points/groups/4/delete"),
        )

    def test_point_group_methods_validate_ids(self):
        client, session = self.make_mautic_client()

        with self.assertRaisesRegex(
            PermanentMauticError,
            "point group ID is required",
        ):
            client.get_point_group("")
        with self.assertRaisesRegex(
            PermanentMauticError,
            "point group ID is required",
        ):
            client.update_point_group("", {"name": "Updated"})
        with self.assertRaisesRegex(
            PermanentMauticError,
            "point group ID is required",
        ):
            client.delete_point_group("")

        session.request.assert_not_called()

    def test_list_contact_point_groups_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "total": 1,
                    "groupScores": [
                        {
                            "score": 7,
                            "group": {
                                "id": 4,
                                "name": "Engagement",
                                "description": "",
                            },
                        }
                    ],
                },
            )
        )

        data = client.list_contact_point_groups(12)

        self.assertEqual(data["total"], 1)
        self.assertEqual(data["groupScores"][0]["score"], 7)
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "GET",
                "http://mautic.local/api/contacts/12/points/groups",
            ),
        )

    def test_get_contact_point_group_returns_group_score(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "groupScore": {
                        "score": 7,
                        "group": {
                            "id": 4,
                            "name": "Engagement",
                            "description": "",
                        },
                    }
                },
            )
        )

        score = client.get_contact_point_group(" 12 ", " 4 ")

        self.assertEqual(score["score"], 7)
        self.assertEqual(score["group"]["id"], 4)
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "GET",
                "http://mautic.local/api/contacts/12/points/groups/4",
            ),
        )

    def test_adjust_contact_group_points_forwards_audit_labels(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "groupScore": {
                        "score": 7,
                        "group": {
                            "id": 4,
                            "name": "Engagement",
                            "description": "",
                        },
                    }
                },
            )
        )

        score = client.adjust_contact_group_points(
            12,
            4,
            "plus",
            7,
            event_name="Manual group adjustment",
            action_name="ECP Newsletter",
        )

        self.assertEqual(score["score"], 7)
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "POST",
                "http://mautic.local/api/contacts/12/points/groups/4/plus/7",
            ),
        )
        self.assertEqual(
            session.request.call_args.kwargs["data"],
            {
                "eventName": "Manual group adjustment",
                "actionName": "ECP Newsletter",
            },
        )

    def test_adjust_contact_group_points_supports_minus_and_validates_input(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "groupScore": {
                        "score": 0,
                        "group": {
                            "id": 4,
                            "name": "Engagement",
                        },
                    }
                },
            )
        )

        client.adjust_contact_group_points(12, 4, "minus", 3)

        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "POST",
                "http://mautic.local/api/contacts/12/points/groups/4/minus/3",
            ),
        )
        self.assertIsNone(session.request.call_args.kwargs["data"])

        invalid_cases = [
            ("", "4", "plus", 1),
            ("12", "", "plus", 1),
            ("12", "4", "set", 1),
            ("12", "4", "plus", 0),
            ("12", "4", "plus", True),
            ("12", "4", "plus", "abc"),
        ]
        for contact_id, group_id, operator, amount in invalid_cases:
            with self.assertRaises(PermanentMauticError):
                client.adjust_contact_group_points(
                    contact_id,
                    group_id,
                    operator,
                    amount,
                )

    def test_contact_point_group_methods_validate_and_reject_malformed_response(self):
        client, session = self.make_mautic_client()

        with self.assertRaisesRegex(
            PermanentMauticError,
            "contact ID is required",
        ):
            client.list_contact_point_groups("")
        with self.assertRaisesRegex(
            PermanentMauticError,
            "contact ID and point group ID are required",
        ):
            client.get_contact_point_group("", 4)

        session.request.assert_not_called()

        malformed_client, _ = self.make_mautic_client(
            response(200, {"groupScore": {"score": 7}})
        )
        with self.assertRaisesRegex(
            TemporaryMauticError,
            "point group lookup returned an invalid response",
        ):
            malformed_client.get_contact_point_group(12, 4)

        malformed_list_client, _ = self.make_mautic_client(
            response(200, {"total": 0})
        )
        with self.assertRaisesRegex(
            TemporaryMauticError,
            "point group list returned an invalid response",
        ):
            malformed_list_client.list_contact_point_groups(12)

    def test_list_point_triggers_calls_expected_endpoint_and_accepts_empty_list(self):
        client, session = self.make_mautic_client(
            response(200, {"total": 0, "triggers": []})
        )

        data = client.list_point_triggers(start=0, limit=100)

        self.assertEqual(data, {"total": 0, "triggers": []})
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/points/triggers"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["params"],
            {"start": 0, "limit": 100},
        )

    def test_list_point_triggers_rejects_malformed_response(self):
        client, _ = self.make_mautic_client(
            response(200, {"total": 0})
        )

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "point trigger list returned an invalid response",
        ):
            client.list_point_triggers()

    def test_list_point_trigger_event_types_returns_provider_types(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "eventTypes": {
                        "lead.changelists": "Modify contact's segments",
                        "email.send": "Send an email",
                    }
                },
            )
        )

        event_types = client.list_point_trigger_event_types()

        self.assertEqual(
            event_types,
            {
                "lead.changelists": "Modify contact's segments",
                "email.send": "Send an email",
            },
        )
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "GET",
                "http://mautic.local/api/points/triggers/events/types",
            ),
        )

    def test_get_point_trigger_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "trigger": {
                        "id": 4,
                        "name": "Warm lead",
                        "points": 25,
                        "color": "a0acb8",
                        "events": [],
                    }
                },
            )
        )

        trigger = client.get_point_trigger(" 4 ")

        self.assertEqual(trigger["id"], 4)
        self.assertEqual(trigger["points"], 25)
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "GET",
                "http://mautic.local/api/points/triggers/4",
            ),
        )

    def test_create_and_update_point_trigger_use_standard_endpoints(self):
        payload = {
            "name": "Warm lead",
            "description": "Reached scoring threshold",
            "points": 25,
            "color": "f59e0b",
            "triggerExistingLeads": False,
            "isPublished": True,
        }
        client, session = self.make_mautic_client(
            response(
                201,
                {
                    "trigger": {
                        "id": 4,
                        **payload,
                        "events": [],
                    }
                },
            )
        )

        created = client.create_point_trigger(payload)

        self.assertEqual(created["id"], 4)
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "POST",
                "http://mautic.local/api/points/triggers/new",
            ),
        )
        self.assertEqual(
            session.request.call_args.kwargs["data"],
            payload,
        )

        session.reset_mock()
        session.request.return_value = response(
            200,
            {
                "trigger": {
                    "id": 4,
                    **payload,
                    "points": 50,
                    "events": [],
                }
            },
        )

        updated = client.update_point_trigger(
            4,
            {"points": 50},
        )

        self.assertEqual(updated["points"], 50)
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "PATCH",
                "http://mautic.local/api/points/triggers/4/edit",
            ),
        )
        self.assertEqual(
            session.request.call_args.kwargs["data"],
            {"points": 50},
        )

    def test_delete_point_trigger_accepts_response_without_id(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "trigger": {
                        "id": None,
                        "name": "Warm lead",
                    }
                },
            )
        )

        deleted = client.delete_point_trigger(4)

        self.assertIsNone(deleted["id"])
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "DELETE",
                "http://mautic.local/api/points/triggers/4/delete",
            ),
        )

    def test_create_point_trigger_event_uses_direct_v2_resource(self):
        payload = {
            "name": "Add to segment",
            "description": "Warm lead routing",
            "type": "lead.changelists",
            "order": 1,
            "properties": {
                "addToLists": [3],
                "removeFromLists": [],
            },
        }
        client, session = self.make_mautic_client(
            response(
                201,
                {
                    "@context": "/api/v2/contexts/TriggerEvent",
                    "@id": "/api/v2/trigger_events/10",
                    "@type": "TriggerEvent",
                    "id": 10,
                    **payload,
                    "trigger": {
                        "@id": "/api/v2/triggers/4",
                        "@type": "Trigger",
                    },
                },
            )
        )

        event = client.create_point_trigger_event(4, payload)

        self.assertEqual(event["id"], 10)
        self.assertEqual(event["type"], "lead.changelists")
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "POST",
                "http://mautic.local/api/v2/trigger_events",
            ),
        )
        self.assertEqual(
            session.request.call_args.kwargs["json"],
            {
                **payload,
                "trigger": "/api/v2/triggers/4",
            },
        )
        self.assertEqual(
            session.request.call_args.kwargs["headers"],
            {
                "Content-Type": "application/ld+json",
            },
        )
        self.assertNotIn("trigger", payload)

    def test_get_point_trigger_event_uses_direct_v2_resource(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "@context": "/api/v2/contexts/TriggerEvent",
                    "@id": "/api/v2/trigger_events/10",
                    "@type": "TriggerEvent",
                    "id": 10,
                    "name": "Add to segment",
                    "type": "lead.changelists",
                    "order": 1,
                    "properties": {
                        "addToLists": [3],
                    },
                },
            )
        )

        event = client.get_point_trigger_event(" 10 ")

        self.assertEqual(event["id"], 10)
        self.assertEqual(event["type"], "lead.changelists")
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "GET",
                "http://mautic.local/api/v2/trigger_events/10",
            ),
        )

    def test_get_point_trigger_event_rejects_malformed_response(self):
        client, _ = self.make_mautic_client(
            response(
                200,
                {
                    "@context": "/api/v2/contexts/TriggerEvent",
                    "@type": "TriggerEvent",
                },
            )
        )

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "point trigger event lookup returned an invalid response",
        ):
            client.get_point_trigger_event(10)

    def test_update_point_trigger_event_uses_merge_patch_json(self):
        payload = {
            "name": "Updated segment event",
            "description": "Updated through direct API",
            "properties": {
                "addToLists": [3],
                "removeFromLists": [],
            },
        }
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "@context": "/api/v2/contexts/TriggerEvent",
                    "@id": "/api/v2/trigger_events/10",
                    "@type": "TriggerEvent",
                    "id": 10,
                    "name": "Updated segment event",
                    "type": "lead.changelists",
                    "order": 1,
                    "properties": payload["properties"],
                },
            )
        )

        event = client.update_point_trigger_event(10, payload)

        self.assertEqual(event["id"], 10)
        self.assertEqual(event["name"], "Updated segment event")
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "PATCH",
                "http://mautic.local/api/v2/trigger_events/10",
            ),
        )
        self.assertEqual(
            session.request.call_args.kwargs["json"],
            payload,
        )
        self.assertEqual(
            session.request.call_args.kwargs["headers"],
            {
                "Content-Type": "application/merge-patch+json",
            },
        )

    def test_delete_point_trigger_event_uses_direct_v2_resource(self):
        client, session = self.make_mautic_client(
            response(204, None)
        )

        result = client.delete_point_trigger_event(10)

        self.assertIsNone(result)
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "DELETE",
                "http://mautic.local/api/v2/trigger_events/10",
            ),
        )

    def test_point_trigger_methods_validate_ids_and_event_payload(self):
        client, session = self.make_mautic_client()

        with self.assertRaisesRegex(
            PermanentMauticError,
            "point trigger ID is required",
        ):
            client.get_point_trigger("")
        with self.assertRaisesRegex(
            PermanentMauticError,
            "point trigger ID is required",
        ):
            client.update_point_trigger("", {"points": 25})
        with self.assertRaisesRegex(
            PermanentMauticError,
            "point trigger ID is required",
        ):
            client.delete_point_trigger("")

        with self.assertRaisesRegex(
            PermanentMauticError,
            "point trigger ID is required",
        ):
            client.create_point_trigger_event("", {"name": "Event"})
        with self.assertRaisesRegex(
            PermanentMauticError,
            "event creation payload is required",
        ):
            client.create_point_trigger_event(4, {})
        with self.assertRaisesRegex(
            PermanentMauticError,
            "event creation payload is required",
        ):
            client.create_point_trigger_event(4, [])
        with self.assertRaisesRegex(
            PermanentMauticError,
            "point trigger event ID is required",
        ):
            client.get_point_trigger_event("")
        with self.assertRaisesRegex(
            PermanentMauticError,
            "point trigger event ID is required",
        ):
            client.update_point_trigger_event("", {"name": "Updated"})
        with self.assertRaisesRegex(
            PermanentMauticError,
            "point trigger event ID is required",
        ):
            client.delete_point_trigger_event("")
        with self.assertRaisesRegex(
            PermanentMauticError,
            "event update payload is required",
        ):
            client.update_point_trigger_event(10, {})
        with self.assertRaisesRegex(
            PermanentMauticError,
            "event update payload is required",
        ):
            client.update_point_trigger_event(10, [])

        session.request.assert_not_called()

    def test_adjust_contact_points_calls_mautic_and_forwards_audit_labels(self):
        client, session = self.make_mautic_client(
            response(200, {"success": 1})
        )

        result = client.adjust_contact_points(
            12,
            "plus",
            5,
            event_name="Manual engagement adjustment",
            action_name="ECP Newsletter",
        )

        self.assertEqual(result, {"success": 1})
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "POST",
                "http://mautic.local/api/contacts/12/points/plus/5",
            ),
        )
        self.assertEqual(
            session.request.call_args.kwargs["data"],
            {
                "eventName": "Manual engagement adjustment",
                "actionName": "ECP Newsletter",
            },
        )

    def test_adjust_contact_points_supports_minus_and_validates_input(self):
        client, session = self.make_mautic_client(
            response(200, {"success": 1})
        )

        client.adjust_contact_points(12, "minus", 3)

        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "POST",
                "http://mautic.local/api/contacts/12/points/minus/3",
            ),
        )
        self.assertIsNone(session.request.call_args.kwargs["data"])

        invalid_cases = [
            ("", "plus", 1),
            ("12", "set", 1),
            ("12", "plus", 0),
            ("12", "plus", True),
            ("12", "plus", "abc"),
        ]
        for contact_id, operator, amount in invalid_cases:
            with self.assertRaises(PermanentMauticError):
                client.adjust_contact_points(contact_id, operator, amount)

    def test_adjust_contact_points_rejects_unsuccessful_provider_response(self):
        client, _ = self.make_mautic_client(
            response(200, {"success": 0})
        )

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "unsuccessful response",
        ):
            client.adjust_contact_points(12, "plus", 5)

    def test_list_stages_calls_expected_endpoint_and_accepts_empty_list(self):
        client, session = self.make_mautic_client(
            response(200, {"total": 0, "stages": []})
        )

        data = client.list_stages(start=0, limit=30)

        self.assertEqual(data, {"total": 0, "stages": []})
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/stages"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["params"],
            {"start": 0, "limit": 30},
        )

    def test_list_stages_rejects_malformed_response(self):
        client, _ = self.make_mautic_client(response(200, {"total": 0}))

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "stage list returned an invalid response",
        ):
            client.list_stages()

    def test_get_stage_returns_stage_payload(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "stage": {
                        "id": 4,
                        "name": "Engaged",
                        "weight": 20,
                        "isPublished": True,
                    }
                },
            )
        )

        stage = client.get_stage(" 4 ")

        self.assertEqual(stage["id"], 4)
        self.assertEqual(stage["name"], "Engaged")
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/stages/4"),
        )

    def test_get_stage_requires_stage_id(self):
        client, session = self.make_mautic_client()

        with self.assertRaisesRegex(PermanentMauticError, "stage ID is required"):
            client.get_stage("")

        session.request.assert_not_called()

    def test_create_stage_calls_new_endpoint(self):
        client, session = self.make_mautic_client(
            response(
                201,
                {
                    "stage": {
                        "id": 5,
                        "name": "Subscriber",
                        "weight": 10,
                    }
                },
            )
        )
        payload = {
            "name": "Subscriber",
            "description": "Newsletter subscriber",
            "weight": 10,
            "isPublished": True,
        }

        stage = client.create_stage(payload)

        self.assertEqual(stage["id"], 5)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/stages/new"),
        )
        self.assertEqual(session.request.call_args.kwargs["data"], payload)

    def test_update_stage_calls_edit_endpoint(self):
        client, session = self.make_mautic_client(
            response(
                200,
                {
                    "stage": {
                        "id": 5,
                        "name": "Engaged",
                        "weight": 20,
                    }
                },
            )
        )

        stage = client.update_stage(5, {"name": "Engaged", "weight": 20})

        self.assertEqual(stage["id"], 5)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/stages/5/edit"),
        )

    def test_delete_stage_accepts_mautic_response_without_id(self):
        client, session = self.make_mautic_client(
            response(200, {"stage": {"id": None, "name": "Subscriber"}})
        )

        deleted = client.delete_stage(5)

        self.assertIsNone(deleted["id"])
        self.assertEqual(deleted["name"], "Subscriber")
        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/stages/5/delete"),
        )

    def test_add_contact_to_stage_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(response(200, {"success": 1}))

        client.add_contact_to_stage(5, 51)

        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/stages/5/contact/51/add"),
        )

    def test_remove_contact_from_stage_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(response(200, {"success": 1}))

        client.remove_contact_from_stage(5, 51)

        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/stages/5/contact/51/remove"),
        )

    def test_stage_contact_assignment_requires_both_ids(self):
        client, session = self.make_mautic_client()

        with self.assertRaisesRegex(
            PermanentMauticError,
            "stage ID and contact ID are required",
        ):
            client.add_contact_to_stage("", 51)

        with self.assertRaisesRegex(
            PermanentMauticError,
            "stage ID and contact ID are required",
        ):
            client.remove_contact_from_stage(5, "")

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

    def test_list_forms_calls_expected_endpoint(self):
        client, session = self.make_mautic_client(
            response(200, {"forms": {"7": {"id": 7, "name": "Signup"}}})
        )

        data = client.list_forms(limit=20)

        self.assertEqual(data["forms"]["7"]["id"], 7)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/forms"),
        )
        self.assertEqual(session.request.call_args.kwargs["params"], {"limit": 20})

    def test_list_forms_rejects_malformed_response(self):
        client, _ = self.make_mautic_client(response(200, {}))

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "form list returned an invalid response",
        ):
            client.list_forms()

    def test_get_campaign_builder_capabilities_calls_plugin_endpoint(self):
        payload = {
            "actions": [
                {
                    "key": "lead.changepoints",
                    "type": "lead.changepoints",
                    "eventType": "action",
                    "label": "Adjust contact points",
                }
            ],
            "conditions": [
                {
                    "key": "lead.field_value",
                    "type": "lead.field_value",
                    "eventType": "condition",
                    "label": "Contact field value",
                }
            ],
            "decisions": [
                {
                    "key": "page.pagehit",
                    "type": "page.pagehit",
                    "eventType": "decision",
                    "label": "Visits a page",
                }
            ],
            "connectionRestrictions": {"lead.changepoints": {"source": {}}},
            "formSchema": {"available": False},
        }
        client, session = self.make_mautic_client(response(200, payload))

        data = client.get_campaign_builder_capabilities()

        self.assertEqual(data["actions"][0]["key"], "lead.changepoints")
        self.assertEqual(
            session.request.call_args.args[:2],
            (
                "GET",
                "http://mautic.local/api/ecp/campaign-builder/capabilities",
            ),
        )

    def test_get_campaign_builder_capabilities_rejects_malformed_response(self):
        client, _ = self.make_mautic_client(
            response(
                200,
                {
                    "actions": {},
                    "conditions": [],
                    "decisions": [],
                    "connectionRestrictions": {},
                },
            )
        )

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "campaign builder capabilities returned invalid actions",
        ):
            client.get_campaign_builder_capabilities()

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
