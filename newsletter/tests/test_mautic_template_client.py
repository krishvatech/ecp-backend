from unittest.mock import Mock

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
class MauticTemplateClientTests(SimpleTestCase):
    def make_client(self):
        session = Mock()
        return MauticClient(session=session), session

    def test_list_templates_filters_mixed_email_types_in_ecp(self):
        client, session = self.make_client()
        session.request.return_value = response(
            200,
            {
                "total": 3,
                "emails": {
                    "9": {
                        "id": 9,
                        "name": "Campaign",
                        "emailType": "list",
                    },
                    "10": {
                        "id": 10,
                        "name": "Template A",
                        "emailType": "template",
                    },
                    "11": {
                        "id": 11,
                        "name": "Template B",
                        "emailType": "template",
                    },
                },
            },
        )

        result = client.list_email_templates(
            start=0,
            limit=25,
            search="Template",
            email_type="template",
        )

        self.assertEqual(result["total"], 2)
        self.assertEqual(
            [item["id"] for item in result["emails"]],
            [10, 11],
        )
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/emails"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["params"],
            {
                "search": "Template",
                "start": 0,
                "limit": 100,
            },
        )

    def test_list_templates_applies_pagination_after_type_filter(self):
        client, session = self.make_client()
        session.request.return_value = response(
            200,
            {
                "total": 4,
                "emails": [
                    {"id": 1, "emailType": "list"},
                    {"id": 2, "emailType": "template"},
                    {"id": 3, "emailType": "list"},
                    {"id": 4, "emailType": "template"},
                ],
            },
        )

        result = client.list_email_templates(start=1, limit=1)

        self.assertEqual(result["total"], 2)
        self.assertEqual(
            [item["id"] for item in result["emails"]],
            [4],
        )

    def test_list_templates_rejects_malformed_provider_response(self):
        client, session = self.make_client()
        session.request.return_value = response(
            200,
            {"total": 0},
        )

        with self.assertRaisesRegex(
            TemporaryMauticError,
            "template list returned an invalid response",
        ):
            client.list_email_templates()

    def test_list_templates_validates_pagination(self):
        client, session = self.make_client()

        for start, limit in [
            (-1, 25),
            (0, 0),
            ("bad", 25),
            (0, True),
        ]:
            with self.assertRaisesRegex(
                PermanentMauticError,
                "pagination is invalid",
            ):
                client.list_email_templates(
                    start=start,
                    limit=limit,
                )

        session.request.assert_not_called()

    def test_get_template_rejects_list_email(self):
        client, session = self.make_client()
        session.request.return_value = response(
            200,
            {
                "email": {
                    "id": 7,
                    "name": "Campaign",
                    "emailType": "list",
                }
            },
        )

        with self.assertRaisesRegex(
            PermanentMauticError,
            "is not a Mautic template email",
        ):
            client.get_email_template(7)

    def test_create_template_forces_template_type(self):
        client, session = self.make_client()
        session.request.return_value = response(
            201,
            {
                "email": {
                    "id": 18,
                    "name": "Reusable",
                    "emailType": "template",
                }
            },
        )

        created = client.create_email_template(
            {
                "name": "Reusable",
                "subject": "Subject",
                "isPublished": False,
            }
        )

        self.assertEqual(created["id"], 18)
        form_data = session.request.call_args.kwargs["data"]
        self.assertIn(("emailType", "template"), form_data)

        with self.assertRaisesRegex(
            PermanentMauticError,
            "type must be template",
        ):
            client.create_email_template(
                {
                    "name": "Unsafe",
                    "emailType": "list",
                }
            )

    def test_update_template_verifies_existing_type_and_keeps_template_type(self):
        client, session = self.make_client()
        session.request.side_effect = [
            response(
                200,
                {
                    "email": {
                        "id": 18,
                        "name": "Reusable",
                        "emailType": "template",
                    }
                },
            ),
            response(
                200,
                {
                    "email": {
                        "id": 18,
                        "name": "Updated",
                        "emailType": "template",
                    }
                },
            ),
        ]

        updated = client.update_email_template(
            18,
            {"name": "Updated"},
        )

        self.assertEqual(updated["name"], "Updated")
        self.assertEqual(session.request.call_count, 2)
        self.assertEqual(
            session.request.call_args_list[0].args[:2],
            ("GET", "http://mautic.local/api/emails/18"),
        )
        self.assertEqual(
            session.request.call_args_list[1].args[:2],
            ("PATCH", "http://mautic.local/api/emails/18/edit"),
        )
        self.assertIn(
            ("emailType", "template"),
            session.request.call_args_list[1].kwargs["data"],
        )

    def test_delete_template_verifies_type_before_delete(self):
        client, session = self.make_client()
        session.request.side_effect = [
            response(
                200,
                {
                    "email": {
                        "id": 18,
                        "name": "Reusable",
                        "emailType": "template",
                    }
                },
            ),
            response(
                200,
                {
                    "email": {
                        "id": None,
                        "name": "Reusable",
                        "emailType": "template",
                    }
                },
            ),
        ]

        deleted = client.delete_email_template(18)

        self.assertIsNone(deleted["id"])
        self.assertEqual(
            session.request.call_args_list[1].args[:2],
            ("DELETE", "http://mautic.local/api/emails/18/delete"),
        )

    def test_duplicate_template_creates_draft_without_provider_metadata(self):
        client, session = self.make_client()
        session.request.side_effect = [
            response(
                200,
                {
                    "email": {
                        "id": 18,
                        "name": "Reusable",
                        "subject": "Subject",
                        "emailType": "template",
                        "category": {"id": 4, "title": "Email"},
                        "template": "blank",
                        "customHtml": "<h1>HTML</h1>",
                        "plainText": "Plain",
                        "sentCount": 99,
                        "readCount": 25,
                    }
                },
            ),
            response(
                201,
                {
                    "email": {
                        "id": 22,
                        "name": "Reusable Copy",
                        "emailType": "template",
                    }
                },
            ),
        ]

        duplicated = client.duplicate_email_template(18)

        self.assertEqual(duplicated["id"], 22)
        form_data = session.request.call_args_list[1].kwargs["data"]
        self.assertIn(("name", "Reusable Copy"), form_data)
        self.assertIn(("isPublished", "0"), form_data)
        self.assertIn(("category", 4), form_data)
        self.assertIn(("template", "blank"), form_data)
        self.assertNotIn(("id", 18), form_data)
        self.assertNotIn(("sentCount", 99), form_data)
        self.assertNotIn(("readCount", 25), form_data)

    def test_list_categories_uses_official_rest_endpoint(self):
        client, session = self.make_client()
        session.request.return_value = response(
            200,
            {"categories": [{"id": 4, "bundle": "email"}]},
        )

        result = client.list_categories(start=0, limit=500)

        self.assertEqual(result["categories"][0]["id"], 4)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/categories"),
        )
        self.assertEqual(
            session.request.call_args.kwargs["params"],
            {"start": 0, "limit": 500},
        )

    def test_list_themes_uses_official_rest_endpoint(self):
        client, session = self.make_client()
        session.request.return_value = response(
            200,
            {"themes": {"blank": {"key": "blank"}}},
        )

        result = client.list_themes()

        self.assertEqual(result["themes"]["blank"]["key"], "blank")
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/themes"),
        )
