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
class MauticCampaignClientTests(SimpleTestCase):
    def make_client(self):
        session = Mock()
        return MauticClient(session=session), session

    def test_campaign_form_data_encodes_nested_workflow_payload(self):
        encoded = MauticClient._campaign_form_data({
            "name": "Native Campaign",
            "isPublished": False,
            "lists": [{"id": 3}],
            "events": [{
                "id": "new_1",
                "type": "lead.field_value",
                "eventType": "condition",
                "properties": {
                    "field": "country",
                    "operator": "=",
                    "value": "India",
                },
                "children": ["new_2"],
                "parent": None,
            }],
            "canvasSettings": {
                "nodes": [{
                    "id": "new_1",
                    "positionX": "400",
                    "positionY": "220",
                }],
                "connections": [],
            },
        })
        self.assertIn(("isPublished", "0"), encoded)
        self.assertIn(("lists[0][id]", 3), encoded)
        self.assertIn(("events[0][properties][field]", "country"), encoded)
        self.assertIn(("events[0][children][0]", "new_2"), encoded)
        self.assertIn(("events[0][parent]", ""), encoded)
        self.assertIn(("canvasSettings[nodes][0][positionX]", "400"), encoded)

    def test_campaign_form_data_requires_non_empty_mapping(self):
        for payload in ({}, None, [], "bad"):
            with self.assertRaisesRegex(PermanentMauticError, "campaign payload is required"):
                MauticClient._campaign_form_data(payload)

    def test_list_campaigns_returns_provider_collection(self):
        client, session = self.make_client()
        session.request.return_value = response(200, {
            "total": 1,
            "campaigns": {"2": {"id": 2, "name": "Native Campaign"}},
        })
        result = client.list_campaigns(
            start=0, limit=25, search="Native", withContactCounts="true"
        )
        self.assertEqual(result["total"], 1)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/campaigns"),
        )
        self.assertEqual(session.request.call_args.kwargs["params"], {
            "start": 0,
            "limit": 25,
            "search": "Native",
            "withContactCounts": "true",
        })

    def test_list_campaigns_rejects_invalid_collection(self):
        client, session = self.make_client()
        session.request.return_value = response(200, {"total": 0})
        with self.assertRaisesRegex(TemporaryMauticError, "campaign list returned invalid campaigns"):
            client.list_campaigns()

    def test_get_campaign_requires_id_and_returns_campaign(self):
        client, session = self.make_client()
        session.request.return_value = response(200, {
            "campaign": {"id": 2, "name": "Native Campaign"}
        })
        campaign = client.get_campaign("2")
        self.assertEqual(campaign["id"], 2)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("GET", "http://mautic.local/api/campaigns/2"),
        )
        with self.assertRaisesRegex(PermanentMauticError, "campaign ID is required"):
            client.get_campaign("")

    def test_create_campaign_posts_nested_provider_payload(self):
        client, session = self.make_client()
        session.request.return_value = response(201, {
            "campaign": {"id": 2, "name": "Native Campaign"}
        })
        created = client.create_campaign({
            "name": "Native Campaign",
            "isPublished": False,
            "lists": [{"id": 1}],
            "events": [{
                "id": "new_1",
                "name": "Change Points",
                "type": "lead.changepoints",
                "eventType": "action",
                "properties": {"points": 1, "group": ""},
            }],
            "forms": [],
            "canvasSettings": {"nodes": [], "connections": []},
        })
        self.assertEqual(created["id"], 2)
        self.assertEqual(
            session.request.call_args.args[:2],
            ("POST", "http://mautic.local/api/campaigns/new"),
        )
        form_data = session.request.call_args.kwargs["data"]
        self.assertIn(("lists[0][id]", 1), form_data)
        self.assertIn(("events[0][type]", "lead.changepoints"), form_data)
        self.assertIn(("events[0][properties][points]", 1), form_data)

    def test_update_campaign_uses_patch(self):
        client, session = self.make_client()
        session.request.return_value = response(200, {
            "campaign": {"id": 2, "name": "Updated Native Campaign"}
        })
        updated = client.update_campaign(2, {
            "name": "Updated Native Campaign",
            "isPublished": False,
        })
        self.assertEqual(updated["name"], "Updated Native Campaign")
        self.assertEqual(
            session.request.call_args.args[:2],
            ("PATCH", "http://mautic.local/api/campaigns/2/edit"),
        )
        self.assertIn(("isPublished", "0"), session.request.call_args.kwargs["data"])
        with self.assertRaisesRegex(PermanentMauticError, "campaign ID is required"):
            client.update_campaign("", {"name": "Bad"})

    def test_delete_campaign_requires_id_and_returns_provider_entity(self):
        client, session = self.make_client()
        session.request.return_value = response(200, {
            "campaign": {"id": 2, "name": "Deleted Campaign"}
        })
        deleted = client.delete_campaign(2)
        self.assertEqual(deleted["name"], "Deleted Campaign")
        self.assertEqual(
            session.request.call_args.args[:2],
            ("DELETE", "http://mautic.local/api/campaigns/2/delete"),
        )
        with self.assertRaisesRegex(PermanentMauticError, "campaign ID is required"):
            client.delete_campaign("")

    def test_campaign_detail_rejects_malformed_provider_response(self):
        client, session = self.make_client()
        session.request.return_value = response(200, {"campaign": []})
        with self.assertRaisesRegex(TemporaryMauticError, "campaign lookup returned an invalid response"):
            client.get_campaign(2)
