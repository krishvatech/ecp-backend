from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError


User = get_user_model()


class NewsletterAdminMauticCampaignsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="native-campaign-staff",
            email="native-campaign-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="native-campaign-normal",
            email="native-campaign-normal@example.test",
            password="test-password",
        )
        self.list_url = reverse("newsletter-admin-mautic-campaign-list")
        self.detail_url = reverse(
            "newsletter-admin-mautic-campaign-detail",
            args=["2"],
        )
        self.capabilities_url = reverse(
            "newsletter-admin-mautic-campaign-capabilities"
        )

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    @staticmethod
    def _campaign(**overrides):
        data = {
            "id": 2,
            "name": "Native Workflow",
            "description": "Provider-backed workflow",
            "isPublished": False,
            "dateAdded": "2026-09-09T10:00:00+00:00",
            "dateModified": "2026-09-09T10:05:00+00:00",
            "contactCount": 4,
            "lists": {
                "1": {
                    "id": 1,
                    "name": "IMAA Events",
                    "alias": "imaa-events",
                }
            },
            "forms": [],
            "events": {
                "5": {
                    "id": 5,
                    "name": "Country Condition",
                    "description": "",
                    "type": "lead.field_value",
                    "eventType": "condition",
                    "order": 1,
                    "properties": {
                        "field": "country",
                        "operator": "=",
                        "value": "India",
                    },
                    "parent": None,
                    "children": {
                        "6": {"id": 6},
                    },
                    "decisionPath": None,
                    "triggerMode": "immediate",
                },
                "6": {
                    "id": 6,
                    "name": "Change Points",
                    "description": "",
                    "type": "lead.changepoints",
                    "eventType": "action",
                    "order": 2,
                    "properties": {
                        "points": "1",
                        "group": "",
                    },
                    "parent": {"id": 5},
                    "children": [],
                    "decisionPath": "yes",
                    "triggerMode": "immediate",
                },
            },
            "canvasSettings": {
                "nodes": [
                    {
                        "id": "lists",
                        "positionX": "500",
                        "positionY": "50",
                    }
                ],
                "connections": [],
            },
        }
        data.update(overrides)
        return data

    @staticmethod
    def _create_payload(**overrides):
        payload = {
            "name": "Native Workflow",
            "description": "Provider-backed workflow",
            "isPublished": False,
            "lists": [1],
            "forms": [],
            "events": [
                {
                    "id": "new_1",
                    "name": "Change Points",
                    "type": "lead.changepoints",
                    "eventType": "action",
                    "properties": {
                        "points": 1,
                        "group": "",
                    },
                    "children": [],
                    "parent": None,
                    "decisionPath": None,
                    "triggerMode": "immediate",
                }
            ],
            "canvasSettings": {
                "nodes": [],
                "connections": [],
            },
        }
        payload.update(overrides)
        return payload

    @staticmethod
    def _builder_capabilities():
        return {
            "actions": [
                {
                    "key": "email.send",
                    "type": "email.send",
                    "eventType": "action",
                    "label": "Send email",
                    "formSchema": {
                        "available": True,
                        "fields": [
                            {
                                "name": "email",
                                "label": "Email",
                                "required": True,
                                "renderable": True,
                                "choices": [
                                    {
                                        "label": "QA Campaign Builder Email (23)",
                                        "value": "23",
                                    }
                                ],
                            },
                            {
                                "name": "newEmailButton",
                                "label": "New Email",
                                "required": True,
                                "renderable": False,
                                "controlType": "action",
                            },
                        ],
                    },
                }
            ],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_capabilities_lists_provider_sources(self, client_cls):
        client_cls.return_value.get_campaign_builder_capabilities.return_value = {
            "actions": [
                {
                    "key": "lead.changepoints",
                    "type": "lead.changepoints",
                    "eventType": "action",
                    "label": "Adjust contact points",
                    "formType": "Mautic\\LeadBundle\\Form\\Type\\PointActionType",
                    "triggerModes": {
                        "available": True,
                        "modes": ["immediate", "interval", "date"],
                    },
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
            "connectionRestrictions": {
                "lead.changepoints": {
                    "source": {"action": [], "condition": [], "decision": []},
                }
            },
            "formSchema": {
                "available": False,
                "reason": "Symfony forms are not normalized yet.",
            },
        }
        client_cls.return_value.list_segments.return_value = {
            "lists": {
                "3": {
                    "id": 3,
                    "name": "IMAA Events",
                    "alias": "imaa-events",
                    "isPublished": True,
                }
            }
        }
        client_cls.return_value.list_forms.return_value = {
            "forms": {
                "7": {
                    "id": 7,
                    "name": "Signup",
                    "alias": "signup",
                    "isPublished": False,
                }
            }
        }
        self._authenticate(self.staff)

        response = self.client.get(self.capabilities_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["actions"][0]["key"], "lead.changepoints")
        self.assertEqual(response.data["conditions"][0]["key"], "lead.field_value")
        self.assertEqual(response.data["decisions"][0]["key"], "page.pagehit")
        self.assertEqual(
            response.data["connection_restrictions"],
            {
                "lead.changepoints": {
                    "source": {"action": [], "condition": [], "decision": []},
                }
            },
        )
        self.assertTrue(response.data["builder_metadata"]["available"])
        self.assertEqual(
            response.data["builder_metadata"]["source"],
            "runtime-mautic-eventcollector-plugin-bridge",
        )
        self.assertFalse(response.data["form_schema"]["available"])
        self.assertEqual(
            response.data["sources"]["segments"],
            [
                {
                    "id": "3",
                    "name": "IMAA Events",
                    "alias": "imaa-events",
                    "isPublished": True,
                }
            ],
        )
        self.assertEqual(response.data["sources"]["forms"][0]["id"], "7")
        client_cls.return_value.get_campaign_builder_capabilities.assert_called_once_with()
        client_cls.return_value.list_segments.assert_called_once_with(limit=200)
        client_cls.return_value.list_forms.assert_called_once_with(limit=200)

    def test_capabilities_requires_staff(self):
        self._authenticate(self.normal_user)

        response = self.client.get(self.capabilities_url)

        self.assertEqual(response.status_code, 403)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_capabilities_maps_provider_failure(self, client_cls):
        client_cls.return_value.get_campaign_builder_capabilities.side_effect = (
            TemporaryMauticError("Mautic capability bridge failed")
        )
        self._authenticate(self.staff)

        response = self.client.get(self.capabilities_url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("Mautic capability bridge failed", response.data["detail"])
        client_cls.return_value.list_segments.assert_not_called()
        client_cls.return_value.list_forms.assert_not_called()

    def test_guest_and_normal_user_are_denied(self):
        for url in (self.list_url, self.detail_url):
            self.assertIn(self.client.get(url).status_code, (401, 403))

        self._authenticate(self.normal_user)
        for url in (self.list_url, self.detail_url):
            self.assertEqual(self.client.get(url).status_code, 403)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_list_forwards_provider_pagination_search_and_counts(self, client_cls):
        client_cls.return_value.list_campaigns.return_value = {
            "total": 1,
            "campaigns": {"2": self._campaign()},
        }
        self._authenticate(self.staff)

        response = self.client.get(
            self.list_url,
            {
                "page": 2,
                "page_size": 25,
                "search": "Native",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["page"], 2)
        self.assertEqual(response.data["results"][0]["id"], "2")
        self.assertEqual(response.data["results"][0]["contactCount"], 4)
        client_cls.return_value.list_campaigns.assert_called_once_with(
            start=25,
            limit=25,
            withContactCounts="true",
            search="Native",
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_list_normalizes_sources_events_and_relationships(self, client_cls):
        client_cls.return_value.list_campaigns.return_value = {
            "total": 1,
            "campaigns": [self._campaign()],
        }
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 200)
        result = response.data["results"][0]
        self.assertEqual(result["lists"][0]["id"], "1")
        self.assertEqual(result["events"][0]["children"], ["6"])
        self.assertEqual(result["events"][1]["parent"], "5")
        self.assertEqual(result["events"][1]["decisionPath"], "yes")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_create_converts_source_ids_and_defaults_to_unpublished(self, client_cls):
        client = client_cls.return_value
        client.create_campaign.return_value = self._campaign()
        self._authenticate(self.staff)

        payload = self._create_payload()
        payload.pop("isPublished")

        response = self.client.post(
            self.list_url,
            payload,
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        called = client.create_campaign.call_args.args[0]
        self.assertEqual(called["lists"], [{"id": 1}])
        self.assertEqual(called["forms"], [])
        self.assertFalse(called["isPublished"])
        self.assertEqual(called["events"][0]["eventType"], "action")
        self.assertEqual(called["events"][0]["type"], "lead.changepoints")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_create_accepts_published_state_and_multiple_source_shapes(self, client_cls):
        client_cls.return_value.create_campaign.return_value = self._campaign(
            isPublished=True
        )
        self._authenticate(self.staff)

        payload = self._create_payload(
            isPublished=True,
            lists=[{"id": "1"}, 2, "2"],
        )

        response = self.client.post(
            self.list_url,
            payload,
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        called = client_cls.return_value.create_campaign.call_args.args[0]
        self.assertTrue(called["isPublished"])
        self.assertEqual(called["lists"], [{"id": 1}, {"id": 2}])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_create_builder_event_ignores_non_renderable_required_schema_controls(self, client_cls):
        client = client_cls.return_value
        client.get_campaign_builder_capabilities.return_value = self._builder_capabilities()
        client.create_campaign.return_value = self._campaign()
        self._authenticate(self.staff)

        payload = self._create_payload(
            events=[
                {
                    "id": "event-1",
                    "key": "email.send",
                    "eventType": "action",
                    "properties": {"email": "23"},
                }
            ]
        )

        response = self.client.post(self.list_url, payload, format="json")

        self.assertEqual(response.status_code, 201)
        called_event = client.create_campaign.call_args.args[0]["events"][0]
        self.assertEqual(called_event["properties"], {"email": "23"})
        client.get_campaign_builder_capabilities.assert_called_once_with()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_create_builder_event_still_requires_renderable_schema_field(self, client_cls):
        client = client_cls.return_value
        client.get_campaign_builder_capabilities.return_value = self._builder_capabilities()
        self._authenticate(self.staff)

        payload = self._create_payload(
            events=[
                {
                    "id": "event-1",
                    "key": "email.send",
                    "eventType": "action",
                    "properties": {},
                }
            ]
        )

        response = self.client.post(self.list_url, payload, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertIn("missing required property email", response.data["detail"])
        client.create_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_create_rejects_missing_source_or_events(self, client_cls):
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            self._create_payload(lists=[], forms=[]),
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            self.list_url,
            self._create_payload(events=[]),
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        client_cls.return_value.create_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_create_rejects_bad_event_or_unsupported_field(self, client_cls):
        self._authenticate(self.staff)

        bad_event = self._create_payload()
        bad_event["events"][0]["eventType"] = "something-else"
        response = self.client.post(
            self.list_url,
            bad_event,
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            self.list_url,
            {
                **self._create_payload(),
                "uuid": "ecp-owned-field-not-allowed",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        client_cls.return_value.create_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_create_rejects_invalid_source_id_and_canvas(self, client_cls):
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            self._create_payload(lists=["bad"]),
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            self.list_url,
            self._create_payload(
                canvasSettings={"nodes": {}, "connections": []}
            ),
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        client_cls.return_value.create_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_detail_get_returns_provider_campaign(self, client_cls):
        client_cls.return_value.get_campaign.return_value = self._campaign()
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["id"], "2")
        self.assertEqual(response.data["name"], "Native Workflow")
        self.assertEqual(len(response.data["events"]), 2)
        client_cls.return_value.get_campaign.assert_called_once_with("2")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_patch_updates_only_supplied_fields(self, client_cls):
        client_cls.return_value.update_campaign.return_value = self._campaign(
            name="Updated Native Workflow",
            isPublished=True,
        )
        self._authenticate(self.staff)

        response = self.client.patch(
            self.detail_url,
            {
                "name": " Updated Native Workflow ",
                "isPublished": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["name"], "Updated Native Workflow")
        self.assertTrue(response.data["isPublished"])
        client_cls.return_value.update_campaign.assert_called_once_with(
            "2",
            {
                "name": "Updated Native Workflow",
                "isPublished": True,
            },
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_patch_can_forward_workflow_changes_without_ecp_model(self, client_cls):
        client_cls.return_value.update_campaign.return_value = self._campaign()
        self._authenticate(self.staff)

        response = self.client.patch(
            self.detail_url,
            {
                "lists": [1],
                "events": self._create_payload()["events"],
                "canvasSettings": {
                    "nodes": [{"id": "new_1"}],
                    "connections": [],
                },
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        called = client_cls.return_value.update_campaign.call_args.args[1]
        self.assertEqual(called["lists"], [{"id": 1}])
        self.assertEqual(called["events"][0]["type"], "lead.changepoints")
        # The caller's own canvas node survives, and the provider-native graph
        # Mautic needs to apply the events at all is added alongside it.
        nodes = called["canvasSettings"]["nodes"]
        self.assertIn("new_1", [node["id"] for node in nodes])
        self.assertIn("lists", [node["id"] for node in nodes])
        self.assertEqual(
            called["canvasSettings"]["connections"],
            [
                {
                    "sourceId": "lists",
                    "targetId": "new_1",
                    "anchors": {"source": "leadsource", "target": "top"},
                }
            ],
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_patch_rejects_empty_payload(self, client_cls):
        self._authenticate(self.staff)

        response = self.client.patch(
            self.detail_url,
            {},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        client_cls.return_value.update_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_delete_removes_native_provider_campaign(self, client_cls):
        self._authenticate(self.staff)

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 204)
        client_cls.return_value.delete_campaign.assert_called_once_with("2")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_provider_404_is_not_found(self, client_cls):
        client_cls.return_value.get_campaign.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_provider_validation_failure_returns_400(self, client_cls):
        client_cls.return_value.create_campaign.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 422): Invalid Campaign"
        )
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            self._create_payload(),
            format="json",
        )

        self.assertEqual(response.status_code, 400)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_provider_temporary_failure_returns_502(self, client_cls):
        client_cls.return_value.list_campaigns.side_effect = TemporaryMauticError(
            "Mautic API request failed (HTTP 503)"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 502)


class NewsletterAdminMauticCampaignMultiEventTests(TestCase):
    """Multiple workflow events must all reach the provider on one save.

    Mautic only applies a campaign's `events` array when `canvasSettings` is sent
    too, and it reads parent/child links from canvas connections rather than from
    each event's `parent` field, so every request carrying events must carry the
    provider-native graph as well.
    """

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="multi-event-staff",
            email="multi-event-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.detail_url = reverse(
            "newsletter-admin-mautic-campaign-detail",
            args=["7"],
        )
        self.list_url = reverse("newsletter-admin-mautic-campaign-list")

    @staticmethod
    def _capabilities():
        return {
            "actions": [
                {
                    "key": "email.send",
                    "type": "email.send",
                    "eventType": "action",
                    "label": "Send email",
                    "formSchema": {
                        "available": True,
                        "fields": [
                            {
                                "name": "email",
                                "label": "Email to send",
                                "required": True,
                                "renderable": True,
                                "choices": [
                                    {"label": "QA Email (23)", "value": "23"},
                                ],
                            },
                            {
                                "name": "priority",
                                "label": "Priority",
                                "renderable": True,
                                "choices": [
                                    {"label": "Normal", "value": "2"},
                                    {"label": "High", "value": "1"},
                                ],
                            },
                            {
                                "name": "attempts",
                                "label": "Attempts",
                                "renderable": True,
                            },
                        ],
                    },
                },
                {
                    "key": "lead.changetags",
                    "type": "lead.changetags",
                    "eventType": "action",
                    "label": "Modify contact's tags",
                    "formSchema": {
                        "available": True,
                        "fields": [
                            {
                                "name": "add_tags",
                                "label": "Add tags",
                                "multiple": True,
                                "renderable": True,
                                "choices": [
                                    {"label": "QA Campaign Builder Tag", "value": "4"},
                                    {"label": "Hiii", "value": "1"},
                                ],
                            },
                            {
                                "name": "remove_tags",
                                "label": "Remove tags",
                                "multiple": True,
                                "renderable": True,
                                "choices": [
                                    {"label": "QA Campaign Builder Tag", "value": "4"},
                                    {"label": "Hiii", "value": "1"},
                                ],
                            },
                        ],
                    },
                },
                {
                    "key": "lead.changepoints",
                    "type": "lead.changepoints",
                    "eventType": "action",
                    "label": "Adjust contact points",
                    "formTypeOptions": {
                        "points": {"required": False},
                        "notify": {"required": False},
                    },
                },
            ],
            "conditions": [
                {
                    "key": "lead.field_value",
                    "type": "lead.field_value",
                    "eventType": "condition",
                    "label": "Contact field value",
                }
            ],
            "decisions": [],
            "connectionRestrictions": {},
        }

    @staticmethod
    def _event(event_id, key, properties, **overrides):
        event = {
            "id": event_id,
            "key": key,
            "eventType": overrides.pop("eventType", "action"),
            "properties": properties,
            "name": overrides.pop("name", None),
            "order": overrides.pop("order", None),
            "parent": overrides.pop("parent", None),
            "triggerMode": "immediate",
        }
        event.update(overrides)
        return {key: value for key, value in event.items() if value is not None}

    def _patch(self, client_cls, events, canvas=None):
        client_cls.return_value.get_campaign_builder_capabilities.return_value = (
            self._capabilities()
        )
        client_cls.return_value.update_campaign.return_value = {
            "id": 7,
            "name": "QA Provider Schema Campaign",
            "events": [],
        }

        response = self.client.patch(
            self.detail_url,
            {
                "name": "QA Provider Schema Campaign",
                "sources": {"segments": [10], "forms": []},
                "events": events,
                "canvasSettings": canvas or {"nodes": [], "connections": []},
            },
            format="json",
        )
        self.assertEqual(response.status_code, 200, getattr(response, "data", None))
        return client_cls.return_value.update_campaign.call_args.args[1]

    @staticmethod
    def _sent_ids(payload):
        return [event["id"] for event in payload["events"]]

    @staticmethod
    def _connection(payload, target):
        for connection in payload["canvasSettings"]["connections"]:
            if connection["targetId"] == str(target):
                return connection
        return None

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_persisted_event_and_new_event_are_both_forwarded(self, client_cls):
        """Case A: the bug — a new event added next to a persisted one vanished."""
        payload = self._patch(
            client_cls,
            [
                self._event("12", "email.send", {"email": "23"}, order=1),
                self._event(
                    "new_2",
                    "lead.changetags",
                    {"add_tags": ["4"], "remove_tags": []},
                    order=2,
                ),
            ],
        )

        self.assertEqual(self._sent_ids(payload), ["12", "new_2"])
        self.assertEqual(
            [event["type"] for event in payload["events"]],
            ["email.send", "lead.changetags"],
        )
        self.assertEqual(payload["events"][0]["properties"], {"email": "23"})
        self.assertEqual(
            payload["events"][1]["properties"],
            {"add_tags": ["4"], "remove_tags": []},
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_events_are_always_accompanied_by_a_provider_canvas(self, client_cls):
        """Root cause: Mautic ignores `events` entirely without `canvasSettings`."""
        payload = self._patch(
            client_cls,
            [
                self._event("12", "email.send", {"email": "23"}, order=1),
                self._event("new_2", "lead.changetags", {"add_tags": ["4"]}, order=2),
            ],
        )

        node_ids = [node["id"] for node in payload["canvasSettings"]["nodes"]]
        self.assertIn("12", node_ids)
        self.assertIn("new_2", node_ids)
        self.assertIn("lists", node_ids)
        for node in payload["canvasSettings"]["nodes"]:
            self.assertIn("positionX", node)
            self.assertIn("positionY", node)
        for connection in payload["canvasSettings"]["connections"]:
            self.assertIn("sourceId", connection)
            self.assertIn("targetId", connection)
            self.assertIn("source", connection["anchors"])
            self.assertIn("target", connection["anchors"])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_two_new_events_are_both_forwarded(self, client_cls):
        """Case B."""
        payload = self._patch(
            client_cls,
            [
                self._event("new_1", "email.send", {"email": "23"}, order=1),
                self._event("new_2", "lead.changetags", {"add_tags": ["4"]}, order=2),
            ],
        )

        self.assertEqual(self._sent_ids(payload), ["new_1", "new_2"])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_existing_event_keeps_its_provider_id_when_properties_change(
        self, client_cls
    ):
        """Case C: an update must not become a duplicate create."""
        payload = self._patch(
            client_cls,
            [self._event("12", "email.send", {"email": "23", "priority": "1"}, order=1)],
        )

        self.assertEqual(self._sent_ids(payload), ["12"])
        self.assertEqual(
            payload["events"][0]["properties"],
            {"email": "23", "priority": "1"},
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_event_without_provider_id_is_kept_as_a_new_event(self, client_cls):
        """Case D: a missing ID means "create", never "ignore"."""
        payload = self._patch(
            client_cls,
            [
                self._event("12", "email.send", {"email": "23"}, order=1),
                {
                    "key": "lead.changetags",
                    "eventType": "action",
                    "properties": {"add_tags": ["4"]},
                },
            ],
        )

        self.assertEqual(len(payload["events"]), 2)
        self.assertEqual(payload["events"][1]["id"], "new_2")
        self.assertEqual(payload["events"][1]["type"], "lead.changetags")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_ui_local_event_ids_become_new_event_ids(self, client_cls):
        payload = self._patch(
            client_cls,
            [
                self._event("event-1736-abc", "email.send", {"email": "23"}),
                self._event("event-1736-def", "lead.changetags", {"add_tags": ["4"]}),
            ],
        )

        self.assertEqual(self._sent_ids(payload), ["new_1", "new_2"])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_events_of_different_provider_types_do_not_overwrite_each_other(
        self, client_cls
    ):
        """Case E."""
        payload = self._patch(
            client_cls,
            [
                self._event(
                    "12",
                    "lead.field_value",
                    {"field": "country"},
                    eventType="condition",
                    order=1,
                ),
                self._event("new_2", "email.send", {"email": "23"}, order=2),
                self._event("new_3", "lead.changetags", {"add_tags": ["4"]}, order=3),
            ],
        )

        self.assertEqual(self._sent_ids(payload), ["12", "new_2", "new_3"])
        self.assertEqual(
            [event["eventType"] for event in payload["events"]],
            ["condition", "action", "action"],
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_multiple_events_of_the_same_provider_type_survive(self, client_cls):
        """Case F."""
        payload = self._patch(
            client_cls,
            [
                self._event("12", "email.send", {"email": "23"}, order=1),
                self._event("new_2", "email.send", {"email": "23"}, order=2),
            ],
        )

        self.assertEqual(self._sent_ids(payload), ["12", "new_2"])
        self.assertEqual(
            [event["type"] for event in payload["events"]],
            ["email.send", "email.send"],
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_property_value_types_are_forwarded_untouched(self, client_cls):
        """Case G: strings, numbers, boolean false and empty lists all survive."""
        payload = self._patch(
            client_cls,
            [
                self._event(
                    "12",
                    "email.send",
                    {"email": "23", "attempts": 3},
                    order=1,
                ),
                self._event(
                    "new_2",
                    "lead.changetags",
                    {"add_tags": ["4"], "remove_tags": []},
                    order=2,
                ),
                self._event(
                    "new_3",
                    "lead.changepoints",
                    {"points": 0, "notify": False},
                    order=3,
                ),
            ],
        )

        self.assertEqual(payload["events"][0]["properties"]["attempts"], 3)
        self.assertEqual(payload["events"][1]["properties"]["remove_tags"], [])
        self.assertEqual(payload["events"][2]["properties"]["points"], 0)
        self.assertIs(payload["events"][2]["properties"]["notify"], False)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_event_order_is_preserved(self, client_cls):
        """Case H."""
        payload = self._patch(
            client_cls,
            [
                self._event("new_1", "lead.changetags", {"add_tags": ["4"]}, order=1),
                self._event("12", "email.send", {"email": "23"}, order=2),
                self._event("new_3", "lead.changepoints", {"points": 5}, order=3),
            ],
        )

        self.assertEqual(self._sent_ids(payload), ["new_1", "12", "new_3"])
        self.assertEqual([event["order"] for event in payload["events"]], [1, 2, 3])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_parent_links_are_expressed_as_canvas_connections(self, client_cls):
        """Mautic ignores each event's `parent` field and reads connections instead."""
        payload = self._patch(
            client_cls,
            [
                self._event("12", "email.send", {"email": "23"}, order=1),
                self._event(
                    "new_2",
                    "lead.changetags",
                    {"add_tags": ["4"]},
                    order=2,
                    parent="12",
                ),
            ],
        )

        self.assertEqual(
            self._connection(payload, "new_2"),
            {
                "sourceId": "12",
                "targetId": "new_2",
                "anchors": {"source": "bottom", "target": "top"},
            },
        )
        # Root events hang off the campaign source, not off another event.
        self.assertEqual(
            self._connection(payload, "12"),
            {
                "sourceId": "lists",
                "targetId": "12",
                "anchors": {"source": "leadsource", "target": "top"},
            },
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_decision_paths_choose_the_matching_anchor(self, client_cls):
        payload = self._patch(
            client_cls,
            [
                self._event(
                    "12",
                    "lead.field_value",
                    {"field": "country"},
                    eventType="condition",
                    order=1,
                ),
                self._event(
                    "new_2",
                    "email.send",
                    {"email": "23"},
                    order=2,
                    parent="12",
                    decisionPath="yes",
                ),
            ],
        )

        self.assertEqual(
            self._connection(payload, "new_2")["anchors"]["source"],
            "yes",
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_caller_canvas_nodes_and_edges_are_preserved(self, client_cls):
        payload = self._patch(
            client_cls,
            [self._event("12", "email.send", {"email": "23"}, order=1)],
            canvas={
                "nodes": [
                    {
                        "id": "node-trigger",
                        "nodeType": "trigger",
                        "positionX": "60",
                        "positionY": "120",
                    },
                    {
                        "id": "node-action",
                        "nodeType": "action",
                        "positionX": "320",
                        "positionY": "120",
                    },
                ],
                "connections": [{"sourceId": "node-trigger", "targetId": "node-action"}],
            },
        )

        node_ids = [node["id"] for node in payload["canvasSettings"]["nodes"]]
        self.assertIn("node-trigger", node_ids)
        self.assertIn("12", node_ids)
        # Mautic dereferences anchors on every connection it is given.
        caller_connection = next(
            connection
            for connection in payload["canvasSettings"]["connections"]
            if connection["sourceId"] == "node-trigger"
        )
        self.assertEqual(
            caller_connection["anchors"],
            {"source": "bottom", "target": "top"},
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_update_without_events_leaves_provider_events_untouched(self, client_cls):
        """Case I: an unrelated update must not rewrite the event graph."""
        client_cls.return_value.update_campaign.return_value = {
            "id": 7,
            "name": "Renamed",
            "events": [],
        }

        response = self.client.patch(
            self.detail_url,
            {"name": "Renamed"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        payload = client_cls.return_value.update_campaign.call_args.args[1]
        self.assertEqual(payload, {"name": "Renamed"})
        self.assertNotIn("events", payload)
        self.assertNotIn("canvasSettings", payload)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_create_also_sends_the_provider_canvas(self, client_cls):
        client_cls.return_value.get_campaign_builder_capabilities.return_value = (
            self._capabilities()
        )
        client_cls.return_value.create_campaign.return_value = {
            "id": 9,
            "name": "QA Provider Schema Campaign",
            "events": [],
        }

        response = self.client.post(
            self.list_url,
            {
                "name": "QA Provider Schema Campaign",
                "sources": {"segments": [10], "forms": []},
                "events": [
                    self._event("new_1", "email.send", {"email": "23"}, order=1),
                    self._event(
                        "new_2",
                        "lead.changetags",
                        {"add_tags": ["4"]},
                        order=2,
                        parent="new_1",
                    ),
                ],
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201, getattr(response, "data", None))
        payload = client_cls.return_value.create_campaign.call_args.args[0]
        self.assertEqual([event["id"] for event in payload["events"]], ["new_1", "new_2"])
        self.assertEqual(
            [node["id"] for node in payload["canvasSettings"]["nodes"]],
            ["lists", "new_1", "new_2"],
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_form_sourced_campaign_anchors_events_to_the_form_node(self, client_cls):
        client_cls.return_value.get_campaign_builder_capabilities.return_value = (
            self._capabilities()
        )
        client_cls.return_value.update_campaign.return_value = {"id": 7, "name": "x"}

        response = self.client.patch(
            self.detail_url,
            {
                "sources": {"segments": [], "forms": [3]},
                "events": [self._event("new_1", "email.send", {"email": "23"})],
                "canvasSettings": {"nodes": [], "connections": []},
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))
        payload = client_cls.return_value.update_campaign.call_args.args[1]
        self.assertEqual(
            payload["canvasSettings"]["connections"][0]["sourceId"],
            "forms",
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_unknown_provider_event_key_is_rejected_without_calling_provider(
        self, client_cls
    ):
        client_cls.return_value.get_campaign_builder_capabilities.return_value = (
            self._capabilities()
        )

        response = self.client.patch(
            self.detail_url,
            {
                "sources": {"segments": [10], "forms": []},
                "events": [
                    self._event("12", "email.send", {"email": "23"}),
                    self._event("new_2", "plugin.removed", {"legacy": "keep"}),
                ],
                "canvasSettings": {"nodes": [], "connections": []},
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        client_cls.return_value.update_campaign.assert_not_called()

    def test_multi_event_update_requires_staff(self):
        self.client.force_authenticate(user=None)
        normal_user = User.objects.create_user(
            username="multi-event-normal",
            email="multi-event-normal@example.test",
            password="test-password",
        )
        self.client.force_authenticate(user=normal_user)

        response = self.client.patch(
            self.detail_url,
            {
                "sources": {"segments": [10], "forms": []},
                "events": [self._event("new_1", "email.send", {"email": "23"})],
            },
            format="json",
        )

        self.assertEqual(response.status_code, 403)


class NewsletterAdminMauticCampaignChoicesAPITests(TestCase):
    """Lookup for provider choice lists that capabilities no longer inline.

    Reference catalogs are served by the field-metadata bridge that already
    publishes them; everything else is resolved by the campaign event's own
    provider form. Django only routes and normalizes.
    """

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="campaign-choices-staff",
            email="campaign-choices-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="campaign-choices-normal",
            email="campaign-choices-normal@example.test",
            password="test-password",
        )
        self.url = reverse("newsletter-admin-mautic-campaign-choices")

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    @staticmethod
    def _event_field_params(**overrides):
        params = {
            "source": "event_field",
            "eventType": "condition",
            "key": "lead.device",
            "field": "device_brand",
        }
        params.update(overrides)
        return params

    def test_choice_lookup_requires_authentication(self):
        response = self.client.get(self.url, self._event_field_params())
        self.assertIn(response.status_code, (401, 403))

    def test_choice_lookup_rejects_non_staff(self):
        self._authenticate(self.normal_user)

        response = self.client.get(self.url, self._event_field_params())

        self.assertEqual(response.status_code, 403)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_event_field_choices_are_normalized(self, client_cls):
        client_cls.return_value.get_campaign_builder_event_field_choices.return_value = {
            "source": "event_field",
            "field": "device_brand",
            "total": 2106,
            "start": 0,
            "limit": 2,
            "hasMore": True,
            "choices": [
                {"label": "Apple", "value": "AP", "data": "AP", "attr": []},
                {"label": "Samsung", "value": "SA", "data": "SA", "attr": []},
            ],
        }
        self._authenticate(self.staff)

        response = self.client.get(self.url, self._event_field_params(limit=2))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["results"],
            [
                {"value": "AP", "label": "Apple"},
                {"value": "SA", "label": "Samsung"},
            ],
        )
        self.assertEqual(response.data["total"], 2106)
        self.assertTrue(response.data["hasMore"])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_event_field_search_and_paging_reach_the_provider(self, client_cls):
        client_cls.return_value.get_campaign_builder_event_field_choices.return_value = {
            "total": 1,
            "hasMore": False,
            "choices": [{"label": "Apple", "value": "AP"}],
        }
        self._authenticate(self.staff)

        response = self.client.get(
            self.url,
            self._event_field_params(search="apple", start=100, limit=25),
        )

        self.assertEqual(response.status_code, 200)
        kwargs = (
            client_cls.return_value.get_campaign_builder_event_field_choices.call_args.kwargs
        )
        self.assertEqual(kwargs["event_type"], "condition")
        self.assertEqual(kwargs["key"], "lead.device")
        self.assertEqual(kwargs["field"], "device_brand")
        self.assertEqual(kwargs["search"], "apple")
        self.assertEqual(kwargs["start"], 100)
        self.assertEqual(kwargs["limit"], 25)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_page_size_is_bounded(self, client_cls):
        client_cls.return_value.get_campaign_builder_event_field_choices.return_value = {
            "total": 0,
            "choices": [],
        }
        self._authenticate(self.staff)

        self.client.get(self.url, self._event_field_params(limit=100000))

        kwargs = (
            client_cls.return_value.get_campaign_builder_event_field_choices.call_args.kwargs
        )
        self.assertEqual(kwargs["limit"], 200)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_negative_paging_is_clamped(self, client_cls):
        client_cls.return_value.get_campaign_builder_event_field_choices.return_value = {
            "total": 0,
            "choices": [],
        }
        self._authenticate(self.staff)

        self.client.get(self.url, self._event_field_params(start=-5, limit=-1))

        kwargs = (
            client_cls.return_value.get_campaign_builder_event_field_choices.call_args.kwargs
        )
        self.assertEqual(kwargs["start"], 0)
        self.assertEqual(kwargs["limit"], 1)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_saved_values_are_resolved_to_labels(self, client_cls):
        client_cls.return_value.get_campaign_builder_event_field_choices.return_value = {
            "total": 1,
            "hasMore": False,
            "choices": [{"label": "Apple", "value": "AP"}],
        }
        self._authenticate(self.staff)

        response = self.client.get(
            f"{self.url}?source=event_field&eventType=condition&key=lead.device"
            "&field=device_brand&values=AP&values=SA"
        )

        self.assertEqual(response.status_code, 200)
        kwargs = (
            client_cls.return_value.get_campaign_builder_event_field_choices.call_args.kwargs
        )
        self.assertEqual(kwargs["values"], ["AP", "SA"])
        self.assertEqual(response.data["results"], [{"value": "AP", "label": "Apple"}])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_event_field_source_requires_scope(self, client_cls):
        self._authenticate(self.staff)

        response = self.client.get(self.url, {"source": "event_field"})

        self.assertEqual(response.status_code, 400)
        client_cls.return_value.get_campaign_builder_event_field_choices.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_reference_catalog_reuses_the_existing_field_bridge(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = {
            "type": "region",
            "total": 3,
            "choices": [
                {"label": "Alabama", "value": "Alabama", "group": "United States"},
                {"label": "Alaska", "value": "Alaska", "group": "United States"},
                {"label": "Bavaria", "value": "Bavaria", "group": "Germany"},
            ],
        }
        self._authenticate(self.staff)

        response = self.client.get(self.url, {"source": "region", "limit": 2})

        self.assertEqual(response.status_code, 200)
        client_cls.return_value.get_field_type_choices.assert_called_once_with("region")
        # Never the campaign-builder bridge: that would duplicate a capability.
        client_cls.return_value.get_campaign_builder_event_field_choices.assert_not_called()
        self.assertEqual(
            response.data["results"],
            [
                {"value": "Alabama", "label": "Alabama", "group": "United States"},
                {"value": "Alaska", "label": "Alaska", "group": "United States"},
            ],
        )
        self.assertEqual(response.data["total"], 3)
        self.assertTrue(response.data["hasMore"])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_reference_catalog_supports_search(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = {
            "choices": [
                {"label": "Alabama", "value": "Alabama"},
                {"label": "Bavaria", "value": "Bavaria"},
            ],
        }
        self._authenticate(self.staff)

        response = self.client.get(self.url, {"source": "country", "search": "bav"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["results"],
            [{"value": "Bavaria", "label": "Bavaria"}],
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_reference_catalog_resolves_saved_values(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = {
            "choices": [
                {"label": "Alabama", "value": "Alabama"},
                {"label": "Bavaria", "value": "Bavaria"},
            ],
        }
        self._authenticate(self.staff)

        response = self.client.get(f"{self.url}?source=locale&values=Bavaria")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["results"],
            [{"value": "Bavaria", "label": "Bavaria"}],
        )
        self.assertFalse(response.data["hasMore"])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_unsupported_source_fails_safely(self, client_cls):
        self._authenticate(self.staff)

        response = self.client.get(self.url, {"source": "planet"})

        self.assertEqual(response.status_code, 400)
        client_cls.return_value.get_field_type_choices.assert_not_called()
        client_cls.return_value.get_campaign_builder_event_field_choices.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_provider_failure_is_normalized(self, client_cls):
        client_cls.return_value.get_campaign_builder_event_field_choices.side_effect = (
            TemporaryMauticError("Mautic API request failed (HTTP 503)")
        )
        self._authenticate(self.staff)

        response = self.client.get(self.url, self._event_field_params())

        self.assertEqual(response.status_code, 502)
        self.assertIn("detail", response.data)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_provider_rejection_is_reported_as_bad_request(self, client_cls):
        client_cls.return_value.get_campaign_builder_event_field_choices.side_effect = (
            PermanentMauticError("Mautic API request failed (HTTP 400)")
        )
        self._authenticate(self.staff)

        response = self.client.get(self.url, self._event_field_params())

        self.assertEqual(response.status_code, 400)


class NewsletterAdminMauticCampaignRemoteSchemaTests(TestCase):
    """Remote choice metadata must not break event validation or the builder view."""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="remote-schema-staff",
            email="remote-schema-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.detail_url = reverse(
            "newsletter-admin-mautic-campaign-detail",
            args=["7"],
        )

    @staticmethod
    def _capabilities():
        return {
            "actions": [],
            "conditions": [
                {
                    "key": "lead.device",
                    "type": "lead.device",
                    "eventType": "condition",
                    "label": "Contact device",
                    "formSchema": {
                        "available": True,
                        "root": {"name": "", "compound": True},
                        "fields": [
                            {
                                "name": "device_brand",
                                "label": "Device brand",
                                "renderable": True,
                                "multiple": True,
                                "choiceKind": "enum",
                                "choiceMode": "remote",
                                "choiceCount": 2106,
                                "choices": [],
                                "choiceSource": {
                                    "type": "event_field",
                                    "kind": "enum",
                                    "searchable": True,
                                    "paginated": True,
                                    "total": 2106,
                                    "scope": {
                                        "eventType": "condition",
                                        "key": "lead.device",
                                        "field": "device_brand",
                                    },
                                },
                            },
                            {
                                "name": "device_type",
                                "label": "Device type",
                                "renderable": True,
                                "choiceMode": "inline",
                                "choiceCount": 2,
                                "choices": [
                                    {"label": "Desktop", "value": "desktop"},
                                    {"label": "Smartphone", "value": "smartphone"},
                                ],
                            },
                        ],
                    },
                }
            ],
            "decisions": [],
            "connectionRestrictions": {},
        }

    @patch("newsletter.native_campaign_views.MauticClient")
    def _patch_device_event(self, properties, client_cls):
        client_cls.return_value.get_campaign_builder_capabilities.return_value = (
            self._capabilities()
        )
        client_cls.return_value.update_campaign.return_value = {"id": 7, "name": "x"}

        response = self.client.patch(
            self.detail_url,
            {
                "sources": {"segments": [10], "forms": []},
                "events": [
                    {
                        "id": "12",
                        "key": "lead.device",
                        "eventType": "condition",
                        "properties": properties,
                    }
                ],
                "canvasSettings": {"nodes": [], "connections": []},
            },
            format="json",
        )
        return response, client_cls.return_value.update_campaign

    def test_remote_choice_values_are_not_rejected_for_missing_inline_choices(self):
        response, update = self._patch_device_event(
            {"device_brand": ["AP"], "device_type": ["desktop"]}
        )

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))
        payload = update.call_args.args[1]
        self.assertEqual(payload["events"][0]["properties"]["device_brand"], ["AP"])

    def test_inline_choice_validation_still_rejects_unknown_values(self):
        response, update = self._patch_device_event({"device_type": ["hologram"]})

        self.assertEqual(response.status_code, 400)
        update.assert_not_called()


class NewsletterAdminMauticCampaignChoicePagingTests(TestCase):
    """The dropdown must never pull a whole provider catalog in one request."""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="choice-paging-staff",
            email="choice-paging-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.url = reverse("newsletter-admin-mautic-campaign-choices")

    @staticmethod
    def _brands(count, start=0):
        return [
            {"label": f"Brand {index}", "value": f"v{index}"}
            for index in range(start, start + count)
        ]

    def _params(self, **overrides):
        params = {
            "source": "event_field",
            "eventType": "condition",
            "key": "lead.device",
            "field": "device_brand",
        }
        params.update(overrides)
        return params

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_first_page_is_the_requested_slice_only(self, client_cls):
        client_cls.return_value.get_campaign_builder_event_field_choices.return_value = {
            "total": 2106,
            "start": 0,
            "limit": 25,
            "hasMore": True,
            "choices": self._brands(25),
        }

        response = self.client.get(self.url, self._params(start=0, limit=25))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data["results"]), 25)
        self.assertEqual(response.data["total"], 2106)
        self.assertTrue(response.data["hasMore"])
        kwargs = (
            client_cls.return_value.get_campaign_builder_event_field_choices.call_args.kwargs
        )
        self.assertEqual(kwargs["start"], 0)
        self.assertEqual(kwargs["limit"], 25)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_second_page_forwards_its_offset(self, client_cls):
        client_cls.return_value.get_campaign_builder_event_field_choices.return_value = {
            "total": 2106,
            "start": 25,
            "limit": 25,
            "hasMore": True,
            "choices": self._brands(25, start=25),
        }

        response = self.client.get(self.url, self._params(start=25, limit=25))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["start"], 25)
        self.assertEqual(response.data["results"][0]["value"], "v25")
        kwargs = (
            client_cls.return_value.get_campaign_builder_event_field_choices.call_args.kwargs
        )
        self.assertEqual(kwargs["start"], 25)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_last_page_reports_no_more(self, client_cls):
        client_cls.return_value.get_campaign_builder_event_field_choices.return_value = {
            "total": 2106,
            "start": 2100,
            "limit": 25,
            "hasMore": False,
            "choices": self._brands(6, start=2100),
        }

        response = self.client.get(self.url, self._params(start=2100, limit=25))

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["hasMore"])
        self.assertEqual(len(response.data["results"]), 6)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_reference_catalog_slice_and_has_more_are_computed_locally(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = {
            "choices": self._brands(100),
        }

        first = self.client.get(self.url, {"source": "region", "start": 0, "limit": 25})
        last = self.client.get(self.url, {"source": "region", "start": 75, "limit": 25})

        self.assertEqual(len(first.data["results"]), 25)
        self.assertEqual(first.data["results"][0]["value"], "v0")
        self.assertTrue(first.data["hasMore"])
        self.assertEqual(len(last.data["results"]), 25)
        self.assertEqual(last.data["results"][0]["value"], "v75")
        self.assertFalse(last.data["hasMore"])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_bracket_form_values_are_still_read_as_a_value_lookup(self, client_cls):
        """Some clients serialize arrays as values[]; that must not page instead."""
        client_cls.return_value.get_campaign_builder_event_field_choices.return_value = {
            "total": 1,
            "hasMore": False,
            "choices": [{"label": "Apple", "value": "AP"}],
        }

        response = self.client.get(
            f"{self.url}?source=event_field&eventType=condition&key=lead.device"
            "&field=device_brand&values%5B%5D=AP"
        )

        self.assertEqual(response.status_code, 200)
        kwargs = (
            client_cls.return_value.get_campaign_builder_event_field_choices.call_args.kwargs
        )
        self.assertEqual(kwargs["values"], ["AP"])
        self.assertEqual(response.data["results"], [{"value": "AP", "label": "Apple"}])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_reference_catalog_bracket_values_are_read_too(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = {
            "choices": [
                {"label": "Alabama", "value": "Alabama"},
                {"label": "Bavaria", "value": "Bavaria"},
            ],
        }

        response = self.client.get(f"{self.url}?source=region&values%5B%5D=Bavaria")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["results"], [{"value": "Bavaria", "label": "Bavaria"}]
        )


class NewsletterAdminMauticCampaignEventDeleteTests(TestCase):
    """Deleting one workflow event goes to the provider and touches nothing else."""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="event-delete-staff",
            email="event-delete-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="event-delete-normal",
            email="event-delete-normal@example.test",
            password="test-password",
        )
        self.url = reverse(
            "newsletter-admin-mautic-campaign-event",
            args=["7", "26"],
        )

    @staticmethod
    def _deleted(**overrides):
        payload = {
            "deleted": {"id": 26, "campaignId": 7},
            "detachedChildren": [],
            "remainingEventIds": [12, 23, 24, 25],
        }
        payload.update(overrides)
        return payload

    def test_delete_requires_authentication(self):
        response = self.client.delete(self.url)

        self.assertIn(response.status_code, (401, 403))

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_delete_rejects_non_staff(self, client_cls):
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, 403)
        client_cls.return_value.delete_campaign_event.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_staff_delete_uses_provider_campaign_and_event_ids(self, client_cls):
        client_cls.return_value.delete_campaign_event.return_value = self._deleted()
        self.client.force_authenticate(user=self.staff)

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, 200)
        client_cls.return_value.delete_campaign_event.assert_called_once_with("7", "26")
        self.assertEqual(response.data["deleted"], {"id": 26, "campaignId": 7})
        self.assertEqual(
            response.data["remainingEventIds"],
            ["12", "23", "24", "25"],
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_detached_children_are_reported(self, client_cls):
        client_cls.return_value.delete_campaign_event.return_value = self._deleted(
            detachedChildren=[27, 28],
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["detachedChildren"], ["27", "28"])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_non_numeric_ids_are_rejected_before_calling_the_provider(self, client_cls):
        self.client.force_authenticate(user=self.staff)

        response = self.client.delete(
            reverse(
                "newsletter-admin-mautic-campaign-event",
                args=["7", "event-local-1"],
            )
        )

        self.assertEqual(response.status_code, 400)
        client_cls.return_value.delete_campaign_event.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_unknown_campaign_or_event_is_not_found(self, client_cls):
        client_cls.return_value.delete_campaign_event.side_effect = (
            PermanentMauticError("Mautic API request failed (HTTP 404)")
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_provider_permission_error_is_forbidden(self, client_cls):
        client_cls.return_value.delete_campaign_event.side_effect = (
            PermanentMauticError("Mautic API request failed (HTTP 403): Access denied.")
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, 403)
        self.assertIn("detail", response.data)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_provider_conflict_is_reported_as_bad_request(self, client_cls):
        client_cls.return_value.delete_campaign_event.side_effect = (
            PermanentMauticError("Mautic API request failed (HTTP 409): conflict")
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, 400)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_provider_temporary_failure_is_normalized_to_502(self, client_cls):
        client_cls.return_value.delete_campaign_event.side_effect = (
            TemporaryMauticError("Mautic API request failed (HTTP 503)")
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, 502)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_delete_does_not_touch_campaign_or_other_events(self, client_cls):
        client_cls.return_value.delete_campaign_event.return_value = self._deleted()
        self.client.force_authenticate(user=self.staff)

        self.client.delete(self.url)

        provider = client_cls.return_value
        provider.update_campaign.assert_not_called()
        provider.delete_campaign.assert_not_called()
        provider.create_campaign.assert_not_called()
        self.assertEqual(provider.delete_campaign_event.call_count, 1)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_event_without_runtime_capability_is_still_deletable(self, client_cls):
        """Deletion identity is campaign ID + event ID; no form schema needed."""
        client_cls.return_value.delete_campaign_event.return_value = {
            "deleted": {"id": 31, "campaignId": 7},
        }
        self.client.force_authenticate(user=self.staff)

        response = self.client.delete(
            reverse("newsletter-admin-mautic-campaign-event", args=["7", "31"])
        )

        self.assertEqual(response.status_code, 200)
        client_cls.return_value.get_campaign_builder_capabilities.assert_not_called()
        client_cls.return_value.delete_campaign_event.assert_called_once_with("7", "31")


class NewsletterAdminMauticCampaignSoftDeletedEventTests(TestCase):
    """Mautic soft-deletes campaign events and still returns them over REST.

    The campaign endpoint serializes the raw events association and does not expose
    the `deleted` field at all, so the builder has to ask the provider which events
    are still part of the workflow.
    """

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="soft-delete-staff",
            email="soft-delete-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.builder_url = reverse(
            "newsletter-admin-mautic-campaign-builder",
            args=["7"],
        )

    @staticmethod
    def _campaign_with_deleted_event():
        return {
            "id": 7,
            "name": "QA Provider Schema Campaign",
            "isPublished": False,
            "lists": [],
            "forms": [],
            "canvasSettings": {"nodes": [], "connections": []},
            "events": {
                "12": {
                    "id": 12,
                    "name": "Send email",
                    "type": "email.send",
                    "eventType": "action",
                    "order": 1,
                    "properties": {"email": "23"},
                    "parent": None,
                    "children": [],
                },
                # Soft-deleted provider-side; REST still returns it, with no flag.
                "27": {
                    "id": 27,
                    "name": "Adjust contact points",
                    "type": "lead.changepoints",
                    "eventType": "action",
                    "order": 2,
                    "properties": {"points": "5"},
                    "parent": None,
                    "children": [],
                },
            },
        }

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_builder_hides_events_the_provider_has_deleted(self, client_cls):
        client_cls.return_value.get_campaign.return_value = (
            self._campaign_with_deleted_event()
        )
        client_cls.return_value.get_campaign_event_states.return_value = {
            "campaignId": 7,
            "activeEventIds": [12],
            "deletedEventIds": [27],
        }

        response = self.client.get(self.builder_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual([event["id"] for event in response.data["events"]], ["12"])
        client_cls.return_value.get_campaign_event_states.assert_called_once_with("7")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_builder_keeps_every_active_event(self, client_cls):
        client_cls.return_value.get_campaign.return_value = (
            self._campaign_with_deleted_event()
        )
        client_cls.return_value.get_campaign_event_states.return_value = {
            "activeEventIds": [12, 27],
        }

        response = self.client.get(self.builder_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [event["id"] for event in response.data["events"]],
            ["12", "27"],
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_builder_reports_provider_failure_rather_than_stale_events(self, client_cls):
        client_cls.return_value.get_campaign.return_value = (
            self._campaign_with_deleted_event()
        )
        client_cls.return_value.get_campaign_event_states.side_effect = (
            TemporaryMauticError("Mautic API request failed (HTTP 503)")
        )

        response = self.client.get(self.builder_url)

        self.assertEqual(response.status_code, 502)

    def test_active_filter_keeps_rows_without_provider_ids(self):
        from newsletter.native_campaign_views import _active_events_only

        events = [{"id": "12"}, {"id": None}, {"id": "27"}]

        self.assertEqual(
            _active_events_only(events, [12]),
            [{"id": "12"}, {"id": None}],
        )
        # No usable provider answer: never silently drop the workflow.
        self.assertEqual(_active_events_only(events, None), events)
        self.assertEqual(_active_events_only(events, "nonsense"), events)


class NewsletterAdminMauticCampaignSaveValidationTests(TestCase):
    """Server-side validation of a campaign payload before it reaches Mautic.

    Every rule comes from the provider's own form schema, so no event type is
    named here either.
    """

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="save-validation-staff",
            email="save-validation-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.detail_url = reverse(
            "newsletter-admin-mautic-campaign-detail",
            args=["7"],
        )

    @staticmethod
    def _capabilities():
        return {
            "actions": [
                {
                    "key": "email.send",
                    "type": "email.send",
                    "eventType": "action",
                    "label": "Send email",
                    "formSchema": {
                        "available": True,
                        "fields": [
                            {
                                "name": "email",
                                "label": "Email to send",
                                "required": True,
                                "renderable": True,
                                "choices": [{"label": "QA Email (23)", "value": "23"}],
                            },
                            {
                                "name": "attempts",
                                "label": "Attempts",
                                "renderable": True,
                                "blockPrefixes": ["form", "number", "_attempts"],
                            },
                        ],
                    },
                },
                {
                    "key": "lead.changetags",
                    "type": "lead.changetags",
                    "eventType": "action",
                    "label": "Modify contact's tags",
                    "formSchema": {
                        "available": True,
                        "fields": [
                            {
                                "name": "add_tags",
                                "label": "Add tags",
                                "multiple": True,
                                "renderable": True,
                                "choices": [{"label": "QA Tag", "value": "4"}],
                            },
                            {
                                "name": "remove_tags",
                                "label": "Remove tags",
                                "multiple": True,
                                "renderable": True,
                                "choices": [{"label": "QA Tag", "value": "4"}],
                            },
                        ],
                    },
                },
                {
                    "key": "lead.changepoints",
                    "type": "lead.changepoints",
                    "eventType": "action",
                    "label": "Adjust contact points",
                    "formSchema": {
                        "available": True,
                        "fields": [
                            {
                                "name": "points",
                                "label": "Points (+/-)",
                                "required": True,
                                "renderable": True,
                                "blockPrefixes": ["form", "number", "_points"],
                            }
                        ],
                    },
                },
            ],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }

    def _patch(self, events, canvas=None):
        with patch("newsletter.native_campaign_views.MauticClient") as client_cls:
            client_cls.return_value.get_campaign_builder_capabilities.return_value = (
                self._capabilities()
            )
            client_cls.return_value.update_campaign.return_value = {
                "id": 7,
                "name": "QA Provider Schema Campaign",
                "events": [],
            }
            response = self.client.patch(
                self.detail_url,
                {
                    "name": "QA Provider Schema Campaign",
                    "sources": {"segments": [10], "forms": []},
                    "events": events,
                    "canvasSettings": canvas or {"nodes": [], "connections": []},
                },
                format="json",
            )
            return response, client_cls.return_value.update_campaign

    @staticmethod
    def _event(event_id, key, properties, **extra):
        event = {
            "id": event_id,
            "key": key,
            "eventType": "action",
            "properties": properties,
        }
        event.update(extra)
        return event

    def test_valid_payload_is_accepted_and_forwarded(self):
        response, update = self._patch(
            [
                self._event("12", "email.send", {"email": "23", "attempts": 3}),
                self._event("23", "lead.changetags", {"add_tags": ["4"]}),
                self._event("25", "lead.changepoints", {"points": "10"}),
            ]
        )

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))
        self.assertEqual(len(update.call_args.args[1]["events"]), 3)

    def test_missing_required_property_is_rejected(self):
        response, update = self._patch(
            [self._event("12", "email.send", {"attempts": 3})]
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("missing required property email", response.data["detail"])
        update.assert_not_called()

    def test_event_with_nothing_configured_is_rejected(self):
        """An "add or remove tags" step with neither set would do nothing."""
        response, update = self._patch(
            [self._event("23", "lead.changetags", {"add_tags": [], "remove_tags": []})]
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("at least one of: Add tags, Remove tags", response.data["detail"])
        update.assert_not_called()

    def test_one_side_configured_is_enough(self):
        response, _ = self._patch(
            [self._event("23", "lead.changetags", {"remove_tags": ["4"]})]
        )

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))

    def test_non_numeric_value_for_a_number_field_is_rejected(self):
        response, update = self._patch(
            [self._event("25", "lead.changepoints", {"points": "many"})]
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("must be a number", response.data["detail"])
        update.assert_not_called()

    def test_numeric_values_of_every_usual_shape_are_accepted(self):
        for points in ("10", 10, "-5", 0, "0", 2.5):
            with self.subTest(points=points):
                response, _ = self._patch(
                    [self._event("25", "lead.changepoints", {"points": points})]
                )
                self.assertEqual(response.status_code, 200, points)

    def test_a_list_is_not_a_number(self):
        response, update = self._patch(
            [self._event("25", "lead.changepoints", {"points": ["10"]})]
        )

        self.assertEqual(response.status_code, 400)
        update.assert_not_called()

    def test_optional_number_is_only_checked_when_supplied(self):
        ok, _ = self._patch([self._event("12", "email.send", {"email": "23"})])
        self.assertEqual(ok.status_code, 200)

        bad, update = self._patch(
            [self._event("12", "email.send", {"email": "23", "attempts": "soon"})]
        )
        self.assertEqual(bad.status_code, 400)
        self.assertIn("attempts must be a number", bad.data["detail"])
        update.assert_not_called()

    def test_unknown_choice_value_is_still_rejected(self):
        response, update = self._patch(
            [self._event("12", "email.send", {"email": "999"})]
        )

        self.assertEqual(response.status_code, 400)
        update.assert_not_called()

    def test_event_following_an_event_outside_the_campaign_is_rejected(self):
        response, update = self._patch(
            [
                self._event("12", "email.send", {"email": "23"}),
                self._event("23", "lead.changetags", {"add_tags": ["4"]}, parent="999"),
            ]
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("not part of this campaign", response.data["detail"])
        update.assert_not_called()

    def test_event_following_itself_is_rejected(self):
        response, update = self._patch(
            [self._event("12", "email.send", {"email": "23"}, parent="12")]
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("cannot follow itself", response.data["detail"])
        update.assert_not_called()

    def test_valid_parent_reference_is_accepted(self):
        response, _ = self._patch(
            [
                self._event("12", "email.send", {"email": "23"}),
                self._event("23", "lead.changetags", {"add_tags": ["4"]}, parent="12"),
            ]
        )

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))

    def test_canvas_connection_to_an_unknown_node_is_rejected(self):
        response, update = self._patch(
            [self._event("12", "email.send", {"email": "23"})],
            canvas={
                "nodes": [{"id": "node-trigger", "nodeType": "trigger"}],
                "connections": [
                    {"sourceId": "node-trigger", "targetId": "node-missing"}
                ],
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("unknown node", response.data["detail"])
        update.assert_not_called()

    def test_canvas_connection_without_endpoints_is_rejected(self):
        response, update = self._patch(
            [self._event("12", "email.send", {"email": "23"})],
            canvas={
                "nodes": [{"id": "node-trigger", "nodeType": "trigger"}],
                "connections": [{"sourceId": "node-trigger"}],
            },
        )

        self.assertEqual(response.status_code, 400)
        update.assert_not_called()

    def test_a_sound_caller_canvas_is_accepted(self):
        response, _ = self._patch(
            [self._event("12", "email.send", {"email": "23"})],
            canvas={
                "nodes": [
                    {"id": "node-trigger", "nodeType": "trigger"},
                    {"id": "node-a", "nodeType": "action", "eventId": "12"},
                ],
                "connections": [{"sourceId": "node-trigger", "targetId": "node-a"}],
            },
        )

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))

    def test_an_update_of_other_fields_is_not_affected_by_event_validation(self):
        with patch("newsletter.native_campaign_views.MauticClient") as client_cls:
            client_cls.return_value.update_campaign.return_value = {
                "id": 7,
                "name": "Renamed",
            }

            response = self.client.patch(
                self.detail_url,
                {"name": "Renamed"},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            client_cls.return_value.update_campaign.call_args.args[1],
            {"name": "Renamed"},
        )

    def test_provider_failure_handling_is_unchanged(self):
        with patch("newsletter.native_campaign_views.MauticClient") as client_cls:
            client_cls.return_value.get_campaign_builder_capabilities.return_value = (
                self._capabilities()
            )
            client_cls.return_value.update_campaign.side_effect = TemporaryMauticError(
                "Mautic API request failed (HTTP 503)"
            )

            response = self.client.patch(
                self.detail_url,
                {
                    "sources": {"segments": [10], "forms": []},
                    "events": [self._event("12", "email.send", {"email": "23"})],
                    "canvasSettings": {"nodes": [], "connections": []},
                },
                format="json",
            )

        self.assertEqual(response.status_code, 502)


class NewsletterAdminMauticCampaignConfigurableFieldTests(TestCase):
    """What counts as configuration, and what a pure state change may skip."""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="configurable-field-staff",
            email="configurable-field-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.detail_url = reverse(
            "newsletter-admin-mautic-campaign-detail",
            args=["7"],
        )

    @staticmethod
    def _capabilities(fields):
        return {
            "actions": [
                {
                    "key": "provider.event",
                    "type": "provider.event",
                    "eventType": "action",
                    "label": "Provider event",
                    "formSchema": {"available": True, "fields": fields},
                }
            ],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }

    def _patch_event(self, fields, properties):
        with patch("newsletter.native_campaign_views.MauticClient") as client_cls:
            client_cls.return_value.get_campaign_builder_capabilities.return_value = (
                self._capabilities(fields)
            )
            client_cls.return_value.update_campaign.return_value = {"id": 7, "name": "x"}

            response = self.client.patch(
                self.detail_url,
                {
                    "sources": {"segments": [10], "forms": []},
                    "events": [
                        {
                            "id": "90",
                            "key": "provider.event",
                            "eventType": "action",
                            "properties": properties,
                        }
                    ],
                    "canvasSettings": {"nodes": [], "connections": []},
                },
                format="json",
            )
            return response, client_cls.return_value.update_campaign

    def test_event_with_no_schema_fields_is_valid_with_empty_properties(self):
        response, update = self._patch_event([], {})

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))
        self.assertEqual(update.call_args.args[1]["events"][0]["properties"], {})

    def test_event_with_only_non_data_controls_is_valid_with_empty_properties(self):
        response, _ = self._patch_event(
            [
                {
                    "name": "newEmailButton",
                    "label": "New Email",
                    "renderable": False,
                    "controlType": "action",
                    "blockPrefixes": ["button", "_newEmailButton"],
                },
                {
                    "name": "save",
                    "label": "Save",
                    "controlType": "action",
                    "blockPrefixes": ["submit", "_save"],
                },
                {"name": "uiOnly", "label": "UI only", "mapped": False},
                {"name": "secret", "label": "Hidden", "blockPrefixes": ["hidden", "_s"]},
            ],
            {},
        )

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))

    def test_optional_configurable_fields_all_blank_are_rejected(self):
        response, update = self._patch_event(
            [
                {"name": "add_tags", "label": "Add tags", "renderable": True},
                {"name": "remove_tags", "label": "Remove tags", "renderable": True},
            ],
            {"add_tags": [], "remove_tags": ""},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("at least one of: Add tags, Remove tags", response.data["detail"])
        update.assert_not_called()

    def test_one_populated_optional_field_is_accepted(self):
        response, _ = self._patch_event(
            [
                {"name": "add_tags", "label": "Add tags", "renderable": True},
                {"name": "remove_tags", "label": "Remove tags", "renderable": True},
            ],
            {"remove_tags": ["4"]},
        )

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))

    def test_non_data_controls_do_not_make_an_event_look_configurable(self):
        """One real field among the controls still carries the rule."""
        fields = [
            {"name": "newEmailButton", "renderable": False, "controlType": "action"},
            {"name": "note", "label": "Note", "renderable": True},
        ]

        blank, update = self._patch_event(fields, {})
        self.assertEqual(blank.status_code, 400)
        self.assertIn("at least one of: Note", blank.data["detail"])
        update.assert_not_called()

        filled, _ = self._patch_event(fields, {"note": "hello"})
        self.assertEqual(filled.status_code, 200)

    def test_button_group_choice_field_is_real_configuration(self):
        # ButtonGroupType's prefixes contain "button_group", not "button".
        response, update = self._patch_event(
            [
                {
                    "name": "email_type",
                    "label": "Email type",
                    "renderable": True,
                    "blockPrefixes": ["form", "choice", "button_group", "_email_type"],
                }
            ],
            {},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("at least one of: Email type", response.data["detail"])
        update.assert_not_called()


class NewsletterAdminMauticCampaignPublishedStateTests(TestCase):
    """Switching a campaign off must never be blocked by its workflow."""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="published-state-staff",
            email="published-state-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.detail_url = reverse(
            "newsletter-admin-mautic-campaign-detail",
            args=["7"],
        )

    @staticmethod
    def _capabilities():
        return {
            "actions": [
                {
                    "key": "email.send",
                    "type": "email.send",
                    "eventType": "action",
                    "label": "Send email",
                    "formSchema": {
                        "available": True,
                        "fields": [
                            {
                                "name": "email",
                                "label": "Email to send",
                                "required": True,
                                "renderable": True,
                                "choices": [{"label": "QA Email (23)", "value": "23"}],
                            }
                        ],
                    },
                }
            ],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_pure_unpublish_skips_workflow_validation_entirely(self, client_cls):
        client_cls.return_value.update_campaign.return_value = {
            "id": 7,
            "name": "QA Provider Schema Campaign",
            "isPublished": False,
        }

        response = self.client.patch(
            self.detail_url,
            {"isPublished": False},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        # The provider call is the same one every other update uses.
        client_cls.return_value.update_campaign.assert_called_once_with(
            "7",
            {"isPublished": False},
        )
        # Capabilities are not even fetched: there is no workflow to check.
        client_cls.return_value.get_campaign_builder_capabilities.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_unpublish_does_not_touch_campaign_events(self, client_cls):
        client_cls.return_value.update_campaign.return_value = {"id": 7, "name": "x"}

        self.client.patch(self.detail_url, {"isPublished": False}, format="json")

        payload = client_cls.return_value.update_campaign.call_args.args[1]
        self.assertNotIn("events", payload)
        self.assertNotIn("canvasSettings", payload)
        self.assertNotIn("lists", payload)
        self.assertNotIn("forms", payload)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_publishing_with_an_invalid_workflow_is_still_rejected(self, client_cls):
        client_cls.return_value.get_campaign_builder_capabilities.return_value = (
            self._capabilities()
        )

        response = self.client.patch(
            self.detail_url,
            {
                "isPublished": True,
                "sources": {"segments": [10], "forms": []},
                "events": [
                    {
                        "id": "12",
                        "key": "email.send",
                        "eventType": "action",
                        "properties": {},
                    }
                ],
                "canvasSettings": {"nodes": [], "connections": []},
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("missing required property email", response.data["detail"])
        client_cls.return_value.update_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_a_state_change_that_also_submits_events_is_still_validated(self, client_cls):
        """Unpublishing is only exempt while it submits nothing but the state."""
        client_cls.return_value.get_campaign_builder_capabilities.return_value = (
            self._capabilities()
        )

        response = self.client.patch(
            self.detail_url,
            {
                "isPublished": False,
                "sources": {"segments": [10], "forms": []},
                "events": [
                    {
                        "id": "12",
                        "key": "email.send",
                        "eventType": "action",
                        "properties": {},
                    }
                ],
                "canvasSettings": {"nodes": [], "connections": []},
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        client_cls.return_value.update_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_unpublish_provider_failure_is_normalized_unchanged(self, client_cls):
        client_cls.return_value.update_campaign.side_effect = TemporaryMauticError(
            "Mautic API request failed (HTTP 503)"
        )

        response = self.client.patch(
            self.detail_url,
            {"isPublished": False},
            format="json",
        )

        self.assertEqual(response.status_code, 502)


class NewsletterAdminMauticCampaignEntityChoiceTests(TestCase):
    """A provider UI command is not a selection.

    Mautic's EntityLookupChoiceLoader prepends "Create new…" => "new" to every
    entity field that has a creation modal. It opens a modal in the browser and is
    never a stored selection, so it cannot satisfy a required entity field.
    """

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="entity-choice-staff",
            email="entity-choice-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.detail_url = reverse(
            "newsletter-admin-mautic-campaign-detail",
            args=["7"],
        )

    @staticmethod
    def _capabilities(field_overrides=None):
        field = {
            "name": "email",
            "label": "Email to send",
            "required": True,
            "renderable": True,
            "choiceKind": "entity",
            "choiceMode": "inline",
            "choices": [
                {"label": "Create new...", "labelKey": None, "value": "new", "data": "new"},
                {
                    "label": "en",
                    "choices": [
                        {"label": "QA Email (23)", "value": "23", "data": 23},
                    ],
                },
            ],
        }
        field.update(field_overrides or {})
        return {
            "actions": [
                {
                    "key": "email.send",
                    "type": "email.send",
                    "eventType": "action",
                    "label": "Send email",
                    "formSchema": {"available": True, "fields": [field]},
                }
            ],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }

    def _patch(self, properties, field_overrides=None):
        with patch("newsletter.native_campaign_views.MauticClient") as client_cls:
            client_cls.return_value.get_campaign_builder_capabilities.return_value = (
                self._capabilities(field_overrides)
            )
            client_cls.return_value.update_campaign.return_value = {"id": 7, "name": "x"}

            response = self.client.patch(
                self.detail_url,
                {
                    "sources": {"segments": [10], "forms": []},
                    "events": [
                        {
                            "id": "12",
                            "key": "email.send",
                            "eventType": "action",
                            "properties": properties,
                        }
                    ],
                    "canvasSettings": {"nodes": [], "connections": []},
                },
                format="json",
            )
            return response, client_cls.return_value.update_campaign

    def test_a_real_entity_choice_satisfies_the_required_field(self):
        response, update = self._patch({"email": "23"})

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))
        self.assertEqual(update.call_args.args[1]["events"][0]["properties"]["email"], "23")

    def test_the_create_new_command_does_not_satisfy_the_required_field(self):
        response, update = self._patch({"email": "new"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("missing required property email", response.data["detail"])
        update.assert_not_called()

    def test_an_empty_required_entity_field_is_rejected(self):
        response, update = self._patch({"email": ""})

        self.assertEqual(response.status_code, 400)
        update.assert_not_called()

    def test_a_command_value_does_not_count_as_configuration_either(self):
        """With nothing required, a command still configures nothing."""
        response, update = self._patch(
            {"email": "new"},
            field_overrides={"required": False},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("at least one of: Email to send", response.data["detail"])
        update.assert_not_called()

    def test_a_multi_select_entity_field_needs_one_real_entity(self):
        only_command, update = self._patch(
            {"email": ["new"]},
            field_overrides={"multiple": True},
        )
        self.assertEqual(only_command.status_code, 400)
        update.assert_not_called()

        with_entity, _ = self._patch(
            {"email": ["new", "23"]},
            field_overrides={"multiple": True},
        )
        self.assertEqual(with_entity.status_code, 200, getattr(with_entity, "data", None))

    def test_entity_choices_carrying_an_id_object_are_selectable(self):
        response, _ = self._patch(
            {"email": "4"},
            field_overrides={
                "choices": [
                    {"label": "Create new...", "value": "new", "data": "new"},
                    {"label": "QA Tag", "value": "4", "data": {"id": 4}},
                ]
            },
        )

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))

    def test_a_non_entity_choice_field_is_unaffected(self):
        """Plain choice fields have no command entry and keep working."""
        response, _ = self._patch(
            {"email": "new"},
            field_overrides={
                "choiceKind": "enum",
                "choices": [
                    {"label": "New contacts", "value": "new", "data": "new"},
                    {"label": "All", "value": "all", "data": "all"},
                ],
            },
        )

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))
