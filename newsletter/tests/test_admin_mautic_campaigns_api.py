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

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_capabilities_lists_provider_sources(self, client_cls):
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
        self.assertEqual(response.data["actions"], [])
        self.assertFalse(response.data["builder_metadata"]["available"])
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
        client_cls.return_value.list_segments.assert_called_once_with(limit=200)
        client_cls.return_value.list_forms.assert_called_once_with(limit=200)

    def test_capabilities_requires_staff(self):
        self._authenticate(self.normal_user)

        response = self.client.get(self.capabilities_url)

        self.assertEqual(response.status_code, 403)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_capabilities_maps_provider_failure(self, client_cls):
        client_cls.return_value.list_segments.side_effect = TemporaryMauticError(
            "Mautic segment list failed"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.capabilities_url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("Mautic segment list failed", response.data["detail"])

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
        self.assertEqual(
            called["canvasSettings"]["nodes"],
            [{"id": "new_1"}],
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
