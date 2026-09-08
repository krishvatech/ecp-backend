from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError


User = get_user_model()


class NewsletterAdminPointTriggerAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="trigger-staff",
            email="trigger-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="trigger-normal",
            email="trigger-normal@example.test",
            password="test-password",
        )
        self.list_url = reverse("newsletter-admin-point-trigger-list")
        self.types_url = reverse("newsletter-admin-point-trigger-event-types")
        self.detail_url = reverse(
            "newsletter-admin-point-trigger-detail",
            args=["4"],
        )
        self.events_url = reverse(
            "newsletter-admin-point-trigger-event-list",
            args=["4"],
        )
        self.event_detail_url = reverse(
            "newsletter-admin-point-trigger-event-detail",
            args=["4", "10"],
        )

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def test_guest_and_normal_user_are_denied(self):
        urls = (
            self.list_url,
            self.types_url,
            self.detail_url,
            self.events_url,
            self.event_detail_url,
        )
        for url in urls:
            self.assertIn(self.client.get(url).status_code, (401, 403))

        self._authenticate(self.normal_user)
        for url in urls:
            self.assertEqual(self.client.get(url).status_code, 403)

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_event_types_returns_live_provider_types(self, client_cls):
        client_cls.return_value.list_point_trigger_event_types.return_value = {
            "lead.changelists": "Modify contact's segments",
            "email.send": "Send an email",
        }
        self._authenticate(self.staff)

        response = self.client.get(self.types_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["types"],
            [
                {
                    "value": "lead.changelists",
                    "label": "Modify contact's segments",
                },
                {
                    "value": "email.send",
                    "label": "Send an email",
                },
            ],
        )

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_list_forwards_search_pagination_and_normalizes_events(self, client_cls):
        client = client_cls.return_value
        client.list_point_triggers.return_value = {
            "total": 1,
            "triggers": [
                {
                    "id": 4,
                    "name": "Warm lead",
                    "description": "Reached threshold",
                    "points": "25",
                    "color": "f59e0b",
                    "triggerExistingLeads": 1,
                    "isPublished": True,
                    "events": [
                        {
                            "id": 10,
                            "name": "Add to segment",
                            "type": "lead.changelists",
                            "order": 1,
                            "properties": {"addToLists": [3]},
                        }
                    ],
                }
            ],
        }
        client.list_point_trigger_event_types.return_value = {
            "lead.changelists": "Modify contact's segments"
        }
        self._authenticate(self.staff)

        response = self.client.get(
            self.list_url,
            {"page": 2, "page_size": 25, "search": "warm"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["page"], 2)
        trigger = response.data["results"][0]
        self.assertEqual(trigger["id"], "4")
        self.assertEqual(trigger["points"], 25)
        self.assertTrue(trigger["triggerExistingLeads"])
        self.assertEqual(trigger["events"][0]["id"], "10")
        self.assertEqual(
            trigger["events"][0]["type_label"],
            "Modify contact's segments",
        )
        client.list_point_triggers.assert_called_once_with(
            start=25,
            limit=25,
            search="warm",
        )

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_create_trigger_validates_and_normalizes_payload(self, client_cls):
        client = client_cls.return_value
        client.create_point_trigger.return_value = {
            "id": 4,
            "name": "Warm lead",
            "description": "Reached threshold",
            "points": 25,
            "color": "f59e0b",
            "triggerExistingLeads": False,
            "isPublished": False,
            "events": [],
        }
        client.list_point_trigger_event_types.return_value = {}
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {
                "name": " Warm lead ",
                "description": " Reached threshold ",
                "points": "25",
                "color": "#F59E0B",
                "triggerExistingLeads": False,
                "isPublished": False,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["id"], "4")
        self.assertEqual(response.data["color"], "f59e0b")
        client.create_point_trigger.assert_called_once_with(
            {
                "name": "Warm lead",
                "description": "Reached threshold",
                "points": 25,
                "color": "f59e0b",
                "triggerExistingLeads": False,
                "isPublished": False,
            }
        )

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_create_trigger_rejects_invalid_input_before_provider_create(self, client_cls):
        self._authenticate(self.staff)

        invalid_payloads = (
            {"name": "", "points": 25},
            {"name": "A", "points": "1.5"},
            {"name": "A", "color": "bad"},
            {"name": "A", "triggerExistingLeads": "maybe"},
            {"name": "A", "unknown": 1},
        )
        for payload in invalid_payloads:
            response = self.client.post(self.list_url, payload, format="json")
            self.assertEqual(response.status_code, 400)

        client_cls.return_value.create_point_trigger.assert_not_called()

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_trigger_detail_get_patch_and_delete(self, client_cls):
        client = client_cls.return_value
        client.get_point_trigger.return_value = {
            "id": 4,
            "name": "Warm lead",
            "points": 25,
            "color": "f59e0b",
            "events": [],
        }
        client.update_point_trigger.return_value = {
            "id": 4,
            "name": "Warm lead",
            "points": 30,
            "color": "0f766e",
            "events": [],
        }
        client.delete_point_trigger.return_value = {
            "id": None,
            "name": "Warm lead",
        }
        client.list_point_trigger_event_types.return_value = {}
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["id"], "4")

        response = self.client.patch(
            self.detail_url,
            {"points": 30, "color": "#0F766E"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["points"], 30)
        client.update_point_trigger.assert_called_once_with(
            "4",
            {"points": 30, "color": "0f766e"},
        )

        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, 204)
        client.delete_point_trigger.assert_called_once_with("4")

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_trigger_provider_404_returns_404(self, client_cls):
        client_cls.return_value.get_point_trigger.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_event_list_uses_parent_trigger_events(self, client_cls):
        client = client_cls.return_value
        client.get_point_trigger.return_value = {
            "id": 4,
            "events": [
                {
                    "id": 10,
                    "name": "Add to segment",
                    "type": "lead.changelists",
                    "order": 1,
                    "properties": {"addToLists": [3]},
                }
            ],
        }
        client.list_point_trigger_event_types.return_value = {
            "lead.changelists": "Modify contact's segments"
        }
        self._authenticate(self.staff)

        response = self.client.get(self.events_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["id"], "10")

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_create_event_validates_live_type_and_uses_direct_client_create(self, client_cls):
        client = client_cls.return_value
        client.get_point_trigger.return_value = {"id": 4, "events": []}
        client.list_point_trigger_event_types.return_value = {
            "lead.changelists": "Modify contact's segments"
        }
        client.create_point_trigger_event.return_value = {
            "id": 10,
            "name": "Add to segment",
            "description": "Route warm lead",
            "type": "lead.changelists",
            "order": 1,
            "properties": {
                "addToLists": [3],
                "removeFromLists": [],
            },
            "trigger": {
                "@id": "/api/v2/triggers/4",
            },
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.events_url,
            {
                "name": " Add to segment ",
                "description": " Route warm lead ",
                "type": "lead.changelists",
                "properties": {
                    "addToLists": [3],
                    "removeFromLists": [],
                },
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["id"], "10")
        self.assertEqual(response.data["trigger_id"], "4")
        client.create_point_trigger_event.assert_called_once_with(
            "4",
            {
                "name": "Add to segment",
                "description": "Route warm lead",
                "type": "lead.changelists",
                "order": 1,
                "properties": {
                    "addToLists": [3],
                    "removeFromLists": [],
                },
            },
        )

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_create_event_rejects_invalid_or_unknown_type(self, client_cls):
        client = client_cls.return_value
        client.get_point_trigger.return_value = {"id": 4, "events": []}
        client.list_point_trigger_event_types.return_value = {
            "lead.changelists": "Modify contact's segments"
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.events_url,
            {
                "name": "Unknown",
                "type": "plugin.missing",
                "properties": {},
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            self.events_url,
            {
                "name": "Bad properties",
                "type": "lead.changelists",
                "properties": [],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        client.create_point_trigger_event.assert_not_called()

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_event_detail_get_checks_parent_membership(self, client_cls):
        client = client_cls.return_value
        client.get_point_trigger_event.return_value = {
            "id": 10,
            "name": "Add to segment",
            "type": "lead.changelists",
            "order": 1,
            "properties": {"addToLists": [3]},
            "trigger": {
                "@id": "/api/v2/triggers/4",
            },
        }
        client.list_point_trigger_event_types.return_value = {
            "lead.changelists": "Modify contact's segments"
        }
        self._authenticate(self.staff)

        response = self.client.get(self.event_detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["trigger_id"], "4")

        client.get_point_trigger_event.return_value["trigger"] = {
            "@id": "/api/v2/triggers/99",
        }
        response = self.client.get(self.event_detail_url)
        self.assertEqual(response.status_code, 404)

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_event_patch_uses_direct_update_and_keeps_type_fixed(self, client_cls):
        client = client_cls.return_value
        client.get_point_trigger_event.return_value = {
            "id": 10,
            "name": "Add to segment",
            "type": "lead.changelists",
            "order": 1,
            "properties": {"addToLists": [3]},
            "trigger": {
                "@id": "/api/v2/triggers/4",
            },
        }
        client.list_point_trigger_event_types.return_value = {
            "lead.changelists": "Modify contact's segments",
            "email.send": "Send an email",
        }
        client.update_point_trigger_event.return_value = {
            "id": 10,
            "name": "Updated event",
            "type": "lead.changelists",
            "order": 1,
            "properties": {
                "addToLists": [3],
                "removeFromLists": [],
            },
            "trigger": {
                "@id": "/api/v2/triggers/4",
            },
        }
        self._authenticate(self.staff)

        response = self.client.patch(
            self.event_detail_url,
            {
                "name": "Updated event",
                "properties": {
                    "addToLists": [3],
                    "removeFromLists": [],
                },
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        client.update_point_trigger_event.assert_called_once_with(
            "10",
            {
                "name": "Updated event",
                "properties": {
                    "addToLists": [3],
                    "removeFromLists": [],
                },
            },
        )

        client.update_point_trigger_event.reset_mock()
        response = self.client.patch(
            self.event_detail_url,
            {"type": "email.send"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("type cannot be changed", response.data["detail"])
        client.update_point_trigger_event.assert_not_called()

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_event_delete_uses_persistent_direct_delete_after_membership_check(self, client_cls):
        client = client_cls.return_value
        client.get_point_trigger_event.return_value = {
            "id": 10,
            "type": "lead.changelists",
            "trigger": {
                "@id": "/api/v2/triggers/4",
            },
        }
        self._authenticate(self.staff)

        response = self.client.delete(self.event_detail_url)

        self.assertEqual(response.status_code, 204)
        client.delete_point_trigger_event.assert_called_once_with("10")

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_trigger_provider_failure_returns_502(self, client_cls):
        client_cls.return_value.list_point_triggers.side_effect = TemporaryMauticError(
            "Mautic trigger provider unavailable"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 502)
        self.assertIn(
            "Mautic trigger provider unavailable",
            response.data["detail"],
        )
