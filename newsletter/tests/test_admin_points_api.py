from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError


User = get_user_model()


class NewsletterAdminPointsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="points-staff",
            email="points-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="points-normal",
            email="points-normal@example.test",
            password="test-password",
        )
        self.list_url = reverse("newsletter-admin-point-action-list")
        self.types_url = reverse("newsletter-admin-point-action-types")
        self.detail_url = reverse(
            "newsletter-admin-point-action-detail",
            args=["5"],
        )
        self.contact_points_url = reverse(
            "newsletter-admin-contact-points",
            args=["12"],
        )

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def test_guest_and_normal_user_are_denied(self):
        for url in (
            self.list_url,
            self.types_url,
            self.detail_url,
            self.contact_points_url,
        ):
            response = self.client.get(url) if url != self.contact_points_url else self.client.post(url, {})
            self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        self.assertEqual(self.client.get(self.list_url).status_code, 403)
        self.assertEqual(self.client.get(self.types_url).status_code, 403)
        self.assertEqual(self.client.get(self.detail_url).status_code, 403)
        self.assertEqual(
            self.client.post(
                self.contact_points_url,
                {"operation": "add", "amount": 1},
                format="json",
            ).status_code,
            403,
        )

    @patch("newsletter.point_views.MauticClient")
    def test_types_returns_provider_action_types(self, client_cls):
        client_cls.return_value.list_point_action_types.return_value = {
            "email.open": "Opens an email",
            "url.hit": "Visits specific URL",
        }
        self._authenticate(self.staff)

        response = self.client.get(self.types_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["types"],
            [
                {"value": "email.open", "label": "Opens an email"},
                {"value": "url.hit", "label": "Visits specific URL"},
            ],
        )

    @patch("newsletter.point_views.MauticClient")
    def test_list_forwards_search_pagination_and_normalizes(self, client_cls):
        client = client_cls.return_value
        client.list_point_actions.return_value = {
            "total": 1,
            "points": [
                {
                    "id": 5,
                    "name": "Newsletter open",
                    "description": "Engagement",
                    "type": "email.open",
                    "delta": "2",
                    "repeatable": 1,
                    "isPublished": True,
                    "properties": {"emails": [7]},
                    "category": None,
                    "group": None,
                }
            ],
        }
        client.list_point_action_types.return_value = {
            "email.open": "Opens an email"
        }
        self._authenticate(self.staff)

        response = self.client.get(
            self.list_url,
            {"page": 2, "page_size": 25, "search": "open"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["page"], 2)
        self.assertEqual(response.data["page_size"], 25)
        self.assertEqual(response.data["results"][0]["id"], "5")
        self.assertEqual(response.data["results"][0]["delta"], 2)
        self.assertTrue(response.data["results"][0]["repeatable"])
        self.assertEqual(
            response.data["results"][0]["type_label"],
            "Opens an email",
        )
        client.list_point_actions.assert_called_once_with(
            start=25,
            limit=25,
            search="open",
        )

    @patch("newsletter.point_views.MauticClient")
    def test_list_accepts_real_empty_provider_shape(self, client_cls):
        client = client_cls.return_value
        client.list_point_actions.return_value = {"total": 0, "points": []}
        client.list_point_action_types.return_value = {
            "url.hit": "Visits specific URL"
        }
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 0)
        self.assertEqual(response.data["num_pages"], 0)
        self.assertEqual(response.data["results"], [])

    @patch("newsletter.point_views.MauticClient")
    def test_create_flattens_properties_and_validates_live_type(self, client_cls):
        client = client_cls.return_value
        client.list_point_action_types.return_value = {
            "url.hit": "Visits specific URL"
        }
        client.create_point_action.return_value = {
            "id": 7,
            "name": "Important URL",
            "description": "High intent",
            "type": "url.hit",
            "delta": 5,
            "repeatable": True,
            "isPublished": True,
            "properties": {
                "page_url": "https://example.com/pricing",
                "page_hits": 1,
            },
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {
                "name": " Important URL ",
                "description": " High intent ",
                "type": "url.hit",
                "delta": "5",
                "repeatable": True,
                "isPublished": True,
                "properties": {
                    "page_url": "https://example.com/pricing",
                    "page_hits": 1,
                },
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["id"], "7")
        self.assertEqual(response.data["type_label"], "Visits specific URL")
        client.create_point_action.assert_called_once_with(
            {
                "name": "Important URL",
                "description": "High intent",
                "type": "url.hit",
                "delta": 5,
                "repeatable": True,
                "isPublished": True,
                "properties[page_url]": "https://example.com/pricing",
                "properties[page_hits]": 1,
            }
        )

    @patch("newsletter.point_views.MauticClient")
    def test_create_rejects_invalid_payload_before_create(self, client_cls):
        client_cls.return_value.list_point_action_types.return_value = {
            "url.hit": "Visits specific URL"
        }
        self._authenticate(self.staff)

        invalid_payloads = (
            {"name": "", "type": "url.hit", "delta": 1},
            {"name": "A", "type": "", "delta": 1},
            {"name": "A", "type": "url.hit", "delta": "1.5"},
            {"name": "A", "type": "url.hit", "delta": 1, "repeatable": "maybe"},
            {"name": "A", "type": "url.hit", "delta": 1, "properties": []},
            {"name": "A", "type": "url.hit", "delta": 1, "unknown": 1},
        )
        for payload in invalid_payloads:
            response = self.client.post(
                self.list_url,
                payload,
                format="json",
            )
            self.assertEqual(response.status_code, 400)

        client_cls.return_value.create_point_action.assert_not_called()

    @patch("newsletter.point_views.MauticClient")
    def test_create_rejects_type_not_exposed_by_live_mautic(self, client_cls):
        client_cls.return_value.list_point_action_types.return_value = {
            "url.hit": "Visits specific URL"
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {
                "name": "Unknown",
                "type": "plugin.missing",
                "delta": 5,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("Unsupported Mautic Point Action type", response.data["detail"])
        client_cls.return_value.create_point_action.assert_not_called()

    @patch("newsletter.point_views.MauticClient")
    def test_detail_get_patch_and_delete(self, client_cls):
        client = client_cls.return_value
        client.list_point_action_types.return_value = {
            "url.hit": "Visits specific URL"
        }
        client.get_point_action.return_value = {
            "id": 5,
            "name": "Important URL",
            "type": "url.hit",
            "delta": 3,
            "properties": {
                "page_url": "https://example.com/old",
            },
        }
        client.update_point_action.return_value = {
            "id": 5,
            "name": "Important URL",
            "type": "url.hit",
            "delta": 5,
            "properties": {
                "page_url": "https://example.com/new",
            },
        }
        client.delete_point_action.return_value = {
            "id": None,
            "name": "Important URL",
        }
        self._authenticate(self.staff)

        get_response = self.client.get(self.detail_url)
        self.assertEqual(get_response.status_code, 200)
        self.assertEqual(get_response.data["id"], "5")

        patch_response = self.client.patch(
            self.detail_url,
            {
                "delta": 5,
                "properties": {
                    "page_url": "https://example.com/new",
                },
            },
            format="json",
        )
        self.assertEqual(patch_response.status_code, 200)
        client.update_point_action.assert_called_once_with(
            "5",
            {
                "delta": 5,
                "properties[page_url]": "https://example.com/new",
                "type": "url.hit",
            },
        )

        delete_response = self.client.delete(self.detail_url)
        self.assertEqual(delete_response.status_code, 204)
        client.delete_point_action.assert_called_once_with("5")

    @patch("newsletter.point_views.MauticClient")
    def test_detail_provider_404_returns_404(self, client_cls):
        client_cls.return_value.get_point_action.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.point_views.MauticClient")
    def test_provider_failure_returns_502(self, client_cls):
        client_cls.return_value.list_point_actions.side_effect = TemporaryMauticError(
            "Mautic points unavailable"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("Mautic points unavailable", response.data["detail"])

    @patch("newsletter.point_views.MauticClient")
    def test_contact_point_adjustment_adds_and_verifies_score(self, client_cls):
        client = client_cls.return_value
        client.get_contact.side_effect = [
            {"id": 12, "points": 10},
            {"id": 12, "points": 15},
        ]
        client.adjust_contact_points.return_value = {"success": 1}
        self._authenticate(self.staff)

        response = self.client.post(
            self.contact_points_url,
            {
                "operation": "add",
                "amount": 5,
                "reason": "Sales engagement",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["previous_points"], 10)
        self.assertEqual(response.data["points"], 15)
        client.adjust_contact_points.assert_called_once_with(
            "12",
            "plus",
            5,
            event_name="Sales engagement",
            action_name="ECP Newsletter",
        )

    @patch("newsletter.point_views.MauticClient")
    def test_contact_point_adjustment_subtracts_and_uses_default_reason(self, client_cls):
        client = client_cls.return_value
        client.get_contact.side_effect = [
            {"id": 12, "points": 10},
            {"id": 12, "points": 7},
        ]
        client.adjust_contact_points.return_value = {"success": 1}
        self._authenticate(self.staff)

        response = self.client.post(
            self.contact_points_url,
            {
                "operation": "subtract",
                "amount": 3,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["points"], 7)
        self.assertEqual(
            response.data["reason"],
            "Manual Point adjustment from ECP",
        )
        client.adjust_contact_points.assert_called_once_with(
            "12",
            "minus",
            3,
            event_name="Manual Point adjustment from ECP",
            action_name="ECP Newsletter",
        )

    @patch("newsletter.point_views.MauticClient")
    def test_contact_point_adjustment_rejects_invalid_input(self, client_cls):
        self._authenticate(self.staff)

        invalid_payloads = (
            {"operation": "set", "amount": 5},
            {"operation": "add", "amount": 0},
            {"operation": "add", "amount": True},
            {"operation": "add", "amount": "abc"},
            {"operation": "add", "amount": 1, "extra": "x"},
            {"operation": "add", "amount": 1, "reason": "x" * 241},
        )
        for payload in invalid_payloads:
            response = self.client.post(
                self.contact_points_url,
                payload,
                format="json",
            )
            self.assertEqual(response.status_code, 400)

        client_cls.return_value.adjust_contact_points.assert_not_called()

    @patch("newsletter.point_views.MauticClient")
    def test_contact_point_adjustment_provider_404_returns_404(self, client_cls):
        client_cls.return_value.get_contact.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        self._authenticate(self.staff)

        response = self.client.post(
            self.contact_points_url,
            {"operation": "add", "amount": 5},
            format="json",
        )

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.point_views.MauticClient")
    def test_contact_point_adjustment_detects_unconfirmed_score(self, client_cls):
        client = client_cls.return_value
        client.get_contact.side_effect = [
            {"id": 12, "points": 10},
            {"id": 12, "points": 14},
        ]
        client.adjust_contact_points.return_value = {"success": 1}
        self._authenticate(self.staff)

        response = self.client.post(
            self.contact_points_url,
            {"operation": "add", "amount": 5},
            format="json",
        )

        self.assertEqual(response.status_code, 502)
        self.assertIn("did not confirm", response.data["detail"])
