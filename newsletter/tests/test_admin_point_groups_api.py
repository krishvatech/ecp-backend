from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError


User = get_user_model()


class NewsletterAdminPointGroupsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="point-groups-staff",
            email="point-groups-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="point-groups-normal",
            email="point-groups-normal@example.test",
            password="test-password",
        )
        self.list_url = reverse("newsletter-admin-point-group-list")
        self.detail_url = reverse(
            "newsletter-admin-point-group-detail",
            args=["5"],
        )
        self.delete_check_url = reverse(
            "newsletter-admin-point-group-delete-check",
            args=["5"],
        )
        self.contact_list_url = reverse(
            "newsletter-admin-contact-point-group-list",
            args=["12"],
        )
        self.contact_detail_url = reverse(
            "newsletter-admin-contact-point-group-detail",
            args=["12", "5"],
        )

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def test_guest_and_normal_user_are_denied(self):
        urls = (
            self.list_url,
            self.detail_url,
            self.delete_check_url,
            self.contact_list_url,
            self.contact_detail_url,
        )
        for url in urls:
            response = self.client.get(url)
            self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        for url in urls:
            self.assertEqual(self.client.get(url).status_code, 403)

    @patch("newsletter.point_group_views.MauticClient")
    def test_list_forwards_search_pagination_and_normalizes(self, client_cls):
        client = client_cls.return_value
        client.list_point_groups.return_value = {
            "total": 1,
            "pointGroups": [
                {
                    "id": 5,
                    "name": " Engagement ",
                    "description": "Newsletter engagement",
                    "isPublished": 1,
                    "dateAdded": "2026-09-09T04:00:00+00:00",
                }
            ],
        }
        self._authenticate(self.staff)

        response = self.client.get(
            self.list_url,
            {"page": 2, "page_size": 25, "search": "engagement"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["page"], 2)
        self.assertEqual(response.data["page_size"], 25)
        self.assertEqual(response.data["results"][0]["id"], "5")
        self.assertEqual(response.data["results"][0]["name"], "Engagement")
        self.assertTrue(response.data["results"][0]["isPublished"])
        client.list_point_groups.assert_called_once_with(
            start=25,
            limit=25,
            search="engagement",
        )

    @patch("newsletter.point_group_views.MauticClient")
    def test_list_accepts_real_empty_provider_shape(self, client_cls):
        client_cls.return_value.list_point_groups.return_value = {
            "total": 0,
            "pointGroups": [],
        }
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 0)
        self.assertEqual(response.data["num_pages"], 0)
        self.assertEqual(response.data["results"], [])

    @patch("newsletter.point_group_views.MauticClient")
    def test_create_validates_payload_and_normalizes(self, client_cls):
        client = client_cls.return_value
        client.create_point_group.return_value = {
            "id": 7,
            "name": "Engagement",
            "description": "Newsletter engagement",
            "isPublished": False,
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {
                "name": " Engagement ",
                "description": " Newsletter engagement ",
                "isPublished": False,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["id"], "7")
        client.create_point_group.assert_called_once_with(
            {
                "name": "Engagement",
                "description": "Newsletter engagement",
                "isPublished": False,
            }
        )

    @patch("newsletter.point_group_views.MauticClient")
    def test_create_rejects_invalid_payload(self, client_cls):
        self._authenticate(self.staff)
        invalid_payloads = (
            {"name": ""},
            {"name": "A", "isPublished": "maybe"},
            {"name": "A", "unknown": 1},
        )
        for payload in invalid_payloads:
            response = self.client.post(self.list_url, payload, format="json")
            self.assertEqual(response.status_code, 400)
        client_cls.return_value.create_point_group.assert_not_called()

    @patch("newsletter.point_group_views.MauticClient")
    def test_detail_get_normalizes_group(self, client_cls):
        client = client_cls.return_value
        client.get_point_group.return_value = {
            "id": 5,
            "name": "Engagement",
            "description": "",
            "isPublished": False,
        }
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["id"], "5")
        self.assertEqual(response.data["name"], "Engagement")
        client.list_point_actions.assert_not_called()
        client.list_point_triggers.assert_not_called()

    @patch("newsletter.point_group_views.MauticClient")
    def test_delete_check_returns_conservative_guard(self, client_cls):
        client = client_cls.return_value
        client.get_point_group.return_value = {"id": 5, "name": "Engagement"}
        client.list_point_actions.return_value = {"total": 2, "points": [{}]}
        client.list_point_triggers.return_value = {"total": 1, "triggers": [{}]}
        self._authenticate(self.staff)

        response = self.client.get(self.delete_check_url)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["delete_allowed"])
        self.assertEqual(response.data["point_actions"], 2)
        self.assertEqual(response.data["point_triggers"], 1)
        self.assertEqual(response.data["mode"], "global_conservative")

    @patch("newsletter.point_group_views.MauticClient")
    def test_detail_patch_updates_supported_fields(self, client_cls):
        client = client_cls.return_value
        client.update_point_group.return_value = {
            "id": 5,
            "name": "Engagement Updated",
            "description": "Updated",
            "isPublished": True,
        }
        self._authenticate(self.staff)

        response = self.client.patch(
            self.detail_url,
            {
                "name": " Engagement Updated ",
                "description": " Updated ",
                "isPublished": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        client.update_point_group.assert_called_once_with(
            "5",
            {
                "name": "Engagement Updated",
                "description": "Updated",
                "isPublished": True,
            },
        )

    @patch("newsletter.point_group_views.MauticClient")
    def test_delete_allows_only_when_no_point_actions_or_triggers_exist(self, client_cls):
        client = client_cls.return_value
        client.get_point_group.return_value = {"id": 5, "name": "Engagement"}
        client.list_point_actions.return_value = {"total": 0, "points": []}
        client.list_point_triggers.return_value = {"total": 0, "triggers": []}
        client.delete_point_group.return_value = {"id": None, "name": "Engagement"}
        self._authenticate(self.staff)

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 204)
        client.delete_point_group.assert_called_once_with("5")

    @patch("newsletter.point_group_views.MauticClient")
    def test_delete_blocks_when_any_point_action_exists(self, client_cls):
        client = client_cls.return_value
        client.get_point_group.return_value = {"id": 5, "name": "Engagement"}
        client.list_point_actions.return_value = {"total": 1, "points": [{"id": 9}]}
        client.list_point_triggers.return_value = {"total": 0, "triggers": []}
        self._authenticate(self.staff)

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 409)
        self.assertIn("cascade-delete", response.data["detail"])
        self.assertEqual(response.data["delete_guard"]["point_actions"], 1)
        client.delete_point_group.assert_not_called()

    @patch("newsletter.point_group_views.MauticClient")
    def test_delete_blocks_when_any_point_trigger_exists(self, client_cls):
        client = client_cls.return_value
        client.get_point_group.return_value = {"id": 5, "name": "Engagement"}
        client.list_point_actions.return_value = {"total": 0, "points": []}
        client.list_point_triggers.return_value = {
            "total": 1,
            "triggers": [{"id": 4}],
        }
        self._authenticate(self.staff)

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["delete_guard"]["point_triggers"], 1)
        client.delete_point_group.assert_not_called()

    @patch("newsletter.point_group_views.MauticClient")
    def test_provider_404_and_failure_are_mapped(self, client_cls):
        self._authenticate(self.staff)
        client = client_cls.return_value
        client.get_point_group.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        self.assertEqual(self.client.get(self.detail_url).status_code, 404)

        client.reset_mock()
        client.get_point_group.side_effect = None
        client.list_point_groups.side_effect = TemporaryMauticError(
            "Mautic groups unavailable"
        )
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 502)
        self.assertIn("Mautic groups unavailable", response.data["detail"])

    @patch("newsletter.point_group_views.MauticClient")
    def test_contact_group_score_list_normalizes(self, client_cls):
        client_cls.return_value.list_contact_point_groups.return_value = {
            "total": 1,
            "groupScores": [
                {
                    "score": "7",
                    "group": {
                        "id": 5,
                        "name": "Engagement",
                        "description": "Newsletter engagement",
                    },
                }
            ],
        }
        self._authenticate(self.staff)

        response = self.client.get(self.contact_list_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["group_id"], "5")
        self.assertEqual(response.data["results"][0]["score"], 7)

    @patch("newsletter.point_group_views.MauticClient")
    def test_contact_group_score_detail_normalizes(self, client_cls):
        client_cls.return_value.get_contact_point_group.return_value = {
            "score": 4,
            "group": {"id": 5, "name": "Engagement", "description": ""},
        }
        self._authenticate(self.staff)

        response = self.client.get(self.contact_detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["mautic_contact_id"], "12")
        self.assertEqual(response.data["group_id"], "5")
        self.assertEqual(response.data["score"], 4)

    @patch("newsletter.point_group_views.MauticClient")
    def test_contact_group_adjustment_adds_and_verifies_score(self, client_cls):
        client = client_cls.return_value
        client.list_contact_point_groups.return_value = {
            "total": 1,
            "groupScores": [
                {"score": 10, "group": {"id": 5, "name": "Engagement"}}
            ],
        }
        client.adjust_contact_group_points.return_value = {
            "score": 15,
            "group": {"id": 5, "name": "Engagement", "description": ""},
        }
        client.get_contact_point_group.return_value = {
            "score": 15,
            "group": {"id": 5, "name": "Engagement", "description": ""},
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.contact_detail_url,
            {"operation": "add", "amount": 5, "reason": "Sales engagement"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["previous_score"], 10)
        self.assertEqual(response.data["score"], 15)
        client.adjust_contact_group_points.assert_called_once_with(
            "12",
            "5",
            "plus",
            5,
            event_name="Sales engagement",
            action_name="ECP Newsletter",
        )

    @patch("newsletter.point_group_views.MauticClient")
    def test_contact_group_adjustment_supports_new_score_and_default_reason(self, client_cls):
        client = client_cls.return_value
        client.list_contact_point_groups.return_value = {
            "total": 0,
            "groupScores": [],
        }
        client.adjust_contact_group_points.return_value = {
            "score": -3,
            "group": {"id": 5, "name": "Engagement", "description": ""},
        }
        client.get_contact_point_group.return_value = {
            "score": -3,
            "group": {"id": 5, "name": "Engagement", "description": ""},
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.contact_detail_url,
            {"operation": "subtract", "amount": 3},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["previous_score"], 0)
        self.assertEqual(response.data["score"], -3)
        self.assertEqual(
            response.data["reason"],
            "Manual Point Group adjustment from ECP",
        )

    @patch("newsletter.point_group_views.MauticClient")
    def test_contact_group_adjustment_rejects_invalid_input(self, client_cls):
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
                self.contact_detail_url,
                payload,
                format="json",
            )
            self.assertEqual(response.status_code, 400)
        client_cls.return_value.adjust_contact_group_points.assert_not_called()

    @patch("newsletter.point_group_views.MauticClient")
    def test_contact_group_adjustment_detects_unconfirmed_score(self, client_cls):
        client = client_cls.return_value
        client.list_contact_point_groups.return_value = {
            "total": 1,
            "groupScores": [
                {"score": 10, "group": {"id": 5, "name": "Engagement"}}
            ],
        }
        client.adjust_contact_group_points.return_value = {
            "score": 15,
            "group": {"id": 5, "name": "Engagement", "description": ""},
        }
        client.get_contact_point_group.return_value = {
            "score": 14,
            "group": {"id": 5, "name": "Engagement", "description": ""},
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.contact_detail_url,
            {"operation": "add", "amount": 5},
            format="json",
        )

        self.assertEqual(response.status_code, 502)
        self.assertIn("did not confirm", response.data["detail"])
