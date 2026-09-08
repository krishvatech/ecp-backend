from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError


User = get_user_model()


class NewsletterAdminStagesAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="stages-staff",
            email="stages-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="stages-normal",
            email="stages-normal@example.test",
            password="test-password",
        )
        self.list_url = reverse("newsletter-admin-stage-list")
        self.detail_url = reverse("newsletter-admin-stage-detail", args=["5"])

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def test_guest_and_normal_user_are_denied(self):
        response = self.client.get(self.list_url)
        self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 403)

        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, 403)

    @patch("newsletter.admin_views.MauticClient")
    def test_list_stages_forwards_search_and_pagination_and_normalizes(self, client_cls):
        client_cls.return_value.list_stages.return_value = {
            "total": 2,
            "stages": [
                {
                    "id": 5,
                    "name": "Subscriber",
                    "description": "Subscribed contact",
                    "weight": "10",
                    "isPublished": 1,
                    "category": None,
                    "dateAdded": "2026-09-08T05:00:00+00:00",
                },
                {
                    "id": 6,
                    "name": "Engaged",
                    "description": "",
                    "weight": 20,
                    "isPublished": False,
                    "category": {"id": 2, "title": "Lifecycle"},
                },
            ],
        }
        self._authenticate(self.staff)

        response = self.client.get(
            self.list_url,
            {"page": 2, "page_size": 25, "search": "engaged"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 2)
        self.assertEqual(response.data["page"], 2)
        self.assertEqual(response.data["page_size"], 25)
        self.assertEqual(response.data["num_pages"], 1)
        self.assertEqual(response.data["results"][0]["id"], "5")
        self.assertEqual(response.data["results"][0]["weight"], 10)
        self.assertTrue(response.data["results"][0]["isPublished"])
        self.assertEqual(
            response.data["results"][1]["category"],
            {"id": 2, "title": "Lifecycle"},
        )
        client_cls.return_value.list_stages.assert_called_once_with(
            start=25,
            limit=25,
            search="engaged",
        )

    @patch("newsletter.admin_views.MauticClient")
    def test_list_stages_accepts_real_empty_mautic_shape(self, client_cls):
        client_cls.return_value.list_stages.return_value = {
            "total": 0,
            "stages": [],
        }
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 0)
        self.assertEqual(response.data["num_pages"], 0)
        self.assertEqual(response.data["results"], [])

    @patch("newsletter.admin_views.MauticClient")
    def test_list_provider_failure_returns_502(self, client_cls):
        client_cls.return_value.list_stages.side_effect = TemporaryMauticError(
            "Mautic stages unavailable"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("Mautic stages unavailable", response.data["detail"])

    @patch("newsletter.admin_views.MauticClient")
    def test_staff_can_create_stage(self, client_cls):
        client_cls.return_value.create_stage.return_value = {
            "id": 5,
            "name": "Subscriber",
            "description": "Newsletter subscriber",
            "weight": 10,
            "isPublished": True,
            "category": None,
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {
                "name": " Subscriber ",
                "description": " Newsletter subscriber ",
                "weight": "10",
                "isPublished": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["id"], "5")
        self.assertEqual(response.data["name"], "Subscriber")
        client_cls.return_value.create_stage.assert_called_once_with(
            {
                "name": "Subscriber",
                "description": "Newsletter subscriber",
                "weight": 10,
                "isPublished": True,
            }
        )

    @patch("newsletter.admin_views.MauticClient")
    def test_create_rejects_invalid_payload_before_provider_call(self, client_cls):
        self._authenticate(self.staff)

        for payload in (
            {"name": " ", "weight": 10},
            {"name": "Subscriber", "weight": "10.5"},
            {"name": "Subscriber", "isPublished": "maybe"},
            {"name": "Subscriber", "unknown": "field"},
        ):
            response = self.client.post(self.list_url, payload, format="json")
            self.assertEqual(response.status_code, 400)

        client_cls.return_value.create_stage.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_create_provider_failure_returns_502(self, client_cls):
        client_cls.return_value.create_stage.side_effect = PermanentMauticError(
            "Mautic validation failed"
        )
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {"name": "Subscriber", "weight": 10},
            format="json",
        )

        self.assertEqual(response.status_code, 502)
        self.assertIn("Mautic validation failed", response.data["detail"])

    @patch("newsletter.admin_views.MauticClient")
    def test_staff_can_get_stage_detail(self, client_cls):
        client_cls.return_value.get_stage.return_value = {
            "id": 5,
            "name": "Subscriber",
            "description": "Subscribed",
            "weight": 10,
            "isPublished": True,
            "category": None,
        }
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["id"], "5")
        self.assertEqual(response.data["name"], "Subscriber")
        client_cls.return_value.get_stage.assert_called_once_with("5")

    @patch("newsletter.admin_views.MauticClient")
    def test_stage_detail_provider_404_returns_404(self, client_cls):
        client_cls.return_value.get_stage.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.admin_views.MauticClient")
    def test_staff_can_patch_stage(self, client_cls):
        client_cls.return_value.update_stage.return_value = {
            "id": 5,
            "name": "Engaged",
            "description": "Updated",
            "weight": 20,
            "isPublished": False,
            "category": None,
        }
        self._authenticate(self.staff)

        response = self.client.patch(
            self.detail_url,
            {
                "name": " Engaged ",
                "weight": 20,
                "isPublished": False,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["name"], "Engaged")
        self.assertEqual(response.data["weight"], 20)
        self.assertFalse(response.data["isPublished"])
        client_cls.return_value.update_stage.assert_called_once_with(
            "5",
            {
                "name": "Engaged",
                "weight": 20,
                "isPublished": False,
            },
        )

    @patch("newsletter.admin_views.MauticClient")
    def test_patch_rejects_empty_or_unsupported_payload(self, client_cls):
        self._authenticate(self.staff)

        response = self.client.patch(self.detail_url, {}, format="json")
        self.assertEqual(response.status_code, 400)

        response = self.client.patch(
            self.detail_url,
            {"category": 3},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        client_cls.return_value.update_stage.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_patch_provider_404_returns_404(self, client_cls):
        client_cls.return_value.update_stage.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        self._authenticate(self.staff)

        response = self.client.patch(
            self.detail_url,
            {"name": "Engaged"},
            format="json",
        )

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.admin_views.MauticClient")
    def test_delete_stage_returns_204(self, client_cls):
        client_cls.return_value.delete_stage.return_value = {
            "id": None,
            "name": "Subscriber",
        }
        self._authenticate(self.staff)

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 204)
        client_cls.return_value.delete_stage.assert_called_once_with("5")

    @patch("newsletter.admin_views.MauticClient")
    def test_delete_provider_404_returns_404(self, client_cls):
        client_cls.return_value.delete_stage.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        self._authenticate(self.staff)

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.admin_views.MauticClient")
    def test_delete_provider_failure_returns_502(self, client_cls):
        client_cls.return_value.delete_stage.side_effect = TemporaryMauticError(
            "Mautic delete unavailable"
        )
        self._authenticate(self.staff)

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("Mautic delete unavailable", response.data["detail"])
