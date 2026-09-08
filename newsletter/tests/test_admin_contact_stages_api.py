from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError


User = get_user_model()


class NewsletterAdminContactStagesAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="contact-stage-staff",
            email="contact-stage-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="contact-stage-normal",
            email="contact-stage-normal@example.test",
            password="test-password",
        )
        self.list_url = reverse("newsletter-admin-contact-list")
        self.detail_url = reverse(
            "newsletter-admin-contact-detail",
            args=["2"],
        )
        self.stage_url = reverse(
            "newsletter-admin-contact-stage",
            args=["2"],
        )

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def test_guest_and_normal_user_are_denied_stage_changes(self):
        response = self.client.post(
            self.stage_url,
            {"stage_id": "5"},
            format="json",
        )
        self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)

        response = self.client.post(
            self.stage_url,
            {"stage_id": "5"},
            format="json",
        )
        self.assertEqual(response.status_code, 403)

        response = self.client.delete(self.stage_url)
        self.assertEqual(response.status_code, 403)

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_detail_exposes_real_current_stage(self, client_cls):
        client_cls.return_value.get_contact.return_value = {
            "id": 2,
            "points": 4,
            "stage": {
                "id": 5,
                "name": "Engaged",
                "description": "Engaged contact",
                "weight": 20,
                "category": None,
            },
            "fields": {
                "all": {
                    "firstname": "Ravi",
                    "lastname": "Avaiya",
                    "email": "ravi@example.test",
                }
            },
        }
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["current_stage"],
            {
                "id": "5",
                "name": "Engaged",
                "description": "Engaged contact",
                "weight": 20,
                "category": None,
            },
        )

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_list_exposes_stage_and_unstaged_contacts(self, client_cls):
        client_cls.return_value.list_contacts.return_value = {
            "total": 2,
            "contacts": {
                "2": {
                    "id": 2,
                    "stage": {
                        "id": 5,
                        "name": "Engaged",
                        "weight": "20",
                        "description": "",
                        "category": None,
                    },
                    "fields": {
                        "all": {
                            "email": "staged@example.test",
                        }
                    },
                },
                "3": {
                    "id": 3,
                    "stage": None,
                    "fields": {
                        "all": {
                            "email": "unstaged@example.test",
                        }
                    },
                },
            },
        }
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["results"][0]["current_stage"]["id"],
            "5",
        )
        self.assertEqual(
            response.data["results"][0]["current_stage"]["weight"],
            20,
        )
        self.assertIsNone(response.data["results"][1]["current_stage"])

    @patch("newsletter.contact_services.MauticClient")
    def test_staff_can_move_contact_to_published_stage(self, client_cls):
        client = client_cls.return_value
        client.get_contact.side_effect = [
            {
                "id": 2,
                "stage": None,
            },
            {
                "id": 2,
                "stage": {
                    "id": 5,
                    "name": "Engaged",
                    "description": "Engaged contact",
                    "weight": 20,
                    "category": None,
                },
            },
        ]
        client.get_stage.return_value = {
            "id": 5,
            "name": "Engaged",
            "description": "Engaged contact",
            "weight": 20,
            "isPublished": True,
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.stage_url,
            {"stage_id": "5"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["mautic_contact_id"], "2")
        self.assertEqual(response.data["current_stage"]["id"], "5")
        client.get_stage.assert_called_once_with("5")
        client.add_contact_to_stage.assert_called_once_with("5", "2")
        self.assertEqual(client.get_contact.call_count, 2)

    @patch("newsletter.contact_services.MauticClient")
    def test_move_to_current_stage_is_idempotent(self, client_cls):
        client = client_cls.return_value
        client.get_contact.return_value = {
            "id": 2,
            "stage": {
                "id": 5,
                "name": "Engaged",
                "weight": 20,
                "category": None,
            },
        }
        client.get_stage.return_value = {
            "id": 5,
            "name": "Engaged",
            "weight": 20,
            "isPublished": True,
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.stage_url,
            {"stage_id": "5"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["current_stage"]["id"], "5")
        client.add_contact_to_stage.assert_not_called()
        client.get_contact.assert_called_once_with("2")

    @patch("newsletter.contact_services.MauticClient")
    def test_move_validates_payload_before_provider_call(self, client_cls):
        self._authenticate(self.staff)

        response = self.client.post(self.stage_url, {}, format="json")
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            self.stage_url,
            {"stage_id": "5", "unexpected": True},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        client_cls.assert_not_called()

    @patch("newsletter.contact_services.MauticClient")
    def test_missing_contact_or_stage_returns_404(self, client_cls):
        client = client_cls.return_value
        client.get_contact.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        self._authenticate(self.staff)

        response = self.client.post(
            self.stage_url,
            {"stage_id": "5"},
            format="json",
        )
        self.assertEqual(response.status_code, 404)

        client.get_contact.side_effect = None
        client.get_contact.return_value = {"id": 2, "stage": None}
        client.get_stage.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )

        response = self.client.post(
            self.stage_url,
            {"stage_id": "999"},
            format="json",
        )
        self.assertEqual(response.status_code, 404)

    @patch("newsletter.contact_services.MauticClient")
    def test_provider_validation_error_returns_400(self, client_cls):
        client = client_cls.return_value
        client.get_contact.side_effect = [
            {"id": 2, "stage": None},
            {"id": 2, "stage": None},
        ]
        client.get_stage.return_value = {
            "id": 5,
            "name": "Provider Stage",
            "weight": 10,
            "isPublished": True,
        }
        client.add_contact_to_stage.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 400): stage assignment rejected"
        )
        self._authenticate(self.staff)

        response = self.client.post(
            self.stage_url,
            {"stage_id": "5"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("HTTP 400", response.data["detail"])

    @patch("newsletter.contact_services.MauticClient")
    def test_temporary_move_failure_returns_502(self, client_cls):
        client = client_cls.return_value
        client.get_contact.return_value = {"id": 2, "stage": None}
        client.get_stage.return_value = {
            "id": 5,
            "name": "Engaged",
            "weight": 20,
            "isPublished": True,
        }
        client.add_contact_to_stage.side_effect = TemporaryMauticError(
            "Mautic stage change unavailable"
        )
        self._authenticate(self.staff)

        response = self.client.post(
            self.stage_url,
            {"stage_id": "5"},
            format="json",
        )

        self.assertEqual(response.status_code, 502)
        self.assertIn("unavailable", response.data["detail"])

    @patch("newsletter.contact_services.MauticClient")
    def test_staff_can_clear_current_stage(self, client_cls):
        client = client_cls.return_value
        client.get_contact.side_effect = [
            {
                "id": 2,
                "stage": {
                    "id": 5,
                    "name": "Engaged",
                    "weight": 20,
                    "category": None,
                },
            },
            {
                "id": 2,
                "stage": None,
            },
        ]
        self._authenticate(self.staff)

        response = self.client.delete(self.stage_url)

        self.assertEqual(response.status_code, 204)
        client.remove_contact_from_stage.assert_called_once_with("5", "2")
        self.assertEqual(client.get_contact.call_count, 2)

    @patch("newsletter.contact_services.MauticClient")
    def test_clear_without_current_stage_is_idempotent(self, client_cls):
        client = client_cls.return_value
        client.get_contact.return_value = {
            "id": 2,
            "stage": None,
        }
        self._authenticate(self.staff)

        response = self.client.delete(self.stage_url)

        self.assertEqual(response.status_code, 204)
        client.remove_contact_from_stage.assert_not_called()
        client.get_contact.assert_called_once_with("2")
