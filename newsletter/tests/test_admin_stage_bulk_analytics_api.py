from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError


User = get_user_model()


class NewsletterAdminStageBulkAnalyticsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="stage-p4-staff",
            email="stage-p4-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="stage-p4-normal",
            email="stage-p4-normal@example.test",
            password="test-password",
        )
        self.contacts_url = reverse("newsletter-admin-contact-list")
        self.bulk_url = reverse("newsletter-admin-contact-bulk-stage")
        self.analytics_url = reverse("newsletter-admin-stage-analytics")

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def test_guest_and_normal_user_are_denied_bulk_and_analytics(self):
        response = self.client.post(
            self.bulk_url,
            {"action": "move", "contact_ids": ["2"], "stage_id": "5"},
            format="json",
        )
        self.assertIn(response.status_code, (401, 403))
        response = self.client.get(self.analytics_url)
        self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        response = self.client.post(
            self.bulk_url,
            {"action": "clear", "contact_ids": ["2"]},
            format="json",
        )
        self.assertEqual(response.status_code, 403)
        response = self.client.get(self.analytics_url)
        self.assertEqual(response.status_code, 403)

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_list_forwards_exact_stage_filter(self, client_cls):
        client = client_cls.return_value
        client.list_contacts.return_value = {
            "total": 1,
            "contacts": {
                "2": {
                    "id": 2,
                    "stage": {"id": 5, "name": "Engaged", "weight": 20},
                    "fields": {"all": {"email": "stage@example.test"}},
                }
            },
        }
        self._authenticate(self.staff)

        response = self.client.get(self.contacts_url, {"stage_id": "5"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        client.list_contacts.assert_called_once_with(
            start=0,
            limit=25,
            **{
                "where[0][col]": "stage_id",
                "where[0][expr]": "eq",
                "where[0][val]": "5",
            },
        )

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_list_supports_unstaged_filter(self, client_cls):
        client = client_cls.return_value
        client.list_contacts.return_value = {
            "total": 1,
            "contacts": {
                "3": {
                    "id": 3,
                    "stage": None,
                    "fields": {"all": {"email": "none@example.test"}},
                }
            },
        }
        self._authenticate(self.staff)

        response = self.client.get(self.contacts_url, {"stage_id": "none"})

        self.assertEqual(response.status_code, 200)
        client.list_contacts.assert_called_once_with(
            start=0,
            limit=25,
            **{
                "where[0][col]": "stage_id",
                "where[0][expr]": "isNull",
            },
        )

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_list_rejects_invalid_stage_filter(self, client_cls):
        self._authenticate(self.staff)

        response = self.client.get(self.contacts_url, {"stage_id": "abc"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("positive integer", response.data["detail"])
        client_cls.assert_not_called()

    @patch("newsletter.contact_services.MauticClient")
    def test_bulk_move_supports_changed_and_idempotent_contacts(self, client_cls):
        client = client_cls.return_value
        client.get_stage.return_value = {
            "id": 5,
            "name": "Engaged",
            "weight": 20,
        }
        client.get_contact.side_effect = [
            {"id": 2, "stage": None},
            {
                "id": 2,
                "stage": {"id": 5, "name": "Engaged", "weight": 20},
            },
            {
                "id": 3,
                "stage": {"id": 5, "name": "Engaged", "weight": 20},
            },
        ]
        self._authenticate(self.staff)

        response = self.client.post(
            self.bulk_url,
            {
                "action": "move",
                "contact_ids": ["2", "3", "3"],
                "stage_id": "5",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["requested"], 2)
        self.assertEqual(response.data["succeeded"], 2)
        self.assertEqual(response.data["failed"], 0)
        self.assertEqual(response.data["changed"], 1)
        self.assertEqual(response.data["target_stage"]["id"], "5")
        client.get_stage.assert_called_once_with("5")
        client.add_contact_to_stage.assert_called_once_with("5", "2")

    @patch("newsletter.contact_services.MauticClient")
    def test_bulk_move_reports_per_contact_provider_failure(self, client_cls):
        client = client_cls.return_value
        client.get_stage.return_value = {
            "id": 5,
            "name": "Engaged",
            "weight": 20,
        }
        client.get_contact.side_effect = [
            {"id": 2, "stage": None},
            {
                "id": 2,
                "stage": {"id": 5, "name": "Engaged", "weight": 20},
            },
            PermanentMauticError(
                "Mautic API request failed (HTTP 404)"
            ),
        ]
        self._authenticate(self.staff)

        response = self.client.post(
            self.bulk_url,
            {
                "action": "move",
                "contact_ids": ["2", "999"],
                "stage_id": "5",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["succeeded"], 1)
        self.assertEqual(response.data["failed"], 1)
        self.assertTrue(response.data["results"][0]["success"])
        self.assertFalse(response.data["results"][1]["success"])
        self.assertIn("HTTP 404", response.data["results"][1]["error"])

    @patch("newsletter.contact_services.MauticClient")
    def test_bulk_clear_is_idempotent_and_verifies_changed_contact(self, client_cls):
        client = client_cls.return_value
        client.get_contact.side_effect = [
            {
                "id": 2,
                "stage": {"id": 5, "name": "Engaged", "weight": 20},
            },
            {"id": 2, "stage": None},
            {"id": 3, "stage": None},
        ]
        self._authenticate(self.staff)

        response = self.client.post(
            self.bulk_url,
            {"action": "clear", "contact_ids": ["2", "3"]},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["requested"], 2)
        self.assertEqual(response.data["succeeded"], 2)
        self.assertEqual(response.data["changed"], 1)
        client.remove_contact_from_stage.assert_called_once_with("5", "2")

    @patch("newsletter.contact_services.MauticClient")
    def test_bulk_payload_validation_happens_before_provider_calls(self, client_cls):
        self._authenticate(self.staff)

        response = self.client.post(
            self.bulk_url,
            {"action": "move", "contact_ids": [], "stage_id": "5"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            self.bulk_url,
            {
                "action": "move",
                "contact_ids": [str(index + 1) for index in range(101)],
                "stage_id": "5",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            self.bulk_url,
            {
                "action": "clear",
                "contact_ids": ["2"],
                "stage_id": "5",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            self.bulk_url,
            {
                "action": "move",
                "contact_ids": ["2"],
                "stage_id": "5",
                "unexpected": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        client_cls.assert_not_called()

    @patch("newsletter.contact_services.MauticClient")
    def test_missing_bulk_target_stage_maps_to_404(self, client_cls):
        client_cls.return_value.get_stage.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        self._authenticate(self.staff)

        response = self.client.post(
            self.bulk_url,
            {"action": "move", "contact_ids": ["2"], "stage_id": "999"},
            format="json",
        )

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.contact_services.MauticClient")
    def test_stage_analytics_uses_provider_counts_per_stage(self, client_cls):
        client = client_cls.return_value
        client.list_stages.return_value = {
            "total": 2,
            "stages": {
                "5": {"id": 5, "name": "Subscriber", "weight": 10},
                "6": {"id": 6, "name": "Engaged", "weight": 20},
            },
        }
        client.list_contacts.side_effect = [
            {"total": 5, "contacts": {}},
            {"total": 2, "contacts": {}},
            {"total": 1, "contacts": {}},
        ]
        self._authenticate(self.staff)

        response = self.client.get(self.analytics_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["total_contacts"], 5)
        self.assertEqual(response.data["staged_contacts"], 3)
        self.assertEqual(response.data["unstaged_contacts"], 2)
        self.assertEqual(response.data["staged_percentage"], 60.0)
        self.assertEqual(response.data["unstaged_percentage"], 40.0)
        self.assertEqual(
            [(item["id"], item["count"]) for item in response.data["stages"]],
            [("5", 2), ("6", 1)],
        )
        self.assertEqual(response.data["stages"][0]["percentage"], 40.0)
        self.assertEqual(response.data["stages"][1]["percentage"], 20.0)

        first_stage_count = client.list_contacts.call_args_list[1].kwargs
        second_stage_count = client.list_contacts.call_args_list[2].kwargs
        self.assertEqual(first_stage_count["where[0][col]"], "stage_id")
        self.assertEqual(first_stage_count["where[0][val]"], "5")
        self.assertEqual(second_stage_count["where[0][val]"], "6")

    @patch("newsletter.contact_services.MauticClient")
    def test_stage_analytics_provider_failure_returns_502(self, client_cls):
        client_cls.return_value.list_contacts.side_effect = TemporaryMauticError(
            "Mautic analytics unavailable"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.analytics_url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("unavailable", response.data["detail"])
