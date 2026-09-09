from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient


User = get_user_model()


class NewsletterAdminPointGroupAssignmentAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="point-group-assignment-staff",
            email="point-group-assignment-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.point_list_url = reverse(
            "newsletter-admin-point-action-list"
        )
        self.point_detail_url = reverse(
            "newsletter-admin-point-action-detail",
            args=["5"],
        )
        self.trigger_list_url = reverse(
            "newsletter-admin-point-trigger-list"
        )
        self.trigger_detail_url = reverse(
            "newsletter-admin-point-trigger-detail",
            args=["4"],
        )
        self.client.force_authenticate(user=self.staff)

    @staticmethod
    def _point():
        return {
            "id": 5,
            "name": "Grouped Point Action",
            "description": "",
            "type": "email.open",
            "delta": 2,
            "repeatable": False,
            "isPublished": False,
            "properties": {},
            "group": None,
        }

    @staticmethod
    def _trigger():
        return {
            "id": 4,
            "name": "Grouped Point Trigger",
            "description": "",
            "points": 25,
            "color": "a0acb8",
            "triggerExistingLeads": False,
            "isPublished": False,
            "events": [],
            "group": None,
        }

    @patch("newsletter.point_views.MauticClient")
    def test_point_action_create_accepts_group_assignment(
        self,
        client_cls,
    ):
        client = client_cls.return_value
        client.get_point_group.return_value = {
            "id": 7,
            "name": "Engagement",
        }
        client.list_point_action_types.return_value = {
            "email.open": "Opens an email"
        }
        client.create_point_action.return_value = self._point()

        response = self.client.post(
            self.point_list_url,
            {
                "name": "Grouped Point Action",
                "type": "email.open",
                "delta": 2,
                "group": 7,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        client.get_point_group.assert_called_once_with("7")
        client.create_point_action.assert_called_once_with(
            {
                "name": "Grouped Point Action",
                "type": "email.open",
                "delta": 2,
                "group": "7",
            }
        )

    @patch("newsletter.point_views.MauticClient")
    def test_point_action_update_can_reassign_group(
        self,
        client_cls,
    ):
        client = client_cls.return_value
        client.list_point_action_types.return_value = {
            "email.open": "Opens an email"
        }
        client.get_point_group.return_value = {
            "id": 8,
            "name": "Intent",
        }
        client.update_point_action.return_value = self._point()

        response = self.client.patch(
            self.point_detail_url,
            {"group": "8"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        client.get_point_group.assert_called_once_with("8")
        client.update_point_action.assert_called_once_with(
            "5",
            {"group": "8"},
        )

    @patch("newsletter.point_views.MauticClient")
    def test_point_action_update_can_clear_group(
        self,
        client_cls,
    ):
        client = client_cls.return_value
        client.list_point_action_types.return_value = {
            "email.open": "Opens an email"
        }
        client.update_point_action.return_value = self._point()

        response = self.client.patch(
            self.point_detail_url,
            {"group": ""},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        client.get_point_group.assert_not_called()
        client.update_point_action.assert_called_once_with(
            "5",
            {"group": ""},
        )

    @patch("newsletter.point_views.MauticClient")
    def test_point_action_rejects_invalid_group_id(
        self,
        client_cls,
    ):
        response = self.client.post(
            self.point_list_url,
            {
                "name": "Grouped Point Action",
                "type": "email.open",
                "delta": 2,
                "group": "not-a-group",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "positive integer",
            response.data["detail"],
        )
        client_cls.assert_not_called()

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_trigger_create_accepts_group_assignment(
        self,
        client_cls,
    ):
        client = client_cls.return_value
        client.get_point_group.return_value = {
            "id": 7,
            "name": "Engagement",
        }
        client.create_point_trigger.return_value = self._trigger()
        client.list_point_trigger_event_types.return_value = {}

        response = self.client.post(
            self.trigger_list_url,
            {
                "name": "Grouped Point Trigger",
                "points": 25,
                "color": "a0acb8",
                "triggerExistingLeads": False,
                "isPublished": False,
                "group": 7,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        client.get_point_group.assert_called_once_with("7")
        client.create_point_trigger.assert_called_once_with(
            {
                "name": "Grouped Point Trigger",
                "points": 25,
                "color": "a0acb8",
                "triggerExistingLeads": False,
                "isPublished": False,
                "group": "7",
            }
        )

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_trigger_create_allows_no_group(
        self,
        client_cls,
    ):
        client = client_cls.return_value
        client.create_point_trigger.return_value = self._trigger()
        client.list_point_trigger_event_types.return_value = {}

        response = self.client.post(
            self.trigger_list_url,
            {
                "name": "Ungrouped Point Trigger",
                "points": 25,
                "group": "",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        client.get_point_group.assert_not_called()
        client.create_point_trigger.assert_called_once_with(
            {
                "name": "Ungrouped Point Trigger",
                "points": 25,
            }
        )

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_trigger_update_can_reassign_group(
        self,
        client_cls,
    ):
        client = client_cls.return_value
        client.get_point_group.return_value = {
            "id": 8,
            "name": "Intent",
        }
        client.update_point_trigger.return_value = self._trigger()
        client.list_point_trigger_event_types.return_value = {}

        response = self.client.patch(
            self.trigger_detail_url,
            {"group": 8},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        client.get_point_group.assert_called_once_with("8")
        client.update_point_trigger.assert_called_once_with(
            "4",
            {"group": "8"},
        )

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_trigger_update_rejects_empty_group_clear(
        self,
        client_cls,
    ):
        response = self.client.patch(
            self.trigger_detail_url,
            {"group": ""},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "cannot clear",
            response.data["detail"],
        )
        client_cls.assert_not_called()

    @patch("newsletter.point_trigger_views.MauticClient")
    def test_trigger_update_rejects_null_group_clear(
        self,
        client_cls,
    ):
        response = self.client.patch(
            self.trigger_detail_url,
            {"group": None},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "cannot clear",
            response.data["detail"],
        )
        client_cls.assert_not_called()
