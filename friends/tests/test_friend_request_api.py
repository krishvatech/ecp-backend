from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from friends.models import FriendRequest


User = get_user_model()


class FriendRequestCreateApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.sender = User.objects.create_user(
            username="sender",
            email="sender@example.com",
            password="pass123",
        )
        self.recipient = User.objects.create_user(
            username="recipient",
            email="recipient@example.com",
            password="pass123",
        )
        self.client.force_authenticate(self.sender)
        self.url = reverse("friend-requests-list")

    def test_valid_user_id_creates_pending_request(self):
        response = self.client.post(self.url, {"to_user": self.recipient.id}, format="json")

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["status"], "outgoing_pending")
        self.assertTrue(
            FriendRequest.objects.filter(
                from_user=self.sender,
                to_user=self.recipient,
                status=FriendRequest.PENDING,
            ).exists()
        )

    def test_duplicate_pending_request_returns_serializer_detail(self):
        FriendRequest.objects.create(from_user=self.sender, to_user=self.recipient)

        response = self.client.post(self.url, {"to_user": self.recipient.id}, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["detail"], "You already sent a contact request to this user.")

    def test_self_request_returns_serializer_detail(self):
        response = self.client.post(self.url, {"to_user": self.sender.id}, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["detail"], "You cannot send a request to yourself.")

    def test_invalid_user_returns_serializer_field_details(self):
        response = self.client.post(self.url, {"to_user": 999999}, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertIn("to_user", response.data)
        self.assertEqual(response.data["to_user"][0], "Invalid user.")
