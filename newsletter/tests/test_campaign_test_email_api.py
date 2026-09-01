from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.campaign_services import (
    CampaignMauticUnavailable,
    CampaignMauticValidationError,
)
from newsletter.models import NewsletterCampaign


User = get_user_model()


class NewsletterAdminCampaignTestEmailAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.normal_user = User.objects.create_user(
            username="newsletter-test-api-normal",
            email="newsletter-test-api-normal@example.test",
            password="test-password",
        )
        self.staff = User.objects.create_user(
            username="newsletter-test-api-staff",
            email="newsletter-test-api-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.superuser = User.objects.create_superuser(
            username="newsletter-test-api-superuser",
            email="newsletter-test-api-superuser@example.test",
            password="test-password",
        )
        self.campaign = NewsletterCampaign.objects.create(name="Test Email API")
        self.url = reverse(
            "newsletter-admin-campaign-test-email",
            args=[self.campaign.uuid],
        )

    def test_guest_and_normal_user_are_denied(self):
        guest = self.client.post(
            self.url,
            {"email": "test@example.com"},
            format="json",
        )
        self.assertIn(guest.status_code, (401, 403))

        self.client.force_authenticate(user=self.normal_user)
        response = self.client.post(
            self.url,
            {"email": "test@example.com"},
            format="json",
        )
        self.assertEqual(response.status_code, 403)

    @patch("newsletter.admin_views.send_campaign_test_email")
    def test_staff_can_send_test_email(self, send_mock):
        send_mock.return_value = {
            "recipient_email": "test@example.com",
            "contact_id": "51",
            "temporary_contact": True,
        }
        self.client.force_authenticate(user=self.staff)

        response = self.client.post(
            self.url,
            {"email": "test@example.com"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data,
            {
                "success": True,
                "recipient_email": "test@example.com",
            },
        )
        send_mock.assert_called_once_with(
            self.campaign,
            "test@example.com",
            actor=self.staff,
        )
        self.assertNotIn("contact_id", response.data)
        self.assertNotIn("temporary_contact", response.data)

    @patch("newsletter.admin_views.send_campaign_test_email")
    def test_superuser_can_send_test_email(self, send_mock):
        send_mock.return_value = {
            "recipient_email": "admin-test@example.com",
            "contact_id": "52",
            "temporary_contact": False,
        }
        self.client.force_authenticate(user=self.superuser)

        response = self.client.post(
            self.url,
            {"email": "admin-test@example.com"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        send_mock.assert_called_once_with(
            self.campaign,
            "admin-test@example.com",
            actor=self.superuser,
        )

    @patch("newsletter.admin_views.send_campaign_test_email")
    def test_invalid_or_missing_email_is_rejected_before_service(self, send_mock):
        self.client.force_authenticate(user=self.staff)

        for payload in ({}, {"email": ""}, {"email": "not-an-email"}):
            with self.subTest(payload=payload):
                response = self.client.post(self.url, payload, format="json")
                self.assertEqual(response.status_code, 400)

        send_mock.assert_not_called()

    @patch("newsletter.admin_views.send_campaign_test_email")
    def test_service_validation_error_is_returned_as_400(self, send_mock):
        send_mock.side_effect = CampaignMauticValidationError(
            "Campaign subject is required before Mautic sync."
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.post(
            self.url,
            {"email": "test@example.com"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)

    @patch("newsletter.admin_views.send_campaign_test_email")
    def test_service_unavailable_is_returned_as_503(self, send_mock):
        send_mock.side_effect = CampaignMauticUnavailable(
            "Mautic newsletter test email is temporarily unavailable."
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.post(
            self.url,
            {"email": "test@example.com"},
            format="json",
        )

        self.assertEqual(response.status_code, 503)

    @patch("newsletter.admin_views.send_campaign_test_email")
    def test_missing_campaign_returns_404_without_send(self, send_mock):
        missing = NewsletterCampaign.objects.create(name="Temporary")
        missing_uuid = missing.uuid
        missing.delete()
        self.client.force_authenticate(user=self.staff)

        response = self.client.post(
            reverse(
                "newsletter-admin-campaign-test-email",
                args=[missing_uuid],
            ),
            {"email": "test@example.com"},
            format="json",
        )

        self.assertEqual(response.status_code, 404)
        send_mock.assert_not_called()
