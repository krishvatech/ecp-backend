from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.models import (
    MauticContactMapping,
    NewsletterCampaign,
    NewsletterSubscription,
    NewsletterSyncEvent,
)


User = get_user_model()


class NewsletterAdminCampaignPreviewAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.normal_user = User.objects.create_user(
            username="newsletter-preview-normal",
            email="newsletter-preview-normal@example.test",
            password="test-password",
        )
        self.staff = User.objects.create_user(
            username="newsletter-preview-staff",
            email="newsletter-preview-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.superuser = User.objects.create_superuser(
            username="newsletter-preview-superuser",
            email="newsletter-preview-superuser@example.test",
            password="test-password",
        )
        self.campaign = NewsletterCampaign.objects.create(
            name="Preview Campaign",
            subject="Preview Subject",
            preview_text="Preview preheader",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            html_content="<p>Preview HTML</p>",
            plain_text="Preview plain text",
        )
        self.url = reverse(
            "newsletter-admin-campaign-preview",
            args=[self.campaign.uuid],
        )

    def test_guest_and_normal_user_are_denied(self):
        guest_response = self.client.get(self.url)
        self.assertIn(guest_response.status_code, (401, 403))

        self.client.force_authenticate(user=self.normal_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_staff_and_superuser_can_preview_campaign(self):
        for user in (self.staff, self.superuser):
            with self.subTest(user=user.email):
                self.client.force_authenticate(user=user)
                response = self.client.get(self.url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.data,
                    {
                        "name": "Preview Campaign",
                        "subject": "Preview Subject",
                        "preview_text": "Preview preheader",
                        "from_name": "IMAA Connect",
                        "from_email": "newsletter@example.test",
                        "html_content": "<p>Preview HTML</p>",
                        "plain_text": "Preview plain text",
                        "status": NewsletterCampaign.Status.DRAFT,
                    },
                )

    def test_preview_does_not_require_audience_or_mautic_sync(self):
        self.assertEqual(self.campaign.audiences.count(), 0)
        before = {
            "events": NewsletterSyncEvent.objects.count(),
            "subscriptions": NewsletterSubscription.objects.count(),
            "mappings": MauticContactMapping.objects.count(),
        }
        self.client.force_authenticate(user=self.staff)

        with patch("newsletter.admin_views.sync_campaign_to_mautic") as sync_mock:
            response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        sync_mock.assert_not_called()
        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.DRAFT)
        self.assertEqual(self.campaign.mautic_email_id, "")
        self.assertIsNone(self.campaign.last_synced_to_mautic_at)
        after = {
            "events": NewsletterSyncEvent.objects.count(),
            "subscriptions": NewsletterSubscription.objects.count(),
            "mappings": MauticContactMapping.objects.count(),
        }
        self.assertEqual(after, before)

    def test_missing_campaign_returns_404(self):
        missing = NewsletterCampaign.objects.create(name="Temporary")
        missing_uuid = missing.uuid
        missing.delete()
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(
            reverse("newsletter-admin-campaign-preview", args=[missing_uuid])
        )

        self.assertEqual(response.status_code, 404)
