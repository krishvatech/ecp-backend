from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.campaign_services import (
    CampaignMauticDeleteFailed,
    CampaignMauticUnavailable,
    CampaignNotEditable,
    delete_draft_campaign,
)
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.models import NewsletterCampaign


User = get_user_model()


@override_settings(
    MAUTIC_SYNC_ENABLED=True,
    MAUTIC_BASE_URL="http://mautic.local",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="secret",
)
class CampaignMauticDeleteServiceTests(TestCase):
    def test_local_only_draft_delete_does_not_contact_mautic(self):
        campaign = NewsletterCampaign.objects.create(name="Local Draft")

        with patch("newsletter.campaign_services.MauticClient") as client_cls:
            delete_draft_campaign(campaign)

        client_cls.assert_not_called()
        self.assertFalse(
            NewsletterCampaign.objects.filter(pk=campaign.pk).exists()
        )

    @patch("newsletter.campaign_services.MauticClient")
    def test_linked_draft_deletes_mautic_first_then_local(self, client_cls):
        campaign = NewsletterCampaign.objects.create(
            name="Linked Draft",
            mautic_email_id="91",
        )
        client_cls.return_value.delete_email.return_value = {"id": 91}

        delete_draft_campaign(campaign)

        client_cls.return_value.delete_email.assert_called_once_with("91")
        self.assertFalse(
            NewsletterCampaign.objects.filter(pk=campaign.pk).exists()
        )

    @patch("newsletter.campaign_services.MauticClient")
    def test_temporary_mautic_failure_keeps_campaign(self, client_cls):
        campaign = NewsletterCampaign.objects.create(
            name="Temporary Failure",
            mautic_email_id="92",
        )
        client_cls.return_value.delete_email.side_effect = TemporaryMauticError(
            "provider temporarily unavailable"
        )

        with self.assertRaises(CampaignMauticUnavailable):
            delete_draft_campaign(campaign)

        campaign.refresh_from_db()
        self.assertEqual(campaign.mautic_email_id, "92")
        self.assertIn("temporarily unavailable", campaign.last_error)

    @patch("newsletter.campaign_services.MauticClient")
    def test_permanent_mautic_failure_keeps_campaign(self, client_cls):
        campaign = NewsletterCampaign.objects.create(
            name="Permanent Failure",
            mautic_email_id="93",
        )
        client_cls.return_value.delete_email.side_effect = PermanentMauticError(
            "provider rejected deletion"
        )

        with self.assertRaises(CampaignMauticDeleteFailed):
            delete_draft_campaign(campaign)

        campaign.refresh_from_db()
        self.assertEqual(campaign.mautic_email_id, "93")
        self.assertIn("provider rejected deletion", campaign.last_error)

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    @patch("newsletter.campaign_services.MauticClient")
    def test_disabled_sync_keeps_linked_campaign_without_provider_call(
        self,
        client_cls,
    ):
        campaign = NewsletterCampaign.objects.create(
            name="Disabled Delete",
            mautic_email_id="94",
        )

        with self.assertRaisesRegex(CampaignMauticUnavailable, "disabled"):
            delete_draft_campaign(campaign)

        client_cls.assert_not_called()
        self.assertTrue(
            NewsletterCampaign.objects.filter(pk=campaign.pk).exists()
        )

    @patch("newsletter.campaign_services.MauticClient")
    def test_non_draft_is_rejected_before_provider_call(self, client_cls):
        campaign = NewsletterCampaign.objects.create(
            name="Scheduled",
            status=NewsletterCampaign.Status.SCHEDULED,
            mautic_email_id="95",
        )

        with self.assertRaises(CampaignNotEditable):
            delete_draft_campaign(campaign)

        client_cls.assert_not_called()
        self.assertTrue(
            NewsletterCampaign.objects.filter(pk=campaign.pk).exists()
        )


@override_settings(
    MAUTIC_SYNC_ENABLED=True,
    MAUTIC_BASE_URL="http://mautic.local",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="secret",
)
class CampaignMauticDeleteAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="campaign-delete-staff",
            email="campaign-delete-staff@example.test",
            password="test-password",
            is_staff=True,
        )

    def _delete_url(self, campaign):
        return reverse("newsletter-admin-campaign-detail", args=[campaign.uuid])

    @patch("newsletter.campaign_services.MauticClient")
    def test_linked_draft_api_delete_removes_remote_then_local(self, client_cls):
        campaign = NewsletterCampaign.objects.create(
            name="API Linked Draft",
            mautic_email_id="101",
        )
        client_cls.return_value.delete_email.return_value = {"id": 101}
        self.client.force_authenticate(user=self.staff)

        response = self.client.delete(self._delete_url(campaign))

        self.assertEqual(response.status_code, 204)
        client_cls.return_value.delete_email.assert_called_once_with("101")
        self.assertFalse(
            NewsletterCampaign.objects.filter(pk=campaign.pk).exists()
        )

    @patch("newsletter.campaign_services.MauticClient")
    def test_provider_failure_returns_502_and_keeps_campaign(self, client_cls):
        campaign = NewsletterCampaign.objects.create(
            name="API Failed Delete",
            mautic_email_id="102",
        )
        client_cls.return_value.delete_email.side_effect = PermanentMauticError(
            "provider rejected deletion"
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.delete(self._delete_url(campaign))

        self.assertEqual(response.status_code, 502)
        self.assertTrue(
            NewsletterCampaign.objects.filter(pk=campaign.pk).exists()
        )

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    @patch("newsletter.campaign_services.MauticClient")
    def test_disabled_sync_returns_503_and_keeps_linked_campaign(
        self,
        client_cls,
    ):
        campaign = NewsletterCampaign.objects.create(
            name="API Disabled Delete",
            mautic_email_id="103",
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.delete(self._delete_url(campaign))

        self.assertEqual(response.status_code, 503)
        client_cls.assert_not_called()
        self.assertTrue(
            NewsletterCampaign.objects.filter(pk=campaign.pk).exists()
        )
