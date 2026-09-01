from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from newsletter.campaign_services import (
    CampaignMauticTestEmailFailed,
    CampaignMauticUnavailable,
    CampaignMauticValidationError,
    send_campaign_test_email,
)
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.models import NewsletterCampaign, NewsletterCategory


User = get_user_model()


@override_settings(
    MAUTIC_SYNC_ENABLED=True,
    MAUTIC_BASE_URL="http://mautic.local",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="secret",
)
class CampaignTestEmailServiceTests(TestCase):
    def setUp(self):
        self.actor = User.objects.create_user(
            username="newsletter-test-email-staff",
            email="newsletter-test-email-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.category = NewsletterCategory.objects.get(slug="imaa-events")
        self.campaign = NewsletterCampaign.objects.create(
            name="Test Email Campaign",
            subject="Test Email Subject",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            html_content="<p>Test email</p>",
            plain_text="Test email",
            mautic_email_id="44",
        )
        self.campaign.audiences.set([self.category])

    @patch("newsletter.campaign_services.sync_campaign_to_mautic")
    @patch("newsletter.campaign_services.MauticClient")
    def test_existing_contact_is_reused_without_create_or_delete(
        self,
        client_cls,
        sync_mock,
    ):
        sync_mock.return_value = self.campaign
        client = client_cls.return_value
        client.find_contact_by_email.return_value = {"id": 51}
        client.send_email_to_contact.return_value = {"success": True}

        result = send_campaign_test_email(
            self.campaign,
            " TEST@EXAMPLE.COM ",
            actor=self.actor,
        )

        sync_mock.assert_called_once_with(self.campaign, actor=self.actor)
        client.find_contact_by_email.assert_called_once_with("test@example.com")
        client.create_contact.assert_not_called()
        client.send_email_to_contact.assert_called_once_with("44", "51")
        client.delete_contact.assert_not_called()
        self.assertEqual(result["recipient_email"], "test@example.com")
        self.assertFalse(result["temporary_contact"])

    @patch("newsletter.campaign_services.sync_campaign_to_mautic")
    @patch("newsletter.campaign_services.MauticClient")
    def test_missing_contact_is_created_sent_and_cleaned_up(
        self,
        client_cls,
        sync_mock,
    ):
        sync_mock.return_value = self.campaign
        client = client_cls.return_value
        client.find_contact_by_email.return_value = None
        client.create_contact.return_value = {"id": 52}
        client.send_email_to_contact.return_value = {"success": True}

        result = send_campaign_test_email(
            self.campaign,
            "new-test@example.com",
            actor=self.actor,
        )

        client.create_contact.assert_called_once_with(
            {"email": "new-test@example.com"}
        )
        client.send_email_to_contact.assert_called_once_with("44", "52")
        client.delete_contact.assert_called_once_with("52")
        self.assertTrue(result["temporary_contact"])

    @patch("newsletter.campaign_services.sync_campaign_to_mautic")
    @patch("newsletter.campaign_services.MauticClient")
    def test_temporary_send_failure_records_error_and_cleans_up(
        self,
        client_cls,
        sync_mock,
    ):
        sync_mock.return_value = self.campaign
        client = client_cls.return_value
        client.find_contact_by_email.return_value = None
        client.create_contact.return_value = {"id": 53}
        client.send_email_to_contact.side_effect = TemporaryMauticError(
            "provider temporarily unavailable"
        )

        with self.assertRaises(CampaignMauticUnavailable):
            send_campaign_test_email(
                self.campaign,
                "temporary@example.com",
                actor=self.actor,
            )

        client.delete_contact.assert_called_once_with("53")
        self.campaign.refresh_from_db()
        self.assertIn("temporarily unavailable", self.campaign.last_error)

    @patch("newsletter.campaign_services.sync_campaign_to_mautic")
    @patch("newsletter.campaign_services.MauticClient")
    def test_permanent_send_failure_records_error_and_cleans_up(
        self,
        client_cls,
        sync_mock,
    ):
        sync_mock.return_value = self.campaign
        client = client_cls.return_value
        client.find_contact_by_email.return_value = None
        client.create_contact.return_value = {"id": 54}
        client.send_email_to_contact.side_effect = PermanentMauticError(
            "provider rejected send"
        )

        with self.assertRaises(CampaignMauticTestEmailFailed):
            send_campaign_test_email(
                self.campaign,
                "permanent@example.com",
                actor=self.actor,
            )

        client.delete_contact.assert_called_once_with("54")
        self.campaign.refresh_from_db()
        self.assertIn("provider rejected send", self.campaign.last_error)

    @patch("newsletter.campaign_services.sync_campaign_to_mautic")
    @patch("newsletter.campaign_services.MauticClient")
    def test_cleanup_failure_does_not_turn_successful_send_into_retry(
        self,
        client_cls,
        sync_mock,
    ):
        sync_mock.return_value = self.campaign
        client = client_cls.return_value
        client.find_contact_by_email.return_value = None
        client.create_contact.return_value = {"id": 55}
        client.send_email_to_contact.return_value = {"success": True}
        client.delete_contact.side_effect = TemporaryMauticError(
            "cleanup unavailable"
        )

        result = send_campaign_test_email(
            self.campaign,
            "cleanup-warning@example.com",
            actor=self.actor,
        )

        self.assertEqual(result["contact_id"], "55")
        self.assertTrue(result["temporary_contact"])

    @patch("newsletter.campaign_services.sync_campaign_to_mautic")
    @patch("newsletter.campaign_services.MauticClient")
    def test_invalid_recipient_is_rejected_before_sync_or_provider(
        self,
        client_cls,
        sync_mock,
    ):
        with self.assertRaises(CampaignMauticValidationError):
            send_campaign_test_email(
                self.campaign,
                "not-an-email",
                actor=self.actor,
            )

        sync_mock.assert_not_called()
        client_cls.assert_not_called()
