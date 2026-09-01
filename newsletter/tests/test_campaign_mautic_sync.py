from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.campaign_services import (
    CampaignMauticSyncFailed,
    CampaignMauticUnavailable,
    CampaignMauticValidationError,
    sync_campaign_to_mautic,
    validate_campaign_for_mautic_sync,
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
class CampaignMauticSyncServiceTests(TestCase):
    def setUp(self):
        self.actor = User.objects.create_user(
            username="campaign-sync-staff",
            email="campaign-sync-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.category = NewsletterCategory.objects.create(
            name="Campaign Sync Segment",
            slug="campaign-sync-segment",
            mautic_segment_id="31",
        )
        self.campaign = NewsletterCampaign.objects.create(
            name="Campaign Sync Draft",
            subject="Campaign sync subject",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            html_content="<p>Hello</p>",
            plain_text="Hello",
        )
        self.campaign.audiences.set([self.category])

    def test_validation_accepts_complete_draft(self):
        audiences = validate_campaign_for_mautic_sync(self.campaign)

        self.assertEqual([category.pk for category in audiences], [self.category.pk])

    def test_validation_rejects_non_draft_campaign(self):
        self.campaign.status = NewsletterCampaign.Status.SCHEDULED
        self.campaign.save(update_fields=["status"])

        with self.assertRaises(CampaignMauticValidationError):
            validate_campaign_for_mautic_sync(self.campaign)

    def test_validation_rejects_missing_required_fields(self):
        cases = (
            ("name", "", "name"),
            ("subject", "", "subject"),
            ("from_name", "", "sender name"),
            ("from_email", "", "sender email"),
        )

        for field, value, message in cases:
            with self.subTest(field=field):
                original = getattr(self.campaign, field)
                setattr(self.campaign, field, value)
                with self.assertRaisesRegex(CampaignMauticValidationError, message):
                    validate_campaign_for_mautic_sync(self.campaign)
                setattr(self.campaign, field, original)

    def test_validation_rejects_invalid_sender_email(self):
        self.campaign.from_email = "not-an-email"

        with self.assertRaisesRegex(CampaignMauticValidationError, "must be valid"):
            validate_campaign_for_mautic_sync(self.campaign)

    def test_validation_rejects_missing_content(self):
        self.campaign.html_content = " "
        self.campaign.plain_text = ""

        with self.assertRaisesRegex(CampaignMauticValidationError, "content"):
            validate_campaign_for_mautic_sync(self.campaign)

    def test_validation_rejects_missing_audience(self):
        self.campaign.audiences.clear()

        with self.assertRaisesRegex(CampaignMauticValidationError, "At least one"):
            validate_campaign_for_mautic_sync(self.campaign)

    def test_validation_rejects_inactive_audience(self):
        self.category.is_active = False
        self.category.save(update_fields=["is_active"])

        with self.assertRaisesRegex(CampaignMauticValidationError, "inactive"):
            validate_campaign_for_mautic_sync(self.campaign)

    def test_validation_rejects_unmapped_audience(self):
        self.category.mautic_segment_id = ""
        self.category.save(update_fields=["mautic_segment_id"])

        with self.assertRaisesRegex(CampaignMauticValidationError, "not mapped"):
            validate_campaign_for_mautic_sync(self.campaign)

    @patch("newsletter.campaign_services.MauticClient")
    def test_first_sync_creates_draft_and_stores_mautic_id(self, client_cls):
        client = client_cls.return_value
        client.create_email.return_value = {"id": 77}

        synced = sync_campaign_to_mautic(self.campaign, actor=self.actor)

        synced.refresh_from_db()
        self.assertEqual(synced.mautic_email_id, "77")
        self.assertIsNotNone(synced.last_synced_to_mautic_at)
        self.assertEqual(synced.last_error, "")
        self.assertEqual(synced.status, NewsletterCampaign.Status.DRAFT)
        self.assertEqual(synced.updated_by, self.actor)
        client.create_email.assert_called_once()
        client.update_email.assert_not_called()
        payload = client.create_email.call_args.args[0]
        self.assertEqual(payload["lists"], [31])
        self.assertEqual(payload["emailType"], "list")
        self.assertIs(payload["isPublished"], False)

    @patch("newsletter.campaign_services.MauticClient")
    def test_repeat_sync_updates_same_mautic_email(self, client_cls):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        client = client_cls.return_value
        client.update_email.return_value = {"id": 77}

        synced = sync_campaign_to_mautic(self.campaign, actor=self.actor)

        synced.refresh_from_db()
        self.assertEqual(synced.mautic_email_id, "77")
        client.update_email.assert_called_once()
        self.assertEqual(client.update_email.call_args.args[0], "77")
        client.create_email.assert_not_called()

    @patch("newsletter.campaign_services.MauticClient")
    def test_create_failure_records_error_without_false_success(self, client_cls):
        client_cls.return_value.create_email.side_effect = TemporaryMauticError(
            "provider temporarily unavailable"
        )

        with self.assertRaises(CampaignMauticUnavailable):
            sync_campaign_to_mautic(self.campaign, actor=self.actor)

        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.mautic_email_id, "")
        self.assertIsNone(self.campaign.last_synced_to_mautic_at)
        self.assertIn("temporarily unavailable", self.campaign.last_error)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.DRAFT)

    @patch("newsletter.campaign_services.MauticClient")
    def test_update_failure_preserves_existing_mapping_and_timestamp(self, client_cls):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        original_timestamp = self.campaign.last_synced_to_mautic_at
        client_cls.return_value.update_email.side_effect = PermanentMauticError(
            "provider rejected update"
        )

        with self.assertRaises(CampaignMauticSyncFailed):
            sync_campaign_to_mautic(self.campaign, actor=self.actor)

        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.mautic_email_id, "77")
        self.assertEqual(self.campaign.last_synced_to_mautic_at, original_timestamp)
        self.assertIn("provider rejected update", self.campaign.last_error)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.DRAFT)

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    @patch("newsletter.campaign_services.MauticClient")
    def test_disabled_flag_does_not_construct_mautic_client(self, client_cls):
        with self.assertRaisesRegex(CampaignMauticUnavailable, "disabled"):
            sync_campaign_to_mautic(self.campaign, actor=self.actor)

        client_cls.assert_not_called()


@override_settings(
    MAUTIC_SYNC_ENABLED=True,
    MAUTIC_BASE_URL="http://mautic.local",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="secret",
)
class CampaignMauticSyncAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.normal_user = User.objects.create_user(
            username="campaign-sync-normal",
            email="campaign-sync-normal@example.test",
            password="test-password",
        )
        self.staff = User.objects.create_user(
            username="campaign-sync-api-staff",
            email="campaign-sync-api-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.superuser = User.objects.create_superuser(
            username="campaign-sync-api-super",
            email="campaign-sync-api-super@example.test",
            password="test-password",
        )
        self.category = NewsletterCategory.objects.create(
            name="Campaign Sync API Segment",
            slug="campaign-sync-api-segment",
            mautic_segment_id="44",
        )
        self.campaign = NewsletterCampaign.objects.create(
            name="Campaign Sync API Draft",
            subject="Campaign sync API subject",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            html_content="<p>Hello</p>",
        )
        self.campaign.audiences.set([self.category])
        self.url = reverse("newsletter-admin-campaign-sync", args=[self.campaign.uuid])

    def test_guest_and_normal_user_are_denied(self):
        guest = self.client.post(self.url, format="json")
        self.assertIn(guest.status_code, (401, 403))

        self.client.force_authenticate(user=self.normal_user)
        normal = self.client.post(self.url, format="json")
        self.assertEqual(normal.status_code, 403)

    @patch("newsletter.campaign_services.MauticClient")
    def test_staff_and_superuser_can_sync(self, client_cls):
        client_cls.return_value.create_email.return_value = {"id": 88}

        for index, user in enumerate((self.staff, self.superuser), start=1):
            campaign = NewsletterCampaign.objects.create(
                name=f"Role Draft {index}",
                subject="Role subject",
                from_name="IMAA Connect",
                from_email="newsletter@example.test",
                html_content="<p>Hello</p>",
            )
            campaign.audiences.set([self.category])
            url = reverse("newsletter-admin-campaign-sync", args=[campaign.uuid])
            self.client.force_authenticate(user=user)

            response = self.client.post(url, format="json")

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data["mautic_email_id"], "88")
            self.assertEqual(response.data["status"], "draft")

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    @patch("newsletter.campaign_services.MauticClient")
    def test_disabled_sync_returns_503_without_provider_call(self, client_cls):
        self.client.force_authenticate(user=self.staff)

        response = self.client.post(self.url, format="json")

        self.assertEqual(response.status_code, 503)
        self.assertIn("disabled", str(response.data["detail"]).lower())
        client_cls.assert_not_called()

    @patch("newsletter.campaign_services.MauticClient")
    def test_sync_validation_error_returns_400(self, client_cls):
        self.campaign.subject = ""
        self.campaign.save(update_fields=["subject"])
        self.client.force_authenticate(user=self.staff)

        response = self.client.post(self.url, format="json")

        self.assertEqual(response.status_code, 400)
        client_cls.assert_not_called()
