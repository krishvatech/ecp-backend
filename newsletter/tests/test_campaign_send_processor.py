from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from newsletter.campaign_send_events import create_campaign_send_event
from newsletter.campaign_send_processor import process_campaign_send_event
from newsletter.campaign_services import CampaignMauticUnavailable
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.models import (
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCategory,
)


User = get_user_model()


@override_settings(
    MAUTIC_SYNC_ENABLED=True,
    MAUTIC_BASE_URL="http://mautic.local",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="secret",
)
class NewsletterCampaignSendProcessorTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            username="newsletter-send-processor-staff",
            email="newsletter-send-processor-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.category = NewsletterCategory.objects.create(
            name="Send Processor Segment",
            slug="send-processor-segment",
            mautic_segment_id="31",
        )
        self.campaign = NewsletterCampaign.objects.create(
            name="Send Processor Draft",
            subject="Send processor subject",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            html_content="<p>Hello send processor</p>",
            plain_text="Hello send processor",
        )
        self.campaign.audiences.set([self.category])
        self.event = create_campaign_send_event(
            self.campaign,
            requested_by=self.staff,
        )

    def refresh(self):
        self.event.refresh_from_db()
        self.campaign.refresh_from_db()

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_to_mautic")
    def test_success_publishes_and_broadcasts_once(self, sync, client_cls):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        sync.return_value = self.campaign
        client = client_cls.return_value
        client.update_email.return_value = {"id": 77}
        client.send_email_to_segments.return_value = {
            "success": 1,
            "sentCount": 4,
            "failedRecipients": [],
        }

        result = process_campaign_send_event(self.event.pk)

        self.refresh()
        self.assertEqual(
            self.event.status,
            NewsletterCampaignSendEvent.Status.SUCCEEDED,
        )
        self.assertEqual(self.event.attempt_count, 1)
        self.assertIsNotNone(self.event.processing_started_at)
        self.assertIsNotNone(self.event.provider_send_started_at)
        self.assertIsNotNone(self.event.completed_at)
        self.assertEqual(self.event.last_error, "")
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.SENT)
        self.assertIsNotNone(self.campaign.send_started_at)
        self.assertIsNotNone(self.campaign.sent_at)
        self.assertEqual(self.campaign.last_error, "")
        self.assertEqual(result["sent_count"], 4)

        sync.assert_called_once_with(self.campaign, actor=self.staff)
        client.update_email.assert_called_once()
        publish_payload = client.update_email.call_args.args[1]
        self.assertIs(publish_payload["isPublished"], True)
        self.assertEqual(publish_payload["lists"], [31])
        client.send_email_to_segments.assert_called_once_with("77", [31])

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_to_mautic")
    def test_successful_event_cannot_send_again(self, sync, client_cls):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        sync.return_value = self.campaign
        client_cls.return_value.send_email_to_segments.return_value = {
            "success": 1,
            "sentCount": 1,
            "failedRecipients": [],
        }

        first = process_campaign_send_event(self.event.pk)
        second = process_campaign_send_event(self.event.pk)

        self.assertTrue(first["processed"])
        self.assertFalse(second["processed"])
        self.assertEqual(
            second["status"],
            NewsletterCampaignSendEvent.Status.SUCCEEDED,
        )
        client_cls.return_value.send_email_to_segments.assert_called_once()

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch(
        "newsletter.campaign_send_processor.sync_campaign_to_mautic",
        side_effect=CampaignMauticUnavailable("Mautic unavailable"),
    )
    def test_sync_failure_before_provider_boundary_is_retry_safe(
        self,
        _sync,
        client_cls,
    ):
        result = process_campaign_send_event(self.event.pk)

        self.refresh()
        self.assertEqual(
            self.event.status,
            NewsletterCampaignSendEvent.Status.FAILED,
        )
        self.assertIsNone(self.event.provider_send_started_at)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.DRAFT)
        self.assertTrue(result["retry_safe"])
        client_cls.assert_not_called()

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_to_mautic")
    def test_publish_failure_before_provider_boundary_is_retry_safe(
        self,
        sync,
        client_cls,
    ):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        sync.return_value = self.campaign
        client_cls.return_value.update_email.side_effect = TemporaryMauticError(
            "publish temporarily unavailable"
        )

        result = process_campaign_send_event(self.event.pk)

        self.refresh()
        self.assertEqual(
            self.event.status,
            NewsletterCampaignSendEvent.Status.FAILED,
        )
        self.assertIsNone(self.event.provider_send_started_at)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.DRAFT)
        self.assertIn("publish temporarily unavailable", self.event.last_error)
        self.assertTrue(result["retry_safe"])
        client_cls.return_value.send_email_to_segments.assert_not_called()

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_to_mautic")
    def test_pre_provider_failed_event_can_retry_same_event(
        self,
        sync,
        client_cls,
    ):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        sync.return_value = self.campaign
        client = client_cls.return_value
        client.update_email.side_effect = [
            TemporaryMauticError("first publish failed"),
            {"id": 77},
        ]
        client.send_email_to_segments.return_value = {
            "success": 1,
            "sentCount": 2,
            "failedRecipients": [],
        }

        first = process_campaign_send_event(self.event.pk)
        second = process_campaign_send_event(self.event.pk)

        self.refresh()
        self.assertTrue(first["retry_safe"])
        self.assertEqual(
            second["status"],
            NewsletterCampaignSendEvent.Status.SUCCEEDED,
        )
        self.assertEqual(self.event.attempt_count, 2)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.SENT)
        self.assertEqual(client.send_email_to_segments.call_count, 1)

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_to_mautic")
    def test_transport_failure_after_provider_boundary_is_terminal(
        self,
        sync,
        client_cls,
    ):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        sync.return_value = self.campaign
        client = client_cls.return_value
        client.update_email.return_value = {"id": 77}
        client.send_email_to_segments.side_effect = TemporaryMauticError(
            "provider response timed out"
        )

        first = process_campaign_send_event(self.event.pk)
        second = process_campaign_send_event(self.event.pk)

        self.refresh()
        self.assertEqual(
            self.event.status,
            NewsletterCampaignSendEvent.Status.FAILED,
        )
        self.assertIsNotNone(self.event.provider_send_started_at)
        self.assertEqual(self.event.attempt_count, 1)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.FAILED)
        self.assertFalse(first["retry_safe"])
        self.assertFalse(second["processed"])
        self.assertEqual(client.send_email_to_segments.call_count, 1)

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_to_mautic")
    def test_permanent_broadcast_failure_is_terminal(
        self,
        sync,
        client_cls,
    ):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        sync.return_value = self.campaign
        client = client_cls.return_value
        client.update_email.return_value = {"id": 77}
        client.send_email_to_segments.side_effect = PermanentMauticError(
            "provider rejected broadcast"
        )

        result = process_campaign_send_event(self.event.pk)

        self.refresh()
        self.assertEqual(
            self.event.status,
            NewsletterCampaignSendEvent.Status.FAILED,
        )
        self.assertIsNotNone(self.event.provider_send_started_at)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.FAILED)
        self.assertIn("provider rejected broadcast", self.campaign.last_error)
        self.assertFalse(result["retry_safe"])

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_to_mautic")
    def test_disabled_sync_does_not_claim_or_call_provider(
        self,
        sync,
        client_cls,
    ):
        result = process_campaign_send_event(self.event.pk)

        self.refresh()
        self.assertFalse(result["processed"])
        self.assertEqual(result["reason"], "mautic_sync_disabled")
        self.assertEqual(
            self.event.status,
            NewsletterCampaignSendEvent.Status.PENDING,
        )
        self.assertEqual(self.event.attempt_count, 0)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.DRAFT)
        sync.assert_not_called()
        client_cls.assert_not_called()

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_to_mautic")
    def test_non_draft_campaign_fails_before_provider_call(
        self,
        sync,
        client_cls,
    ):
        NewsletterCampaign.objects.filter(pk=self.campaign.pk).update(
            status=NewsletterCampaign.Status.CANCELLED
        )

        result = process_campaign_send_event(self.event.pk)

        self.refresh()
        self.assertEqual(
            self.event.status,
            NewsletterCampaignSendEvent.Status.FAILED,
        )
        self.assertIsNone(self.event.provider_send_started_at)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.CANCELLED)
        self.assertTrue(result["processed"])
        sync.assert_not_called()
        client_cls.assert_not_called()

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_to_mautic")
    def test_processing_event_is_not_claimed_twice(self, sync, client_cls):
        NewsletterCampaignSendEvent.objects.filter(pk=self.event.pk).update(
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            processing_started_at=timezone.now(),
        )

        result = process_campaign_send_event(self.event.pk)

        self.assertFalse(result["processed"])
        sync.assert_not_called()
        client_cls.assert_not_called()

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_to_mautic")
    def test_stale_pre_provider_processing_event_can_be_recovered(
        self,
        sync,
        client_cls,
    ):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        sync.return_value = self.campaign
        client = client_cls.return_value
        client.update_email.return_value = {"id": 77}
        client.send_email_to_segments.return_value = {
            "success": 1,
            "sentCount": 1,
            "failedRecipients": [],
        }
        NewsletterCampaignSendEvent.objects.filter(pk=self.event.pk).update(
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            processing_started_at=timezone.now() - timedelta(minutes=20),
        )

        result = process_campaign_send_event(self.event.pk)

        self.refresh()
        self.assertTrue(result["processed"])
        self.assertEqual(
            self.event.status,
            NewsletterCampaignSendEvent.Status.SUCCEEDED,
        )
        self.assertEqual(self.event.attempt_count, 1)
        client.send_email_to_segments.assert_called_once_with("77", [31])

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_to_mautic")
    def test_stale_post_provider_processing_event_is_never_recovered(
        self,
        sync,
        client_cls,
    ):
        old_time = timezone.now() - timedelta(minutes=20)
        NewsletterCampaignSendEvent.objects.filter(pk=self.event.pk).update(
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            processing_started_at=old_time,
            provider_send_started_at=old_time,
        )
        NewsletterCampaign.objects.filter(pk=self.campaign.pk).update(
            status=NewsletterCampaign.Status.SENDING,
            send_started_at=old_time,
        )

        result = process_campaign_send_event(self.event.pk)

        self.assertFalse(result["processed"])
        sync.assert_not_called()
        client_cls.assert_not_called()
