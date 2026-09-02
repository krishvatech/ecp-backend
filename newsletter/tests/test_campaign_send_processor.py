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
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
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
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
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
        "newsletter.campaign_send_processor.sync_campaign_for_worker_delivery",
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
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
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
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
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
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
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
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
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
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
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
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
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
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
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
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
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
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
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

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
    def test_scheduled_campaign_can_send_successfully(self, sync, client_cls):
        scheduled = NewsletterCampaign.objects.create(
            name="Scheduled Processor",
            subject="Scheduled processor subject",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            html_content="<p>Scheduled body</p>",
            plain_text="Scheduled body",
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at=timezone.now() - timedelta(minutes=1),
        )
        scheduled.audiences.set([self.category])
        event = NewsletterCampaignSendEvent.objects.create(
            campaign=scheduled,
            requested_by=self.staff,
            idempotency_key=f"mautic:newsletter:campaign:{scheduled.uuid}:send",
        )
        scheduled.mautic_email_id = "88"
        scheduled.save(update_fields=["mautic_email_id"])
        sync.return_value = scheduled
        client = client_cls.return_value
        client.update_email.return_value = {"id": 88}
        client.send_email_to_segments.return_value = {
            "success": 1,
            "sentCount": 3,
            "failedRecipients": [],
        }

        result = process_campaign_send_event(event.pk)

        event.refresh_from_db()
        scheduled.refresh_from_db()
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.SUCCEEDED)
        self.assertEqual(scheduled.status, NewsletterCampaign.Status.SENT)
        self.assertIsNotNone(scheduled.send_started_at)
        self.assertIsNotNone(scheduled.sent_at)
        self.assertIsNotNone(scheduled.scheduled_at)
        self.assertEqual(result["sent_count"], 3)
        client.send_email_to_segments.assert_called_once_with("88", [31])

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
    def test_future_scheduled_campaign_event_cannot_send_early(
        self,
        sync,
        client_cls,
    ):
        scheduled = NewsletterCampaign.objects.create(
            name="Future Scheduled Processor",
            subject="Scheduled processor subject",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            html_content="<p>Scheduled body</p>",
            plain_text="Scheduled body",
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at=timezone.now() + timedelta(hours=1),
        )
        scheduled.audiences.set([self.category])
        event = NewsletterCampaignSendEvent.objects.create(
            campaign=scheduled,
            requested_by=self.staff,
            idempotency_key=f"mautic:newsletter:campaign:{scheduled.uuid}:send",
        )

        early = process_campaign_send_event(event.pk)

        event.refresh_from_db()
        scheduled.refresh_from_db()
        self.assertFalse(early["processed"])
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.PENDING)
        self.assertEqual(event.attempt_count, 0)
        self.assertIsNone(event.provider_send_started_at)
        self.assertEqual(scheduled.status, NewsletterCampaign.Status.SCHEDULED)
        sync.assert_not_called()
        client_cls.assert_not_called()

        NewsletterCampaign.objects.filter(pk=scheduled.pk).update(
            scheduled_at=timezone.now() - timedelta(minutes=1),
            mautic_email_id="88",
        )
        scheduled.refresh_from_db()
        sync.return_value = scheduled
        client = client_cls.return_value
        client.update_email.return_value = {"id": 88}
        client.send_email_to_segments.return_value = {
            "success": 1,
            "sentCount": 1,
            "failedRecipients": [],
        }

        due = process_campaign_send_event(event.pk)

        event.refresh_from_db()
        scheduled.refresh_from_db()
        self.assertTrue(due["processed"])
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.SUCCEEDED)
        self.assertEqual(scheduled.status, NewsletterCampaign.Status.SENT)
        client.send_email_to_segments.assert_called_once_with("88", [31])

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
    def test_missing_scheduled_at_campaign_event_cannot_send(
        self,
        sync,
        client_cls,
    ):
        scheduled = NewsletterCampaign.objects.create(
            name="Missing Scheduled At Processor",
            subject="Scheduled processor subject",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            html_content="<p>Scheduled body</p>",
            plain_text="Scheduled body",
            status=NewsletterCampaign.Status.SCHEDULED,
        )
        scheduled.audiences.set([self.category])
        event = NewsletterCampaignSendEvent.objects.create(
            campaign=scheduled,
            requested_by=self.staff,
            idempotency_key=f"mautic:newsletter:campaign:{scheduled.uuid}:send",
        )

        result = process_campaign_send_event(event.pk)

        event.refresh_from_db()
        scheduled.refresh_from_db()
        self.assertFalse(result["processed"])
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.PENDING)
        self.assertEqual(event.attempt_count, 0)
        self.assertIsNone(event.provider_send_started_at)
        self.assertEqual(scheduled.status, NewsletterCampaign.Status.SCHEDULED)
        sync.assert_not_called()
        client_cls.assert_not_called()

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch(
        "newsletter.campaign_send_processor.sync_campaign_for_worker_delivery",
        side_effect=CampaignMauticUnavailable("Mautic unavailable"),
    )
    def test_scheduled_pre_provider_failure_remains_scheduled(
        self,
        _sync,
        client_cls,
    ):
        scheduled = NewsletterCampaign.objects.create(
            name="Scheduled Pre Failure",
            subject="Scheduled processor subject",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            html_content="<p>Scheduled body</p>",
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at=timezone.now() - timedelta(minutes=1),
        )
        scheduled.audiences.set([self.category])
        event = NewsletterCampaignSendEvent.objects.create(
            campaign=scheduled,
            requested_by=self.staff,
            idempotency_key=f"mautic:newsletter:campaign:{scheduled.uuid}:send",
        )

        result = process_campaign_send_event(event.pk)

        event.refresh_from_db()
        scheduled.refresh_from_db()
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.FAILED)
        self.assertIsNone(event.provider_send_started_at)
        self.assertEqual(scheduled.status, NewsletterCampaign.Status.SCHEDULED)
        self.assertTrue(result["retry_safe"])
        client_cls.assert_not_called()

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
    def test_scheduled_provider_failure_becomes_failed(self, sync, client_cls):
        scheduled = NewsletterCampaign.objects.create(
            name="Scheduled Provider Failure",
            subject="Scheduled processor subject",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            html_content="<p>Scheduled body</p>",
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at=timezone.now() - timedelta(minutes=1),
            mautic_email_id="88",
        )
        scheduled.audiences.set([self.category])
        event = NewsletterCampaignSendEvent.objects.create(
            campaign=scheduled,
            requested_by=self.staff,
            idempotency_key=f"mautic:newsletter:campaign:{scheduled.uuid}:send",
        )
        sync.return_value = scheduled
        client_cls.return_value.update_email.return_value = {"id": 88}
        client_cls.return_value.send_email_to_segments.side_effect = (
            TemporaryMauticError("provider timed out")
        )

        result = process_campaign_send_event(event.pk)

        event.refresh_from_db()
        scheduled.refresh_from_db()
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.FAILED)
        self.assertIsNotNone(event.provider_send_started_at)
        self.assertEqual(scheduled.status, NewsletterCampaign.Status.FAILED)
        self.assertFalse(result["retry_safe"])

    @patch("newsletter.campaign_send_processor.MauticClient")
    @patch("newsletter.campaign_send_processor.sync_campaign_for_worker_delivery")
    def test_cancelled_scheduled_campaign_never_calls_mautic(self, sync, client_cls):
        scheduled = NewsletterCampaign.objects.create(
            name="Cancelled Scheduled Processor",
            status=NewsletterCampaign.Status.CANCELLED,
            scheduled_at=timezone.now() - timedelta(minutes=1),
        )
        event = NewsletterCampaignSendEvent.objects.create(
            campaign=scheduled,
            requested_by=self.staff,
            idempotency_key=f"mautic:newsletter:campaign:{scheduled.uuid}:send",
        )

        result = process_campaign_send_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.FAILED)
        self.assertIsNone(event.provider_send_started_at)
        self.assertTrue(result["processed"])
        sync.assert_not_called()
        client_cls.assert_not_called()
