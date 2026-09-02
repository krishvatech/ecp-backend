from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from newsletter.campaign_send_events import create_campaign_send_event
from newsletter.campaign_send_operations import (
    dispatch_due_campaign_send_events,
    dispatch_due_scheduled_campaigns,
    due_campaign_send_event_ids,
    due_scheduled_campaign_ids,
)
from newsletter.models import (
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
)
from newsletter.tasks import dispatch_due_newsletter_campaign_send_events
from newsletter.tasks import dispatch_due_newsletter_scheduled_campaigns


User = get_user_model()


@override_settings(
    MAUTIC_SYNC_ENABLED=True,
    MAUTIC_SYNC_PROCESSING_TIMEOUT_SECONDS=600,
)
class NewsletterCampaignSendRecoveryTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            username="campaign-send-recovery-staff",
            email="campaign-send-recovery-staff@example.test",
            password="test-password",
            is_staff=True,
        )

    def _event(self, name):
        campaign = NewsletterCampaign.objects.create(name=name)
        return create_campaign_send_event(
            campaign,
            requested_by=self.staff,
        )

    def test_due_ids_include_pending_and_stale_pre_provider_only(self):
        pending = self._event("Pending")
        failed = self._event("Failed")
        fresh_processing = self._event("Fresh Processing")
        stale_processing = self._event("Stale Processing")
        post_provider = self._event("Post Provider")
        succeeded = self._event("Succeeded")

        now = timezone.now()
        stale = now - timedelta(minutes=20)

        NewsletterCampaignSendEvent.objects.filter(pk=failed.pk).update(
            status=NewsletterCampaignSendEvent.Status.FAILED,
            last_error="provider preparation rejected",
        )
        NewsletterCampaignSendEvent.objects.filter(pk=fresh_processing.pk).update(
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            processing_started_at=now,
        )
        NewsletterCampaignSendEvent.objects.filter(pk=stale_processing.pk).update(
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            processing_started_at=stale,
        )
        NewsletterCampaignSendEvent.objects.filter(pk=post_provider.pk).update(
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            processing_started_at=stale,
            provider_send_started_at=stale,
        )
        NewsletterCampaignSendEvent.objects.filter(pk=succeeded.pk).update(
            status=NewsletterCampaignSendEvent.Status.SUCCEEDED,
            provider_send_started_at=stale,
            completed_at=now,
        )

        selected = set(due_campaign_send_event_ids())

        self.assertEqual(selected, {pending.pk, stale_processing.pk})

    def test_due_ids_respect_batch_size(self):
        self._event("Batch 1")
        self._event("Batch 2")
        self._event("Batch 3")

        self.assertEqual(len(due_campaign_send_event_ids(batch_size=2)), 2)

    @patch(
        "newsletter.campaign_send_operations."
        "process_newsletter_campaign_send_event.delay"
    )
    def test_dispatch_sends_only_safe_due_events(self, delay):
        pending = self._event("Dispatch Pending")
        failed = self._event("Dispatch Failed")
        NewsletterCampaignSendEvent.objects.filter(pk=failed.pk).update(
            status=NewsletterCampaignSendEvent.Status.FAILED,
        )

        result = dispatch_due_campaign_send_events()

        self.assertEqual(result["selected"], 1)
        self.assertEqual(result["dispatched"], 1)
        self.assertEqual(result["failed"], 0)
        delay.assert_called_once_with(pending.pk)

    @patch(
        "newsletter.campaign_send_operations."
        "process_newsletter_campaign_send_event.delay",
        side_effect=ConnectionError("broker unavailable"),
    )
    def test_broker_failure_keeps_event_for_next_recovery_pass(self, delay):
        event = self._event("Broker Failure")

        result = dispatch_due_campaign_send_events()

        event.refresh_from_db()
        self.assertEqual(result["selected"], 1)
        self.assertEqual(result["dispatched"], 0)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.PENDING)
        self.assertIsNone(event.provider_send_started_at)
        delay.assert_called_once_with(event.pk)

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    @patch(
        "newsletter.campaign_send_operations."
        "process_newsletter_campaign_send_event.delay"
    )
    def test_disabled_sync_does_not_dispatch(self, delay):
        self._event("Disabled")

        result = dispatch_due_campaign_send_events()

        self.assertTrue(result["disabled"])
        self.assertEqual(result["selected"], 0)
        delay.assert_not_called()

    def test_cancelled_campaign_event_is_never_recovered(self):
        event = self._event("Cancelled Recovery")
        NewsletterCampaignSendEvent.objects.filter(pk=event.pk).update(
            status=NewsletterCampaignSendEvent.Status.FAILED,
            last_error="Newsletter campaign cancelled before provider delivery started.",
            completed_at=timezone.now(),
        )
        NewsletterCampaign.objects.filter(pk=event.campaign_id).update(
            status=NewsletterCampaign.Status.CANCELLED,
            scheduled_at=timezone.now() - timedelta(minutes=1),
        )

        self.assertNotIn(event.pk, due_campaign_send_event_ids())

    @patch(
        "newsletter.campaign_send_operations.dispatch_campaign_send_event_safely"
    )
    def test_due_scheduled_campaign_creates_one_event_and_dispatches(self, dispatch):
        campaign = NewsletterCampaign.objects.create(
            name="Due Scheduled",
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at=timezone.now() - timedelta(minutes=1),
            updated_by=self.staff,
        )

        selected = due_scheduled_campaign_ids()
        first = dispatch_due_scheduled_campaigns()
        second = dispatch_due_scheduled_campaigns()

        self.assertIn(campaign.pk, selected)
        self.assertEqual(
            NewsletterCampaignSendEvent.objects.filter(campaign=campaign).count(),
            1,
        )
        event = NewsletterCampaignSendEvent.objects.get(campaign=campaign)
        self.assertEqual(event.requested_by, self.staff)
        self.assertEqual(first["created"], 1)
        self.assertEqual(second["created"], 0)
        self.assertEqual(dispatch.call_count, 2)

    @patch(
        "newsletter.campaign_send_operations.dispatch_campaign_send_event_safely"
    )
    def test_scheduled_dispatch_skips_future_disabled_and_cancelled(self, dispatch):
        NewsletterCampaign.objects.create(
            name="Future Scheduled",
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at=timezone.now() + timedelta(minutes=5),
        )
        NewsletterCampaign.objects.create(
            name="Cancelled Scheduled",
            status=NewsletterCampaign.Status.CANCELLED,
            scheduled_at=timezone.now() - timedelta(minutes=5),
        )

        self.assertEqual(due_scheduled_campaign_ids(), [])

        with override_settings(MAUTIC_SYNC_ENABLED=False):
            result = dispatch_due_scheduled_campaigns()

        self.assertTrue(result["disabled"])
        dispatch.assert_not_called()

    @patch(
        "newsletter.campaign_send_operations.dispatch_campaign_send_event_safely",
        return_value=False,
    )
    def test_scheduled_broker_failure_keeps_durable_event(self, dispatch):
        campaign = NewsletterCampaign.objects.create(
            name="Scheduled Broker Failure",
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at=timezone.now() - timedelta(minutes=1),
        )

        result = dispatch_due_scheduled_campaigns()

        event = NewsletterCampaignSendEvent.objects.get(campaign=campaign)
        self.assertEqual(result["created"], 1)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.PENDING)
        self.assertIsNone(event.provider_send_started_at)
        dispatch.assert_called_once_with(event.pk)


class NewsletterCampaignSendRecoveryTaskTests(SimpleTestCase):
    @patch(
        "newsletter.campaign_send_operations.dispatch_due_campaign_send_events"
    )
    def test_recovery_task_delegates_without_retry_wrapper(self, dispatch):
        dispatch.return_value = {
            "disabled": False,
            "selected": 2,
            "dispatched": 2,
            "failed": 0,
        }

        result = dispatch_due_newsletter_campaign_send_events.run(batch_size=25)

        dispatch.assert_called_once_with(batch_size=25)
        self.assertEqual(result["dispatched"], 2)

    def test_recovery_task_name_is_stable(self):
        self.assertEqual(
            dispatch_due_newsletter_campaign_send_events.name,
            "newsletter.dispatch_due_campaign_send_events",
        )

    @patch(
        "newsletter.campaign_send_operations.dispatch_due_scheduled_campaigns"
    )
    def test_scheduled_dispatch_task_delegates(self, dispatch):
        dispatch.return_value = {
            "disabled": False,
            "selected": 1,
            "created": 1,
            "dispatched": 1,
            "failed": 0,
        }

        result = dispatch_due_newsletter_scheduled_campaigns.run(batch_size=10)

        dispatch.assert_called_once_with(batch_size=10)
        self.assertEqual(result["created"], 1)

    def test_scheduled_dispatch_task_name_is_stable(self):
        self.assertEqual(
            dispatch_due_newsletter_scheduled_campaigns.name,
            "newsletter.dispatch_due_scheduled_campaigns",
        )
