from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from newsletter.models import NewsletterCategory, NewsletterSyncEvent
from newsletter.operations import (
    dispatch_due_sync_events,
    due_sync_event_ids,
)


@override_settings(
    MAUTIC_SYNC_ENABLED=True,
    MAUTIC_SYNC_PROCESSING_TIMEOUT_SECONDS=600,
)
class NewsletterSyncOperationsTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.category = NewsletterCategory.objects.create(
            name="Recovery Test",
            slug="recovery-test",
        )

    def event(
        self,
        *,
        status=NewsletterSyncEvent.Status.PENDING,
        next_retry_at=None,
        processing_started_at=None,
    ):
        index = NewsletterSyncEvent.objects.count()
        return NewsletterSyncEvent.objects.create(
            idempotency_key=f"recovery:{index}:{status}",
            user_id=str(index + 1000),
            category=self.category,
            desired_subscribed=True,
            status=status,
            next_retry_at=next_retry_at,
            processing_started_at=processing_started_at,
        )

    def test_due_selection_includes_pending_due_retry_and_stale_processing(self):
        now = timezone.now()

        pending = self.event(status=NewsletterSyncEvent.Status.PENDING)
        retry_due = self.event(
            status=NewsletterSyncEvent.Status.RETRYING,
            next_retry_at=now - timedelta(seconds=1),
        )
        retry_without_time = self.event(
            status=NewsletterSyncEvent.Status.RETRYING,
        )
        stale = self.event(
            status=NewsletterSyncEvent.Status.PROCESSING,
            processing_started_at=now - timedelta(seconds=601),
        )

        future_retry = self.event(
            status=NewsletterSyncEvent.Status.RETRYING,
            next_retry_at=now + timedelta(hours=1),
        )
        fresh_processing = self.event(
            status=NewsletterSyncEvent.Status.PROCESSING,
            processing_started_at=now - timedelta(seconds=10),
        )
        succeeded = self.event(status=NewsletterSyncEvent.Status.SUCCEEDED)

        selected = set(due_sync_event_ids())

        self.assertEqual(
            selected,
            {
                pending.pk,
                retry_due.pk,
                retry_without_time.pk,
                stale.pk,
            },
        )
        self.assertNotIn(future_retry.pk, selected)
        self.assertNotIn(fresh_processing.pk, selected)
        self.assertNotIn(succeeded.pk, selected)

    def test_due_selection_respects_batch_size(self):
        for _ in range(3):
            self.event()

        self.assertEqual(len(due_sync_event_ids(batch_size=2)), 2)

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    @patch("newsletter.operations.process_newsletter_sync_event.delay")
    def test_dispatch_is_disabled_by_rollout_flag(self, delay):
        self.event()

        result = dispatch_due_sync_events()

        self.assertEqual(
            result,
            {
                "disabled": True,
                "selected": 0,
                "dispatched": 0,
                "failed": 0,
            },
        )
        delay.assert_not_called()

    @patch("newsletter.operations.process_newsletter_sync_event.delay")
    def test_dispatch_due_events_is_best_effort(self, delay):
        first = self.event()
        second = self.event()
        delay.side_effect = [None, ConnectionError("broker unavailable")]

        result = dispatch_due_sync_events()

        self.assertFalse(result["disabled"])
        self.assertEqual(result["selected"], 2)
        self.assertEqual(result["dispatched"], 1)
        self.assertEqual(result["failed"], 1)

        statuses = list(
            NewsletterSyncEvent.objects.filter(pk__in=[first.pk, second.pk])
            .order_by("pk")
            .values_list("status", flat=True)
        )
        self.assertEqual(
            statuses,
            [
                NewsletterSyncEvent.Status.PENDING,
                NewsletterSyncEvent.Status.PENDING,
            ],
        )
