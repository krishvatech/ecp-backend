from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.models import (
    MauticContactMapping,
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterSyncEvent,
)
from newsletter.processor import (
    mark_retry_exhausted,
    process_newsletter_sync_event,
    retry_delay_seconds,
)


@override_settings(
    MAUTIC_SYNC_ENABLED=True,
    MAUTIC_BASE_URL="http://mautic.local",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="secret",
)
class NewsletterSyncProcessorTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_user(
            username="mautic-processor-user",
            email="processor@example.com",
            first_name="Process",
            last_name="User",
            password="test-password",
        )
        cls.category = NewsletterCategory.objects.create(
            name="Processor Test",
            slug="processor-test",
            mautic_segment_id="77",
        )

    def setUp(self):
        self.subscription = NewsletterSubscription.objects.create(
            user=self.user,
            category=self.category,
            is_subscribed=True,
        )

    def event(self, *, desired=True, status=NewsletterSyncEvent.Status.PENDING):
        return NewsletterSyncEvent.objects.create(
            idempotency_key=(
                f"processor:{NewsletterSyncEvent.objects.count()}:{desired}"
            ),
            user_id=str(self.user.pk),
            category=self.category,
            desired_subscribed=desired,
            status=status,
        )

    @patch("newsletter.processor.MauticClient")
    def test_existing_mapping_updates_contact_and_adds_segment(self, client_cls):
        mapping = MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="88",
        )
        client = client_cls.return_value
        client.update_contact.return_value = {"id": 88}
        event = self.event()

        result = process_newsletter_sync_event(event.pk)

        event.refresh_from_db()
        mapping.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.SUCCEEDED)
        self.assertEqual(event.attempt_count, 1)
        self.assertIsNotNone(event.completed_at)
        self.assertIsNotNone(mapping.last_synced_at)
        client.update_contact.assert_called_once()
        client.add_contact_to_segment.assert_called_once_with("77", "88")
        self.assertEqual(result["mautic_contact_id"], "88")
        self.assertFalse(result["created"])

    @patch("newsletter.processor.MauticClient")
    def test_missing_mapping_finds_existing_contact_and_saves_mapping(self, client_cls):
        client = client_cls.return_value
        client.find_contact_by_email.return_value = {
            "id": 91,
            "email": "processor@example.com",
        }
        client.update_contact.return_value = {"id": 91}
        event = self.event()

        result = process_newsletter_sync_event(event.pk)

        mapping = MauticContactMapping.objects.get(user=self.user)
        self.assertEqual(mapping.mautic_contact_id, "91")
        self.assertFalse(result["created"])
        client.create_contact.assert_not_called()

    @patch("newsletter.processor.MauticClient")
    def test_missing_contact_is_created_for_subscribe(self, client_cls):
        client = client_cls.return_value
        client.find_contact_by_email.return_value = None
        client.create_contact.return_value = {"id": 92}
        event = self.event()

        result = process_newsletter_sync_event(event.pk)

        mapping = MauticContactMapping.objects.get(user=self.user)
        self.assertEqual(mapping.mautic_contact_id, "92")
        self.assertTrue(result["created"])

    @patch("newsletter.processor.MauticClient")
    def test_unsubscribe_removes_mapped_contact_from_segment(self, client_cls):
        NewsletterSubscription.objects.filter(pk=self.subscription.pk).update(
            is_subscribed=False
        )
        MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="93",
        )
        client = client_cls.return_value
        client.update_contact.return_value = {"id": 93}
        event = self.event(desired=False)

        result = process_newsletter_sync_event(event.pk)

        self.assertEqual(result["status"], NewsletterSyncEvent.Status.SUCCEEDED)
        client.remove_contact_from_segment.assert_called_once_with("77", "93")
        client.add_contact_to_segment.assert_not_called()

    @patch("newsletter.processor.MauticClient")
    def test_unsubscribe_missing_contact_does_not_create_one(self, client_cls):
        NewsletterSubscription.objects.filter(pk=self.subscription.pk).update(
            is_subscribed=False
        )
        client = client_cls.return_value
        client.find_contact_by_email.return_value = None
        event = self.event(desired=False)

        result = process_newsletter_sync_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.SUCCEEDED)
        self.assertIsNone(result["mautic_contact_id"])
        client.create_contact.assert_not_called()
        client.remove_contact_from_segment.assert_not_called()
        self.assertFalse(MauticContactMapping.objects.filter(user=self.user).exists())

    @patch("newsletter.processor.MauticClient")
    def test_superseded_event_is_skipped_without_provider_call(self, client_cls):
        NewsletterSubscription.objects.filter(pk=self.subscription.pk).update(
            is_subscribed=False
        )
        event = self.event(desired=True)

        result = process_newsletter_sync_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.SKIPPED)
        self.assertEqual(result["reason"], "superseded")
        client_cls.assert_not_called()

    @patch("newsletter.processor.MauticClient")
    def test_missing_segment_is_terminal_without_provider_call(self, client_cls):
        NewsletterCategory.objects.filter(pk=self.category.pk).update(
            mautic_segment_id=""
        )
        event = self.event()

        result = process_newsletter_sync_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.FAILED)
        self.assertIn("segment ID", event.last_error)
        client_cls.assert_not_called()
        self.assertTrue(result["processed"])

    @patch("newsletter.processor.MauticClient")
    def test_temporary_failure_is_scheduled_for_retry(self, client_cls):
        client = client_cls.return_value
        client.find_contact_by_email.side_effect = TemporaryMauticError(
            "temporary outage"
        )
        event = self.event()

        with self.assertRaises(TemporaryMauticError) as raised:
            process_newsletter_sync_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.RETRYING)
        self.assertEqual(event.attempt_count, 1)
        self.assertIsNotNone(event.next_retry_at)
        self.assertEqual(raised.exception.retry_delay, 30)

    @patch("newsletter.processor.MauticClient")
    def test_permanent_failure_is_terminal(self, client_cls):
        client_cls.side_effect = PermanentMauticError("bad config")
        event = self.event()

        result = process_newsletter_sync_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.FAILED)
        self.assertEqual(event.last_error, "bad config")
        self.assertEqual(result["status"], NewsletterSyncEvent.Status.FAILED)

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    @patch("newsletter.processor.MauticClient")
    def test_disabled_sync_does_not_claim_or_call_provider(self, client_cls):
        event = self.event()

        result = process_newsletter_sync_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.PENDING)
        self.assertEqual(event.attempt_count, 0)
        self.assertFalse(result["processed"])
        self.assertEqual(result["reason"], "mautic_sync_disabled")
        client_cls.assert_not_called()

    @patch("newsletter.processor.MauticClient")
    def test_successful_event_is_not_processed_twice(self, client_cls):
        MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="94",
        )
        client = client_cls.return_value
        client.update_contact.return_value = {"id": 94}
        event = self.event()

        first = process_newsletter_sync_event(event.pk)
        second = process_newsletter_sync_event(event.pk)

        self.assertTrue(first["processed"])
        self.assertFalse(second["processed"])
        self.assertEqual(client_cls.call_count, 1)

    def test_deleted_user_is_skipped(self):
        event = self.event()
        self.user.delete()

        result = process_newsletter_sync_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.SKIPPED)
        self.assertTrue(result["processed"])

    @override_settings(
        MAUTIC_SYNC_RETRY_BASE_SECONDS=10,
        MAUTIC_SYNC_RETRY_MAX_SECONDS=25,
    )
    def test_retry_delay_is_exponential_and_bounded(self):
        self.assertEqual(retry_delay_seconds(1), 10)
        self.assertEqual(retry_delay_seconds(2), 20)
        self.assertEqual(retry_delay_seconds(3), 25)
        self.assertEqual(retry_delay_seconds(10), 25)

    def test_mark_retry_exhausted_is_terminal(self):
        event = self.event(status=NewsletterSyncEvent.Status.RETRYING)
        NewsletterSyncEvent.objects.filter(pk=event.pk).update(
            next_retry_at=timezone.now() - timedelta(seconds=1)
        )

        mark_retry_exhausted(event.pk)

        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.FAILED)
        self.assertEqual(event.last_error, "Mautic retry limit exhausted")
        self.assertIsNone(event.next_retry_at)
        self.assertIsNotNone(event.completed_at)
