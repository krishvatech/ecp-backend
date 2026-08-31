from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import transaction
from django.test import TestCase, override_settings

from newsletter.models import (
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterSyncEvent,
)
from newsletter.services import update_user_preferences


@override_settings(MAUTIC_SYNC_ENABLED=True)
class NewsletterPreferenceSyncIntegrationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_user(
            username="newsletter-preference-sync",
            email="preference-sync@example.com",
            password="test-password",
        )
        cls.events = NewsletterCategory.objects.create(
            name="IMAA Events Test",
            slug="imaa-events-test",
            mautic_segment_id="101",
        )
        cls.deal_alert = NewsletterCategory.objects.create(
            name="IMAA Deal Alert Test",
            slug="imaa-deal-alert-test",
            mautic_segment_id="102",
        )

    def test_changed_preference_creates_durable_event(self):
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            update_user_preferences(
                self.user,
                [{"slug": self.events.slug, "subscribed": True}],
            )

        subscription = NewsletterSubscription.objects.get(
            user=self.user,
            category=self.events,
        )
        event = NewsletterSyncEvent.objects.get(
            user_id=str(self.user.pk),
            category=self.events,
        )

        self.assertTrue(subscription.is_subscribed)
        self.assertEqual(event.status, NewsletterSyncEvent.Status.PENDING)
        self.assertTrue(event.desired_subscribed)
        self.assertEqual(len(callbacks), 1)

    def test_explicit_opt_out_from_missing_row_creates_unsubscribe_event(self):
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            update_user_preferences(
                self.user,
                [{"slug": self.events.slug, "subscribed": False}],
            )

        subscription = NewsletterSubscription.objects.get(
            user=self.user,
            category=self.events,
        )
        event = NewsletterSyncEvent.objects.get(
            user_id=str(self.user.pk),
            category=self.events,
        )

        self.assertFalse(subscription.is_subscribed)
        self.assertFalse(event.desired_subscribed)
        self.assertIsNotNone(subscription.unsubscribed_at)
        self.assertEqual(len(callbacks), 1)

    def test_same_state_patch_does_not_create_another_event(self):
        subscription = NewsletterSubscription.objects.create(
            user=self.user,
            category=self.events,
            is_subscribed=True,
        )
        NewsletterSyncEvent.objects.create(
            idempotency_key="preexisting-event",
            user_id=str(self.user.pk),
            category=self.events,
            desired_subscribed=True,
            status=NewsletterSyncEvent.Status.SUCCEEDED,
        )

        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            update_user_preferences(
                self.user,
                [{"slug": self.events.slug, "subscribed": True}],
            )

        subscription.refresh_from_db()
        self.assertTrue(subscription.is_subscribed)
        self.assertEqual(
            NewsletterSyncEvent.objects.filter(
                user_id=str(self.user.pk),
                category=self.events,
            ).count(),
            1,
        )
        self.assertEqual(callbacks, [])

    @patch("newsletter.tasks.process_newsletter_sync_event.delay")
    def test_dispatch_runs_only_from_on_commit_callback(self, delay):
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            update_user_preferences(
                self.user,
                [{"slug": self.events.slug, "subscribed": True}],
            )
            delay.assert_not_called()

        self.assertEqual(len(callbacks), 1)
        delay.assert_not_called()

        callbacks[0]()

        event = NewsletterSyncEvent.objects.get(
            user_id=str(self.user.pk),
            category=self.events,
        )
        delay.assert_called_once_with(event.pk)

    @patch(
        "newsletter.tasks.process_newsletter_sync_event.delay",
        side_effect=ConnectionError("broker unavailable"),
    )
    def test_broker_failure_does_not_escape_and_event_remains_pending(self, delay):
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            result = update_user_preferences(
                self.user,
                [{"slug": self.events.slug, "subscribed": True}],
            )

        self.assertTrue(
            next(
                item["subscribed"]
                for item in result
                if item["slug"] == self.events.slug
            )
        )

        callbacks[0]()

        event = NewsletterSyncEvent.objects.get(
            user_id=str(self.user.pk),
            category=self.events,
        )
        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.PENDING)
        delay.assert_called_once_with(event.pk)

    def test_multiple_changes_create_one_event_and_callback_each(self):
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            update_user_preferences(
                self.user,
                [
                    {"slug": self.events.slug, "subscribed": True},
                    {"slug": self.deal_alert.slug, "subscribed": False},
                ],
            )

        self.assertEqual(
            NewsletterSyncEvent.objects.filter(
                user_id=str(self.user.pk)
            ).count(),
            2,
        )
        self.assertEqual(len(callbacks), 2)

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    @patch("newsletter.tasks.process_newsletter_sync_event.delay")
    def test_disabled_sync_saves_preference_without_event_or_dispatch(self, delay):
        with self.captureOnCommitCallbacks(execute=True):
            result = update_user_preferences(
                self.user,
                [{"slug": self.events.slug, "subscribed": True}],
            )

        self.assertTrue(
            next(
                item["subscribed"]
                for item in result
                if item["slug"] == self.events.slug
            )
        )
        self.assertTrue(
            NewsletterSubscription.objects.filter(
                user=self.user,
                category=self.events,
                is_subscribed=True,
            ).exists()
        )
        self.assertFalse(
            NewsletterSyncEvent.objects.filter(
                user_id=str(self.user.pk),
                category=self.events,
            ).exists()
        )
        delay.assert_not_called()

    @patch(
        "newsletter.services.create_newsletter_sync_event",
        side_effect=RuntimeError("outbox write failed"),
    )
    def test_outbox_creation_failure_rolls_back_preference_change(self, _create):
        with self.assertRaisesMessage(RuntimeError, "outbox write failed"):
            update_user_preferences(
                self.user,
                [{"slug": self.events.slug, "subscribed": True}],
            )

        self.assertFalse(
            NewsletterSubscription.objects.filter(
                user=self.user,
                category=self.events,
            ).exists()
        )

    def test_existing_preference_change_creates_new_desired_state_event(self):
        NewsletterSubscription.objects.create(
            user=self.user,
            category=self.events,
            is_subscribed=True,
        )
        previous = NewsletterSyncEvent.objects.create(
            idempotency_key="previous-subscribe",
            user_id=str(self.user.pk),
            category=self.events,
            desired_subscribed=True,
            status=NewsletterSyncEvent.Status.SUCCEEDED,
        )

        with self.captureOnCommitCallbacks(execute=False):
            update_user_preferences(
                self.user,
                [{"slug": self.events.slug, "subscribed": False}],
            )

        latest = (
            NewsletterSyncEvent.objects.filter(
                user_id=str(self.user.pk),
                category=self.events,
            )
            .exclude(pk=previous.pk)
            .get()
        )
        self.assertFalse(latest.desired_subscribed)
        self.assertEqual(latest.status, NewsletterSyncEvent.Status.PENDING)
