from django.contrib.auth import get_user_model
from django.test import TestCase

from newsletter.models import (
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterSyncEvent,
)
from newsletter.sync_events import (
    build_newsletter_sync_idempotency_key,
    create_newsletter_sync_event,
)


class NewsletterSyncEventCreationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_user(
            username="newsletter-event-user",
            email="newsletter-event@example.com",
            password="test-password",
        )
        cls.category = NewsletterCategory.objects.create(
            name="Sync Event Test",
            slug="sync-event-test",
        )
        cls.subscription = NewsletterSubscription.objects.create(
            user=cls.user,
            category=cls.category,
            is_subscribed=True,
        )

    def refresh_subscription(self):
        return NewsletterSubscription.objects.select_related("category").get(
            pk=self.subscription.pk
        )

    def test_builds_stable_idempotency_key(self):
        key = build_newsletter_sync_idempotency_key(
            user_id=self.user.pk,
            category_id=self.category.pk,
            desired_subscribed=True,
        )
        self.assertEqual(
            key,
            (
                f"mautic:newsletter:user:{self.user.pk}:"
                f"category:{self.category.pk}:subscribed"
            ),
        )

    def test_creates_pending_event_from_current_subscription_state(self):
        event = create_newsletter_sync_event(self.refresh_subscription())

        self.assertEqual(event.user_id, str(self.user.pk))
        self.assertEqual(event.category, self.category)
        self.assertTrue(event.desired_subscribed)
        self.assertEqual(event.status, NewsletterSyncEvent.Status.PENDING)

    def test_identical_in_flight_state_is_deduplicated(self):
        first = create_newsletter_sync_event(self.refresh_subscription())
        second = create_newsletter_sync_event(self.refresh_subscription())

        self.assertEqual(second.pk, first.pk)
        self.assertEqual(NewsletterSyncEvent.objects.count(), 1)

    def test_changed_subscription_state_creates_new_event(self):
        subscribed = create_newsletter_sync_event(self.refresh_subscription())

        NewsletterSubscription.objects.filter(pk=self.subscription.pk).update(
            is_subscribed=False
        )
        unsubscribed = create_newsletter_sync_event(self.refresh_subscription())

        self.assertNotEqual(unsubscribed.pk, subscribed.pk)
        self.assertFalse(unsubscribed.desired_subscribed)
        self.assertEqual(NewsletterSyncEvent.objects.count(), 2)

    def test_returning_to_completed_state_creates_new_event(self):
        first = create_newsletter_sync_event(self.refresh_subscription())
        NewsletterSyncEvent.objects.filter(pk=first.pk).update(
            status=NewsletterSyncEvent.Status.SUCCEEDED
        )

        NewsletterSubscription.objects.filter(pk=self.subscription.pk).update(
            is_subscribed=False
        )
        create_newsletter_sync_event(self.refresh_subscription())

        NewsletterSubscription.objects.filter(pk=self.subscription.pk).update(
            is_subscribed=True
        )
        returned = create_newsletter_sync_event(self.refresh_subscription())

        self.assertNotEqual(returned.pk, first.pk)
        self.assertNotEqual(returned.idempotency_key, first.idempotency_key)
        self.assertTrue(
            returned.idempotency_key.startswith(first.idempotency_key + ":")
        )
        self.assertEqual(NewsletterSyncEvent.objects.count(), 3)

    def test_retrying_equal_state_is_reused(self):
        event = create_newsletter_sync_event(self.refresh_subscription())
        NewsletterSyncEvent.objects.filter(pk=event.pk).update(
            status=NewsletterSyncEvent.Status.RETRYING
        )

        reused = create_newsletter_sync_event(self.refresh_subscription())

        self.assertEqual(reused.pk, event.pk)

    def test_event_uses_database_state_not_stale_in_memory_state(self):
        stale = self.refresh_subscription()
        self.assertTrue(stale.is_subscribed)

        NewsletterSubscription.objects.filter(pk=self.subscription.pk).update(
            is_subscribed=False
        )

        event = create_newsletter_sync_event(stale)

        self.assertFalse(event.desired_subscribed)

    def test_rejects_unsaved_subscription(self):
        unsaved = NewsletterSubscription(
            user=self.user,
            category=self.category,
            is_subscribed=True,
        )
        with self.assertRaisesRegex(
            ValueError,
            "Saved newsletter subscription is required",
        ):
            create_newsletter_sync_event(unsaved)
