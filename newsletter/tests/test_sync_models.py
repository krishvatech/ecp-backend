from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase

from newsletter.models import (
    MauticContactMapping,
    NewsletterCategory,
    NewsletterSyncEvent,
)


class NewsletterSyncModelTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_user(
            username="newsletter-sync-user",
            email="newsletter-sync@example.com",
            password="test-password",
        )
        cls.category = NewsletterCategory.objects.create(
            name="Sync Test",
            slug="sync-test",
        )

    def test_mautic_mapping_is_unique_per_user_and_contact(self):
        MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="101",
        )

        with self.assertRaises(IntegrityError), transaction.atomic():
            MauticContactMapping.objects.create(
                user=self.user,
                mautic_contact_id="102",
            )

        User = get_user_model()
        other = User.objects.create_user(
            username="newsletter-sync-other",
            email="newsletter-sync-other@example.com",
            password="test-password",
        )
        with self.assertRaises(IntegrityError), transaction.atomic():
            MauticContactMapping.objects.create(
                user=other,
                mautic_contact_id="101",
            )

    def test_sync_event_defaults_to_pending(self):
        event = NewsletterSyncEvent.objects.create(
            idempotency_key="newsletter:test:pending",
            user_id=str(self.user.pk),
            category=self.category,
            desired_subscribed=True,
        )

        self.assertEqual(event.status, NewsletterSyncEvent.Status.PENDING)
        self.assertEqual(event.attempt_count, 0)
        self.assertEqual(event.last_error, "")
        self.assertIsNone(event.next_retry_at)
        self.assertIsNone(event.processing_started_at)
        self.assertIsNone(event.completed_at)

    def test_sync_event_idempotency_key_is_unique(self):
        NewsletterSyncEvent.objects.create(
            idempotency_key="newsletter:test:unique",
            user_id=str(self.user.pk),
            category=self.category,
            desired_subscribed=True,
        )

        with self.assertRaises(IntegrityError), transaction.atomic():
            NewsletterSyncEvent.objects.create(
                idempotency_key="newsletter:test:unique",
                user_id=str(self.user.pk),
                category=self.category,
                desired_subscribed=False,
            )

    def test_sync_event_survives_user_deletion(self):
        user_id = str(self.user.pk)
        event = NewsletterSyncEvent.objects.create(
            idempotency_key="newsletter:test:user-deleted",
            user_id=user_id,
            category=self.category,
            desired_subscribed=True,
        )

        self.user.delete()

        event.refresh_from_db()
        self.assertEqual(event.user_id, user_id)

    def test_category_is_protected_while_sync_event_exists(self):
        NewsletterSyncEvent.objects.create(
            idempotency_key="newsletter:test:category-protected",
            user_id=str(self.user.pk),
            category=self.category,
            desired_subscribed=True,
        )

        with self.assertRaises(Exception) as raised:
            self.category.delete()

        self.assertEqual(
            raised.exception.__class__.__name__,
            "ProtectedError",
        )
