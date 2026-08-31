from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.models import NewsletterCategory, NewsletterSubscription


User = get_user_model()


class NewsletterPreferencesAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="newsletter-user",
            email="newsletter-user@example.test",
            password="test-password",
        )
        self.other_user = User.objects.create_user(
            username="newsletter-other",
            email="newsletter-other@example.test",
            password="test-password",
        )
        self.url = reverse("newsletter-preferences")

    def _authenticate(self, user=None):
        self.client.force_authenticate(user=user or self.user)

    def test_unauthenticated_get_is_rejected(self):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, (401, 403))

    def test_get_returns_seeded_categories_for_user_with_no_rows(self):
        self._authenticate()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        by_slug = {item["slug"]: item for item in response.data["preferences"]}
        self.assertEqual(
            set(by_slug),
            {"imaa-events", "imaa-pharma-ma-news", "imaa-deal-alert"},
        )
        self.assertTrue(all(not item["subscribed"] for item in by_slug.values()))
        self.assertFalse(
            NewsletterSubscription.objects.filter(user=self.user).exists()
        )

    def test_subscribe_creates_subscription(self):
        self._authenticate()
        response = self.client.patch(
            self.url,
            {"preferences": [{"slug": "imaa-events", "subscribed": True}]},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        subscription = NewsletterSubscription.objects.get(
            user=self.user,
            category__slug="imaa-events",
        )
        self.assertTrue(subscription.is_subscribed)
        self.assertIsNotNone(subscription.subscribed_at)
        self.assertIsNone(subscription.unsubscribed_at)

    def test_explicit_unsubscribe_creates_and_preserves_row(self):
        self._authenticate()
        response = self.client.patch(
            self.url,
            {"preferences": [{"slug": "imaa-deal-alert", "subscribed": False}]},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        subscription = NewsletterSubscription.objects.get(
            user=self.user,
            category__slug="imaa-deal-alert",
        )
        self.assertFalse(subscription.is_subscribed)
        self.assertIsNone(subscription.subscribed_at)
        self.assertIsNotNone(subscription.unsubscribed_at)

    def test_unsubscribe_does_not_delete_existing_subscription(self):
        self._authenticate()
        self.client.patch(
            self.url,
            {"preferences": [{"slug": "imaa-events", "subscribed": True}]},
            format="json",
        )
        subscription = NewsletterSubscription.objects.get(
            user=self.user,
            category__slug="imaa-events",
        )
        original_pk = subscription.pk
        original_subscribed_at = subscription.subscribed_at

        response = self.client.patch(
            self.url,
            {"preferences": [{"slug": "imaa-events", "subscribed": False}]},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        subscription.refresh_from_db()
        self.assertEqual(subscription.pk, original_pk)
        self.assertFalse(subscription.is_subscribed)
        self.assertEqual(subscription.subscribed_at, original_subscribed_at)
        self.assertIsNotNone(subscription.unsubscribed_at)

    def test_resubscribe_sets_new_current_opt_in_timestamp(self):
        self._authenticate()
        category = NewsletterCategory.objects.get(slug="imaa-events")
        subscription = NewsletterSubscription.objects.create(
            user=self.user,
            category=category,
            is_subscribed=False,
        )
        self.assertIsNone(subscription.subscribed_at)

        response = self.client.patch(
            self.url,
            {"preferences": [{"slug": "imaa-events", "subscribed": True}]},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        subscription.refresh_from_db()
        self.assertTrue(subscription.is_subscribed)
        self.assertIsNotNone(subscription.subscribed_at)
        self.assertIsNone(subscription.unsubscribed_at)

    def test_same_state_patch_is_idempotent_for_timestamps(self):
        self._authenticate()
        category = NewsletterCategory.objects.get(slug="imaa-events")
        self.client.patch(
            self.url,
            {"preferences": [{"slug": "imaa-events", "subscribed": True}]},
            format="json",
        )
        subscription = NewsletterSubscription.objects.get(
            user=self.user,
            category=category,
        )
        original_subscribed_at = subscription.subscribed_at
        original_updated_at = subscription.updated_at

        response = self.client.patch(
            self.url,
            {"preferences": [{"slug": "imaa-events", "subscribed": True}]},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        subscription.refresh_from_db()
        self.assertEqual(subscription.subscribed_at, original_subscribed_at)
        self.assertEqual(subscription.updated_at, original_updated_at)

    def test_user_cannot_change_another_users_preferences(self):
        category = NewsletterCategory.objects.get(slug="imaa-events")
        NewsletterSubscription.objects.create(
            user=self.other_user,
            category=category,
            is_subscribed=False,
        )
        self._authenticate()
        response = self.client.patch(
            self.url,
            {
                "user_id": self.other_user.pk,
                "preferences": [{"slug": "imaa-events", "subscribed": True}],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        other = NewsletterSubscription.objects.get(
            user=self.other_user,
            category=category,
        )
        own = NewsletterSubscription.objects.get(
            user=self.user,
            category=category,
        )
        self.assertFalse(other.is_subscribed)
        self.assertTrue(own.is_subscribed)

    def test_inactive_category_is_not_returned_and_is_rejected_for_update(self):
        self._authenticate()
        NewsletterCategory.objects.filter(slug="imaa-events").update(is_active=False)

        get_response = self.client.get(self.url)
        self.assertEqual(get_response.status_code, 200)
        self.assertNotIn(
            "imaa-events",
            {item["slug"] for item in get_response.data["preferences"]},
        )

        patch_response = self.client.patch(
            self.url,
            {"preferences": [{"slug": "imaa-events", "subscribed": True}]},
            format="json",
        )
        self.assertEqual(patch_response.status_code, 400)
        self.assertFalse(
            NewsletterSubscription.objects.filter(user=self.user).exists()
        )

    def test_unknown_category_is_rejected(self):
        self._authenticate()
        response = self.client.patch(
            self.url,
            {
                "preferences": [
                    {"slug": "not-a-real-newsletter", "subscribed": True}
                ]
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(
            NewsletterSubscription.objects.filter(user=self.user).exists()
        )

    def test_duplicate_category_in_payload_is_rejected(self):
        self._authenticate()
        response = self.client.patch(
            self.url,
            {
                "preferences": [
                    {"slug": "imaa-events", "subscribed": True},
                    {"slug": "imaa-events", "subscribed": False},
                ]
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_unique_user_category_constraint(self):
        category = NewsletterCategory.objects.get(slug="imaa-events")
        NewsletterSubscription.objects.create(
            user=self.user,
            category=category,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                NewsletterSubscription.objects.create(
                    user=self.user,
                    category=category,
                )
