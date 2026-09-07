from datetime import datetime
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.models import (
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterSyncEvent,
)


User = get_user_model()


class NewsletterCategoryContactAnalyticsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.normal_user = User.objects.create_user(
            username="timeline-normal",
            email="timeline-normal@example.test",
            password="test-password",
        )
        self.staff = User.objects.create_user(
            username="timeline-staff",
            email="timeline-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.category = NewsletterCategory.objects.get(slug="imaa-events")
        self.url = reverse(
            "newsletter-admin-category-contact-analytics",
            args=[self.category.slug],
        )

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def _dt(self, day, hour=12, minute=0):
        return timezone.make_aware(datetime(2026, 9, day, hour, minute))

    def _event(self, *, user, desired, occurred_at, suffix):
        event = NewsletterSyncEvent.objects.create(
            idempotency_key=f"timeline:{user.pk}:{suffix}",
            user_id=str(user.pk),
            category=self.category,
            desired_subscribed=desired,
            status=NewsletterSyncEvent.Status.SUCCEEDED,
            completed_at=occurred_at,
        )
        NewsletterSyncEvent.objects.filter(pk=event.pk).update(
            created_at=occurred_at
        )
        event.created_at = occurred_at
        return event

    def test_guest_and_normal_user_are_denied(self):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    @patch("newsletter.admin_views.MauticClient")
    def test_timeline_counts_real_transitions_and_ignores_reconciliation_duplicates(
        self,
        client_cls,
    ):
        active_user = User.objects.create_user(
            username="timeline-active",
            email="timeline-active@example.test",
        )
        former_user = User.objects.create_user(
            username="timeline-former",
            email="timeline-former@example.test",
        )

        NewsletterSubscription.objects.create(
            user=active_user,
            category=self.category,
            is_subscribed=True,
            subscribed_at=self._dt(1, 9),
        )
        NewsletterSubscription.objects.create(
            user=former_user,
            category=self.category,
            is_subscribed=False,
            subscribed_at=self._dt(1, 10),
            unsubscribed_at=self._dt(3, 10),
        )

        self._event(
            user=active_user,
            desired=True,
            occurred_at=self._dt(1, 9, 1),
            suffix="active-subscribe",
        )
        self._event(
            user=active_user,
            desired=True,
            occurred_at=self._dt(2, 9),
            suffix="active-reconcile",
        )
        self._event(
            user=former_user,
            desired=True,
            occurred_at=self._dt(1, 10, 1),
            suffix="former-subscribe",
        )
        self._event(
            user=former_user,
            desired=False,
            occurred_at=self._dt(3, 10, 1),
            suffix="former-unsubscribe",
        )
        self._event(
            user=former_user,
            desired=False,
            occurred_at=self._dt(4, 10),
            suffix="former-reconcile",
        )

        self._authenticate(self.staff)
        response = self.client.get(
            self.url,
            {"from": "2026-09-01", "to": "2026-09-04"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["current_total"], 1)
        self.assertEqual(response.data["range_start_total"], 0)
        self.assertEqual(
            response.data["series"],
            [
                {"date": "2026-09-01", "added": 2, "removed": 0, "total": 2},
                {"date": "2026-09-02", "added": 0, "removed": 0, "total": 2},
                {"date": "2026-09-03", "added": 0, "removed": 1, "total": 1},
                {"date": "2026-09-04", "added": 0, "removed": 0, "total": 1},
            ],
        )
        client_cls.assert_not_called()

    def test_subscription_timestamps_fill_history_when_sync_events_are_missing(self):
        user = User.objects.create_user(
            username="timeline-local-only",
            email="timeline-local-only@example.test",
        )
        NewsletterSubscription.objects.create(
            user=user,
            category=self.category,
            is_subscribed=True,
            subscribed_at=self._dt(2, 8),
        )
        self._authenticate(self.staff)

        response = self.client.get(
            self.url,
            {"from": "2026-09-01", "to": "2026-09-03"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["series"],
            [
                {"date": "2026-09-01", "added": 0, "removed": 0, "total": 0},
                {"date": "2026-09-02", "added": 1, "removed": 0, "total": 1},
                {"date": "2026-09-03", "added": 0, "removed": 0, "total": 1},
            ],
        )

    def test_invalid_dates_and_oversized_ranges_return_400(self):
        self._authenticate(self.staff)

        invalid = self.client.get(
            self.url,
            {"from": "not-a-date", "to": "2026-09-03"},
        )
        self.assertEqual(invalid.status_code, 400)

        reversed_range = self.client.get(
            self.url,
            {"from": "2026-09-04", "to": "2026-09-03"},
        )
        self.assertEqual(reversed_range.status_code, 400)

        oversized = self.client.get(
            self.url,
            {"from": "2025-01-01", "to": "2026-09-03"},
        )
        self.assertEqual(oversized.status_code, 400)

    def test_unknown_category_returns_404(self):
        self._authenticate(self.staff)
        response = self.client.get(
            reverse(
                "newsletter-admin-category-contact-analytics",
                args=["missing-newsletter"],
            )
        )
        self.assertEqual(response.status_code, 404)

