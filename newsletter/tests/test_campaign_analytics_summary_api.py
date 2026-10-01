"""Broadcast list analytics: one read-only request for many Broadcasts."""

import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.forms.models import model_to_dict
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter import marketing_cache
from newsletter.analytics_services import get_campaign_analytics
from newsletter.mautic import TemporaryMauticError
from newsletter.models import (
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCampaignTrackingEvent,
)
from newsletter.tests.marketing_actors import grant_marketing_access


User = get_user_model()

CACHE_ON = dict(
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "broadcast-analytics-summary-tests",
        }
    },
    MARKETING_RESPONSE_CACHE_ENABLED=True,
)


def stats(rows, total=None):
    return {"total": len(rows) if total is None else total, "data": rows}


def read_row(lead_id, read=True):
    return {"lead_id": lead_id, "email_address": f"r{lead_id}@example.test", "is_read": read}


class AnalyticsSummaryTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_superuser(
            username="summary-staff",
            email="summary-staff@example.test",
            password="test-password",
        )
        grant_marketing_access(self.staff)
        self.client.force_authenticate(user=self.staff)
        self.url = reverse("newsletter-admin-campaign-analytics-summary")
        patcher = patch("newsletter.analytics_services.MauticClient")
        self.mautic = patcher.start().return_value
        self.addCleanup(patcher.stop)

    def broadcast(self, **fields):
        return NewsletterCampaign.objects.create(name="Broadcast", **fields)

    def track(self, campaign, event_type, identity):
        return NewsletterCampaignTrackingEvent.objects.create(
            campaign=campaign,
            event_type=event_type,
            recipient_email=f"{identity}@example.test",
            occurred_at=timezone.now(),
        )

    def summary(self, *campaigns, **params):
        return self.client.get(
            self.url,
            {"uuids": ",".join(str(c.uuid) for c in campaigns), **params},
        )

    def detail(self, campaign):
        return self.client.get(
            reverse("newsletter-admin-campaign-analytics", args=[campaign.uuid])
        )


class NewsletterCampaignAnalyticsSummaryAPITests(AnalyticsSummaryTestCase):
    def test_sent_broadcast_with_engagement_matches_the_detail_endpoint(self):
        sent = self.broadcast(status="sent", mautic_email_id="77")
        self.mautic.get_email_stats.return_value = stats(
            [read_row(1), read_row(2), read_row(3, read=False), read_row(4, read=False)]
        )
        self.track(sent, NewsletterCampaignTrackingEvent.EventType.CLICKED, "r1")

        response = self.summary(sent)

        self.assertEqual(response.status_code, 200)
        entry = response.data["results"][str(sent.uuid)]
        self.assertEqual(entry["send_summary"]["sent_count"], 4)
        self.assertEqual(entry["engagement"]["unique_open_count"], 2)
        self.assertEqual(entry["engagement"]["unique_click_count"], 1)
        # Same denominator as the editor: delivered, else provider sends.
        self.assertEqual(entry["rates"]["open_rate"], 0.5)
        self.assertEqual(entry["rates"]["click_rate"], 0.25)
        self.assertTrue(entry["metadata"]["mautic_available"])
        self.assertEqual(entry["metadata"]["send_summary_source"], "mautic")

        detail = self.detail(sent).data
        for section in ("send_summary", "engagement", "rates"):
            self.assertEqual(entry[section], detail[section], section)

    def test_sent_broadcast_with_zero_engagement_has_a_real_zero_rate(self):
        sent = self.broadcast(status="sent")
        NewsletterCampaignSendEvent.objects.create(
            campaign=sent,
            idempotency_key=f"summary-{uuid.uuid4()}",
            status=NewsletterCampaignSendEvent.Status.SUCCEEDED,
            provider_sent_count=10,
        )

        entry = self.summary(sent).data["results"][str(sent.uuid)]

        self.assertEqual(entry["send_summary"]["sent_count"], 10)
        self.assertEqual(entry["rates"]["open_rate"], 0)
        self.assertEqual(entry["rates"]["click_rate"], 0)
        self.assertEqual(entry["metadata"]["send_summary_source"], "ecp")

    def test_draft_without_mautic_email_has_no_send_data_and_no_mautic_call(self):
        draft = self.broadcast(status="draft")

        entry = self.summary(draft).data["results"][str(draft.uuid)]

        self.assertEqual(entry["send_summary"]["sent_count"], 0)
        self.assertEqual(entry["engagement"]["delivered_count"], 0)
        self.assertIsNone(entry["metadata"]["mautic_email_id"])
        self.mautic.get_email_stats.assert_not_called()

    def test_synced_but_unsent_broadcast_has_no_sends(self):
        synced = self.broadcast(status="draft", mautic_email_id="78")
        self.mautic.get_email_stats.return_value = stats([])

        entry = self.summary(synced).data["results"][str(synced.uuid)]

        self.assertEqual(entry["send_summary"]["sent_count"], 0)
        self.assertTrue(entry["metadata"]["mautic_available"])

    def test_mautic_unavailable_is_reported_per_broadcast(self):
        sent = self.broadcast(status="sent", mautic_email_id="79")
        self.mautic.get_email_stats.side_effect = TemporaryMauticError("Stats unavailable")

        response = self.summary(sent)

        self.assertEqual(response.status_code, 200)
        entry = response.data["results"][str(sent.uuid)]
        self.assertFalse(entry["metadata"]["mautic_available"])
        self.assertEqual(entry["metadata"]["mautic_email_id"], "79")
        # Provider text stays on the per-Broadcast endpoint, not in the list.
        self.assertNotIn("warnings", entry["metadata"])

    def test_one_failing_broadcast_does_not_hide_the_others(self):
        good = self.broadcast(status="draft")
        bad = self.broadcast(status="sent")
        def flaky(campaign):
            if campaign.pk == bad.pk:
                raise RuntimeError("boom")
            return get_campaign_analytics(campaign)

        with patch("newsletter.admin_views.get_campaign_analytics", side_effect=flaky):
            with self.assertLogs("newsletter.admin_views", level="WARNING"):
                response = self.summary(good, bad)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["results"][str(bad.uuid)], {"error": "unavailable"})
        self.assertIn("rates", response.data["results"][str(good.uuid)])

    def test_unknown_uuids_are_omitted_and_empty_requests_are_empty(self):
        known = self.broadcast(status="draft")

        response = self.client.get(self.url, {"uuids": f"{known.uuid},{uuid.uuid4()}"})
        self.assertEqual(list(response.data["results"]), [str(known.uuid)])

        self.assertEqual(self.client.get(self.url).data, {"results": {}})

    def test_invalid_or_too_many_uuids_are_rejected(self):
        self.assertEqual(self.client.get(self.url, {"uuids": "not-a-uuid"}).status_code, 400)
        many = ",".join(str(uuid.uuid4()) for _ in range(201))
        self.assertEqual(self.client.get(self.url, {"uuids": many}).status_code, 400)

    def test_reading_analytics_writes_nothing(self):
        sent = self.broadcast(status="sent", mautic_email_id="80", last_error="")
        self.track(sent, NewsletterCampaignTrackingEvent.EventType.OPENED, "r1")
        self.mautic.get_email_stats.return_value = stats([read_row(1)])
        before = model_to_dict(sent)
        counts = (
            NewsletterCampaign.objects.count(),
            NewsletterCampaignSendEvent.objects.count(),
            NewsletterCampaignTrackingEvent.objects.count(),
        )

        self.summary(sent)

        sent.refresh_from_db()
        self.assertEqual(model_to_dict(sent), before)
        self.assertEqual(
            counts,
            (
                NewsletterCampaign.objects.count(),
                NewsletterCampaignSendEvent.objects.count(),
                NewsletterCampaignTrackingEvent.objects.count(),
            ),
        )
        # Only the read endpoint of the client is used.
        self.assertEqual(
            {name for name, _, _ in self.mautic.method_calls},
            {"get_email_stats"},
        )

    def test_requires_marketing_hub_access(self):
        normal = User.objects.create_user(
            username="summary-normal",
            email="summary-normal@example.test",
            password="test-password",
        )
        self.client.force_authenticate(user=normal)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.client.force_authenticate(user=None)
        self.assertIn(self.client.get(self.url).status_code, (401, 403))


@override_settings(**CACHE_ON)
class NewsletterCampaignAnalyticsSummaryCacheTests(AnalyticsSummaryTestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        marketing_cache.reset_failure_state()
        self.addCleanup(marketing_cache.reset_failure_state)

    def test_complete_results_are_cached_and_refresh_rebuilds(self):
        sent = self.broadcast(status="sent", mautic_email_id="81")
        self.mautic.get_email_stats.return_value = stats([read_row(1)])

        first = self.summary(sent)
        second = self.summary(sent)
        refreshed = self.summary(sent, refresh=1)

        self.assertEqual(first[marketing_cache.CACHE_HEADER], "MISS")
        self.assertEqual(second[marketing_cache.CACHE_HEADER], "HIT")
        self.assertEqual(refreshed[marketing_cache.CACHE_HEADER], "MISS")
        self.assertEqual(self.mautic.get_email_stats.call_count, 2)
        self.assertEqual(first.data, second.data)

    def test_results_with_mautic_unavailable_are_never_cached(self):
        sent = self.broadcast(status="sent", mautic_email_id="82")
        self.mautic.get_email_stats.side_effect = TemporaryMauticError("down")

        self.summary(sent)
        again = self.summary(sent)

        self.assertEqual(again[marketing_cache.CACHE_HEADER], "MISS")
        self.assertEqual(self.mautic.get_email_stats.call_count, 2)
