import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.mautic import TemporaryMauticError
from newsletter.models import (
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCampaignTrackingEvent,
)


User = get_user_model()


class NewsletterCampaignAnalyticsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.normal_user = User.objects.create_user(
            username="analytics-normal",
            email="analytics-normal@example.test",
            password="test-password",
        )
        self.staff = User.objects.create_user(
            username="analytics-staff",
            email="analytics-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.campaign = NewsletterCampaign.objects.create(
            name="Analytics Campaign",
            status=NewsletterCampaign.Status.SENT,
        )
        self.url = reverse(
            "newsletter-admin-campaign-analytics",
            args=[self.campaign.uuid],
        )

    def create_send_event(self, **overrides):
        values = {
            "campaign": self.campaign,
            "idempotency_key": f"analytics-send-{uuid.uuid4()}",
            "status": NewsletterCampaignSendEvent.Status.SUCCEEDED,
            "attempt_count": 1,
            "provider_sent_count": 100,
            "provider_failed_count": 2,
        }
        values.update(overrides)
        return NewsletterCampaignSendEvent.objects.create(**values)

    def create_tracking_event(self, event_type, **overrides):
        values = {
            "campaign": self.campaign,
            "event_type": event_type,
            "occurred_at": timezone.now(),
        }
        values.update(overrides)
        return NewsletterCampaignTrackingEvent.objects.create(**values)

    def authenticate_staff(self):
        self.client.force_authenticate(user=self.staff)

    def test_staff_user_can_access_endpoint(self):
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["campaign_uuid"], str(self.campaign.uuid))

    def test_non_staff_user_is_denied(self):
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)

    def test_anonymous_user_is_denied(self):
        response = self.client.get(self.url)

        self.assertIn(response.status_code, (401, 403))

    def test_unknown_campaign_uuid_returns_404(self):
        self.authenticate_staff()
        url = reverse("newsletter-admin-campaign-analytics", args=[uuid.uuid4()])

        response = self.client.get(url)

        self.assertEqual(response.status_code, 404)

    def test_send_summary_uses_provider_counts(self):
        self.create_send_event(
            status=NewsletterCampaignSendEvent.Status.SUCCEEDED,
            attempt_count=3,
            provider_sent_count=98,
            provider_failed_count=2,
        )
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["send_summary"]["sent_count"], 98)
        self.assertEqual(response.data["send_summary"]["failed_count"], 2)
        self.assertEqual(response.data["send_summary"]["success_rate"], 0.98)
        self.assertEqual(response.data["send_summary"]["attempt_count"], 3)
        self.assertEqual(
            response.data["send_summary"]["send_status"],
            NewsletterCampaignSendEvent.Status.SUCCEEDED,
        )

    def test_tracking_events_are_aggregated_by_type(self):
        self.create_tracking_event(NewsletterCampaignTrackingEvent.EventType.DELIVERED)
        self.create_tracking_event(NewsletterCampaignTrackingEvent.EventType.OPENED)
        self.create_tracking_event(NewsletterCampaignTrackingEvent.EventType.CLICKED)
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.UNSUBSCRIBED
        )
        self.create_tracking_event(NewsletterCampaignTrackingEvent.EventType.BOUNCED)
        self.create_tracking_event(NewsletterCampaignTrackingEvent.EventType.FAILED)
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["engagement"]["delivered_count"], 1)
        self.assertEqual(response.data["engagement"]["opened_count"], 1)
        self.assertEqual(response.data["engagement"]["clicked_count"], 1)
        self.assertEqual(response.data["engagement"]["unsubscribe_count"], 1)
        self.assertEqual(response.data["engagement"]["bounced_count"], 1)
        self.assertEqual(response.data["engagement"]["failed_count"], 1)

    def test_duplicate_open_and_click_identity_counts_once(self):
        user = User.objects.create_user(
            username="analytics-recipient",
            email="analytics-recipient@example.test",
            password="test-password",
        )
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.OPENED,
            user=user,
            recipient_email="ignored-first@example.test",
        )
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.OPENED,
            user=user,
            recipient_email="ignored-second@example.test",
        )
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.CLICKED,
            mautic_contact_id="101",
        )
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.CLICKED,
            mautic_contact_id="101",
        )
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["engagement"]["opened_count"], 2)
        self.assertEqual(response.data["engagement"]["unique_open_count"], 1)
        self.assertEqual(response.data["engagement"]["clicked_count"], 2)
        self.assertEqual(response.data["engagement"]["unique_click_count"], 1)

    def test_different_recipient_identities_increase_unique_counts(self):
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.OPENED,
            mautic_contact_id="101",
        )
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.OPENED,
            mautic_contact_id="102",
        )
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.CLICKED,
            recipient_email="First@example.test",
        )
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.CLICKED,
            recipient_email="second@example.test",
        )
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["engagement"]["unique_open_count"], 2)
        self.assertEqual(response.data["engagement"]["unique_click_count"], 2)

    def test_events_without_identity_are_not_unique(self):
        self.create_tracking_event(NewsletterCampaignTrackingEvent.EventType.OPENED)
        self.create_tracking_event(NewsletterCampaignTrackingEvent.EventType.CLICKED)
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["engagement"]["opened_count"], 1)
        self.assertEqual(response.data["engagement"]["unique_open_count"], 0)
        self.assertEqual(response.data["engagement"]["clicked_count"], 1)
        self.assertEqual(response.data["engagement"]["unique_click_count"], 0)

    def test_empty_campaign_returns_zero_metrics(self):
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["send_summary"]["sent_count"], 0)
        self.assertEqual(response.data["send_summary"]["failed_count"], 0)
        self.assertEqual(response.data["send_summary"]["success_rate"], 0)
        self.assertEqual(response.data["send_summary"]["attempt_count"], 0)
        self.assertEqual(response.data["send_summary"]["send_status"], "")
        self.assertEqual(response.data["engagement"]["delivered_count"], 0)
        self.assertEqual(response.data["engagement"]["opened_count"], 0)
        self.assertEqual(response.data["engagement"]["unique_open_count"], 0)
        self.assertEqual(response.data["engagement"]["clicked_count"], 0)
        self.assertEqual(response.data["engagement"]["unique_click_count"], 0)
        self.assertEqual(response.data["engagement"]["unsubscribe_count"], 0)
        self.assertEqual(response.data["engagement"]["bounced_count"], 0)
        self.assertEqual(response.data["engagement"]["failed_count"], 0)
        self.assertEqual(response.data["rates"]["open_rate"], 0)
        self.assertEqual(response.data["rates"]["click_rate"], 0)
        self.assertEqual(response.data["rates"]["unsubscribe_rate"], 0)

    @patch("newsletter.analytics_services.MauticClient")
    def test_campaign_without_mautic_email_id_uses_ecp_only(self, client_cls):
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        client_cls.assert_not_called()
        self.assertEqual(response.data["metadata"]["sources"], ["ecp"])
        self.assertIsNone(response.data["metadata"]["mautic_email_id"])
        self.assertFalse(response.data["metadata"]["mautic_available"])

    @patch("newsletter.analytics_services.MauticClient")
    def test_mautic_stats_success_adds_metadata_and_open_counts(self, client_cls):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        client_cls.return_value.get_email_stats.return_value = {
            "total": 3,
            "data": [
                {
                    "id": 1,
                    "email_id": 77,
                    "lead_id": 101,
                    "email_address": "first@example.test",
                    "is_read": True,
                },
                {
                    "id": 2,
                    "email_id": 77,
                    "lead_id": 102,
                    "email_address": "second@example.test",
                    "date_read": "2026-09-03T10:00:00+00:00",
                },
                {
                    "id": 3,
                    "email_id": 77,
                    "lead_id": 103,
                    "email_address": "third@example.test",
                    "is_read": False,
                },
            ],
        }
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        client_cls.return_value.get_email_stats.assert_called_once_with("77")
        self.assertEqual(response.data["engagement"]["opened_count"], 2)
        self.assertEqual(response.data["engagement"]["unique_open_count"], 2)
        self.assertEqual(response.data["metadata"]["sources"], ["ecp", "mautic"])
        self.assertEqual(response.data["metadata"]["mautic_email_id"], "77")
        self.assertTrue(response.data["metadata"]["mautic_available"])
        self.assertEqual(response.data["metadata"]["mautic_stats_count"], 3)

    @patch("newsletter.analytics_services.MauticClient")
    def test_mautic_stats_unavailable_returns_ecp_analytics_with_warning(self, client_cls):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.OPENED,
            recipient_email="local-open@example.test",
        )
        client_cls.return_value.get_email_stats.side_effect = TemporaryMauticError(
            "Stats unavailable"
        )
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["engagement"]["opened_count"], 1)
        self.assertEqual(response.data["engagement"]["unique_open_count"], 1)
        self.assertEqual(response.data["metadata"]["sources"], ["ecp", "mautic"])
        self.assertFalse(response.data["metadata"]["mautic_available"])
        self.assertIn("Stats unavailable", response.data["metadata"]["warnings"])

    @patch("newsletter.analytics_services.MauticClient")
    def test_mautic_open_counts_replace_webhook_opens_without_double_counting(
        self,
        client_cls,
    ):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        self.create_send_event(provider_sent_count=10, provider_failed_count=0)
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.OPENED,
            recipient_email="webhook-open@example.test",
        )
        client_cls.return_value.get_email_stats.return_value = {
            "total": 2,
            "data": [
                {
                    "id": 1,
                    "lead_id": 101,
                    "email_address": "first@example.test",
                    "is_read": True,
                },
                {
                    "id": 2,
                    "lead_id": 101,
                    "email_address": "first@example.test",
                    "last_opened": "2026-09-03T10:00:00+00:00",
                },
            ],
        }
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["engagement"]["opened_count"], 2)
        self.assertEqual(response.data["engagement"]["unique_open_count"], 1)
        self.assertEqual(response.data["rates"]["open_rate"], 0.1)

    @patch("newsletter.analytics_services.MauticClient")
    def test_existing_webhook_click_counts_remain_when_mautic_stats_are_used(
        self,
        client_cls,
    ):
        self.campaign.mautic_email_id = "77"
        self.campaign.save(update_fields=["mautic_email_id"])
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.CLICKED,
            mautic_contact_id="101",
        )
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.CLICKED,
            mautic_contact_id="101",
        )
        client_cls.return_value.get_email_stats.return_value = {
            "total": 1,
            "data": [
                {
                    "id": 1,
                    "lead_id": 101,
                    "email_address": "first@example.test",
                    "is_read": True,
                },
            ],
        }
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["engagement"]["opened_count"], 1)
        self.assertEqual(response.data["engagement"]["clicked_count"], 2)
        self.assertEqual(response.data["engagement"]["unique_click_count"], 1)

    def test_rates_use_delivered_count_then_provider_sent_count(self):
        self.create_send_event(provider_sent_count=10, provider_failed_count=0)
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.OPENED,
            recipient_email="open@example.test",
        )
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.CLICKED,
            recipient_email="click@example.test",
        )
        self.create_tracking_event(
            NewsletterCampaignTrackingEvent.EventType.UNSUBSCRIBED,
            recipient_email="unsubscribe@example.test",
        )
        self.authenticate_staff()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["rates"]["open_rate"], 0.1)
        self.assertEqual(response.data["rates"]["click_rate"], 0.1)
        self.assertEqual(response.data["rates"]["unsubscribe_rate"], 0.1)

        self.create_tracking_event(NewsletterCampaignTrackingEvent.EventType.DELIVERED)
        self.create_tracking_event(NewsletterCampaignTrackingEvent.EventType.DELIVERED)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["rates"]["open_rate"], 0.5)
        self.assertEqual(response.data["rates"]["click_rate"], 0.5)
        self.assertEqual(response.data["rates"]["unsubscribe_rate"], 0.5)
