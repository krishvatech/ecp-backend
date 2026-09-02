import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

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
