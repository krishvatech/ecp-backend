from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from newsletter.models import (
    NewsletterCampaign,
    NewsletterCampaignTrackingEvent,
)


class NewsletterCampaignTrackingEventModelTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_user(
            username="newsletter-tracking-user",
            email="newsletter-tracking@example.test",
            password="test-password",
        )
        cls.campaign = NewsletterCampaign.objects.create(
            name="Tracking Campaign",
            subject="Tracking subject",
        )

    def create_event(self, **overrides):
        values = {
            "campaign": self.campaign,
            "event_type": NewsletterCampaignTrackingEvent.EventType.OPENED,
            "occurred_at": timezone.now(),
        }
        values.update(overrides)
        return NewsletterCampaignTrackingEvent.objects.create(**values)

    def test_tracking_event_can_be_created(self):
        event = self.create_event(
            user=self.user,
            mautic_contact_id="101",
            recipient_email="recipient@example.test",
            provider_event_id="mautic-open-1",
        )

        self.assertEqual(event.campaign, self.campaign)
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.source, "mautic")
        self.assertIsNotNone(event.event_uuid)
        self.assertIsNotNone(event.created_at)

    def test_event_type_choices_work(self):
        values = {choice[0] for choice in NewsletterCampaignTrackingEvent.EventType.choices}

        self.assertEqual(
            values,
            {
                "delivered",
                "opened",
                "clicked",
                "unsubscribed",
                "bounced",
                "failed",
            },
        )

    def test_payload_json_stores_correctly(self):
        payload = {
            "event": "email_on_open",
            "contact": {"id": 101, "email": "recipient@example.test"},
        }

        event = self.create_event(payload=payload)

        event.refresh_from_db()
        self.assertEqual(event.payload, payload)

    def test_multiple_events_can_belong_to_same_campaign(self):
        self.create_event(
            event_type=NewsletterCampaignTrackingEvent.EventType.OPENED,
            provider_event_id="tracking-open-1",
        )
        self.create_event(
            event_type=NewsletterCampaignTrackingEvent.EventType.CLICKED,
            provider_event_id="tracking-click-1",
            url="https://example.test/news",
        )

        self.assertEqual(self.campaign.tracking_events.count(), 2)

    def test_optional_user_and_contact_fields_allow_blank_values(self):
        event = self.create_event()

        self.assertIsNone(event.user)
        self.assertEqual(event.mautic_contact_id, "")
        self.assertEqual(event.recipient_email, "")
        self.assertEqual(event.provider_event_id, "")
        self.assertEqual(event.url, "")

    def test_provider_event_id_is_unique_per_source_when_present(self):
        self.create_event(source="mautic", provider_event_id="provider-event-1")

        with self.assertRaises(IntegrityError), transaction.atomic():
            self.create_event(source="mautic", provider_event_id="provider-event-1")

    def test_different_sources_can_reuse_same_provider_event_id(self):
        self.create_event(source="mautic", provider_event_id="provider-event-2")
        second = self.create_event(
            source="manual-import",
            provider_event_id="provider-event-2",
        )

        self.assertEqual(second.provider_event_id, "provider-event-2")

    def test_empty_provider_event_id_allows_multiple_events(self):
        self.create_event()
        self.create_event()

        self.assertEqual(self.campaign.tracking_events.count(), 2)
