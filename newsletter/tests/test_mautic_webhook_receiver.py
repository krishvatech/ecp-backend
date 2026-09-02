import base64
import hashlib
import hmac
import json

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.models import (
    MauticContactMapping,
    NewsletterCampaign,
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterCampaignTrackingEvent,
)


User = get_user_model()


@override_settings(MAUTIC_WEBHOOK_SECRET="webhook-secret")
class MauticNewsletterWebhookReceiverTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("newsletter-mautic-webhook")
        self.campaign = NewsletterCampaign.objects.create(
            name="Webhook Campaign",
            subject="Webhook subject",
            mautic_email_id="77",
        )
        self.user = User.objects.create_user(
            username="mautic-webhook-user",
            email="mautic-webhook-user@example.test",
            password="test-password",
        )

    def signed_post(self, payload, *, signature=None):
        if isinstance(payload, bytes):
            body = payload
        else:
            body = json.dumps(payload).encode("utf-8")
        if signature is None:
            digest = hmac.new(
                b"webhook-secret",
                body,
                hashlib.sha256,
            ).digest()
            signature = base64.b64encode(digest).decode()
        return self.client.post(
            self.url,
            data=body,
            content_type="application/json",
            HTTP_WEBHOOK_SIGNATURE=signature,
        )

    def event_payload(self, **overrides):
        payload = {
            "email": {"id": 77, "name": "Webhook Campaign"},
            "contact": {
                "id": 101,
                "fields": {
                    "core": {
                        "email": {
                            "value": "recipient@example.test",
                        },
                    },
                },
            },
            "idHash": "send-hash-1",
            "timestamp": "2026-09-02T10:00:00+00:00",
        }
        payload.update(overrides)
        return payload

    def click_payload(self, **overrides):
        payload = {
            "hit": {
                "id": 501,
                "source": "email",
                "sourceId": 77,
                "url": "https://example.test/story",
                "lead": {
                    "id": 101,
                    "fields": {
                        "core": {
                            "email": {
                                "value": "recipient@example.test",
                            },
                        },
                    },
                },
            },
            "timestamp": "2026-09-02T10:15:00+00:00",
        }
        payload.update(overrides)
        return payload

    def unsubscribe_payload(self, **overrides):
        payload = {
            "email": {"id": 77, "name": "Webhook Campaign"},
            "contact": {
                "id": 101,
                "fields": {
                    "core": {
                        "email": {
                            "value": "recipient@example.test",
                        },
                    },
                },
            },
            "eventId": "unsubscribe-event-1",
            "channel": "email",
            "subscribed": False,
            "reason": "unsubscribed",
            "timestamp": "2026-09-02T10:30:00+00:00",
        }
        payload.update(overrides)
        return payload

    def bounce_payload(self, **overrides):
        payload = {
            "email": {"id": 77, "name": "Webhook Campaign"},
            "contact": {
                "id": 101,
                "fields": {
                    "core": {
                        "email": {
                            "value": "recipient@example.test",
                        },
                    },
                },
            },
            "eventId": "bounce-event-1",
            "channel": "email",
            "subscribed": False,
            "reason": "bounced",
            "timestamp": "2026-09-02T10:45:00+00:00",
        }
        payload.update(overrides)
        return payload

    def test_valid_signature_creates_opened_event(self):
        response = self.signed_post(
            {
                "mautic.email_on_open": [
                    self.event_payload(idHash="open-hash-1"),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["created"], 1)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertEqual(event.campaign, self.campaign)
        self.assertEqual(
            event.event_type,
            NewsletterCampaignTrackingEvent.EventType.OPENED,
        )
        self.assertEqual(event.mautic_contact_id, "101")
        self.assertEqual(event.recipient_email, "recipient@example.test")
        self.assertEqual(event.provider_event_id, "open-hash-1")
        self.assertEqual(event.payload["idHash"], "open-hash-1")
        self.assertEqual(event.occurred_at.isoformat(), "2026-09-02T10:00:00+00:00")

    def test_valid_signature_creates_delivered_event(self):
        response = self.signed_post(
            {
                "mautic.email_on_send": [
                    self.event_payload(idHash="send-hash-2"),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertEqual(
            event.event_type,
            NewsletterCampaignTrackingEvent.EventType.DELIVERED,
        )

    def test_valid_signature_creates_clicked_event(self):
        response = self.signed_post(
            {
                "mautic.page_on_hit": [
                    self.click_payload(),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["created"], 1)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertEqual(
            event.event_type,
            NewsletterCampaignTrackingEvent.EventType.CLICKED,
        )
        self.assertEqual(event.mautic_contact_id, "101")
        self.assertEqual(event.recipient_email, "recipient@example.test")
        self.assertEqual(event.provider_event_id, "501")
        self.assertEqual(event.url, "https://example.test/story")
        self.assertEqual(event.payload["hit"]["url"], "https://example.test/story")
        self.assertEqual(event.occurred_at.isoformat(), "2026-09-02T10:15:00+00:00")

    def test_valid_signature_creates_unsubscribed_event(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.unsubscribe_payload(),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["created"], 1)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertEqual(event.campaign, self.campaign)
        self.assertEqual(
            event.event_type,
            NewsletterCampaignTrackingEvent.EventType.UNSUBSCRIBED,
        )
        self.assertEqual(event.mautic_contact_id, "101")
        self.assertEqual(event.recipient_email, "recipient@example.test")
        self.assertEqual(event.provider_event_id, "unsubscribe-event-1")
        self.assertEqual(event.payload["reason"], "unsubscribed")
        self.assertEqual(event.occurred_at.isoformat(), "2026-09-02T10:30:00+00:00")

    def test_valid_signature_creates_bounced_event(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.bounce_payload(),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["created"], 1)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertEqual(event.campaign, self.campaign)
        self.assertEqual(
            event.event_type,
            NewsletterCampaignTrackingEvent.EventType.BOUNCED,
        )
        self.assertEqual(event.mautic_contact_id, "101")
        self.assertEqual(event.recipient_email, "recipient@example.test")
        self.assertEqual(event.provider_event_id, "bounce-event-1")
        self.assertEqual(event.payload["reason"], "bounced")
        self.assertEqual(event.occurred_at.isoformat(), "2026-09-02T10:45:00+00:00")

    def test_click_event_can_match_campaign_with_deprecated_hit_email(self):
        response = self.signed_post(
            {
                "mautic.page_on_hit": [
                    self.click_payload(
                        hit={
                            "id": 502,
                            "email": {"id": 77},
                            "url": "https://example.test/deprecated",
                            "lead": {"id": 101},
                        }
                    ),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertEqual(
            event.event_type,
            NewsletterCampaignTrackingEvent.EventType.CLICKED,
        )
        self.assertEqual(event.url, "https://example.test/deprecated")

    def test_invalid_signature_returns_401(self):
        response = self.signed_post(
            {"mautic.email_on_open": [self.event_payload()]},
            signature="not-valid",
        )

        self.assertEqual(response.status_code, 401)
        self.assertFalse(NewsletterCampaignTrackingEvent.objects.exists())

    def test_missing_signature_returns_401(self):
        response = self.signed_post(
            {"mautic.email_on_open": [self.event_payload()]},
            signature="",
        )

        self.assertEqual(response.status_code, 401)
        self.assertFalse(NewsletterCampaignTrackingEvent.objects.exists())

    def test_invalid_json_returns_400(self):
        response = self.signed_post(b"{not-json")

        self.assertEqual(response.status_code, 400)
        self.assertFalse(NewsletterCampaignTrackingEvent.objects.exists())

    def test_duplicate_provider_event_id_does_not_create_duplicate(self):
        payload = {
            "mautic.email_on_open": [
                self.event_payload(idHash="duplicate-hash"),
            ],
        }

        first = self.signed_post(payload)
        second = self.signed_post(payload)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.data["created"], 1)
        self.assertEqual(second.data["duplicate"], 1)
        self.assertEqual(NewsletterCampaignTrackingEvent.objects.count(), 1)

    def test_duplicate_click_provider_event_id_does_not_create_duplicate(self):
        payload = {
            "mautic.page_on_hit": [
                self.click_payload(hit={**self.click_payload()["hit"], "id": 503}),
            ],
        }

        first = self.signed_post(payload)
        second = self.signed_post(payload)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.data["created"], 1)
        self.assertEqual(second.data["duplicate"], 1)
        self.assertEqual(NewsletterCampaignTrackingEvent.objects.count(), 1)

    def test_duplicate_unsubscribe_provider_event_id_does_not_create_duplicate(self):
        payload = {
            "mautic.lead_channel_subscription_changed": [
                self.unsubscribe_payload(eventId="unsubscribe-duplicate"),
            ],
        }

        first = self.signed_post(payload)
        second = self.signed_post(payload)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.data["created"], 1)
        self.assertEqual(second.data["duplicate"], 1)
        self.assertEqual(NewsletterCampaignTrackingEvent.objects.count(), 1)

    def test_duplicate_bounce_provider_event_id_does_not_create_duplicate(self):
        payload = {
            "mautic.lead_channel_subscription_changed": [
                self.bounce_payload(eventId="bounce-duplicate"),
            ],
        }

        first = self.signed_post(payload)
        second = self.signed_post(payload)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.data["created"], 1)
        self.assertEqual(second.data["duplicate"], 1)
        self.assertEqual(NewsletterCampaignTrackingEvent.objects.count(), 1)

    def test_unknown_mautic_email_id_returns_200_ignored(self):
        response = self.signed_post(
            {
                "mautic.email_on_open": [
                    self.event_payload(
                        email={"id": 999, "name": "Unknown Campaign"},
                        idHash="unknown-email-hash",
                    ),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["ignored"], 1)
        self.assertFalse(NewsletterCampaignTrackingEvent.objects.exists())

    def test_unknown_click_campaign_is_ignored_safely(self):
        response = self.signed_post(
            {
                "mautic.page_on_hit": [
                    self.click_payload(hit={**self.click_payload()["hit"], "sourceId": 999}),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["ignored"], 1)
        self.assertFalse(NewsletterCampaignTrackingEvent.objects.exists())

    def test_unknown_unsubscribe_campaign_is_ignored_safely(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.unsubscribe_payload(
                        email={"id": 999, "name": "Unknown Campaign"},
                        eventId="unknown-unsubscribe-campaign",
                    ),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["ignored"], 1)
        self.assertFalse(NewsletterCampaignTrackingEvent.objects.exists())

    def test_unknown_bounce_campaign_is_ignored_safely(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.bounce_payload(
                        email={"id": 999, "name": "Unknown Campaign"},
                        eventId="unknown-bounce-campaign",
                    ),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["ignored"], 1)
        self.assertFalse(NewsletterCampaignTrackingEvent.objects.exists())

    def test_unknown_contact_creates_event_with_null_user(self):
        response = self.signed_post(
            {
                "mautic.email_on_open": [
                    self.event_payload(idHash="unknown-contact-hash"),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertIsNone(event.user)
        self.assertEqual(event.mautic_contact_id, "101")

    def test_unknown_click_contact_creates_event_with_null_user(self):
        response = self.signed_post(
            {
                "mautic.page_on_hit": [
                    self.click_payload(),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertIsNone(event.user)
        self.assertEqual(event.mautic_contact_id, "101")

    def test_unknown_unsubscribe_contact_creates_event_with_null_user(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.unsubscribe_payload(eventId="unknown-unsubscribe-contact"),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertIsNone(event.user)
        self.assertEqual(event.mautic_contact_id, "101")

    def test_unknown_bounce_contact_creates_event_with_null_user(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.bounce_payload(eventId="unknown-bounce-contact"),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertIsNone(event.user)
        self.assertEqual(event.mautic_contact_id, "101")

    def test_known_mautic_contact_maps_user(self):
        MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="101",
        )

        response = self.signed_post(
            {
                "mautic.email_on_open": [
                    self.event_payload(idHash="known-contact-hash"),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertEqual(event.user, self.user)

    def test_known_mautic_contact_maps_user_for_unsubscribe(self):
        MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="101",
        )

        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.unsubscribe_payload(eventId="known-unsubscribe-contact"),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertEqual(event.user, self.user)

    def test_known_mautic_contact_maps_user_for_bounce(self):
        MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="101",
        )

        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.bounce_payload(eventId="known-bounce-contact"),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertEqual(event.user, self.user)

    def test_multiple_events_in_one_payload_create_multiple_tracking_events(self):
        response = self.signed_post(
            {
                "mautic.email_on_open": [
                    self.event_payload(idHash="multi-open-1"),
                    self.event_payload(idHash="multi-open-2"),
                ],
                "mautic.email_on_send": [
                    self.event_payload(idHash="multi-send-1"),
                ],
                "mautic.unknown_event": [
                    {"id": "ignored-event"},
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["created"], 3)
        self.assertEqual(response.data["ignored"], 1)
        self.assertEqual(NewsletterCampaignTrackingEvent.objects.count(), 3)
        self.assertEqual(
            NewsletterCampaignTrackingEvent.objects.filter(
                event_type=NewsletterCampaignTrackingEvent.EventType.OPENED,
            ).count(),
            2,
        )
        self.assertEqual(
            NewsletterCampaignTrackingEvent.objects.filter(
                event_type=NewsletterCampaignTrackingEvent.EventType.DELIVERED,
            ).count(),
            1,
        )

    def test_batched_click_payload_creates_multiple_events(self):
        response = self.signed_post(
            {
                "mautic.page_on_hit": [
                    self.click_payload(hit={**self.click_payload()["hit"], "id": 601}),
                    self.click_payload(
                        hit={
                            **self.click_payload()["hit"],
                            "id": 602,
                            "url": "https://example.test/second",
                        }
                    ),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["created"], 2)
        self.assertEqual(
            NewsletterCampaignTrackingEvent.objects.filter(
                event_type=NewsletterCampaignTrackingEvent.EventType.CLICKED,
            ).count(),
            2,
        )
        self.assertEqual(
            set(NewsletterCampaignTrackingEvent.objects.values_list("url", flat=True)),
            {"https://example.test/story", "https://example.test/second"},
        )

    def test_batched_unsubscribe_payload_creates_multiple_events(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.unsubscribe_payload(eventId="unsubscribe-batch-1"),
                    self.unsubscribe_payload(
                        eventId="unsubscribe-batch-2",
                        contact={
                            "id": 102,
                            "email": "second-recipient@example.test",
                        },
                    ),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["created"], 2)
        self.assertEqual(
            NewsletterCampaignTrackingEvent.objects.filter(
                event_type=NewsletterCampaignTrackingEvent.EventType.UNSUBSCRIBED,
            ).count(),
            2,
        )
        self.assertEqual(
            set(
                NewsletterCampaignTrackingEvent.objects.values_list(
                    "mautic_contact_id",
                    flat=True,
                )
            ),
            {"101", "102"},
        )

    def test_batched_bounce_payload_creates_multiple_events(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.bounce_payload(eventId="bounce-batch-1"),
                    self.bounce_payload(
                        eventId="bounce-batch-2",
                        contact={
                            "id": 102,
                            "email": "second-recipient@example.test",
                        },
                    ),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["created"], 2)
        self.assertEqual(
            NewsletterCampaignTrackingEvent.objects.filter(
                event_type=NewsletterCampaignTrackingEvent.EventType.BOUNCED,
            ).count(),
            2,
        )
        self.assertEqual(
            set(
                NewsletterCampaignTrackingEvent.objects.values_list(
                    "mautic_contact_id",
                    flat=True,
                )
            ),
            {"101", "102"},
        )

    def test_subscribe_channel_change_is_ignored(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.unsubscribe_payload(
                        eventId="subscribe-change",
                        subscribed=True,
                        reason="subscribed",
                    ),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["ignored"], 1)
        self.assertFalse(NewsletterCampaignTrackingEvent.objects.exists())

    def test_unsubscribe_payload_does_not_create_bounced_event(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.unsubscribe_payload(eventId="not-bounce"),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertEqual(
            event.event_type,
            NewsletterCampaignTrackingEvent.EventType.UNSUBSCRIBED,
        )

    def test_subscription_change_without_bounce_reason_is_ignored(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.bounce_payload(
                        eventId="generic-channel-change",
                        subscribed=True,
                        reason="manual",
                        status="active",
                    ),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["ignored"], 1)
        self.assertFalse(NewsletterCampaignTrackingEvent.objects.exists())

    def test_unsubscribe_webhook_does_not_change_newsletter_subscription(self):
        category = NewsletterCategory.objects.create(
            name="Webhook Preference Category",
            slug="webhook-preference-category",
        )
        subscription = NewsletterSubscription.objects.create(
            user=self.user,
            category=category,
            is_subscribed=True,
            subscribed_at=timezone.now(),
        )
        MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="101",
        )

        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.unsubscribe_payload(eventId="preference-unchanged"),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        subscription.refresh_from_db()
        self.assertTrue(subscription.is_subscribed)
        self.assertIsNone(subscription.unsubscribed_at)

    def test_bounce_webhook_does_not_change_newsletter_subscription(self):
        category = NewsletterCategory.objects.create(
            name="Webhook Bounce Preference Category",
            slug="webhook-bounce-preference-category",
        )
        subscription = NewsletterSubscription.objects.create(
            user=self.user,
            category=category,
            is_subscribed=True,
            subscribed_at=timezone.now(),
        )
        MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="101",
        )

        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.bounce_payload(eventId="bounce-preference-unchanged"),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        subscription.refresh_from_db()
        self.assertTrue(subscription.is_subscribed)
        self.assertIsNone(subscription.unsubscribed_at)

    def test_missing_timestamp_falls_back_to_now(self):
        before = timezone.now()

        response = self.signed_post(
            {
                "mautic.email_on_open": [
                    self.event_payload(idHash="no-timestamp", timestamp=""),
                ],
            }
        )

        self.assertEqual(response.status_code, 200)
        event = NewsletterCampaignTrackingEvent.objects.get()
        self.assertGreaterEqual(event.occurred_at, before)
