"""Webhook tracking must only attach to the broadcast an event really names.

A Mautic channel-subscription (DNC) change is contact-level: Mautic 7.1.3 sends
it with no email reference. Every unsynced draft broadcast has a blank
``mautic_email_id``, so an empty id must never be used to look a broadcast up.
Consent suppression still has to apply to such events.
"""

import base64
import hashlib
import hmac
import json

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.models import (
    MauticContactMapping,
    MauticEmailSuppression,
    NewsletterCampaign,
    NewsletterCampaignTrackingEvent,
)
from newsletter.services import get_email_suppression_state

User = get_user_model()

SECRET = "webhook-secret"
DNC = "mautic.lead_channel_subscription_changed"


@override_settings(MAUTIC_WEBHOOK_SECRET=SECRET)
class WebhookBroadcastAttributionTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("newsletter-mautic-webhook")
        self.sent = NewsletterCampaign.objects.create(
            name="Sent Broadcast", subject="Sent", mautic_email_id="77"
        )
        # Unsynced drafts: blank mautic_email_id, the value that used to match.
        self.drafts = [
            NewsletterCampaign.objects.create(name=f"Draft {n}", subject=f"Draft {n}")
            for n in range(3)
        ]
        self.user = User.objects.create_user(
            username="webhook-member", email="member@example.test", password="pw"
        )
        MauticContactMapping.objects.create(user=self.user, mautic_contact_id="101")

    def post(self, payload, *, signature=None):
        body = json.dumps(payload).encode()
        if signature is None:
            signature = base64.b64encode(
                hmac.new(SECRET.encode(), body, hashlib.sha256).digest()
            ).decode()
        return self.client.post(
            self.url, data=body, content_type="application/json",
            HTTP_WEBHOOK_SIGNATURE=signature,
        )

    @staticmethod
    def dnc(new_status="unsubscribed", **extra):
        """The contact-level shape Mautic 7.1.3 actually sends: no email."""
        return {
            "contact": {"id": 101},
            "channel": "email",
            "old_status": "contactable",
            "new_status": new_status,
            "timestamp": "2026-10-08T07:12:00+00:00",
            **extra,
        }

    @staticmethod
    def engagement(email_id=77, event_id="evt-1"):
        return {
            "email": {"id": email_id},
            "contact": {"id": 101},
            "idHash": event_id,
            "timestamp": "2026-10-08T07:11:00+00:00",
        }

    def tracking(self):
        return NewsletterCampaignTrackingEvent.objects

    def assert_no_draft_tracking(self):
        self.assertFalse(self.tracking().filter(campaign__in=self.drafts).exists())

    # --- contact-level DNC events: suppression yes, broadcast tracking no ------

    def test_unsubscribe_without_email_reference_suppresses_but_tracks_nothing(self):
        response = self.post({DNC: [self.dnc()]})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["created"], 0)
        self.assertEqual(response.data["consent_synced"], 1)
        self.assertEqual(self.tracking().count(), 0)
        self.assert_no_draft_tracking()
        state = get_email_suppression_state(self.user)
        self.assertTrue(state["suppressed"])
        self.assertEqual(state["reason"], MauticEmailSuppression.Reason.UNSUBSCRIBED)

    def test_bounce_without_email_reference_suppresses_but_tracks_nothing(self):
        response = self.post({DNC: [self.dnc("bounced")]})

        self.assertEqual(response.data["consent_synced"], 1)
        self.assertEqual(self.tracking().count(), 0)
        self.assertEqual(
            get_email_suppression_state(self.user)["reason"],
            MauticEmailSuppression.Reason.BOUNCED,
        )

    def test_repeated_unattributable_unsubscribe_stays_idempotent(self):
        for _ in range(3):
            self.post({DNC: [self.dnc()]})

        self.assertEqual(self.tracking().count(), 0)
        self.assertEqual(MauticEmailSuppression.objects.filter(user=self.user).count(), 1)

    def test_empty_zero_and_malformed_email_ids_never_select_a_broadcast(self):
        for email in ({"id": ""}, {"id": None}, {"id": 0}, {"id": "0"}, {"id": "abc"},
                      {"id": -5}, {"id": "7.7"}, {"id": "\u00b2"}, {}, "77"):
            with self.subTest(email=email):
                response = self.post({DNC: [self.dnc(email=email)]})
                self.assertEqual(response.data["created"], 0)
        self.assertEqual(self.tracking().count(), 0)
        # Suppression still applied, once.
        self.assertEqual(MauticEmailSuppression.objects.filter(user=self.user).count(), 1)

    def test_unmatched_email_id_is_ignored(self):
        response = self.post({DNC: [self.dnc(email={"id": 999}, eventId="u-999")]})

        self.assertEqual(response.data["created"], 0)
        self.assertEqual(response.data["consent_synced"], 1)
        self.assertEqual(self.tracking().count(), 0)

    def test_unsubscribe_that_names_its_broadcast_is_still_tracked(self):
        response = self.post({DNC: [self.dnc(email={"id": 77}, eventId="u-77")]})

        self.assertEqual(response.data["created"], 1)
        event = self.tracking().get()
        self.assertEqual(event.campaign, self.sent)
        self.assertEqual(event.event_type, NewsletterCampaignTrackingEvent.EventType.UNSUBSCRIBED)
        self.assertTrue(get_email_suppression_state(self.user)["suppressed"])

    def test_ambiguous_email_id_is_not_resolved_by_picking_a_row(self):
        NewsletterCampaign.objects.create(name="Clash", subject="Clash", mautic_email_id="88")
        NewsletterCampaign.objects.create(name="Clash 2", subject="Clash 2", mautic_email_id="88")

        response = self.post({"mautic.email_on_open": [self.engagement(88, "evt-88")]})

        self.assertEqual(response.data["created"], 0)
        self.assertEqual(self.tracking().count(), 0)

    # --- email-specific engagement keeps working -------------------------------

    def test_matched_open_delivered_and_click_are_tracked_to_the_right_broadcast(self):
        response = self.post({
            "mautic.email_on_open": [self.engagement(event_id="open-1")],
            "mautic.email_on_send": [self.engagement(event_id="send-1")],
            "mautic.page_on_hit": [{
                "hit": {"id": 501, "source": "email", "sourceId": 77,
                        "url": "https://example.test/x", "lead": {"id": 101}},
                "timestamp": "2026-10-08T07:13:00+00:00",
            }],
        })

        self.assertEqual(response.data["created"], 3)
        self.assertEqual(
            sorted(self.tracking().values_list("event_type", flat=True)),
            ["clicked", "delivered", "opened"],
        )
        self.assertEqual(set(self.tracking().values_list("campaign_id", flat=True)), {self.sent.pk})
        self.assertEqual(set(self.tracking().values_list("user_id", flat=True)), {self.user.pk})
        self.assert_no_draft_tracking()

    def test_open_with_string_email_id_still_matches(self):
        response = self.post({"mautic.email_on_open": [self.engagement("77", "open-str")]})

        self.assertEqual(response.data["created"], 1)
        self.assertEqual(self.tracking().get().campaign, self.sent)

    def test_open_without_email_reference_is_ignored(self):
        payload = self.engagement(event_id="open-none")
        payload.pop("email")
        response = self.post({"mautic.email_on_open": [payload]})

        self.assertEqual(response.data["created"], 0)
        self.assertEqual(self.tracking().count(), 0)

    def test_replayed_engagement_event_is_counted_once(self):
        self.post({"mautic.email_on_open": [self.engagement(event_id="open-dup")]})
        response = self.post({"mautic.email_on_open": [self.engagement(event_id="open-dup")]})

        self.assertEqual(response.data["duplicate"], 1)
        self.assertEqual(self.tracking().count(), 1)

    # --- authentication and unknown types are unchanged ------------------------

    def test_invalid_signature_changes_nothing(self):
        response = self.post({DNC: [self.dnc()]}, signature="not-a-signature")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.tracking().count(), 0)
        self.assertFalse(MauticEmailSuppression.objects.exists())

    def test_unknown_event_type_is_ignored(self):
        response = self.post({"mautic.form_on_submit": [{"id": 1}]})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["ignored"], 1)
        self.assertEqual(self.tracking().count(), 0)
