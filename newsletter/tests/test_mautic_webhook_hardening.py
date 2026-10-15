"""B15: Mautic webhook validation and event processing, against payloads
shaped like real Mautic 7.1.3 deliveries (see mautic_webhook_fixtures)."""

import json
from datetime import datetime, timezone as dt_timezone
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

from newsletter import webhooks
from newsletter.dnc_services import clear_email_suppression, record_email_suppression
from newsletter.models import (
    MauticContactMapping,
    MauticEmailSuppression,
    NewsletterCampaign,
    NewsletterCampaignTrackingEvent,
)
from newsletter.tests import mautic_webhook_fixtures as fx
from newsletter.webhooks import webhook_observations


User = get_user_model()
SECRET = "b15-webhook-secret"
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "b15-webhook-tests"}}


def at(value):
    return datetime.fromisoformat(value).astimezone(dt_timezone.utc)


@override_settings(MAUTIC_WEBHOOK_SECRET=SECRET, CACHES=LOCMEM)
class MauticWebhookHardeningTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.url = reverse("newsletter-mautic-webhook")
        self.campaign = NewsletterCampaign.objects.create(name="B15", subject="B15", mautic_email_id="100")
        self.user = User.objects.create_user(
            username="b15-member", email="b15@example.test", password="test-password",
        )
        MauticContactMapping.objects.create(user=self.user, mautic_contact_id="4288")

    def post(self, payload, *, signature=None, secret=SECRET, body=None, **extra):
        body = body if body is not None else fx.encode(payload)
        return self.client.post(
            self.url,
            data=body,
            content_type="application/json",
            HTTP_WEBHOOK_SIGNATURE=fx.sign(body, secret) if signature is None else signature,
            **extra,
        )

    def tracking(self, **filters):
        return NewsletterCampaignTrackingEvent.objects.filter(source="mautic", **filters)

    # --- Signature (B15-01..05) -------------------------------------------

    def test_real_mautic_signature_is_accepted(self):
        response = self.post(fx.email_on_send())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["created"], 1)

    def test_missing_wrong_and_foreign_secret_signatures_are_rejected(self):
        payload = fx.email_on_send()
        for signature in ("", "not-base64", fx.sign(fx.encode(payload), "other-secret")):
            with self.subTest(signature=signature):
                response = self.post(payload, signature=signature)
                self.assertEqual(response.status_code, 401)
        self.assertFalse(self.tracking().exists())

    def test_tampered_body_is_rejected(self):
        body = fx.encode(fx.email_on_send())
        signature = fx.sign(body, SECRET)
        tampered = body.replace(b'"id": 100', b'"id": 101')
        self.assertNotEqual(body, tampered)

        response = self.post(None, body=tampered, signature=signature)

        self.assertEqual(response.status_code, 401)
        self.assertFalse(self.tracking().exists())

    @override_settings(MAUTIC_WEBHOOK_SECRET="")
    def test_unconfigured_secret_rejects_every_delivery(self):
        body = fx.encode(fx.email_on_send())

        response = self.post(None, body=body, signature=fx.sign(body, ""))

        self.assertEqual(response.status_code, 401)

    def test_signature_is_checked_before_the_body_is_parsed(self):
        with patch("newsletter.webhooks.json.loads") as loads:
            response = self.post(None, body=b"{not json", signature="bad")

        self.assertEqual(response.status_code, 401)
        loads.assert_not_called()

    def test_signed_invalid_or_non_object_json_is_a_400(self):
        for body in (b"{not json", b"[1, 2]", b"\xff\xfe", b"[" * 5000 + b"]" * 5000):
            with self.subTest(body=body[:12]):
                self.assertEqual(self.post(None, body=body).status_code, 400)

    # --- Event mapping and attribution (B15-06..10) -----------------------

    def test_real_send_payload_is_delivered_and_attributed(self):
        self.post(fx.email_on_send())

        event = self.tracking().get()
        self.assertEqual(event.event_type, NewsletterCampaignTrackingEvent.EventType.DELIVERED)
        self.assertEqual(event.campaign, self.campaign)
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.mautic_contact_id, "4288")
        self.assertEqual(event.recipient_email, "b15@example.test")
        self.assertEqual(event.provider_event_id, "6ad06ee1871c6027239578")
        self.assertEqual(event.occurred_at, at("2026-10-15T06:12:49+00:00"))

    def test_real_open_payload_is_attributed_through_the_stat(self):
        # Before B15 the open was dropped: its email and contact are in "stat".
        response = self.post(fx.email_on_open())

        self.assertEqual(response.data["created"], 1)
        event = self.tracking().get()
        self.assertEqual(event.event_type, NewsletterCampaignTrackingEvent.EventType.OPENED)
        self.assertEqual(event.campaign, self.campaign)
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.mautic_contact_id, "4288")
        self.assertEqual(event.recipient_email, "b15@example.test")
        self.assertEqual(event.provider_event_id, "stat:110")
        self.assertEqual(event.occurred_at, at("2026-10-15T06:14:40+00:00"))

    def test_real_page_hit_is_a_click_with_its_url(self):
        self.post(fx.page_on_hit())

        event = self.tracking().get()
        self.assertEqual(event.event_type, NewsletterCampaignTrackingEvent.EventType.CLICKED)
        self.assertEqual(event.campaign, self.campaign)
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.url, "https://example.test/b15-link?x=1")
        self.assertEqual(event.provider_event_id, "1")

    def test_events_for_unknown_or_draft_emails_are_not_tracked(self):
        NewsletterCampaign.objects.create(name="Draft", subject="Draft", mautic_email_id="")
        for payload in (fx.email_on_open(email_id=999), fx.page_on_hit(email_id=999)):
            with self.subTest(event=next(iter(payload))):
                response = self.post(payload)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data["ignored"], 1)
        self.assertFalse(self.tracking().exists())

    def test_unknown_event_types_are_acknowledged_and_ignored(self):
        response = self.post({"mautic.form_on_submit": [{"id": 1}], "mautic.lead_post_save_new": [{}]})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["ignored"], 2)

    # --- Dedup and replay (B15-11..14) ------------------------------------

    def test_redelivered_batch_is_a_duplicate_not_a_second_row(self):
        payload = {**fx.email_on_send(), **fx.email_on_open(), **fx.page_on_hit()}

        first = self.post(payload)
        second = self.post(payload)

        self.assertEqual(first.data["created"], 3)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.data["duplicate"], 3)
        self.assertEqual(self.tracking().count(), 3)

    def test_repeated_opens_of_one_stat_are_one_open(self):
        self.post(fx.email_on_open(open_count=1, timestamp="2026-10-15T06:14:40+00:00"))
        response = self.post(fx.email_on_open(open_count=2, timestamp="2026-10-15T07:00:00+00:00"))

        self.assertEqual(response.data["duplicate"], 1)
        self.assertEqual(self.tracking(event_type="opened").count(), 1)

    def test_stat_and_hit_ids_with_the_same_number_do_not_collide(self):
        self.post(fx.email_on_open(stat_id=7))
        response = self.post(fx.page_on_hit(hit_id=7))

        self.assertEqual(response.data["created"], 1)
        self.assertEqual(
            set(self.tracking().values_list("provider_event_id", flat=True)), {"stat:7", "7"},
        )

    def test_events_without_identity_get_no_synthetic_id(self):
        payload = fx.email_on_open()
        del payload["mautic.email_on_open"][0]["stat"]["id"]

        self.post(payload)

        self.assertEqual(self.tracking().get().provider_event_id, "")

    # --- Consent and ordering (B15-15..20) --------------------------------

    def test_real_unsubscribe_suppresses_at_the_provider_time(self):
        response = self.post(fx.channel_subscription_changed())

        self.assertEqual(response.data["consent_synced"], 1)
        suppression = MauticEmailSuppression.objects.get(user=self.user)
        self.assertEqual(suppression.reason, MauticEmailSuppression.Reason.UNSUBSCRIBED)
        self.assertEqual(suppression.suppressed_at, at("2026-10-15T06:13:10+00:00"))

    def test_later_contactable_change_lifts_the_suppression(self):
        self.post(fx.channel_subscription_changed())
        response = self.post(fx.channel_subscription_changed(
            old_status="unsubscribed", new_status="contactable", timestamp="2026-10-15T06:13:12+00:00",
        ))

        self.assertEqual(response.data["consent_synced"], 1)
        self.assertFalse(MauticEmailSuppression.objects.filter(user=self.user).exists())

    def test_delayed_contactable_does_not_undo_a_newer_unsubscribe(self):
        # bounce t1, unsubscribe t3 delivered, then a contactable from t2 arrives late.
        self.post(fx.channel_subscription_changed(new_status="bounced", timestamp="2026-10-15T06:00:00+00:00"))
        self.post(fx.channel_subscription_changed(new_status="unsubscribed", timestamp="2026-10-15T06:30:00+00:00"))
        response = self.post(fx.channel_subscription_changed(
            old_status="bounced", new_status="contactable", timestamp="2026-10-15T06:15:00+00:00",
        ))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["consent_synced"], 0)
        suppression = MauticEmailSuppression.objects.get(user=self.user)
        self.assertEqual(suppression.reason, MauticEmailSuppression.Reason.BOUNCED)
        self.assertEqual(suppression.suppressed_at, at("2026-10-15T06:30:00+00:00"))

    def test_late_older_bounce_does_not_move_the_suppression_time_back(self):
        self.post(fx.channel_subscription_changed(new_status="unsubscribed", timestamp="2026-10-15T06:30:00+00:00"))
        self.post(fx.channel_subscription_changed(new_status="bounced", timestamp="2026-10-15T06:00:00+00:00"))
        self.post(fx.channel_subscription_changed(
            old_status="bounced", new_status="contactable", timestamp="2026-10-15T06:15:00+00:00",
        ))

        suppression = MauticEmailSuppression.objects.get(user=self.user)
        self.assertEqual(suppression.reason, MauticEmailSuppression.Reason.BOUNCED)
        self.assertEqual(suppression.suppressed_at, at("2026-10-15T06:30:00+00:00"))

    def test_contactable_with_equal_or_missing_time_keeps_the_suppression(self):
        self.post(fx.channel_subscription_changed(timestamp="2026-10-15T06:13:10+00:00"))
        for timestamp in ("2026-10-15T06:13:10+00:00", None, "not-a-date"):
            with self.subTest(timestamp=timestamp):
                response = self.post(fx.channel_subscription_changed(
                    old_status="unsubscribed", new_status="contactable", timestamp=timestamp,
                ))
                self.assertEqual(response.status_code, 200)
                self.assertTrue(MauticEmailSuppression.objects.filter(user=self.user).exists())

    def test_replayed_unsubscribe_converges_on_one_row(self):
        payload = fx.channel_subscription_changed()
        self.post(payload)
        self.post(payload)

        self.assertEqual(MauticEmailSuppression.objects.filter(user=self.user).count(), 1)

    def test_non_email_channel_and_unmapped_contacts_do_not_touch_consent(self):
        self.post(fx.channel_subscription_changed(channel="sms"))
        self.post(fx.channel_subscription_changed(contact_id=9999))

        self.assertFalse(MauticEmailSuppression.objects.exists())

    def test_explicit_resubscribe_flow_still_clears_regardless_of_time(self):
        record_email_suppression(self.user, MauticEmailSuppression.Reason.UNSUBSCRIBED,
                                 occurred_at=at("2030-01-01T00:00:00+00:00"))
        self.assertTrue(clear_email_suppression(self.user))

    # --- Failure semantics (B15-21..23) -----------------------------------

    def test_one_failing_event_gives_500_with_counts_after_the_rest(self):
        payload = {**fx.email_on_send(), **fx.page_on_hit()}
        real = webhooks._create_tracking_event

        def flaky(provider_event_type, event):
            if provider_event_type == "mautic.email_on_send":
                raise RuntimeError("db down")
            return real(provider_event_type, event)

        with patch("newsletter.webhooks._create_tracking_event", side_effect=flaky):
            response = self.post(payload)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.data["failed"], 1)
        self.assertEqual(response.data["created"], 1)
        self.assertEqual(self.tracking(event_type="clicked").count(), 1)

        # Mautic's retry (command_process mode) is safe: the click is a duplicate.
        retry = self.post(payload)
        self.assertEqual(retry.status_code, 200)
        self.assertEqual((retry.data["created"], retry.data["duplicate"]), (1, 1))

    def test_consent_failure_is_not_acknowledged_as_success(self):
        with patch("newsletter.webhooks.record_email_suppression", side_effect=RuntimeError("locked")):
            response = self.post(fx.channel_subscription_changed())

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.data["failed"], 1)
        self.assertEqual(response.data["consent_synced"], 0)

    def test_ignored_and_duplicate_events_are_not_failures(self):
        self.post(fx.email_on_send())
        response = self.post({**fx.email_on_send(), "mautic.unknown": [{}], **fx.email_on_open(email_id=5)})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["failed"], 0)

    # --- Bounded processing and stored data (B15-24..26) ------------------

    def test_a_burst_from_mautic_is_not_rate_limited(self):
        # Mautic posts from one address, one request per event in immediate
        # mode, and never retries a 429: the anonymous API rate must not apply.
        # DRF reads the rates at import, so the documented default is patched in.
        rates = {**AnonRateThrottle.THROTTLE_RATES, "anon": "10/min", "user": "10/min"}
        with patch.object(AnonRateThrottle, "THROTTLE_RATES", rates), \
                patch.object(UserRateThrottle, "THROTTLE_RATES", rates):
            statuses = {
                self.post(fx.email_on_send(contact_id=5000 + i, id_hash=f"burst-{i}")).status_code
                for i in range(30)
            }

        self.assertEqual(statuses, {200})
        self.assertEqual(self.tracking().count(), 30)

    @override_settings(MAUTIC_WEBHOOK_MAX_BODY_BYTES=512)
    def test_oversized_body_is_a_413_before_any_processing(self):
        body = fx.encode(fx.email_on_send())
        self.assertGreater(len(body), 512)

        response = self.post(None, body=body)

        self.assertEqual(response.status_code, 413)
        self.assertFalse(self.tracking().exists())

    @override_settings(MAUTIC_WEBHOOK_MAX_EVENTS=3)
    def test_event_count_limit(self):
        events = fx.email_on_send()["mautic.email_on_send"][0]
        at_limit = {"mautic.email_on_send": [dict(events, idHash=f"h{i}") for i in range(3)]}
        over = {"mautic.email_on_send": [dict(events, idHash=f"x{i}") for i in range(4)]}

        self.assertEqual(self.post(at_limit).status_code, 200)
        self.assertEqual(self.post(over).status_code, 413)
        self.assertEqual(self.tracking().count(), 3)

    def test_over_long_values_are_truncated_instead_of_losing_the_event(self):
        long_url = "https://example.test/" + "a" * 600
        response = self.post({
            **fx.page_on_hit(url=long_url),
            **fx.email_on_send(id_hash="h" * 400, email=("x" * 300) + "@example.test"),
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["created"], 2)
        click = self.tracking(event_type="clicked").get()
        self.assertEqual(click.url, long_url[:200])
        self.assertEqual(click.payload["hit"]["url"], long_url)
        send = self.tracking(event_type="delivered").get()
        self.assertEqual(len(send.provider_event_id), 255)
        self.assertEqual(send.recipient_email, "")

    def test_stored_payload_keeps_identifiers_not_personal_data_or_content(self):
        self.post({**fx.email_on_send(), **fx.email_on_open(), **fx.page_on_hit()})

        stored = json.dumps(list(self.tracking().values_list("payload", flat=True)))
        for absent in ("203.0.113.7", "Mozilla", "B15 local capture", "unsubscribe_url",
                       "b15@example.test", "firstname", "trackingId", "ipAddress"):
            self.assertNotIn(absent, stored)
        open_payload = self.tracking(event_type="opened").get().payload
        self.assertEqual(open_payload["stat"]["id"], "110")
        self.assertEqual(open_payload["contact_id"], "4288")
        self.assertEqual(open_payload["email_id"], "100")

    # --- Delivery evidence (B15-27..28) -----------------------------------

    def test_accepted_rejected_and_failed_deliveries_are_observed_without_secrets(self):
        self.post(fx.email_on_send())
        self.post(fx.email_on_send(), signature="bad")
        with patch("newsletter.webhooks._create_tracking_event", side_effect=RuntimeError("x")):
            self.post(fx.page_on_hit())

        observed = webhook_observations()
        self.assertTrue(observed["available"])
        self.assertEqual(observed["accepted"]["created"], 1)
        self.assertEqual(observed["rejected"]["reason"], "invalid_signature")
        self.assertEqual(observed["failed"]["error_types"], ["RuntimeError"])
        self.assertNotIn(SECRET, json.dumps(observed))

    def test_an_unavailable_cache_does_not_change_the_answer(self):
        broken = MagicMock()
        broken.set.side_effect = ConnectionError("redis down")
        broken.get_many.side_effect = ConnectionError("redis down")
        with patch("newsletter.webhooks.cache", broken):
            response = self.post(fx.email_on_send())
            observed = webhook_observations()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(observed, {"available": False})
