"""Mautic email DNC <-> ECP newsletter consent synchronization.

Covers both directions: a Mautic-side suppression reaching ECP consent, and an
explicit ECP re-subscribe reversing only a voluntary opt-out.
"""

import base64
import hashlib
import hmac
import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.dnc_services import (
    SuppressionReconciliation,
    classify_dnc_reason,
    email_dnc_reasons,
    record_email_suppression,
    reconcile_email_suppression_for_resubscribe,
)
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.models import (
    MauticContactMapping,
    MauticEmailSuppression,
    NewsletterCategory,
    NewsletterSubscription,
)
from newsletter.services import list_user_preferences, update_user_preferences


User = get_user_model()


def dnc_contact(*reasons, contact_id="101", channel="email"):
    """Build a Mautic contact payload carrying the given DNC reason ids."""
    return {
        "id": contact_id,
        "doNotContact": [
            {"channel": channel, "reason": reason, "comments": ""}
            for reason in reasons
        ],
    }


class MauticDncClassificationTests(TestCase):
    """Reason mapping follows Mautic 7.1.3 DoNotContact constants."""

    def test_known_numeric_reasons_map_to_canonical_values(self):
        self.assertEqual(
            classify_dnc_reason(1),
            MauticEmailSuppression.Reason.UNSUBSCRIBED,
        )
        self.assertEqual(
            classify_dnc_reason(2),
            MauticEmailSuppression.Reason.BOUNCED,
        )
        self.assertEqual(
            classify_dnc_reason(3),
            MauticEmailSuppression.Reason.MANUAL,
        )

    def test_status_verbs_map_to_canonical_values(self):
        self.assertEqual(
            classify_dnc_reason("unsubscribed"),
            MauticEmailSuppression.Reason.UNSUBSCRIBED,
        )
        self.assertEqual(
            classify_dnc_reason("bounced"),
            MauticEmailSuppression.Reason.BOUNCED,
        )
        self.assertEqual(
            classify_dnc_reason("manual"),
            MauticEmailSuppression.Reason.MANUAL,
        )

    def test_unrecognised_reason_fails_closed_as_unknown(self):
        for value in (99, "quarantined", "", None, True):
            self.assertEqual(
                classify_dnc_reason(value),
                MauticEmailSuppression.Reason.UNKNOWN,
                msg=f"{value!r} should classify as UNKNOWN",
            )

    def test_only_email_channel_records_are_returned(self):
        contact = {
            "doNotContact": [
                {"channel": "sms", "reason": 1},
                {"channel": "email", "reason": 2},
            ]
        }
        self.assertEqual(
            email_dnc_reasons(contact),
            [MauticEmailSuppression.Reason.BOUNCED],
        )

    def test_channelless_record_is_not_assumed_to_be_email(self):
        self.assertEqual(email_dnc_reasons({"doNotContact": [{"reason": 1}]}), [])

    def test_multiple_email_reasons_are_all_reported(self):
        self.assertEqual(
            email_dnc_reasons(dnc_contact(1, 2)),
            [
                MauticEmailSuppression.Reason.UNSUBSCRIBED,
                MauticEmailSuppression.Reason.BOUNCED,
            ],
        )


class MauticEmailSuppressionRecordTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="suppression-record",
            email="suppression-record@example.test",
            password="test-password",
        )

    def test_repeated_record_keeps_a_single_row(self):
        for _ in range(3):
            record_email_suppression(
                self.user,
                MauticEmailSuppression.Reason.UNSUBSCRIBED,
                mautic_contact_id="101",
            )
        self.assertEqual(
            MauticEmailSuppression.objects.filter(user=self.user).count(),
            1,
        )

    def test_bounce_escalates_over_voluntary_opt_out(self):
        record_email_suppression(
            self.user,
            MauticEmailSuppression.Reason.UNSUBSCRIBED,
        )
        record_email_suppression(
            self.user,
            MauticEmailSuppression.Reason.BOUNCED,
        )
        suppression = MauticEmailSuppression.objects.get(user=self.user)
        self.assertEqual(
            suppression.reason,
            MauticEmailSuppression.Reason.BOUNCED,
        )
        self.assertFalse(suppression.is_reversible)

    def test_voluntary_opt_out_does_not_downgrade_a_bounce(self):
        record_email_suppression(
            self.user,
            MauticEmailSuppression.Reason.BOUNCED,
        )
        record_email_suppression(
            self.user,
            MauticEmailSuppression.Reason.UNSUBSCRIBED,
        )
        self.assertEqual(
            MauticEmailSuppression.objects.get(user=self.user).reason,
            MauticEmailSuppression.Reason.BOUNCED,
        )


@override_settings(MAUTIC_WEBHOOK_SECRET="webhook-secret")
class MauticDncWebhookConsentTests(TestCase):
    """Mautic -> ECP: a DNC change must reach ECP consent."""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("newsletter-mautic-webhook")
        self.user = User.objects.create_user(
            username="dnc-webhook-user",
            email="dnc-webhook-user@example.test",
            password="test-password",
        )
        MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="101",
        )
        self.category = NewsletterCategory.objects.create(
            name="DNC Webhook List",
            slug="dnc-webhook-list",
            mautic_segment_id="501",
        )
        self.subscription = NewsletterSubscription.objects.create(
            user=self.user,
            category=self.category,
            is_subscribed=True,
            subscribed_at=timezone.now(),
        )

    def preference(self):
        """This test's category, selected by slug: seeded lists share the list."""
        return next(
            item
            for item in list_user_preferences(self.user)
            if item["slug"] == self.category.slug
        )

    def signed_post(self, payload):
        body = json.dumps(payload).encode("utf-8")
        digest = hmac.new(b"webhook-secret", body, hashlib.sha256).digest()
        return self.client.post(
            self.url,
            data=body,
            content_type="application/json",
            HTTP_WEBHOOK_SIGNATURE=base64.b64encode(digest).decode(),
        )

    def channel_event(self, new_status="unsubscribed", **overrides):
        """The payload shape Mautic 7.1.3 actually sends.

        Note it carries no email/broadcast reference at all, which is why
        consent handling must not depend on matching a campaign.
        """
        payload = {
            "contact": {
                "id": 101,
                "fields": {
                    "core": {"email": {"value": "dnc-webhook-user@example.test"}}
                },
            },
            "channel": "email",
            "old_status": "contactable",
            "new_status": new_status,
            "timestamp": "2026-09-22T10:00:00+00:00",
        }
        payload.update(overrides)
        return payload

    def post_channel_event(self, **kwargs):
        return self.signed_post(
            {"mautic.lead_channel_subscription_changed": [self.channel_event(**kwargs)]}
        )

    # A1 — voluntary unsubscribe
    def test_voluntary_unsubscribe_suppresses_ecp_consent(self):
        response = self.post_channel_event(new_status="unsubscribed")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["consent_synced"], 1)

        suppression = MauticEmailSuppression.objects.get(user=self.user)
        self.assertEqual(
            suppression.reason,
            MauticEmailSuppression.Reason.UNSUBSCRIBED,
        )
        self.assertEqual(suppression.mautic_contact_id, "101")

        preference = self.preference()
        self.assertFalse(preference["subscribed"])
        self.assertTrue(preference["suppressed"])
        # The member's own choice is preserved, not overwritten.
        self.assertTrue(preference["locally_subscribed"])
        self.subscription.refresh_from_db()
        self.assertTrue(self.subscription.is_subscribed)

    # A2 — duplicate webhook
    def test_duplicate_unsubscribe_delivery_is_idempotent(self):
        first = self.post_channel_event()
        second = self.post_channel_event()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(
            MauticEmailSuppression.objects.filter(user=self.user).count(),
            1,
        )
        self.assertEqual(
            NewsletterSubscription.objects.filter(user=self.user).count(),
            1,
        )
        self.assertFalse(self.preference()["subscribed"])

    # A3 — unknown contact
    def test_unmapped_contact_changes_nothing(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.channel_event(contact={"id": 999})
                ]
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["consent_synced"], 0)
        self.assertFalse(MauticEmailSuppression.objects.exists())
        self.assertTrue(self.preference()["subscribed"])

    # A4 — no subscription rows at all
    def test_member_without_subscription_rows_is_still_suppressed(self):
        NewsletterSubscription.objects.filter(user=self.user).delete()

        response = self.post_channel_event()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            MauticEmailSuppression.objects.filter(user=self.user).exists()
        )
        preference = self.preference()
        self.assertFalse(preference["subscribed"])
        # Nothing was chosen locally, so nothing is reported as overridden.
        self.assertFalse(preference["suppressed"])

    # A5 — non-email channel
    def test_sms_channel_dnc_does_not_touch_email_consent(self):
        response = self.signed_post(
            {
                "mautic.lead_channel_subscription_changed": [
                    self.channel_event(channel="sms")
                ]
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["consent_synced"], 0)
        self.assertFalse(MauticEmailSuppression.objects.exists())
        self.assertTrue(self.preference()["subscribed"])

    # A6 — non-voluntary reasons are recorded with their real reason
    def test_bounce_is_recorded_as_a_non_reversible_suppression(self):
        self.post_channel_event(new_status="bounced")

        suppression = MauticEmailSuppression.objects.get(user=self.user)
        self.assertEqual(
            suppression.reason,
            MauticEmailSuppression.Reason.BOUNCED,
        )
        self.assertFalse(suppression.is_reversible)

    def test_manual_suppression_is_recorded_without_a_tracking_event(self):
        response = self.post_channel_event(new_status="manual")

        self.assertEqual(response.data["consent_synced"], 1)
        suppression = MauticEmailSuppression.objects.get(user=self.user)
        self.assertEqual(
            suppression.reason,
            MauticEmailSuppression.Reason.MANUAL,
        )
        self.assertFalse(suppression.is_reversible)

    def test_unrecognised_status_is_recorded_as_unknown_and_not_reversible(self):
        self.post_channel_event(new_status="quarantined")

        suppression = MauticEmailSuppression.objects.get(user=self.user)
        self.assertEqual(
            suppression.reason,
            MauticEmailSuppression.Reason.UNKNOWN,
        )
        self.assertFalse(suppression.is_reversible)

    def test_return_to_contactable_clears_suppression(self):
        self.post_channel_event(new_status="unsubscribed")
        self.assertTrue(MauticEmailSuppression.objects.exists())

        response = self.post_channel_event(
            new_status="contactable",
            old_status="unsubscribed",
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(MauticEmailSuppression.objects.exists())
        self.assertTrue(self.preference()["subscribed"])

    def test_malformed_event_does_not_break_the_endpoint(self):
        response = self.signed_post(
            {"mautic.lead_channel_subscription_changed": [{"channel": "email"}]}
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(MauticEmailSuppression.objects.exists())

    def test_invalid_signature_is_still_rejected(self):
        body = json.dumps(
            {"mautic.lead_channel_subscription_changed": [self.channel_event()]}
        ).encode("utf-8")
        response = self.client.post(
            self.url,
            data=body,
            content_type="application/json",
            HTTP_WEBHOOK_SIGNATURE="not-the-signature",
        )

        self.assertEqual(response.status_code, 401)
        self.assertFalse(MauticEmailSuppression.objects.exists())


class MauticResubscribeReconciliationTests(TestCase):
    """ECP -> Mautic: only a voluntary opt-out may be reversed."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="resubscribe-user",
            email="resubscribe-user@example.test",
            password="test-password",
        )
        MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="101",
        )

    def suppress(self, reason):
        return record_email_suppression(
            self.user,
            reason,
            mautic_contact_id="101",
        )

    # B7 — reversible opt-out is cleared
    def test_voluntary_opt_out_is_cleared(self):
        self.suppress(MauticEmailSuppression.Reason.UNSUBSCRIBED)
        provider = _FakeClient(contact=dnc_contact(1))

        result = reconcile_email_suppression_for_resubscribe(
            self.user,
            client=provider,
        )

        self.assertEqual(result.status, SuppressionReconciliation.CLEARED)
        self.assertFalse(result.delivery_blocked)
        self.assertEqual(provider.removed, [("101", "email")])
        self.assertFalse(MauticEmailSuppression.objects.exists())

    # B8 — hard bounce
    def test_hard_bounce_is_never_cleared(self):
        self.suppress(MauticEmailSuppression.Reason.BOUNCED)
        provider = _FakeClient(contact=dnc_contact(2))

        result = reconcile_email_suppression_for_resubscribe(
            self.user,
            client=provider,
        )

        self.assertEqual(result.status, SuppressionReconciliation.BLOCKED)
        self.assertTrue(result.delivery_blocked)
        self.assertEqual(provider.removed, [])
        self.assertTrue(MauticEmailSuppression.objects.exists())

    # B9 — complaint. Mautic 7.1.3 records complaints as bounced or manual;
    # both are non-reversible, so a complaint can never be auto-cleared.
    def test_complaint_recorded_as_manual_is_never_cleared(self):
        self.suppress(MauticEmailSuppression.Reason.MANUAL)
        provider = _FakeClient(contact=dnc_contact(3))

        result = reconcile_email_suppression_for_resubscribe(
            self.user,
            client=provider,
        )

        self.assertEqual(result.status, SuppressionReconciliation.BLOCKED)
        self.assertEqual(provider.removed, [])
        self.assertTrue(MauticEmailSuppression.objects.exists())

    # B10 — admin/manual suppression
    def test_admin_suppression_is_never_cleared(self):
        self.suppress(MauticEmailSuppression.Reason.MANUAL)
        provider = _FakeClient(contact=dnc_contact(3))

        reconcile_email_suppression_for_resubscribe(self.user, client=provider)

        self.assertEqual(provider.removed, [])
        self.assertEqual(
            MauticEmailSuppression.objects.get(user=self.user).reason,
            MauticEmailSuppression.Reason.MANUAL,
        )

    def test_unknown_reason_is_never_cleared(self):
        self.suppress(MauticEmailSuppression.Reason.UNSUBSCRIBED)
        provider = _FakeClient(contact=dnc_contact(97))

        result = reconcile_email_suppression_for_resubscribe(
            self.user,
            client=provider,
        )

        self.assertEqual(result.status, SuppressionReconciliation.BLOCKED)
        self.assertEqual(provider.removed, [])

    # B11 — multiple reasons: removing the opt-out must not drop the bounce.
    def test_bounce_alongside_opt_out_blocks_removal_entirely(self):
        self.suppress(MauticEmailSuppression.Reason.UNSUBSCRIBED)
        provider = _FakeClient(contact=dnc_contact(1, 2))

        result = reconcile_email_suppression_for_resubscribe(
            self.user,
            client=provider,
        )

        # Mautic's REST remove takes no reason and drops the first matching
        # record, so calling it here could silently delete the bounce.
        self.assertEqual(provider.removed, [])
        self.assertEqual(result.status, SuppressionReconciliation.BLOCKED)
        self.assertEqual(
            MauticEmailSuppression.objects.get(user=self.user).reason,
            MauticEmailSuppression.Reason.BOUNCED,
        )

    # B12 — provider failure
    def test_temporary_mautic_failure_keeps_suppression(self):
        self.suppress(MauticEmailSuppression.Reason.UNSUBSCRIBED)
        provider = _FakeClient(get_error=TemporaryMauticError("Mautic down"))

        result = reconcile_email_suppression_for_resubscribe(
            self.user,
            client=provider,
        )

        self.assertEqual(result.status, SuppressionReconciliation.UNKNOWN)
        self.assertTrue(result.delivery_blocked)
        self.assertTrue(MauticEmailSuppression.objects.exists())

    def test_failure_during_removal_keeps_suppression(self):
        self.suppress(MauticEmailSuppression.Reason.UNSUBSCRIBED)
        provider = _FakeClient(
            contact=dnc_contact(1),
            remove_error=PermanentMauticError("rejected"),
        )

        result = reconcile_email_suppression_for_resubscribe(
            self.user,
            client=provider,
        )

        self.assertEqual(result.status, SuppressionReconciliation.UNKNOWN)
        self.assertTrue(MauticEmailSuppression.objects.exists())

    def test_contact_already_contactable_clears_stale_suppression(self):
        self.suppress(MauticEmailSuppression.Reason.UNSUBSCRIBED)
        provider = _FakeClient(contact={"id": "101", "doNotContact": []})

        result = reconcile_email_suppression_for_resubscribe(
            self.user,
            client=provider,
        )

        self.assertEqual(result.status, SuppressionReconciliation.CLEARED)
        self.assertEqual(provider.removed, [])
        self.assertFalse(MauticEmailSuppression.objects.exists())


@override_settings(MAUTIC_SYNC_ENABLED=True)
class ResubscribeThroughPreferencesApiTests(TestCase):
    """The member-facing opt-in path drives reconciliation end to end."""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("newsletter-preferences")
        self.user = User.objects.create_user(
            username="prefs-resubscribe",
            email="prefs-resubscribe@example.test",
            password="test-password",
        )
        MauticContactMapping.objects.create(
            user=self.user,
            mautic_contact_id="101",
        )
        self.category = NewsletterCategory.objects.create(
            name="Resubscribe List",
            slug="resubscribe-list",
            mautic_segment_id="501",
        )
        NewsletterSubscription.objects.create(
            user=self.user,
            category=self.category,
            is_subscribed=True,
            subscribed_at=timezone.now(),
        )
        self.client.force_authenticate(user=self.user)

    def response_preference(self, response):
        return next(
            item
            for item in response.data["preferences"]
            if item["slug"] == self.category.slug
        )

    def patch_subscribe(self, subscribed=True):
        return self.client.patch(
            self.url,
            {
                "preferences": [
                    {"slug": self.category.slug, "subscribed": subscribed}
                ]
            },
            format="json",
        )

    def test_get_reports_suppression_to_the_member(self):
        record_email_suppression(
            self.user,
            MauticEmailSuppression.Reason.BOUNCED,
            mautic_contact_id="101",
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["email_suppression"]["suppressed"])
        self.assertEqual(response.data["email_suppression"]["reason"], "bounced")
        self.assertFalse(response.data["email_suppression"]["reversible"])
        self.assertFalse(self.response_preference(response)["subscribed"])

    def test_opt_in_clears_a_voluntary_opt_out_even_with_no_local_change(self):
        """The stored choice is already True, so only reconciliation can run."""
        record_email_suppression(
            self.user,
            MauticEmailSuppression.Reason.UNSUBSCRIBED,
            mautic_contact_id="101",
        )
        provider = _FakeClient(contact=dnc_contact(1))

        with patch(
            "newsletter.dnc_services.MauticClient",
            return_value=provider,
        ):
            response = self.patch_subscribe()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(provider.removed, [("101", "email")])
        self.assertFalse(response.data["email_suppression"]["suppressed"])
        self.assertTrue(self.response_preference(response)["subscribed"])

    def test_opt_in_with_hard_bounce_does_not_claim_success(self):
        record_email_suppression(
            self.user,
            MauticEmailSuppression.Reason.BOUNCED,
            mautic_contact_id="101",
        )
        provider = _FakeClient(contact=dnc_contact(2))

        with patch(
            "newsletter.dnc_services.MauticClient",
            return_value=provider,
        ):
            response = self.patch_subscribe()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(provider.removed, [])
        # Saved locally, but the response must not imply delivery works.
        self.assertTrue(response.data["email_suppression"]["suppressed"])
        self.assertEqual(response.data["email_suppression"]["reason"], "bounced")
        self.assertFalse(self.response_preference(response)["subscribed"])
        self.assertTrue(self.response_preference(response)["locally_subscribed"])

    def test_mautic_failure_does_not_produce_a_misleading_subscribed_state(self):
        record_email_suppression(
            self.user,
            MauticEmailSuppression.Reason.UNSUBSCRIBED,
            mautic_contact_id="101",
        )
        provider = _FakeClient(get_error=TemporaryMauticError("Mautic down"))

        with patch(
            "newsletter.dnc_services.MauticClient",
            return_value=provider,
        ):
            response = self.patch_subscribe()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["email_suppression"]["suppressed"])
        self.assertFalse(self.response_preference(response)["subscribed"])

    def test_opting_out_never_touches_mautic_suppression(self):
        record_email_suppression(
            self.user,
            MauticEmailSuppression.Reason.UNSUBSCRIBED,
            mautic_contact_id="101",
        )

        with patch("newsletter.dnc_services.MauticClient") as client_class:
            response = self.patch_subscribe(subscribed=False)

        self.assertEqual(response.status_code, 200)
        client_class.assert_not_called()
        self.assertTrue(MauticEmailSuppression.objects.exists())

    def test_unsuppressed_opt_in_does_not_call_mautic_dnc(self):
        with patch("newsletter.dnc_services.MauticClient") as client_class:
            response = self.patch_subscribe()

        self.assertEqual(response.status_code, 200)
        client_class.assert_not_called()


@override_settings(MAUTIC_SYNC_ENABLED=True)
class EcpUnsubscribeRegressionTests(TestCase):
    """C13 — the existing ECP-side opt-out behaviour is unchanged."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="ecp-unsubscribe",
            email="ecp-unsubscribe@example.test",
            password="test-password",
        )
        self.category = NewsletterCategory.objects.create(
            name="ECP Unsubscribe List",
            slug="ecp-unsubscribe-list",
            mautic_segment_id="601",
        )

    def test_opt_out_still_writes_an_unsubscribe_sync_event(self):
        from newsletter.models import NewsletterSyncEvent

        update_user_preferences(
            self.user,
            [{"slug": self.category.slug, "subscribed": True}],
        )
        update_user_preferences(
            self.user,
            [{"slug": self.category.slug, "subscribed": False}],
        )

        subscription = NewsletterSubscription.objects.get(
            user=self.user,
            category=self.category,
        )
        self.assertFalse(subscription.is_subscribed)
        self.assertIsNotNone(subscription.unsubscribed_at)

        event = (
            NewsletterSyncEvent.objects.filter(
                user_id=str(self.user.pk),
                category=self.category,
                desired_subscribed=False,
            )
            .order_by("-created_at")
            .first()
        )
        self.assertIsNotNone(event)

    def test_opt_out_does_not_create_a_mautic_suppression_row(self):
        """An ECP opt-out is segment removal, not a Mautic DNC."""
        update_user_preferences(
            self.user,
            [{"slug": self.category.slug, "subscribed": False}],
        )
        self.assertFalse(MauticEmailSuppression.objects.exists())


class _FakeClient:
    """Minimal stand-in for MauticClient covering the DNC calls used here."""

    def __init__(self, *, contact=None, get_error=None, remove_error=None):
        self._contact = contact or {}
        self._get_error = get_error
        self._remove_error = remove_error
        self.removed = []

    def get_contact(self, contact_id):
        if self._get_error is not None:
            raise self._get_error
        return self._contact

    def remove_contact_dnc(self, contact_id, channel="email"):
        if self._remove_error is not None:
            raise self._remove_error
        self.removed.append((str(contact_id), channel))
        return {"contact": self._contact}
