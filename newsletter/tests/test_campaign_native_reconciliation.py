"""Batch 4: reconcile natively scheduled broadcasts back into ECP.

Covers the pure provider-state classifier, candidate selection, the locked
SENT transition, provider failures, races with Cancel/Reschedule, the post-due
action guard, minute rounding, native analytics and diagnostics.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.campaign_services import (
    cancel_native_schedule,
    reschedule_campaign_natively,
    schedule_campaign,
    schedule_campaign_natively,
)
from newsletter.mautic.exceptions import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.payloads import (
    format_mautic_schedule_datetime,
    round_up_to_schedule_minute,
)
from newsletter.models import (
    MauticIdentityAuditLog,
    MauticUserConnection,
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCategory,
)
from newsletter.native_broadcast_reconciliation import (
    DISARMED_EXTERNALLY_ERROR,
    MISSING_EMAIL_ERROR,
    NATIVE_NO_SEND_GRACE,
    NO_SENDS_YET_ERROR,
    PROVIDER_UNAVAILABLE_ERROR,
    CampaignNativeDeliveryStarted,
    NativeDeliveryState,
    classify_native_delivery,
    classify_provider_error,
    native_delivery_window_started,
    native_reconciliation_candidates,
    reconcile_native_scheduled_campaigns,
)
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_user_identity import IDENTITY_SETTINGS


User = get_user_model()
OWNER = NewsletterCampaign.ScheduleOwner
STATUS = NewsletterCampaign.Status
IST = dt_timezone(timedelta(hours=5, minutes=30))

SYNC_ON = {
    **IDENTITY_SETTINGS,
    "MAUTIC_SYNC_ENABLED": True,
    "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": True,
    # Reconciliation must drain native rows with the flag off.
    "MAUTIC_NATIVE_BROADCAST_SCHEDULING_ENABLED": False,
}

DUE = datetime(2026, 10, 1, 10, 15, tzinfo=dt_timezone.utc)

#: Provider writes reconciliation must never make.
WRITE_METHODS = (
    "create_email",
    "update_email",
    "delete_email",
    "send_email_to_segments",
    "send_email_to_contact",
)


def provider_email(**overrides):
    email = {
        "id": 77,
        "emailType": "list",
        "isPublished": True,
        "publishUp": "2026-10-01T10:15:00+00:00",
        "publishDown": None,
        "sentCount": 0,
    }
    email.update(overrides)
    return email


def classify(now, **overrides):
    return classify_native_delivery(
        provider_email(**overrides), scheduled_at=DUE, now=now
    )


class Base(TestCase):
    _counter = 0

    def campaign(self, *, status=STATUS.SCHEDULED, owner=OWNER.MAUTIC,
                 email_id="77", scheduled_at=None, last_error=""):
        Base._counter += 1
        category = NewsletterCategory.objects.create(
            name=f"Native List {Base._counter}",
            slug=f"native-list-{Base._counter}",
            mautic_segment_id="501",
        )
        campaign = NewsletterCampaign.objects.create(
            name=f"Native {Base._counter}",
            subject="Subject",
            from_name="ECP",
            from_email="news@example.test",
            html_content="<p>Hi</p>",
            status=status,
            schedule_owner=owner,
            mautic_email_id=email_id,
            scheduled_at=scheduled_at or (timezone.now() - timedelta(minutes=3)),
            last_error=last_error,
        )
        campaign.audiences.set([category])
        return campaign

    def provider(self, email=None, *, latest_send=None, error=None):
        client = Mock()
        if error is not None:
            client.get_email.side_effect = error
        else:
            client.get_email.return_value = email
        client.get_latest_email_send.return_value = latest_send
        return client

    def completed_for(self, campaign, sent_count=1):
        return provider_email(
            isPublished=False,
            publishUp=format_mautic_schedule_datetime(campaign.scheduled_at).replace(" ", "T")
            + ":00+00:00",
            sentCount=sent_count,
        )

    def sending_for(self, campaign, sent_count=1):
        email = self.completed_for(campaign, sent_count)
        email["isPublished"] = True
        return email

    def run_batch(self, client, **kwargs):
        with patch(
            "newsletter.native_broadcast_reconciliation.MauticClient",
            return_value=client,
        ) as factory:
            summary = reconcile_native_scheduled_campaigns(**kwargs)
        return summary, factory

    def assert_no_provider_writes(self, client):
        for name in WRITE_METHODS:
            getattr(client, name).assert_not_called()


# ---------------------------------------------------------------------------
# Pure classifier
# ---------------------------------------------------------------------------


class ClassifierTests(TestCase):
    def test_future_armed_schedule_is_not_due(self):
        self.assertEqual(
            classify(DUE - timedelta(minutes=5)).state, NativeDeliveryState.NOT_DUE
        )

    def test_due_published_without_sends_awaits_first_send(self):
        self.assertEqual(
            classify(DUE + timedelta(minutes=1)).state,
            NativeDeliveryState.AWAITING_FIRST_SEND,
        )

    def test_due_published_with_sends_is_still_sending(self):
        # Mautic unpublishes on the run *after* the last send; until then more
        # recipients may still be pending, so this must not read as complete.
        result = classify(DUE + timedelta(minutes=1), sentCount=3)
        self.assertEqual(result.state, NativeDeliveryState.SENDING)
        self.assertEqual(result.sent_count, 3)

    def test_auto_unpublished_after_sending_is_completed(self):
        result = classify(DUE + timedelta(minutes=2), isPublished=False, sentCount=3)
        self.assertEqual(result.state, NativeDeliveryState.COMPLETED)
        self.assertEqual(result.sent_count, 3)

    def test_unpublished_with_zero_sends_is_never_completed(self):
        # Mautic never auto-unpublishes a broadcast that sent nothing, so this
        # state means someone disarmed it outside ECP.
        result = classify(DUE + timedelta(minutes=2), isPublished=False, sentCount=0)
        self.assertEqual(result.state, NativeDeliveryState.DISARMED_EXTERNALLY)

    def test_zero_recipient_due_broadcast_stays_pending_indefinitely(self):
        result = classify(DUE + timedelta(days=3), sentCount=0)
        self.assertEqual(result.state, NativeDeliveryState.AWAITING_FIRST_SEND)

    def test_publish_up_moved_in_provider_is_inconsistent(self):
        result = classify(
            DUE + timedelta(minutes=5),
            isPublished=False,
            sentCount=2,
            publishUp="2026-10-01T11:00:00+00:00",
        )
        self.assertEqual(result.state, NativeDeliveryState.INCONSISTENT)
        self.assertEqual(result.reason, "publish_up_mismatch")

    def test_non_list_email_is_inconsistent(self):
        result = classify(DUE + timedelta(minutes=5), emailType="template")
        self.assertEqual(result.state, NativeDeliveryState.INCONSISTENT)

    def test_published_without_publish_up_is_inconsistent(self):
        result = classify(DUE + timedelta(minutes=5), publishUp=None)
        self.assertEqual(result.state, NativeDeliveryState.INCONSISTENT)

    def test_cleared_publish_up_with_no_sends_is_disarmed(self):
        result = classify(DUE + timedelta(minutes=5), publishUp=None, isPublished=False)
        self.assertEqual(result.state, NativeDeliveryState.DISARMED_EXTERNALLY)

    def test_publish_down_is_inconsistent(self):
        result = classify(
            DUE + timedelta(minutes=5), publishDown="2026-10-02T00:00:00+00:00"
        )
        self.assertEqual(result.state, NativeDeliveryState.INCONSISTENT)

    def test_sent_before_its_own_time_is_inconsistent(self):
        result = classify(DUE - timedelta(minutes=5), isPublished=False, sentCount=1)
        self.assertEqual(result.state, NativeDeliveryState.INCONSISTENT)

    def test_legacy_schedule_with_seconds_matches_truncated_publish_up(self):
        # Rows scheduled before minute rounding carry seconds; Mautic holds the
        # truncated minute. They must still be recognised as the same schedule.
        result = classify_native_delivery(
            provider_email(isPublished=False, sentCount=1),
            scheduled_at=DUE + timedelta(seconds=45),
            now=DUE + timedelta(minutes=3),
        )
        self.assertEqual(result.state, NativeDeliveryState.COMPLETED)

    def test_provider_404_is_missing(self):
        state = classify_provider_error(
            PermanentMauticError("Mautic API request failed (HTTP 404)")
        ).state
        self.assertEqual(state, NativeDeliveryState.MISSING)

    def test_temporary_error_is_unavailable(self):
        state = classify_provider_error(TemporaryMauticError("timeout")).state
        self.assertEqual(state, NativeDeliveryState.PROVIDER_UNAVAILABLE)

    def test_other_permanent_error_is_not_missing(self):
        state = classify_provider_error(
            PermanentMauticError("Mautic API request failed (HTTP 403)")
        ).state
        self.assertEqual(state, NativeDeliveryState.PROVIDER_REJECTED)


# ---------------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------------


class CandidateSelectionTests(Base):
    def test_only_due_mautic_owned_scheduled_rows_are_selected(self):
        due = self.campaign()
        self.campaign(scheduled_at=timezone.now() + timedelta(hours=1))  # future
        self.campaign(status=STATUS.CANCELLED, owner="")  # cancelled, email kept
        self.campaign(owner=OWNER.ECP)  # ECP-owned
        self.campaign(owner="")  # legacy blank = ECP
        self.campaign(email_id="")  # no provider email
        self.campaign(status=STATUS.SENT, owner="")  # already reconciled

        self.assertEqual(
            [c.pk for c in native_reconciliation_candidates()], [due.pk]
        )

    def test_selection_is_ordered_and_bounded(self):
        now = timezone.now()
        later = self.campaign(scheduled_at=now - timedelta(minutes=1))
        earlier = self.campaign(scheduled_at=now - timedelta(minutes=9))
        self.campaign(scheduled_at=now - timedelta(minutes=5))

        picked = native_reconciliation_candidates(batch_size=2)

        self.assertEqual(picked[0].pk, earlier.pk)
        self.assertEqual(len(picked), 2)
        self.assertNotIn(later.pk, [c.pk for c in picked])


# ---------------------------------------------------------------------------
# Reconciliation service
# ---------------------------------------------------------------------------


@override_settings(**SYNC_ON)
class ReconcileTests(Base):
    def test_completion_marks_sent_from_the_provider_send_time(self):
        campaign = self.campaign()
        client = self.provider(
            self.completed_for(campaign),
            latest_send={"date_sent": "2026-10-01 10:15:02"},
        )

        summary, factory = self.run_batch(client)

        self.assertEqual(summary["reconciled"], 1)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SENT)
        self.assertEqual(campaign.schedule_owner, "")
        self.assertEqual(campaign.last_error, "")
        self.assertEqual(
            campaign.sent_at, datetime(2026, 10, 1, 10, 15, 2, tzinfo=dt_timezone.utc)
        )
        self.assertFalse(NewsletterCampaignSendEvent.objects.exists())
        self.assertFalse(MauticIdentityAuditLog.objects.exists())
        self.assert_no_provider_writes(client)
        # A plain service-account client: no assertion provider is passed.
        factory.assert_called_once_with()

    def test_completion_without_a_send_row_uses_detection_time(self):
        campaign = self.campaign()
        client = self.provider(self.completed_for(campaign), latest_send=None)
        before = timezone.now()

        self.run_batch(client)

        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SENT)
        self.assertGreaterEqual(campaign.sent_at, before)

    def test_repeat_runs_are_idempotent(self):
        campaign = self.campaign()
        client = self.provider(self.completed_for(campaign))
        self.run_batch(client)
        client.reset_mock()

        summary, _ = self.run_batch(client)

        self.assertEqual(summary["selected"], 0)
        client.get_email.assert_not_called()
        self.assertFalse(NewsletterCampaignSendEvent.objects.exists())

    def test_still_sending_is_left_scheduled(self):
        campaign = self.campaign()
        client = self.provider(self.sending_for(campaign, 5))

        summary, _ = self.run_batch(client)

        self.assertEqual(summary["pending"], 1)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SCHEDULED)
        self.assertEqual(campaign.schedule_owner, OWNER.MAUTIC)
        self.assertIsNone(campaign.sent_at)

    def test_zero_recipient_broadcast_is_flagged_after_grace_never_sent(self):
        campaign = self.campaign(
            scheduled_at=timezone.now() - NATIVE_NO_SEND_GRACE - timedelta(minutes=2)
        )
        client = self.provider(self.sending_for(campaign, 0))

        summary, _ = self.run_batch(client)

        self.assertEqual(summary["pending"], 1)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SCHEDULED)
        self.assertEqual(campaign.last_error, NO_SENDS_YET_ERROR)

    def test_zero_sends_within_grace_is_not_flagged(self):
        campaign = self.campaign(scheduled_at=timezone.now() - timedelta(minutes=1))
        client = self.provider(self.sending_for(campaign, 0))

        self.run_batch(client)

        campaign.refresh_from_db()
        self.assertEqual(campaign.last_error, "")

    def test_missing_provider_email_is_diagnosed_not_resolved(self):
        campaign = self.campaign()
        client = self.provider(
            error=PermanentMauticError("Mautic API request failed (HTTP 404)")
        )

        summary, _ = self.run_batch(client)

        self.assertEqual(summary["missing"], 1)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SCHEDULED)
        self.assertEqual(campaign.schedule_owner, OWNER.MAUTIC)
        self.assertIsNone(campaign.sent_at)
        self.assertEqual(campaign.last_error, MISSING_EMAIL_ERROR)
        self.assert_no_provider_writes(client)
        self.assertFalse(MauticIdentityAuditLog.objects.exists())

    def test_temporary_failure_changes_nothing_but_the_diagnostic(self):
        campaign = self.campaign()
        client = self.provider(error=TemporaryMauticError("Mautic API request failed"))

        summary, _ = self.run_batch(client)

        self.assertEqual(summary["failed"], 1)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SCHEDULED)
        self.assertEqual(campaign.schedule_owner, OWNER.MAUTIC)
        self.assertEqual(campaign.last_error, PROVIDER_UNAVAILABLE_ERROR)
        # The next healthy run clears the diagnostic.
        client.get_email.side_effect = None
        client.get_email.return_value = self.sending_for(campaign)
        self.run_batch(client)
        campaign.refresh_from_db()
        self.assertEqual(campaign.last_error, "")

    def test_unrelated_last_error_is_not_cleared_by_pending_runs(self):
        campaign = self.campaign(last_error="Something the user must see.")
        client = self.provider(self.sending_for(campaign))

        self.run_batch(client)

        campaign.refresh_from_db()
        self.assertEqual(campaign.last_error, "Something the user must see.")

    def test_externally_disarmed_email_is_diagnosed(self):
        campaign = self.campaign()
        email = self.completed_for(campaign, sent_count=0)
        client = self.provider(email)

        summary, _ = self.run_batch(client)

        self.assertEqual(summary["inconsistent"], 1)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SCHEDULED)
        self.assertEqual(campaign.last_error, DISARMED_EXTERNALLY_ERROR)

    def test_one_broken_candidate_does_not_block_the_next(self):
        first = self.campaign(scheduled_at=timezone.now() - timedelta(minutes=9))
        second = self.campaign(scheduled_at=timezone.now() - timedelta(minutes=2))
        client = Mock()
        client.get_email.side_effect = [RuntimeError("boom"), self.completed_for(second)]
        client.get_latest_email_send.return_value = None

        summary, _ = self.run_batch(client)

        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["reconciled"], 1)
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(first.status, STATUS.SCHEDULED)
        self.assertEqual(second.status, STATUS.SENT)

    def test_runs_with_native_scheduling_flag_off(self):
        campaign = self.campaign()
        client = self.provider(self.completed_for(campaign))

        with override_settings(MAUTIC_NATIVE_BROADCAST_SCHEDULING_ENABLED=False):
            summary, _ = self.run_batch(client)

        self.assertFalse(summary["disabled"])
        self.assertEqual(summary["reconciled"], 1)

    def test_disabled_without_mautic_sync(self):
        self.campaign()
        client = self.provider()

        with override_settings(MAUTIC_SYNC_ENABLED=False):
            summary, factory = self.run_batch(client)

        self.assertTrue(summary["disabled"])
        factory.assert_not_called()

    # --- races between the provider read and the locked update -------------

    def test_cancel_during_provider_read_wins(self):
        campaign = self.campaign()
        completed = self.completed_for(campaign)

        def cancel_then_answer(_email_id):
            NewsletterCampaign.objects.filter(pk=campaign.pk).update(
                status=STATUS.CANCELLED, schedule_owner=""
            )
            return completed

        client = Mock()
        client.get_email.side_effect = cancel_then_answer
        client.get_latest_email_send.return_value = None

        summary, _ = self.run_batch(client)

        self.assertEqual(summary["skipped"], 1)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.CANCELLED)
        self.assertIsNone(campaign.sent_at)

    def test_reschedule_during_provider_read_wins(self):
        campaign = self.campaign()
        completed = self.completed_for(campaign)
        moved = timezone.now() + timedelta(hours=2)

        def reschedule_then_answer(_email_id):
            NewsletterCampaign.objects.filter(pk=campaign.pk).update(scheduled_at=moved)
            return completed

        client = Mock()
        client.get_email.side_effect = reschedule_then_answer
        client.get_latest_email_send.return_value = None

        summary, _ = self.run_batch(client)

        self.assertEqual(summary["skipped"], 1)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SCHEDULED)
        self.assertEqual(campaign.scheduled_at, moved)

    def test_cancelled_row_with_email_is_never_marked_sent(self):
        campaign = self.campaign(status=STATUS.CANCELLED, owner="")
        client = self.provider(self.completed_for(campaign))

        summary, _ = self.run_batch(client)

        self.assertEqual(summary["selected"], 0)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.CANCELLED)


# ---------------------------------------------------------------------------
# Post-due Reschedule/Cancel guard
# ---------------------------------------------------------------------------


@override_settings(**SYNC_ON)
class PostDueActionGuardTests(Base):
    def setUp(self):
        self.api = APIClient()
        self.user = User.objects.create_superuser(
            username="guard-admin", email="guard-admin@example.test", password="pw"
        )
        MauticUserConnection.objects.create(
            user=self.user,
            mautic_user_id=6,
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
            connected_at=timezone.now(),
        )
        self.api.force_authenticate(user=self.user)

    def schedule(self, campaign, when=None):
        return self.api.post(
            reverse("newsletter-admin-campaign-schedule", kwargs={"uuid": campaign.uuid}),
            {"scheduled_at": (when or timezone.now() + timedelta(days=1)).isoformat()},
            format="json",
        )

    def cancel(self, campaign):
        return self.api.post(
            reverse("newsletter-admin-campaign-cancel", kwargs={"uuid": campaign.uuid})
        )

    def guarded(self, client, call):
        with patch(
            "newsletter.native_broadcast_reconciliation.MauticClient",
            return_value=client,
        ), patch("newsletter.admin_views.reschedule_campaign_natively") as resched, patch(
            "newsletter.admin_views.cancel_native_schedule"
        ) as cancel, patch(
            "newsletter.mautic_identity_execution.interactive_mautic_client"
        ) as interactive:
            response = call()
        resched.assert_not_called()
        cancel.assert_not_called()
        interactive.assert_not_called()
        self.assertFalse(MauticIdentityAuditLog.objects.exists())
        return response

    def test_reschedule_after_completion_is_rejected_and_reconciled(self):
        campaign = self.campaign()
        client = self.provider(self.completed_for(campaign))

        response = self.guarded(client, lambda: self.schedule(campaign))

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["detail"].code, "campaign_already_sent")
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SENT)
        self.assert_no_provider_writes(client)

    def test_cancel_while_sending_is_rejected(self):
        campaign = self.campaign()
        client = self.provider(self.sending_for(campaign))

        response = self.guarded(client, lambda: self.cancel(campaign))

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["detail"].code, "native_delivery_started")
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SCHEDULED)
        self.assertEqual(campaign.schedule_owner, OWNER.MAUTIC)

    def test_cancel_after_completion_is_rejected_and_reconciled(self):
        campaign = self.campaign()
        client = self.provider(self.completed_for(campaign))

        response = self.guarded(client, lambda: self.cancel(campaign))

        self.assertEqual(response.status_code, 409)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SENT)

    def test_changes_are_refused_in_the_final_minute_without_a_provider_read(self):
        # The next whole minute: always inside the one-minute cutoff, never yet
        # the provider send minute, so no read is needed to refuse the change.
        next_minute = timezone.now().replace(second=0, microsecond=0) + timedelta(minutes=1)
        campaign = self.campaign(scheduled_at=next_minute)
        client = self.provider()

        response = self.guarded(client, lambda: self.schedule(campaign))

        self.assertEqual(response.status_code, 409)
        client.get_email.assert_not_called()

    def test_provider_outage_still_refuses_a_due_change(self):
        campaign = self.campaign()
        client = self.provider(error=TemporaryMauticError("down"))

        response = self.guarded(client, lambda: self.cancel(campaign))

        self.assertEqual(response.status_code, 409)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SCHEDULED)

    def test_future_native_schedule_can_still_be_rescheduled_and_cancelled(self):
        campaign = self.campaign(scheduled_at=timezone.now() + timedelta(hours=3))
        with patch(
            "newsletter.admin_views.reschedule_campaign_natively",
            side_effect=lambda c, **kw: c,
        ) as resched:
            self.assertEqual(self.schedule(campaign).status_code, 200)
        resched.assert_called_once()
        with patch(
            "newsletter.admin_views.cancel_native_schedule",
            side_effect=lambda c, **kw: c,
        ) as cancel:
            self.assertEqual(self.cancel(campaign).status_code, 200)
        cancel.assert_called_once()

    def test_sent_campaign_cannot_be_rescheduled_or_cancelled(self):
        campaign = self.campaign(status=STATUS.SENT, owner="")
        with override_settings(MAUTIC_NATIVE_BROADCAST_SCHEDULING_ENABLED=True):
            with patch(
                "newsletter.mautic_identity_execution.interactive_mautic_client"
            ) as interactive:
                self.assertEqual(self.schedule(campaign).status_code, 400)
                self.assertEqual(self.cancel(campaign).status_code, 400)
        interactive.assert_not_called()
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, STATUS.SENT)
        self.assertFalse(MauticIdentityAuditLog.objects.exists())

    def test_service_backstop_refuses_due_reschedule_and_cancel_locally(self):
        campaign = self.campaign()
        provider = Mock()
        with self.assertRaises(CampaignNativeDeliveryStarted):
            reschedule_campaign_natively(
                campaign,
                scheduled_at=timezone.now() + timedelta(days=1),
                user=self.user,
                client=provider,
            )
        with self.assertRaises(CampaignNativeDeliveryStarted):
            cancel_native_schedule(campaign, user=self.user, client=provider)
        self.assertEqual(provider.mock_calls, [])

    def test_window_helper_ignores_non_native_rows(self):
        past = timezone.now() - timedelta(minutes=5)
        self.assertFalse(
            native_delivery_window_started(self.campaign(owner=OWNER.ECP, scheduled_at=past))
        )
        self.assertFalse(
            native_delivery_window_started(
                self.campaign(status=STATUS.CANCELLED, owner="", scheduled_at=past)
            )
        )


# ---------------------------------------------------------------------------
# Minute precision
# ---------------------------------------------------------------------------


class MinuteRoundingTests(Base):
    def test_rounding_contract(self):
        base = datetime(2026, 10, 1, 10, 15, tzinfo=dt_timezone.utc)
        cases = {
            base: base,
            base + timedelta(seconds=1): base + timedelta(minutes=1),
            base + timedelta(seconds=59, microseconds=999000): base + timedelta(minutes=1),
            base + timedelta(microseconds=1): base + timedelta(minutes=1),
        }
        for given, expected in cases.items():
            self.assertEqual(round_up_to_schedule_minute(given), expected, given)

    def test_exact_minute_with_offset_keeps_the_same_instant(self):
        ist = datetime(2026, 10, 1, 15, 45, tzinfo=IST)  # 10:15 UTC
        self.assertEqual(
            round_up_to_schedule_minute(ist),
            datetime(2026, 10, 1, 10, 15, tzinfo=dt_timezone.utc),
        )

    @override_settings(**{**SYNC_ON, "MAUTIC_NATIVE_BROADCAST_SCHEDULING_ENABLED": True})
    def test_native_schedule_persists_and_sends_the_same_rounded_minute(self):
        user = User.objects.create_superuser(
            username="rounder", email="rounder@example.test", password="pw"
        )
        campaign = self.campaign(status=STATUS.DRAFT, owner="", email_id="")
        campaign.scheduled_at = None
        campaign.save(update_fields=["scheduled_at"])
        requested = (timezone.now() + timedelta(days=1)).replace(
            second=1, microsecond=0
        ).astimezone(IST)
        provider = Mock()
        provider.get_segment.return_value = {"id": "501", "filters": []}
        provider.create_email.return_value = {"id": "77"}

        with patch("newsletter.campaign_services.MauticClient", return_value=provider):
            result = schedule_campaign_natively(
                campaign, scheduled_at=requested, user=user, client=provider
            )

        expected = requested.astimezone(dt_timezone.utc).replace(second=0) + timedelta(
            minutes=1
        )
        self.assertEqual(result.scheduled_at, expected)
        payload = provider.create_email.call_args.args[0]
        self.assertEqual(payload["publishUp"], expected.strftime("%Y-%m-%d %H:%M"))
        self.assertGreater(result.scheduled_at, requested)

    @override_settings(**SYNC_ON)
    def test_ecp_owned_schedule_precision_is_unchanged(self):
        user = User.objects.create_superuser(
            username="ecp-sched", email="ecp-sched@example.test", password="pw"
        )
        campaign = self.campaign(status=STATUS.DRAFT, owner="", email_id="")
        requested = (timezone.now() + timedelta(days=1)).replace(second=37)

        result = schedule_campaign(campaign, scheduled_at=requested, user=user)

        self.assertEqual(result.scheduled_at, requested)
        self.assertEqual(result.schedule_owner, OWNER.ECP)


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


class NativeAnalyticsTests(Base):
    def setUp(self):
        self.api = APIClient()
        analyst = User.objects.create_superuser(
            username="analyst", email="analyst@example.test", password="pw"
        )
        grant_marketing_access(analyst)
        self.api.force_authenticate(analyst)

    def analytics(self, campaign, client):
        with patch("newsletter.analytics_services.MauticClient", return_value=client):
            return self.api.get(
                reverse(
                    "newsletter-admin-campaign-analytics",
                    kwargs={"uuid": campaign.uuid},
                )
            )

    def test_native_send_summary_comes_from_mautic_stats(self):
        campaign = self.campaign(status=STATUS.SENT, owner="")
        client = Mock()
        client.get_email_stats.return_value = {
            "total": "2",
            "stats": [
                {"lead_id": "1", "is_failed": "0", "is_read": "1"},
                {"lead_id": "2", "is_failed": "1", "is_read": "0"},
            ],
        }

        response = self.analytics(campaign, client)

        self.assertEqual(response.status_code, 200)
        summary = response.data["send_summary"]
        self.assertEqual(summary["sent_count"], 1)
        self.assertEqual(summary["failed_count"], 1)
        self.assertEqual(summary["success_rate"], 0.5)
        self.assertEqual(response.data["metadata"]["send_summary_source"], "mautic")
        # Sends are not deliveries.
        self.assertEqual(response.data["engagement"]["delivered_count"], 0)
        self.assertEqual(response.data["engagement"]["opened_count"], 1)
        client.get_email_stats.assert_called_once_with("77")
        client.count_email_stats.assert_not_called()

    def test_large_sends_use_exact_provider_totals(self):
        campaign = self.campaign(status=STATUS.SENT, owner="")
        client = Mock()
        client.get_email_stats.return_value = {
            "total": "250",
            "stats": [{"lead_id": str(i), "is_failed": "0"} for i in range(100)],
        }
        client.count_email_stats.side_effect = lambda _id, **f: {
            ("is_read", 1): 40,
            ("is_failed", 1): 5,
        }[next(iter(f.items()))]

        response = self.analytics(campaign, client)

        self.assertEqual(response.data["send_summary"]["sent_count"], 245)
        self.assertEqual(response.data["send_summary"]["failed_count"], 5)
        self.assertEqual(response.data["engagement"]["opened_count"], 40)
        self.assertEqual(response.data["metadata"]["mautic_stats_count"], 250)

    def test_send_now_summary_still_comes_from_the_send_event(self):
        campaign = self.campaign(status=STATUS.SENT, owner="")
        NewsletterCampaignSendEvent.objects.create(
            campaign=campaign,
            idempotency_key=f"send-{campaign.uuid}",
            status=NewsletterCampaignSendEvent.Status.SUCCEEDED,
            provider_sent_count=10,
            provider_failed_count=0,
        )
        client = Mock()
        client.get_email_stats.return_value = {
            "total": "3",
            "stats": [{"lead_id": str(i), "is_failed": "1"} for i in range(3)],
        }

        response = self.analytics(campaign, client)

        self.assertEqual(response.data["send_summary"]["sent_count"], 10)
        self.assertEqual(response.data["send_summary"]["failed_count"], 0)
        self.assertEqual(response.data["metadata"]["send_summary_source"], "ecp")
        client.count_email_stats.assert_not_called()

    def test_stats_failure_keeps_local_analytics_with_a_warning(self):
        campaign = self.campaign(status=STATUS.SENT, owner="")
        client = Mock()
        client.get_email_stats.side_effect = TemporaryMauticError("Stats unavailable")

        response = self.analytics(campaign, client)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["metadata"]["mautic_available"])
        self.assertIn("Stats unavailable", response.data["metadata"]["warnings"])
        self.assertEqual(response.data["send_summary"]["sent_count"], 0)


# ---------------------------------------------------------------------------
# Beat registration and diagnostics
# ---------------------------------------------------------------------------


BACKEND_ROOT = Path(__file__).resolve().parents[2]


def beat_tasks(**env):
    code = (
        "import json\n"
        "from ecp_backend.settings import base\n"
        "print(json.dumps([v['task'] for v in base.CELERY_BEAT_SCHEDULE.values()]))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=BACKEND_ROOT,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


class BeatRegistrationTests(TestCase):
    TASK = "newsletter.reconcile_native_scheduled_campaigns"

    def test_registered_once_with_sync_on_and_native_flag_off(self):
        tasks = beat_tasks(
            MAUTIC_SYNC_ENABLED="true",
            MAUTIC_NATIVE_BROADCAST_SCHEDULING_ENABLED="false",
        )
        self.assertEqual(tasks.count(self.TASK), 1)
        # Existing jobs are kept alongside it.
        self.assertIn("newsletter.dispatch_due_scheduled_campaigns", tasks)

    def test_absent_with_sync_off(self):
        tasks = beat_tasks(
            MAUTIC_SYNC_ENABLED="false",
            MAUTIC_NATIVE_BROADCAST_SCHEDULING_ENABLED="true",
        )
        self.assertNotIn(self.TASK, tasks)


class DiagnosticsTests(Base):
    @override_settings(
        CELERY_BEAT_SCHEDULE={
            "r": {"task": "newsletter.reconcile_native_scheduled_campaigns"},
        }
    )
    def test_reports_reconciliation_and_native_counts(self):
        from newsletter.mautic_diagnostics_services import (
            _background_processing_status,
            _native_broadcast_status,
        )

        self.campaign()  # due
        self.campaign(scheduled_at=timezone.now() + timedelta(hours=1))
        self.campaign(last_error=MISSING_EMAIL_ERROR)
        self.campaign(owner=OWNER.ECP)

        self.assertTrue(
            _background_processing_status()["native_broadcast_reconciliation_scheduled"]
        )
        self.assertEqual(
            _native_broadcast_status(), {"scheduled": 3, "due": 2, "needs_attention": 1}
        )
