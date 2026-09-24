"""Native Mautic broadcast scheduling (Batch 2).

Schedule ownership is durable on the row, not derived from the feature flag,
because the one thing that must never happen is a broadcast delivered twice:
once by Mautic's own scheduler and once by the ECP due dispatcher.

Mautic semantics encoded here were verified against the running 7.1.3 instance:
EmailRepository::getPublishedBroadcastsQuery() calls
getPublishedByDateExpression(..., allowNullForPublishedUp: false), so an armed
broadcast is isPublished=true WITH a non-null publishUp, and clearing either
makes it ineligible. The Email form accepts "Y-m-d H:i" interpreted in Mautic's
default_timezone (UTC); an ISO-8601 string with an offset is rejected.
"""

from datetime import timedelta, timezone as datetime_timezone
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.campaign_send_operations import (
    due_campaign_send_event_ids,
    due_scheduled_campaign_ids,
)
from newsletter.campaign_services import (
    CampaignMauticSyncFailed,
    CampaignMauticUnavailable,
    CampaignScheduleNotAllowed,
    cancel_native_schedule,
    effective_schedule_owner,
    is_mautic_scheduled,
    reschedule_campaign_natively,
    resolve_schedule_owner_for_request,
    schedule_campaign_natively,
)
from newsletter.mautic.exceptions import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.payloads import format_mautic_schedule_datetime
from newsletter.models import (
    MauticIdentityAuditLog,
    MauticUserConnection,
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCategory,
)
from newsletter.tests.test_mautic_user_identity import IDENTITY_SETTINGS


User = get_user_model()

OWNER = NewsletterCampaign.ScheduleOwner

NATIVE_ON = {
    **IDENTITY_SETTINGS,
    "MAUTIC_SYNC_ENABLED": True,
    "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": True,
    "MAUTIC_NATIVE_BROADCAST_SCHEDULING_ENABLED": True,
}
NATIVE_OFF = {**NATIVE_ON, "MAUTIC_NATIVE_BROADCAST_SCHEDULING_ENABLED": False}

IST = datetime_timezone(timedelta(hours=5, minutes=30))


class SchedulingBase(TestCase):
    def build_campaign(self, *, status=NewsletterCampaign.Status.DRAFT,
                       schedule_owner="", mautic_email_id="",
                       scheduled_at=None, slug_suffix="a"):
        category = NewsletterCategory.objects.create(
            name=f"Schedule List {slug_suffix}",
            slug=f"schedule-list-{slug_suffix}",
            mautic_segment_id="501",
        )
        campaign = NewsletterCampaign.objects.create(
            name="Scheduled Broadcast",
            subject="Subject",
            from_name="ECP",
            from_email="news@example.test",
            html_content="<p>Hello</p>",
            status=status,
            schedule_owner=schedule_owner,
            mautic_email_id=mautic_email_id,
            scheduled_at=scheduled_at,
        )
        campaign.audiences.set([category])
        return campaign

    def provider(self, **behaviour):
        client = Mock()
        client.get_segment.return_value = {"id": "501", "filters": []}
        client.create_email.return_value = {"id": "77"}
        for name, value in behaviour.items():
            attr = getattr(client, name)
            if isinstance(value, Exception):
                attr.side_effect = value
            else:
                attr.return_value = value
        return client

    def future(self, hours=24):
        return timezone.now() + timedelta(hours=hours)


# ---------------------------------------------------------------------------
# Mautic datetime contract
# ---------------------------------------------------------------------------


class ScheduleDatetimeFormatTests(TestCase):
    def test_instant_is_preserved_across_a_non_utc_offset(self):
        moment = timezone.datetime(2026, 10, 1, 12, 0, tzinfo=IST)
        # 12:00+05:30 is 06:30 UTC; Mautic reads the naive string as UTC.
        self.assertEqual(format_mautic_schedule_datetime(moment), "2026-10-01 06:30")

    def test_utc_instant_round_trips_unchanged(self):
        moment = timezone.datetime(2026, 10, 1, 12, 0, tzinfo=datetime_timezone.utc)
        self.assertEqual(format_mautic_schedule_datetime(moment), "2026-10-01 12:00")

    def test_no_offset_suffix_is_emitted(self):
        rendered = format_mautic_schedule_datetime(
            timezone.datetime(2026, 10, 1, 12, 0, tzinfo=IST)
        )
        # Mautic rejects ISO-8601 with an offset outright.
        self.assertNotIn("+", rendered)
        self.assertNotIn("T", rendered)

    def test_none_renders_as_the_clearing_value(self):
        self.assertEqual(format_mautic_schedule_datetime(None), "")


# ---------------------------------------------------------------------------
# Ownership model
# ---------------------------------------------------------------------------


class ScheduleOwnershipTests(SchedulingBase):
    def test_unscheduled_campaign_has_no_owner(self):
        campaign = self.build_campaign()
        self.assertEqual(campaign.schedule_owner, "")
        self.assertEqual(effective_schedule_owner(campaign), "")
        self.assertFalse(is_mautic_scheduled(campaign))

    def test_blank_owner_on_a_scheduled_row_is_read_as_ecp(self):
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner="",
            scheduled_at=self.future(),
        )
        self.assertEqual(effective_schedule_owner(campaign), OWNER.ECP)
        self.assertFalse(is_mautic_scheduled(campaign))

    @override_settings(**NATIVE_ON)
    def test_flag_chooses_owner_only_for_a_fresh_schedule(self):
        draft = self.build_campaign()
        self.assertEqual(resolve_schedule_owner_for_request(draft), OWNER.MAUTIC)

    @override_settings(**NATIVE_OFF)
    def test_flag_off_gives_a_fresh_schedule_to_ecp(self):
        draft = self.build_campaign()
        self.assertEqual(resolve_schedule_owner_for_request(draft), OWNER.ECP)

    @override_settings(**NATIVE_ON)
    def test_existing_ecp_schedule_keeps_ecp_when_flag_is_on(self):
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.ECP,
            scheduled_at=self.future(),
        )
        self.assertEqual(resolve_schedule_owner_for_request(campaign), OWNER.ECP)

    @override_settings(**NATIVE_OFF)
    def test_existing_mautic_schedule_keeps_mautic_when_flag_is_off(self):
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.MAUTIC,
            scheduled_at=self.future(),
        )
        self.assertEqual(resolve_schedule_owner_for_request(campaign), OWNER.MAUTIC)
        self.assertTrue(is_mautic_scheduled(campaign))


# ---------------------------------------------------------------------------
# The double-send guard
# ---------------------------------------------------------------------------


@override_settings(**NATIVE_ON)
class DueDispatcherOwnershipTests(SchedulingBase):
    def due(self, owner, suffix):
        return self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=owner,
            scheduled_at=timezone.now() - timedelta(minutes=5),
            slug_suffix=suffix,
        )

    def test_ecp_owned_due_campaign_is_selected(self):
        campaign = self.due(OWNER.ECP, "ecp")
        self.assertIn(campaign.pk, due_scheduled_campaign_ids())

    def test_blank_owner_due_campaign_is_selected_defensively(self):
        campaign = self.due("", "blank")
        self.assertIn(campaign.pk, due_scheduled_campaign_ids())

    def test_mautic_owned_due_campaign_is_never_selected(self):
        campaign = self.due(OWNER.MAUTIC, "mautic")
        self.assertNotIn(campaign.pk, due_scheduled_campaign_ids())

    @override_settings(**NATIVE_OFF)
    def test_mautic_owned_is_excluded_even_with_the_flag_off(self):
        """Ownership, not the flag, decides. This is the rollback guarantee."""
        campaign = self.due(OWNER.MAUTIC, "mautic-off")
        self.assertNotIn(campaign.pk, due_scheduled_campaign_ids())

    @override_settings(**NATIVE_OFF)
    def test_ecp_owned_is_still_selected_with_the_flag_off(self):
        campaign = self.due(OWNER.ECP, "ecp-off")
        self.assertIn(campaign.pk, due_scheduled_campaign_ids())

    def test_dispatch_does_not_create_a_send_event_for_a_native_schedule(self):
        from newsletter.campaign_send_operations import dispatch_due_scheduled_campaigns

        campaign = self.due(OWNER.MAUTIC, "dispatch")
        result = dispatch_due_scheduled_campaigns()

        self.assertEqual(result["selected"], 0)
        self.assertFalse(
            NewsletterCampaignSendEvent.objects.filter(campaign=campaign).exists()
        )

    def test_stray_pending_event_for_a_native_schedule_is_not_recovered(self):
        campaign = self.due(OWNER.MAUTIC, "stray")
        event = NewsletterCampaignSendEvent.objects.create(
            campaign=campaign,
            idempotency_key=f"stray:{campaign.uuid}",
        )
        self.assertNotIn(event.pk, due_campaign_send_event_ids())

    def test_ecp_owned_pending_event_is_still_recovered(self):
        campaign = self.due(OWNER.ECP, "recoverable")
        event = NewsletterCampaignSendEvent.objects.create(
            campaign=campaign,
            idempotency_key=f"ok:{campaign.uuid}",
        )
        self.assertIn(event.pk, due_campaign_send_event_ids())

    def test_send_now_event_for_a_draft_is_still_recovered(self):
        campaign = self.build_campaign(slug_suffix="sendnow")
        event = NewsletterCampaignSendEvent.objects.create(
            campaign=campaign,
            idempotency_key=f"sendnow:{campaign.uuid}",
        )
        self.assertIn(event.pk, due_campaign_send_event_ids())


# ---------------------------------------------------------------------------
# Native schedule / reschedule / cancel services
# ---------------------------------------------------------------------------


@override_settings(**NATIVE_ON)
class NativeScheduleServiceTests(SchedulingBase):
    def setUp(self):
        self.user = User.objects.create_superuser(
            username="scheduler", email="scheduler@example.test", password="pw"
        )

    def run_schedule(self, campaign, when, provider, fn=schedule_campaign_natively):
        with patch("newsletter.campaign_services.MauticClient", return_value=provider):
            return fn(campaign, scheduled_at=when, user=self.user, client=provider)

    def test_initial_schedule_creates_one_armed_email(self):
        campaign = self.build_campaign()
        provider = self.provider()
        when = self.future()

        result = self.run_schedule(campaign, when, provider)

        provider.create_email.assert_called_once()
        provider.update_email.assert_not_called()
        payload = provider.create_email.call_args.args[0]
        self.assertEqual(payload["emailType"], "list")
        self.assertEqual(payload["lists"], [501])
        self.assertTrue(payload["isPublished"], "an armed broadcast must be published")
        self.assertEqual(payload["publishUp"], format_mautic_schedule_datetime(when))
        # Content is synchronized together with the schedule.
        self.assertEqual(payload["subject"], "Subject")
        self.assertEqual(payload["fromAddress"], "news@example.test")

        self.assertEqual(result.status, NewsletterCampaign.Status.SCHEDULED)
        self.assertEqual(result.schedule_owner, OWNER.MAUTIC)
        self.assertEqual(result.mautic_email_id, "77")
        self.assertEqual(result.scheduled_at, when)

    def test_schedule_with_existing_email_updates_the_same_one(self):
        campaign = self.build_campaign(mautic_email_id="77")
        provider = self.provider()

        result = self.run_schedule(campaign, self.future(), provider)

        provider.update_email.assert_called_once()
        provider.create_email.assert_not_called()
        self.assertEqual(provider.update_email.call_args.args[0], "77")
        self.assertEqual(result.mautic_email_id, "77")

    def test_schedule_preserves_the_exact_instant_across_offsets(self):
        campaign = self.build_campaign()
        provider = self.provider()
        when = (timezone.now() + timedelta(days=2)).astimezone(IST)

        self.run_schedule(campaign, when, provider)

        payload = provider.create_email.call_args.args[0]
        self.assertEqual(payload["publishUp"], format_mautic_schedule_datetime(when))

    def test_reschedule_keeps_the_email_and_the_owner(self):
        original = self.future(24)
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.MAUTIC,
            mautic_email_id="77",
            scheduled_at=original,
        )
        provider = self.provider()
        moved = self.future(48)

        result = self.run_schedule(
            campaign, moved, provider, fn=reschedule_campaign_natively
        )

        provider.update_email.assert_called_once()
        provider.create_email.assert_not_called()
        self.assertEqual(result.mautic_email_id, "77")
        self.assertEqual(result.scheduled_at, moved)
        self.assertEqual(result.schedule_owner, OWNER.MAUTIC)
        self.assertEqual(result.status, NewsletterCampaign.Status.SCHEDULED)

    def test_reschedule_failure_leaves_the_old_time_intact(self):
        original = self.future(24)
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.MAUTIC,
            mautic_email_id="77",
            scheduled_at=original,
        )
        provider = self.provider(update_email=PermanentMauticError("rejected"))

        with self.assertRaises(CampaignMauticSyncFailed):
            self.run_schedule(
                campaign, self.future(48), provider, fn=reschedule_campaign_natively
            )

        campaign.refresh_from_db()
        self.assertEqual(campaign.scheduled_at, original)
        self.assertEqual(campaign.schedule_owner, OWNER.MAUTIC)
        self.assertEqual(campaign.status, NewsletterCampaign.Status.SCHEDULED)

    def test_reschedule_without_a_linked_email_fails_closed(self):
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.MAUTIC,
            scheduled_at=self.future(),
        )
        provider = self.provider()

        with self.assertRaises(CampaignMauticSyncFailed):
            self.run_schedule(
                campaign, self.future(48), provider, fn=reschedule_campaign_natively
            )

        provider.create_email.assert_not_called()

    def test_schedule_failure_leaves_the_campaign_a_draft(self):
        campaign = self.build_campaign()
        provider = self.provider(create_email=TemporaryMauticError("down"))

        with self.assertRaises(CampaignMauticUnavailable):
            self.run_schedule(campaign, self.future(), provider)

        campaign.refresh_from_db()
        self.assertEqual(campaign.status, NewsletterCampaign.Status.DRAFT)
        self.assertEqual(campaign.schedule_owner, "")
        self.assertIsNone(campaign.scheduled_at)

    def test_past_time_is_rejected_before_any_provider_contact(self):
        campaign = self.build_campaign()
        provider = self.provider()

        with self.assertRaises(CampaignScheduleNotAllowed):
            self.run_schedule(campaign, timezone.now() - timedelta(hours=1), provider)

        provider.create_email.assert_not_called()
        provider.update_email.assert_not_called()

    def test_invalid_draft_is_rejected_before_any_provider_contact(self):
        campaign = self.build_campaign()
        campaign.subject = ""
        campaign.save(update_fields=["subject"])
        provider = self.provider()

        with self.assertRaises(Exception):
            self.run_schedule(campaign, self.future(), provider)

        provider.create_email.assert_not_called()

    def test_local_save_failure_disarms_the_provider_schedule(self):
        campaign = self.build_campaign()
        provider = self.provider()

        with patch("newsletter.campaign_services.MauticClient", return_value=provider), \
             patch.object(
                 NewsletterCampaign, "save", side_effect=RuntimeError("db down")
             ):
            with self.assertRaises(RuntimeError):
                schedule_campaign_natively(
                    campaign,
                    scheduled_at=self.future(),
                    user=self.user,
                    client=provider,
                )

        # The compensating update clears publishUp so Mautic will not deliver a
        # broadcast ECP has no record of.
        compensation = provider.update_email.call_args
        self.assertIsNotNone(compensation, "a compensating disarm must be attempted")
        self.assertEqual(compensation.args[1]["publishUp"], "")
        self.assertFalse(compensation.args[1]["isPublished"])


@override_settings(**NATIVE_ON)
class NativeCancelServiceTests(SchedulingBase):
    def setUp(self):
        self.user = User.objects.create_superuser(
            username="canceller", email="canceller@example.test", password="pw"
        )

    def scheduled(self, **kwargs):
        return self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.MAUTIC,
            mautic_email_id="77",
            scheduled_at=self.future(),
            **kwargs,
        )

    def run_cancel(self, campaign, provider):
        with patch("newsletter.campaign_services.MauticClient", return_value=provider):
            return cancel_native_schedule(campaign, user=self.user, client=provider)

    def test_cancel_disarms_the_email_without_deleting_it(self):
        campaign = self.scheduled()
        provider = self.provider()

        result = self.run_cancel(campaign, provider)

        provider.update_email.assert_called_once()
        provider.delete_email.assert_not_called()
        email_id, payload = provider.update_email.call_args.args
        self.assertEqual(email_id, "77")
        self.assertEqual(payload["publishUp"], "")
        self.assertFalse(payload["isPublished"])

        self.assertEqual(result.status, NewsletterCampaign.Status.CANCELLED)
        self.assertEqual(result.schedule_owner, "")
        self.assertEqual(result.mautic_email_id, "77")

    def test_cancel_failure_keeps_the_campaign_scheduled(self):
        campaign = self.scheduled()
        provider = self.provider(update_email=PermanentMauticError("rejected"))

        with self.assertRaises(CampaignMauticSyncFailed):
            self.run_cancel(campaign, provider)

        campaign.refresh_from_db()
        # Mautic may still deliver it, so ECP must not claim it is cancelled.
        self.assertEqual(campaign.status, NewsletterCampaign.Status.SCHEDULED)
        self.assertEqual(campaign.schedule_owner, OWNER.MAUTIC)

    def test_cancelled_campaign_is_no_longer_due_dispatchable(self):
        campaign = self.scheduled()
        provider = self.provider()

        self.run_cancel(campaign, provider)

        self.assertNotIn(campaign.pk, due_scheduled_campaign_ids())

    def test_cancel_is_refused_after_provider_delivery_started(self):
        campaign = self.scheduled()
        NewsletterCampaignSendEvent.objects.create(
            campaign=campaign,
            idempotency_key=f"started:{campaign.uuid}",
            provider_send_started_at=timezone.now(),
        )
        provider = self.provider()

        with self.assertRaises(CampaignScheduleNotAllowed):
            self.run_cancel(campaign, provider)

        provider.update_email.assert_not_called()

    def test_cancel_without_a_linked_email_fails_closed(self):
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.MAUTIC,
            scheduled_at=self.future(),
        )
        provider = self.provider()

        with self.assertRaises(CampaignMauticSyncFailed):
            self.run_cancel(campaign, provider)

        campaign.refresh_from_db()
        self.assertEqual(campaign.status, NewsletterCampaign.Status.SCHEDULED)


# ---------------------------------------------------------------------------
# API + identity
# ---------------------------------------------------------------------------


@override_settings(**NATIVE_ON)
class NativeScheduleApiTests(SchedulingBase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_superuser(
            username="schedule-admin", email="schedule-admin@example.test", password="pw"
        )
        MauticUserConnection.objects.create(
            user=self.user,
            mautic_user_id=6,
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
            connected_at=timezone.now(),
        )
        self.client.force_authenticate(user=self.user)

    def schedule_url(self, campaign):
        return reverse(
            "newsletter-admin-campaign-schedule", kwargs={"uuid": campaign.uuid}
        )

    def cancel_url(self, campaign):
        return reverse(
            "newsletter-admin-campaign-cancel", kwargs={"uuid": campaign.uuid}
        )

    def test_initial_schedule_audits_email_create_as_asserted_user(self):
        campaign = self.build_campaign()

        with patch(
            "newsletter.admin_views.schedule_campaign_natively",
            side_effect=lambda c, **kw: c,
        ):
            resp = self.client.post(
                self.schedule_url(campaign),
                {"scheduled_at": self.future().isoformat()},
                format="json",
            )

        self.assertEqual(resp.status_code, 200)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.action, MauticIdentityAuditLog.Action.EMAIL_CREATE)
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.SUCCEEDED)
        self.assertEqual(entry.auth_mode, "asserted_user")
        self.assertEqual(entry.mautic_user_id, 6)

    def test_schedule_with_existing_email_audits_email_update(self):
        campaign = self.build_campaign(mautic_email_id="77")

        with patch(
            "newsletter.admin_views.schedule_campaign_natively",
            side_effect=lambda c, **kw: c,
        ):
            resp = self.client.post(
                self.schedule_url(campaign),
                {"scheduled_at": self.future().isoformat()},
                format="json",
            )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            MauticIdentityAuditLog.objects.get().action,
            MauticIdentityAuditLog.Action.EMAIL_UPDATE,
        )

    def test_reschedule_audits_email_update(self):
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.MAUTIC,
            mautic_email_id="77",
            scheduled_at=self.future(),
        )

        with patch(
            "newsletter.admin_views.reschedule_campaign_natively",
            side_effect=lambda c, **kw: c,
        ) as resched:
            resp = self.client.post(
                self.schedule_url(campaign),
                {"scheduled_at": self.future(48).isoformat()},
                format="json",
            )

        self.assertEqual(resp.status_code, 200)
        resched.assert_called_once()
        self.assertEqual(
            MauticIdentityAuditLog.objects.get().action,
            MauticIdentityAuditLog.Action.EMAIL_UPDATE,
        )

    def test_cancel_audits_email_update(self):
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.MAUTIC,
            mautic_email_id="77",
            scheduled_at=self.future(),
        )

        with patch(
            "newsletter.admin_views.cancel_native_schedule",
            side_effect=lambda c, **kw: c,
        ):
            resp = self.client.post(self.cancel_url(campaign))

        self.assertEqual(resp.status_code, 200)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.action, MauticIdentityAuditLog.Action.EMAIL_UPDATE)
        self.assertEqual(entry.auth_mode, "asserted_user")

    def test_provider_failure_writes_exactly_one_failed_row(self):
        campaign = self.build_campaign()

        with patch(
            "newsletter.admin_views.schedule_campaign_natively",
            side_effect=CampaignMauticSyncFailed("rejected"),
        ):
            resp = self.client.post(
                self.schedule_url(campaign),
                {"scheduled_at": self.future().isoformat()},
                format="json",
            )

        self.assertEqual(resp.status_code, 502)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.action, MauticIdentityAuditLog.Action.EMAIL_CREATE)
        self.assertIn(
            entry.status,
            {
                MauticIdentityAuditLog.Status.FAILED,
                MauticIdentityAuditLog.Status.DENIED,
            },
        )

    @override_settings(**{**NATIVE_ON, "ECP_MAUTIC_IDENTITY_PRIVATE_KEY": ""})
    def test_missing_signing_config_fails_closed(self):
        campaign = self.build_campaign()

        with patch("newsletter.admin_views.schedule_campaign_natively") as service:
            resp = self.client.post(
                self.schedule_url(campaign),
                {"scheduled_at": self.future().isoformat()},
                format="json",
            )

        self.assertGreaterEqual(resp.status_code, 400)
        service.assert_not_called()
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, NewsletterCampaign.Status.DRAFT)

    def test_past_time_is_rejected_by_the_api(self):
        campaign = self.build_campaign()

        resp = self.client.post(
            self.schedule_url(campaign),
            {"scheduled_at": (timezone.now() - timedelta(hours=1)).isoformat()},
            format="json",
        )

        self.assertEqual(resp.status_code, 400)

    def test_schedule_owner_is_reported_read_only(self):
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.MAUTIC,
            scheduled_at=self.future(),
        )
        resp = self.client.get(
            reverse("newsletter-admin-campaign-detail", kwargs={"uuid": campaign.uuid})
        )
        self.assertEqual(resp.data["schedule_owner"], OWNER.MAUTIC)


@override_settings(**NATIVE_OFF)
class EcpScheduleRegressionTests(SchedulingBase):
    """Flag off keeps the pre-Batch-2 behaviour exactly."""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_superuser(
            username="ecp-admin", email="ecp-admin@example.test", password="pw"
        )
        MauticUserConnection.objects.create(
            user=self.user,
            mautic_user_id=6,
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
            connected_at=timezone.now(),
        )
        self.client.force_authenticate(user=self.user)

    def test_schedule_is_local_only_and_contacts_no_provider(self):
        campaign = self.build_campaign()

        with patch("newsletter.campaign_services.MauticClient") as provider:
            resp = self.client.post(
                reverse(
                    "newsletter-admin-campaign-schedule",
                    kwargs={"uuid": campaign.uuid},
                ),
                {"scheduled_at": self.future().isoformat()},
                format="json",
            )

        self.assertEqual(resp.status_code, 200)
        provider.assert_not_called()
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, NewsletterCampaign.Status.SCHEDULED)
        self.assertEqual(campaign.schedule_owner, OWNER.ECP)
        # No assertion is minted when no provider mutation happens.
        self.assertFalse(MauticIdentityAuditLog.objects.exists())

    def test_send_now_stays_blocked_while_scheduled(self):
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.ECP,
            scheduled_at=self.future(),
        )

        resp = self.client.post(
            reverse("newsletter-admin-campaign-send", kwargs={"uuid": campaign.uuid})
        )

        self.assertGreaterEqual(resp.status_code, 400)

    def test_cancel_uses_local_behaviour_and_clears_ownership(self):
        campaign = self.build_campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=OWNER.ECP,
            scheduled_at=self.future(),
        )

        with patch("newsletter.campaign_services.MauticClient") as provider:
            resp = self.client.post(
                reverse(
                    "newsletter-admin-campaign-cancel", kwargs={"uuid": campaign.uuid}
                )
            )

        self.assertEqual(resp.status_code, 200)
        provider.assert_not_called()
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, NewsletterCampaign.Status.CANCELLED)
        self.assertEqual(campaign.schedule_owner, "")


@override_settings(**NATIVE_ON)
class NativeScheduleSegmentRecoveryTests(SchedulingBase):
    """Batch 1 stale-segment repair still applies when scheduling natively."""

    def setUp(self):
        self.user = User.objects.create_superuser(
            username="sched-repair", email="sched-repair@example.test", password="pw"
        )

    def test_stale_segment_is_repaired_and_the_schedule_uses_the_new_id(self):
        category = NewsletterCategory.objects.create(
            name="Stale Schedule List",
            slug="stale-schedule-list",
            mautic_segment_id="1",
        )
        campaign = NewsletterCampaign.objects.create(
            name="Stale Scheduled Broadcast",
            subject="Subject",
            from_name="ECP",
            from_email="news@example.test",
            html_content="<p>Hello</p>",
        )
        campaign.audiences.set([category])
        campaign = NewsletterCampaign.objects.prefetch_related("audiences").get(
            pk=campaign.pk
        )

        provider = Mock()
        provider.get_segment.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404): not found"
        )
        provider.list_segments.return_value = {"lists": []}
        provider.create_segment.return_value = {"id": 2}
        provider.create_email.return_value = {"id": "77"}

        with patch("newsletter.campaign_services.MauticClient", return_value=provider):
            result = schedule_campaign_natively(
                campaign,
                scheduled_at=self.future(),
                user=self.user,
                client=provider,
            )

        payload = provider.create_email.call_args.args[0]
        self.assertEqual(payload["lists"], [2], "must schedule against the repaired id")
        category.refresh_from_db()
        self.assertEqual(category.mautic_segment_id, "2")
        self.assertEqual(result.schedule_owner, OWNER.MAUTIC)
