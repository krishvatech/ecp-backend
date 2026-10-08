"""Read-only broadcast delivery inspection (uncertain Send Now, native schedules).

Inspection is diagnosis only: these tests pin that it never sends, never calls
a mutating Mautic method, never writes to the database, never makes a crossed
provider-send boundary retryable, and never claims completion that Mautic's
evidence does not prove.
"""

from datetime import timedelta
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter import broadcast_delivery_inspection as inspection
from newsletter.campaign_send_events import create_campaign_send_event
from newsletter.campaign_send_operations import dispatch_due_campaign_send_events
from newsletter.campaign_send_processor import UNCERTAIN_SEND_MESSAGE
from newsletter.campaign_services import request_campaign_send
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.models import (
    MauticIdentityAuditLog,
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
)
from newsletter.tests.marketing_actors import grant_marketing_access

User = get_user_model()

READ_METHODS = {"get_email", "count_email_stats", "get_latest_email_send"}
BEAT = {"dispatch": {"task": "newsletter.dispatch_due_scheduled_campaigns",
                     "schedule": timedelta(minutes=1)}}


def provider(*, sent=0, recorded=None, failed=0, published=True, publish_up=None,
             email_error=None, stats_error=None):
    client = Mock(spec=MauticClient)
    if email_error:
        client.get_email.side_effect = email_error
    else:
        client.get_email.return_value = {
            "id": 77, "emailType": "list", "isPublished": published, "sentCount": sent,
            "publishUp": publish_up, "publishDown": None,
        }
    recorded = sent if recorded is None else recorded
    if stats_error:
        client.count_email_stats.side_effect = stats_error
    else:
        client.count_email_stats.side_effect = (
            lambda email_id, **filters: failed if filters.get("is_failed") else recorded
        )
    client.get_latest_email_send.return_value = (
        {"date_sent": "2026-10-08 08:34:02"} if recorded else None
    )
    return client


def called_methods(client):
    return {call[0].split(".")[0] for call in client.mock_calls if call[0]}


@override_settings(MAUTIC_SYNC_ENABLED=True, CELERY_BEAT_SCHEDULE=BEAT,
                   MAUTIC_SYNC_PROCESSING_TIMEOUT_SECONDS=600)
class SendNowInspectionTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            username="inspect-admin", email="inspect-admin@example.test", password="pw",
            is_staff=True, is_superuser=True,
        )
        self.campaign = NewsletterCampaign.objects.create(
            name="Lost Response", subject="Hi", mautic_email_id="77",
        )
        self.event = create_campaign_send_event(self.campaign, requested_by=self.admin)

    def cross_boundary(self, *, uncertain=True, started_ago=timedelta(minutes=1)):
        started = timezone.now() - started_ago
        NewsletterCampaignSendEvent.objects.filter(pk=self.event.pk).update(
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            provider_send_started_at=started, processing_started_at=started,
            attempt_count=1, last_error=f"{UNCERTAIN_SEND_MESSAGE} (x)" if uncertain else "",
        )
        NewsletterCampaign.objects.filter(pk=self.campaign.pk).update(
            status=NewsletterCampaign.Status.SENDING, send_started_at=started,
        )
        self.campaign.refresh_from_db()
        self.event.refresh_from_db()

    def inspect(self, client):
        return inspection.inspect_broadcast_delivery(self.campaign, client=client)

    def test_uncertain_send_with_recorded_delivery_is_never_called_complete(self):
        self.cross_boundary()
        client = provider(sent=3, failed=1)
        result = self.inspect(client)

        delivery = result["delivery"]
        self.assertEqual(delivery["category"], "send_outcome_unconfirmed")
        self.assertTrue(delivery["delivery_recorded"])
        self.assertFalse(delivery["completion_provable"])
        self.assertFalse(delivery["automatic_retry_allowed"])
        self.assertTrue(delivery["provider_send_boundary_crossed"])
        self.assertEqual(result["provider"]["sent_count"], 3)
        self.assertEqual(result["provider"]["stats"]["failed"], 1)
        self.assertIn("will not be retried", delivery["guidance"])
        self.assertLessEqual(called_methods(client), READ_METHODS)

    def test_uncertain_send_with_no_recorded_delivery_is_still_unconfirmed(self):
        self.cross_boundary()
        result = self.inspect(provider(sent=0))
        self.assertEqual(result["delivery"]["category"], "send_outcome_unconfirmed")
        self.assertFalse(result["delivery"]["delivery_recorded"])
        self.assertFalse(result["delivery"]["completion_provable"])

    def test_provider_unavailable_reports_unknown_evidence(self):
        self.cross_boundary()
        result = self.inspect(provider(email_error=TemporaryMauticError("down")))
        self.assertFalse(result["provider"]["available"])
        self.assertEqual(result["provider"]["error"], "unavailable")
        self.assertIsNone(result["delivery"]["delivery_recorded"])
        self.assertEqual(result["delivery"]["category"], "send_outcome_unconfirmed")

    def test_stats_unavailable_keeps_email_evidence(self):
        self.cross_boundary()
        result = self.inspect(provider(sent=2, stats_error=TemporaryMauticError("slow")))
        self.assertIsNone(result["provider"]["stats"])
        self.assertTrue(result["delivery"]["delivery_recorded"])

    def test_worker_lost_after_boundary_becomes_unconfirmed_after_timeout(self):
        self.cross_boundary(uncertain=False, started_ago=timedelta(minutes=2))
        self.assertEqual(self.inspect(provider())["delivery"]["category"], "send_in_progress")
        self.cross_boundary(uncertain=False, started_ago=timedelta(minutes=11))
        self.assertEqual(self.inspect(provider())["delivery"]["category"], "send_outcome_unconfirmed")

    def test_send_never_reached_mautic_is_retryable_by_recovery(self):
        result = self.inspect(provider())
        self.assertEqual(result["delivery"]["category"], "send_queued")
        self.assertTrue(result["delivery"]["automatic_retry_allowed"])
        self.assertFalse(result["delivery"]["provider_send_boundary_crossed"])

    def test_missing_mautic_email_does_not_call_mautic(self):
        self.campaign.mautic_email_id = ""
        self.campaign.save(update_fields=["mautic_email_id"])
        client = provider()
        result = self.inspect(client)
        self.assertFalse(result["provider"]["checked"])
        self.assertEqual(client.mock_calls, [])

    def test_sent_and_failed_broadcasts(self):
        NewsletterCampaign.objects.filter(pk=self.campaign.pk).update(status="sent", sent_at=timezone.now())
        self.campaign.refresh_from_db()
        sent = self.inspect(provider(sent=5))["delivery"]
        self.assertEqual((sent["category"], sent["completion_provable"]), ("sent", True))

        NewsletterCampaign.objects.filter(pk=self.campaign.pk).update(status="failed")
        self.campaign.refresh_from_db()
        self.assertEqual(self.inspect(provider())["delivery"]["category"], "failed_before_send")
        self.cross_boundary()
        NewsletterCampaign.objects.filter(pk=self.campaign.pk).update(status="failed")
        self.campaign.refresh_from_db()
        self.assertEqual(self.inspect(provider())["delivery"]["category"], "failed")

    def test_inspection_writes_nothing_and_never_enables_a_resend(self):
        self.cross_boundary()
        before_campaign = NewsletterCampaign.objects.values().get(pk=self.campaign.pk)
        before_event = NewsletterCampaignSendEvent.objects.values().get(pk=self.event.pk)
        before_audit = MauticIdentityAuditLog.objects.count()
        client = provider(sent=1)

        first = self.inspect(client)
        second = self.inspect(client)

        self.assertEqual(first["delivery"], second["delivery"])
        self.assertEqual(NewsletterCampaign.objects.values().get(pk=self.campaign.pk), before_campaign)
        self.assertEqual(NewsletterCampaignSendEvent.objects.values().get(pk=self.event.pk), before_event)
        self.assertEqual(MauticIdentityAuditLog.objects.count(), before_audit)
        self.assertEqual(NewsletterCampaignSendEvent.objects.filter(campaign=self.campaign).count(), 1)
        self.assertLessEqual(called_methods(client), READ_METHODS)
        # Recovery and a repeated Send Now still refuse to resend afterwards.
        self.assertEqual(dispatch_due_campaign_send_events()["selected"], 0)
        with patch("newsletter.campaign_services.dispatch_campaign_send_event_safely") as dispatch:
            with self.captureOnCommitCallbacks(execute=True):
                request_campaign_send(self.campaign, user=self.admin)
        dispatch.assert_not_called()

    def test_audit_history_is_included_and_bounded(self):
        for n in range(12):
            MauticIdentityAuditLog.objects.create(
                action="email.update", status="succeeded", resource="newsletter_campaign",
                resource_id=str(self.campaign.uuid), ecp_user_label="inspect-admin",
            )
        MauticIdentityAuditLog.objects.create(
            action="email.update", status="succeeded", resource="newsletter_campaign",
            resource_id="someone-else",
        )
        audit = self.inspect(provider())["audit"]
        self.assertEqual(len(audit), inspection.AUDIT_HISTORY_LIMIT)
        self.assertTrue(all(row["actor"] == "inspect-admin" for row in audit))


def _due(minutes_ago):
    return (timezone.now() - timedelta(minutes=minutes_ago)).replace(second=0, microsecond=0)


@override_settings(MAUTIC_SYNC_ENABLED=True, CELERY_BEAT_SCHEDULE=BEAT)
class NativeScheduleInspectionTests(TestCase):
    def native(self, scheduled_at):
        return NewsletterCampaign.objects.create(
            name="Native", subject="Hi", status="scheduled", scheduled_at=scheduled_at,
            schedule_owner=NewsletterCampaign.ScheduleOwner.MAUTIC, mautic_email_id="77",
        )

    def category(self, campaign, client):
        result = inspection.inspect_broadcast_delivery(campaign, client=client)
        self.assertLessEqual(called_methods(client), READ_METHODS)
        return result

    def test_lifecycle_categories(self):
        future = _due(-10)
        cases = [
            (future, dict(published=True, sent=0), "native_not_due"),
            (_due(2), dict(published=True, sent=0), "native_awaiting_first_send"),
            (_due(10), dict(published=True, sent=0), "native_due_no_sends_recorded"),
            (_due(10), dict(published=True, sent=4), "native_sending"),
            (_due(10), dict(published=False, sent=4), "native_completed_awaiting_reconciliation"),
            (_due(10), dict(published=False, sent=0), "native_provider_state_mismatch"),
        ]
        for scheduled_at, state, expected in cases:
            with self.subTest(expected=expected):
                campaign = self.native(scheduled_at)
                client = provider(publish_up=scheduled_at.isoformat(), **state)
                result = self.category(campaign, client)
                self.assertEqual(result["delivery"]["category"], expected)

    def test_zero_sends_is_reported_without_guessing_or_closing(self):
        campaign = self.native(_due(30))
        before = NewsletterCampaign.objects.values().get(pk=campaign.pk)
        result = self.category(campaign, provider(publish_up=campaign.scheduled_at.isoformat()))

        delivery = result["delivery"]
        self.assertEqual(delivery["category"], "native_due_no_sends_recorded")
        self.assertFalse(delivery["delivery_recorded"])
        self.assertFalse(delivery["completion_provable"])
        self.assertIn("Mautic cron", delivery["guidance"])
        self.assertIn("never sent it", delivery["guidance"])
        self.assertEqual(NewsletterCampaign.objects.values().get(pk=campaign.pk), before)

    def test_recipients_appearing_later_change_the_category(self):
        campaign = self.native(_due(30))
        publish_up = campaign.scheduled_at.isoformat()
        self.assertEqual(self.category(campaign, provider(publish_up=publish_up))["delivery"]["category"],
                         "native_due_no_sends_recorded")
        self.assertEqual(self.category(campaign, provider(publish_up=publish_up, sent=1))["delivery"]["category"],
                         "native_sending")

    def test_completed_native_is_not_marked_sent_by_inspection(self):
        campaign = self.native(_due(10))
        result = self.category(campaign, provider(publish_up=campaign.scheduled_at.isoformat(),
                                                   published=False, sent=2))
        self.assertTrue(result["delivery"]["completion_provable"])
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, NewsletterCampaign.Status.SCHEDULED)

    def test_provider_unavailable_and_missing_email(self):
        campaign = self.native(_due(10))
        unavailable = self.category(campaign, provider(email_error=TemporaryMauticError("down")))
        self.assertEqual(unavailable["delivery"]["category"], "provider_unavailable")
        missing = self.category(campaign, provider(
            email_error=PermanentMauticError("Mautic API request failed (HTTP 404)")))
        self.assertEqual(missing["delivery"]["category"], "native_provider_email_missing")

    def test_ecp_owned_schedule_is_never_classified_as_native(self):
        ontime = NewsletterCampaign.objects.create(
            name="ECP", subject="Hi", status="scheduled", scheduled_at=timezone.now() + timedelta(hours=1))
        overdue = NewsletterCampaign.objects.create(
            name="ECP late", subject="Hi", status="scheduled", scheduled_at=timezone.now() - timedelta(hours=1))
        self.assertEqual(inspection.inspect_broadcast_delivery(ontime)["delivery"]["category"], "ecp_scheduled")
        self.assertEqual(inspection.inspect_broadcast_delivery(overdue)["delivery"]["category"],
                         "ecp_schedule_overdue")


@override_settings(MAUTIC_SYNC_ENABLED=True, CELERY_BEAT_SCHEDULE=BEAT)
class DeliveryInspectionApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.campaign = NewsletterCampaign.objects.create(name="API", subject="Hi", mautic_email_id="77")
        self.url = reverse("newsletter-admin-campaign-delivery-inspection", args=[self.campaign.uuid])

    def user(self, *, superuser, mapped):
        user = User.objects.create_user(
            username=f"u-{superuser}-{mapped}", email=f"u-{superuser}-{mapped}@example.test",
            password="pw", is_staff=superuser, is_superuser=superuser,
        )
        if mapped:
            grant_marketing_access(user)
        return user

    def test_marketing_admin_can_inspect_with_read_only_provider_calls(self):
        self.client.force_authenticate(self.user(superuser=True, mapped=True))
        client = provider(sent=1)
        with patch("newsletter.broadcast_delivery_inspection.MauticClient", return_value=client):
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["campaign"]["uuid"], str(self.campaign.uuid))
        self.assertLessEqual(called_methods(client), READ_METHODS)

    def test_inspection_is_get_only(self):
        self.client.force_authenticate(self.user(superuser=True, mapped=True))
        for method in ("post", "patch", "put", "delete"):
            self.assertEqual(getattr(self.client, method)(self.url).status_code, 405)

    def test_unauthorized_users_are_refused(self):
        self.assertIn(self.client.get(self.url).status_code, (401, 403))
        self.client.force_authenticate(self.user(superuser=False, mapped=False))
        self.assertEqual(self.client.get(self.url).status_code, 403)
        # A superuser without an active Mautic mapping has no Marketing Hub access.
        self.client.force_authenticate(self.user(superuser=True, mapped=False))
        self.assertEqual(self.client.get(self.url).status_code, 403)

    def test_unknown_broadcast_is_404(self):
        self.client.force_authenticate(self.user(superuser=True, mapped=True))
        url = reverse("newsletter-admin-campaign-delivery-inspection",
                      args=["00000000-0000-0000-0000-000000000000"])
        self.assertEqual(self.client.get(url).status_code, 404)
