"""B11: investigation and safe resolution of a Send Now whose outcome is unknown.

Mautic is a spec'd mock whose only configured method is the read-only
evidence call, so any attempt to send, publish or update fails loudly.
"""

import threading
import uuid
from datetime import timedelta
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter import send_outcome_resolution as outcome
from newsletter.campaign_send_events import create_campaign_send_event
from newsletter.campaign_send_operations import due_campaign_send_event_ids
from newsletter.campaign_send_processor import (
    UNCERTAIN_SEND_MESSAGE,
    _claim_send_event,
    _record_send_success,
    _record_terminal_send_failure,
    _record_uncertain_send,
)
from newsletter.campaign_services import CampaignSendNotAllowed, request_campaign_send
from newsletter.mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from newsletter.models import (
    MauticIdentityAuditLog,
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCampaignTrackingEvent,
)
from newsletter.tests.marketing_actors import grant_marketing_access

User = get_user_model()

SETTLE = 600
SETTINGS = {
    "MAUTIC_SYNC_ENABLED": True,
    "NEWSLETTER_SEND_OUTCOME_SETTLE_SECONDS": SETTLE,
    "MAUTIC_REQUEST_TIMEOUT": 15,
    "MAUTIC_BASE_URL": "https://mautic.example.test",
    "MAUTIC_USERNAME": "api-user",
    "MAUTIC_PASSWORD": "super-secret",
}
EMAIL_ID = "88"


def evidence(*, total=2, before=0, since=None, sent_count=None, pending=0, queued=0,
             email_id=88, email_type="list", related=()):
    since = total - before if since is None else since
    return {
        "generated_at": "2026-10-14T10:00:00Z",
        "since": "2026-10-14T09:00:00Z",
        "email": {
            "id": email_id, "email_type": email_type, "is_published": False,
            "sent_count": total if sent_count is None else sent_count,
            "segment_ids": [7], "related_email_ids": list(related),
        },
        "stats": {
            "total": total, "before_since": before, "since": since, "failed": 0,
            "first_sent_at": "2026-10-14T09:01:00Z" if total else None,
            "last_sent_at": "2026-10-14T09:01:05Z" if total else None,
        },
        "pending": pending,
        "queued": queued,
    }


def provider(report=None, error=None):
    client = Mock(spec=MauticClient)
    if error is not None:
        client.get_email_send_evidence.side_effect = error
    else:
        client.get_email_send_evidence.return_value = report if report is not None else evidence()
    return client


def provider_calls(client):
    return {name.split(".")[0].split("(")[0] for name, *_ in client.mock_calls if name}


class Fixture:
    def make_send(self, *, started_ago=timedelta(minutes=30), uncertain=True):
        self.admin = User.objects.create_user(
            username=f"b11-admin-{uuid.uuid4().hex[:12]}", email="b11-admin@example.test", password="pw",
            is_staff=True, is_superuser=True,
        )
        self.campaign = NewsletterCampaign.objects.create(
            name="B11 Lost Response", subject="Hi", mautic_email_id=EMAIL_ID,
        )
        self.event = create_campaign_send_event(self.campaign, requested_by=self.admin)
        self.boundary = timezone.now() - started_ago
        NewsletterCampaignSendEvent.objects.filter(pk=self.event.pk).update(
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            provider_send_started_at=self.boundary, processing_started_at=self.boundary,
            attempt_count=1, last_error=f"{UNCERTAIN_SEND_MESSAGE} (timeout)" if uncertain else "",
        )
        NewsletterCampaign.objects.filter(pk=self.campaign.pk).update(
            status=NewsletterCampaign.Status.SENDING, send_started_at=self.boundary,
        )
        self.campaign.refresh_from_db()
        self.event.refresh_from_db()

    def state(self):
        self.campaign.refresh_from_db()
        self.event.refresh_from_db()
        return self.event.status, self.campaign.status


@override_settings(**SETTINGS)
class ClassificationTests(Fixture, TestCase):
    def setUp(self):
        self.make_send()

    def classify(self, report, **kwargs):
        return outcome.classify(self.campaign, self.event, report, **kwargs)

    def test_completed_send_is_confirmed_sent(self):
        decision = self.classify(evidence(total=3, pending=0))
        self.assertEqual(decision["classification"], outcome.CONFIRMED_SENT)
        self.assertEqual(decision["allowed_resolution"], outcome.CONFIRMED_SENT)

    def test_no_sends_recorded_is_never_not_sent_however_long_ago(self):
        # A provider request still in flight (or delayed in transit) after
        # the settle period looks exactly like this: nothing recorded yet.
        for hours in (1.5, 24, 24 * 30):
            with self.subTest(hours=hours):
                self.event.provider_send_started_at = timezone.now() - timedelta(hours=hours)
                decision = self.classify(evidence(total=0, sent_count=0, pending=3, queued=0))
                self.assertEqual((decision["classification"], decision["reason"]),
                                 (outcome.UNCERTAIN, "no_sends_recorded"))
                self.assertIsNone(decision["allowed_resolution"])
        self.assertEqual(outcome.RESOLUTIONS, (outcome.CONFIRMED_SENT,))

    def test_empty_queue_with_delayed_provider_execution_stays_uncertain(self):
        for report, reason in (
            (evidence(total=0, pending=3, queued=0), "no_sends_recorded"),
            (evidence(total=0, pending=3, queued=2), "messages_queued"),
            (evidence(total=1, pending=2, queued=0), "partially_sent"),
        ):
            with self.subTest(reason):
                decision = self.classify(report)
                self.assertEqual((decision["classification"], decision["reason"]), (outcome.UNCERTAIN, reason))
                self.assertIsNone(decision["allowed_resolution"])

    def test_segment_membership_changes_after_the_send_began(self):
        # Joiners after the boundary are outside Mautic's cut-off pending
        # count, so a completed send is still confirmed...
        self.assertEqual(self.classify(evidence(total=3, pending=0))["classification"], outcome.CONFIRMED_SENT)
        # ...while members who left make "due" smaller, which can only make
        # the outcome less certain, never "not sent".
        decision = self.classify(evidence(total=0, pending=0))
        self.assertEqual((decision["classification"], decision["reason"]),
                         (outcome.UNCERTAIN, "no_eligible_recipients"))
        partial = self.classify(evidence(total=1, pending=1))
        self.assertEqual(partial["reason"], "partially_sent")

    def test_unresolvable_cases_offer_no_resolution(self):
        cases = {
            "partially_sent": evidence(total=2, pending=1),
            "no_eligible_recipients": evidence(total=0, pending=0),
            "messages_queued": evidence(total=2, queued=1),
            "stats_before_send": evidence(total=3, before=1),
            "sent_count_mismatch": evidence(total=2, sent_count=5),
            "counter_without_stats": evidence(total=0, sent_count=1, pending=2),
            "related_emails": evidence(related=[90]),
            "not_a_segment_email": evidence(email_type="template"),
            "email_mismatch": evidence(email_id=99),
        }
        for reason, report in cases.items():
            with self.subTest(reason):
                decision = self.classify(report)
                self.assertEqual(decision["reason"], reason)
                self.assertIsNone(decision["allowed_resolution"])

    def test_webhook_events_contradicting_no_send_are_conflicting(self):
        decision = self.classify(evidence(total=0, pending=2), tracking_events=1)
        self.assertEqual((decision["classification"], decision["reason"]),
                         (outcome.CONFLICTING, "tracking_without_sends"))

    def test_recent_send_is_still_processing_even_if_it_looks_finished(self):
        NewsletterCampaignSendEvent.objects.filter(pk=self.event.pk).update(
            provider_send_started_at=timezone.now() - timedelta(seconds=SETTLE - 30)
        )
        self.event.refresh_from_db()
        for report in (evidence(total=0, pending=2), evidence(total=2, pending=0)):
            decision = self.classify(report)
            self.assertEqual(decision["classification"], outcome.STILL_PROCESSING)
            self.assertIsNone(decision["allowed_resolution"])

    def test_missing_or_malformed_evidence_is_unavailable(self):
        self.assertEqual(self.classify(None, evidence_error="plugin_outdated")["reason"], "plugin_outdated")
        malformed = evidence()
        malformed["pending"] = "lots"
        self.assertEqual(self.classify(malformed)["reason"], "malformed_evidence")

    def test_only_unresolved_post_boundary_sends_are_judged(self):
        for status in (NewsletterCampaignSendEvent.Status.SUCCEEDED, NewsletterCampaignSendEvent.Status.FAILED):
            self.event.status = status
            self.assertEqual(self.classify(evidence())["classification"], outcome.NOT_APPLICABLE)
        self.event.status = NewsletterCampaignSendEvent.Status.PROCESSING
        self.event.provider_send_started_at = None
        self.assertEqual(self.classify(evidence())["classification"], outcome.NOT_APPLICABLE)

    @override_settings(NEWSLETTER_SEND_OUTCOME_SETTLE_SECONDS=1)
    def test_settle_is_never_shorter_than_the_request_timeout(self):
        self.assertGreater(outcome.settle_seconds(), 15)


@override_settings(**SETTINGS)
class InvestigationTests(Fixture, TestCase):
    def setUp(self):
        self.make_send()

    def test_investigation_reads_once_and_writes_nothing(self):
        client = provider()
        before = (NewsletterCampaign.objects.values().get(pk=self.campaign.pk),
                  NewsletterCampaignSendEvent.objects.values().get(pk=self.event.pk),
                  MauticIdentityAuditLog.objects.count())
        with patch("celery.app.task.Task.apply_async") as apply_async:
            for _ in range(3):
                result = outcome.investigate(self.campaign, self.event, client=client)
        self.assertEqual(result["classification"], outcome.CONFIRMED_SENT)
        self.assertEqual(provider_calls(client), {"get_email_send_evidence"})
        apply_async.assert_not_called()
        self.assertEqual(before, (NewsletterCampaign.objects.values().get(pk=self.campaign.pk),
                                  NewsletterCampaignSendEvent.objects.values().get(pk=self.event.pk),
                                  MauticIdentityAuditLog.objects.count()))
        self.assertEqual(result["send_event"]["event_uuid"], str(self.event.event_uuid))
        self.assertTrue(result["send_event"]["uncertain_response"])
        self.assertIn("not that it reached an inbox", result["evidence"]["limitations"])

    def test_evidence_cut_offs_are_conservative_around_the_boundary(self):
        client = provider()
        outcome.investigate(self.campaign, self.event, client=client)
        _, kwargs = client.get_email_send_evidence.call_args
        boundary = self.event.provider_send_started_at
        # Stats count from just before; "still due" includes anyone who joined
        # up to just after, so recent joiners are never dropped.
        self.assertEqual(kwargs["since"], boundary - outcome.CLOCK_SKEW)
        self.assertEqual(kwargs["due_before"], boundary + outcome.CLOCK_SKEW)

    def test_provider_errors_map_to_unavailable_reasons(self):
        cases = (
            (TemporaryMauticError("timeout"), "evidence_unavailable"),
            (PermanentMauticError("failed (HTTP 404): Email not found."), "email_missing"),
            (PermanentMauticError("failed (HTTP 404): Requested URL not found"), "plugin_outdated"),
            (PermanentMauticError("failed (HTTP 403)"), "evidence_unavailable"),
        )
        for error, reason in cases:
            with self.subTest(reason):
                result = outcome.investigate(self.campaign, self.event, client=provider(error=error))
                self.assertEqual((result["classification"], result["reason"]),
                                 (outcome.EVIDENCE_UNAVAILABLE, reason))
                self.assertFalse(result["investigation_complete"])

    def test_known_provider_outage_makes_no_second_request(self):
        client = provider()
        result = outcome.investigate(self.campaign, self.event, client=client, provider_unavailable=True)
        self.assertEqual(result["classification"], outcome.EVIDENCE_UNAVAILABLE)
        client.get_email_send_evidence.assert_not_called()

    def test_resolved_send_is_not_investigated(self):
        NewsletterCampaignSendEvent.objects.filter(pk=self.event.pk).update(
            status=NewsletterCampaignSendEvent.Status.SUCCEEDED
        )
        self.event.refresh_from_db()
        client = provider()
        result = outcome.investigate(self.campaign, self.event, client=client)
        self.assertFalse(result["applicable"])
        client.get_email_send_evidence.assert_not_called()


@override_settings(**SETTINGS)
class ResolutionTests(Fixture, TestCase):
    def setUp(self):
        self.make_send()

    def resolve(self, resolution, client, **kwargs):
        return outcome.resolve(
            self.campaign, user=self.admin, event_uuid=str(self.event.event_uuid),
            resolution=resolution, client=client, **kwargs,
        )

    def test_confirmed_sent_reconciles_the_original_event_without_sending(self):
        original = NewsletterCampaignSendEvent.objects.values().get(pk=self.event.pk)
        client = provider(evidence(total=3))
        with patch("celery.app.task.Task.apply_async") as apply_async:
            result = self.resolve(outcome.CONFIRMED_SENT, client, note="Checked in Mautic")

        self.assertEqual(result["new_state"], "succeeded/sent")
        self.assertEqual(self.state(), ("succeeded", "sent"))
        self.assertEqual(self.event.pk, original["id"])
        self.assertEqual(self.event.provider_send_started_at, original["provider_send_started_at"])
        self.assertEqual(self.event.attempt_count, original["attempt_count"])
        self.assertEqual(self.event.provider_sent_count, 3)
        self.assertEqual(self.event.requested_by_id, self.admin.pk)
        self.assertEqual(self.campaign.sent_at.isoformat(), "2026-10-14T09:01:05+00:00")
        self.assertEqual(NewsletterCampaignSendEvent.objects.filter(campaign=self.campaign).count(), 1)
        self.assertEqual(provider_calls(client), {"get_email_send_evidence"})
        apply_async.assert_not_called()

        audit = MauticIdentityAuditLog.objects.get(action=outcome.AUDIT_ACTION)
        self.assertEqual((audit.ecp_user_id, audit.status, audit.error_code),
                         (self.admin.pk, "succeeded", "confirmed_sent"))
        self.assertEqual((audit.resource, audit.resource_id, audit.correlation_id),
                         ("newsletter_campaign", str(self.campaign.uuid), str(self.event.event_uuid)))
        for part in ("from=processing/sending", "stats_since=3", "stats_before=0", "pending=0",
                     "note=Checked in Mautic", f"email={EMAIL_ID}"):
            self.assertIn(part, audit.detail)
        self.assertNotIn("super-secret", audit.detail)

        with self.assertRaises(CampaignSendNotAllowed):
            request_campaign_send(self.campaign, user=self.admin)

    def test_not_sent_is_never_a_permitted_decision(self):
        # Even with the evidence that used to qualify, and well past settle.
        NewsletterCampaignSendEvent.objects.filter(pk=self.event.pk).update(
            provider_send_started_at=timezone.now() - timedelta(days=2)
        )
        self.event.refresh_from_db()
        client = provider(evidence(total=0, sent_count=0, pending=4, queued=0))
        with self.assertRaises(outcome.ResolutionRefused) as refused:
            self.resolve(outcome.NOT_SENT_DECISION, client)
        self.assertEqual((refused.exception.code, refused.exception.http_status), ("not_sent_unsupported", 400))
        client.get_email_send_evidence.assert_not_called()
        self.assertEqual(self.state(), ("processing", "sending"))
        self.assertFalse(MauticIdentityAuditLog.objects.filter(action=outcome.AUDIT_ACTION).exists())

    def test_no_send_records_then_later_provider_completion(self):
        """A delayed provider request completes after an investigation that
        found nothing: the send was never closed in between, and the late
        completion is then confirmable without any resend."""
        observations = (
            (evidence(total=0, sent_count=0, pending=3), outcome.UNCERTAIN, "no_sends_recorded"),
            (evidence(total=1, pending=2), outcome.UNCERTAIN, "partially_sent"),
            (evidence(total=3, pending=0), outcome.CONFIRMED_SENT, outcome.CONFIRMED_SENT),
        )
        for report, classification, reason in observations:
            client = provider(report)
            result = outcome.investigate(self.campaign, self.event, client=client)
            self.assertEqual((result["classification"], result["reason"]), (classification, reason))
            self.assertEqual(self.state(), ("processing", "sending"))
        with patch("celery.app.task.Task.apply_async") as apply_async:
            self.resolve(outcome.CONFIRMED_SENT, provider(evidence(total=3, pending=0)))
        apply_async.assert_not_called()
        self.assertEqual(self.state(), ("succeeded", "sent"))
        self.assertEqual(self.event.provider_sent_count, 3)

    def test_decision_the_evidence_does_not_support_changes_nothing(self):
        cases = (
            (outcome.CONFIRMED_SENT, evidence(total=0, pending=3)),
            (outcome.CONFIRMED_SENT, evidence(total=0, pending=0)),
            (outcome.CONFIRMED_SENT, evidence(total=2, pending=1)),
        )
        for resolution, report in cases:
            with self.subTest(resolution):
                with self.assertRaises(outcome.ResolutionRefused) as refused:
                    self.resolve(resolution, provider(report))
                self.assertEqual(refused.exception.code, "evidence_does_not_support")
                self.assertEqual(self.state(), ("processing", "sending"))
        with self.assertRaises(outcome.ResolutionRefused):
            self.resolve(outcome.CONFIRMED_SENT, provider(error=TemporaryMauticError("down")))
        self.assertEqual(self.state(), ("processing", "sending"))
        self.assertFalse(MauticIdentityAuditLog.objects.filter(status="succeeded").exists())

    def test_repeat_and_stale_submissions_are_refused(self):
        self.resolve(outcome.CONFIRMED_SENT, provider())
        with self.assertRaises(outcome.ResolutionRefused) as again:
            self.resolve(outcome.CONFIRMED_SENT, provider())
        self.assertEqual(again.exception.code, "already_resolved")
        with self.assertRaises(outcome.ResolutionRefused) as stale:
            outcome.resolve(self.campaign, user=self.admin, event_uuid="not-this-event",
                            resolution=outcome.CONFIRMED_SENT, client=provider())
        self.assertEqual(stale.exception.code, "stale_event")
        self.assertEqual(MauticIdentityAuditLog.objects.filter(action=outcome.AUDIT_ACTION).count(), 1)

    def test_late_provider_result_during_resolution_is_never_overwritten(self):
        client = provider()

        def worker_finishes_first(*args, **kwargs):
            # The original worker records Mautic's late answer between the
            # evidence read and the locked re-check.
            _record_send_success(self.event.pk, self.campaign.pk, {"sentCount": 2, "failedRecipients": []})
            return evidence(total=3, pending=0)

        client.get_email_send_evidence.side_effect = worker_finishes_first
        with self.assertRaises(outcome.ResolutionRefused) as refused:
            self.resolve(outcome.CONFIRMED_SENT, client)
        self.assertEqual(refused.exception.code, "state_changed")
        self.assertEqual(self.state(), ("succeeded", "sent"))
        self.assertEqual(self.event.provider_sent_count, 2)  # the worker's own result, kept
        self.assertFalse(MauticIdentityAuditLog.objects.filter(status="succeeded").exists())

    def test_late_worker_results_after_resolution_change_nothing(self):
        self.resolve(outcome.CONFIRMED_SENT, provider(evidence(total=3)))
        _record_send_success(self.event.pk, self.campaign.pk, {"sentCount": 9})
        _record_uncertain_send(self.event.pk, self.campaign.pk, "late timeout")
        _record_terminal_send_failure(self.event.pk, self.campaign.pk, "late rejection")
        self.assertEqual(self.state(), ("succeeded", "sent"))
        self.assertEqual(self.event.provider_sent_count, 3)
        self.assertEqual(self.event.last_error, "")

    def test_late_webhook_after_resolution_is_kept_and_changes_no_status(self):
        self.resolve(outcome.CONFIRMED_SENT, provider())
        NewsletterCampaignTrackingEvent.objects.create(
            campaign=self.campaign, event_type="opened", occurred_at=timezone.now(),
        )
        self.assertEqual(self.state(), ("succeeded", "sent"))
        self.assertEqual(NewsletterCampaignTrackingEvent.objects.filter(campaign=self.campaign).count(), 1)

    def test_resolution_is_rolled_back_if_its_audit_row_cannot_be_written(self):
        with patch.object(outcome.MauticIdentityAuditLog.objects, "create", side_effect=RuntimeError("db")), \
                self.assertRaises(RuntimeError):
            self.resolve(outcome.CONFIRMED_SENT, provider())
        self.assertEqual(self.state(), ("processing", "sending"))


@override_settings(**SETTINGS)
class DuplicateSendPreventionTests(Fixture, TestCase):
    """After every post-boundary outcome, no path reaches Mautic's send again."""

    OUTCOMES = ("worker_success", "worker_rejection", "uncertain", "crash_no_record",
                "uncertain_no_sends_after_days", "resolved_sent")

    def put_in(self, name):
        self.make_send(started_ago=timedelta(days=2) if name == "uncertain_no_sends_after_days"
                       else timedelta(minutes=30))
        if name == "worker_success":
            _record_send_success(self.event.pk, self.campaign.pk, {"sentCount": 3, "failedRecipients": []})
        elif name == "worker_rejection":
            _record_terminal_send_failure(self.event.pk, self.campaign.pk, "HTTP 404")
        elif name == "crash_no_record":
            NewsletterCampaignSendEvent.objects.filter(pk=self.event.pk).update(last_error="")
        elif name == "resolved_sent":
            outcome.resolve(self.campaign, user=self.admin, event_uuid=str(self.event.event_uuid),
                            resolution=outcome.CONFIRMED_SENT, client=provider())
        self.campaign.refresh_from_db()
        self.event.refresh_from_db()

    def test_no_resend_path_after_any_outcome(self):
        from newsletter.campaign_send_operations import dispatch_due_campaign_send_events
        from newsletter.campaign_send_processor import process_campaign_send_event

        for name in self.OUTCOMES:
            with self.subTest(name):
                self.put_in(name)
                before = self.state()
                with patch("newsletter.campaign_send_processor.MauticClient") as processor_client, \
                        patch("newsletter.campaign_services.dispatch_campaign_send_event_safely") as dispatch, \
                        patch("celery.app.task.Task.apply_async") as apply_async, \
                        self.captureOnCommitCallbacks(execute=True):
                    for _ in range(2):
                        try:
                            request_campaign_send(self.campaign, user=self.admin)
                        except CampaignSendNotAllowed:
                            pass
                    recovery = dispatch_due_campaign_send_events()
                    redelivered = process_campaign_send_event(self.event.pk)
                dispatch.assert_not_called()
                apply_async.assert_not_called()
                processor_client.assert_not_called()
                self.assertEqual(recovery["selected"], 0)
                self.assertFalse(redelivered["processed"])
                self.assertIsNone(_claim_send_event(self.event.pk))
                self.assertNotIn(self.event.pk, due_campaign_send_event_ids())
                self.assertEqual(self.state(), before)
                self.assertEqual(NewsletterCampaignSendEvent.objects.filter(campaign=self.campaign).count(), 1)


@override_settings(**SETTINGS)
class ConcurrentResolutionTests(Fixture, TransactionTestCase):
    """Two administrators submit at the same moment: one wins, one is refused."""

    def setUp(self):
        self.make_send()

    def test_only_one_of_two_concurrent_resolutions_applies(self):
        both_read = threading.Barrier(2, timeout=10)
        results = []

        def read_then_wait(*args, **kwargs):
            both_read.wait()
            return evidence(total=2)

        def submit():
            client = provider()
            client.get_email_send_evidence.side_effect = read_then_wait
            try:
                outcome.resolve(self.campaign, user=self.admin, event_uuid=str(self.event.event_uuid),
                                resolution=outcome.CONFIRMED_SENT, client=client)
                results.append("applied")
            except outcome.ResolutionRefused as exc:
                results.append(exc.code)
            finally:
                connection.close()

        threads = [threading.Thread(target=submit) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(20)

        self.assertEqual(sorted(results), ["applied", "state_changed"])
        self.assertEqual(self.state(), ("succeeded", "sent"))
        self.assertEqual(MauticIdentityAuditLog.objects.filter(action=outcome.AUDIT_ACTION).count(), 1)


@override_settings(**SETTINGS)
class ResolveApiTests(Fixture, TestCase):
    def setUp(self):
        self.make_send()
        grant_marketing_access(self.admin)
        self.client = APIClient()
        self.url = reverse("newsletter-admin-campaign-send-outcome-resolve", args=[self.campaign.uuid])
        self.inspect_url = reverse("newsletter-admin-campaign-delivery-inspection", args=[self.campaign.uuid])

    def mautic(self, report=None):
        client = provider(report)
        client.get_email.return_value = {"id": 88, "emailType": "list", "isPublished": False, "sentCount": 2}
        client.count_email_stats.return_value = 2
        client.get_latest_email_send.return_value = None
        return client

    def post(self, body, *, report=None, user=None):
        self.client.force_authenticate(user or self.admin)
        client = self.mautic(report)
        with patch("newsletter.broadcast_delivery_inspection.MauticClient", return_value=client), \
                patch("newsletter.mautic.MauticClient", return_value=client), \
                patch("celery.app.task.Task.apply_async") as apply_async:
            response = self.client.post(self.url, body, format="json")
        self.assertEqual(apply_async.call_count, 0)
        self.assertNotIn("send_email_to_segments", provider_calls(client))
        return response

    def body(self, resolution=outcome.CONFIRMED_SENT, **extra):
        return {"event_uuid": str(self.event.event_uuid), "resolution": resolution, "confirm": True, **extra}

    def test_inspection_shows_the_classification_and_permitted_resolution(self):
        self.client.force_authenticate(self.admin)
        with patch("newsletter.broadcast_delivery_inspection.MauticClient", return_value=self.mautic()):
            data = self.client.get(self.inspect_url).data
        send_outcome = data["send_outcome"]
        self.assertEqual(send_outcome["classification"], outcome.CONFIRMED_SENT)
        self.assertEqual(send_outcome["allowed_resolution"], outcome.CONFIRMED_SENT)
        self.assertEqual(send_outcome["send_event"]["event_uuid"], str(self.event.event_uuid))
        self.assertEqual(self.state(), ("processing", "sending"))

    def test_resolve_then_repeat(self):
        response = self.post(self.body(note="ok"))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["result"]["new_state"], "succeeded/sent")
        self.assertEqual(response.data["inspection"]["campaign"]["status"], "sent")
        again = self.post(self.body())
        self.assertEqual((again.status_code, again.data["code"]), (409, "already_resolved"))
        self.assertEqual(MauticIdentityAuditLog.objects.filter(action=outcome.AUDIT_ACTION,
                                                               status="denied").count(), 1)

    def test_unsupported_decision_is_a_conflict_with_fresh_inspection(self):
        response = self.post(self.body(outcome.CONFIRMED_SENT), report=evidence(total=2, pending=1))
        self.assertEqual((response.status_code, response.data["code"]), (409, "evidence_does_not_support"))
        self.assertEqual(response.data["inspection"]["send_outcome"]["reason"], "partially_sent")
        self.assertEqual(self.state(), ("processing", "sending"))
        not_sent = self.post(self.body(outcome.NOT_SENT_DECISION), report=evidence(total=0, pending=3))
        self.assertEqual((not_sent.status_code, not_sent.data["code"]), (400, "not_sent_unsupported"))
        self.assertEqual(self.state(), ("processing", "sending"))

    def test_confirmation_and_valid_input_are_required(self):
        self.assertEqual(self.post(self.body(confirm=False)).status_code, 400)
        self.assertEqual(self.post({**self.body(), "confirm": "true"}).status_code, 400)
        self.assertEqual(self.post(self.body("resend")).status_code, 400)
        self.assertEqual(self.post({**self.body(), "event_uuid": "x"}).data["code"], "stale_event")
        self.assertEqual(self.state(), ("processing", "sending"))

    def test_unavailable_evidence_is_503_and_skips_the_repeat_inspection(self):
        self.client.force_authenticate(self.admin)
        client = provider(error=TemporaryMauticError("timeout"))
        with patch("newsletter.broadcast_delivery_inspection.MauticClient", return_value=client), \
                patch("newsletter.mautic.MauticClient", return_value=client):
            response = self.client.post(self.url, self.body(), format="json")
        self.assertEqual((response.status_code, response.data["code"]), (503, "evidence_unavailable"))
        self.assertIsNone(response.data["inspection"])
        self.assertEqual(client.get_email_send_evidence.call_count, 1)
        self.assertEqual(self.state(), ("processing", "sending"))

    def test_unknown_campaign_is_404(self):
        self.client.force_authenticate(self.admin)
        url = reverse("newsletter-admin-campaign-send-outcome-resolve",
                      args=["00000000-0000-0000-0000-000000000000"])
        self.assertEqual(self.client.post(url, self.body(), format="json").status_code, 404)

    def test_only_marketing_hub_administrators_may_resolve(self):
        self.client.force_authenticate(None)
        self.assertIn(self.client.post(self.url, self.body(), format="json").status_code, (401, 403))
        staff = User.objects.create_user(username="b11-staff", email="s@example.test", password="pw",
                                         is_staff=True)
        unmapped = User.objects.create_user(username="b11-unmapped", email="u@example.test",
                                            password="pw", is_staff=True, is_superuser=True)
        for user in (staff, unmapped):
            self.client.force_authenticate(user)
            self.assertEqual(self.client.post(self.url, self.body(), format="json").status_code, 403)
        self.assertEqual(self.state(), ("processing", "sending"))
        self.assertFalse(MauticIdentityAuditLog.objects.filter(action=outcome.AUDIT_ACTION).exists())


@override_settings(**SETTINGS)
class ClientTests(TestCase):
    def test_evidence_request_is_a_bounded_get_with_utc_since(self):
        session = Mock()
        response = Mock(status_code=200)
        response.json.return_value = evidence()
        session.request.return_value = response
        since = timezone.now().replace(microsecond=0)
        due_before = since + timedelta(minutes=4)
        MauticClient(session=session).get_email_send_evidence(88, since=since, due_before=due_before, timeout=4)
        args, kwargs = session.request.call_args
        self.assertEqual(args, ("GET", "https://mautic.example.test/api/ecp/emails/88/send-evidence"))
        self.assertEqual(kwargs["timeout"], 4)
        self.assertEqual(kwargs["params"], {"since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                            "due_before": due_before.strftime("%Y-%m-%dT%H:%M:%SZ")})

    def test_invalid_payload_is_temporary(self):
        session = Mock()
        response = Mock(status_code=200)
        response.json.return_value = {"email": []}
        session.request.return_value = response
        with self.assertRaises(TemporaryMauticError):
            MauticClient(session=session).get_email_send_evidence(88)
