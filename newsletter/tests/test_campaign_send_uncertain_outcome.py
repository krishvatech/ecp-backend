"""Send Now must never call a lost Mautic response a failure, nor resend it.

Mautic delivers a broadcast synchronously inside ``POST emails/{id}/send`` (its
email transport is ``sync://``), so for any real audience ECP's request can time
out while Mautic keeps sending. Only proof that Mautic never received the
request, or an explicit rejection, is a definitive failure. Everything else is
an uncertain outcome: the broadcast stays SENDING, is never retried, and shows
up in diagnostics for an operator to confirm in Mautic.

The real MauticClient and processor run here; only the HTTP session is faked, so
real ``requests`` exceptions travel the real classification path.
"""

import json
from datetime import timedelta
from unittest.mock import Mock, patch

import requests
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from urllib3.exceptions import NewConnectionError, ProtocolError

from newsletter.campaign_send_events import create_campaign_send_event
from newsletter.campaign_send_operations import (
    dispatch_due_campaign_send_events,
    due_campaign_send_event_ids,
)
from newsletter.campaign_send_processor import process_campaign_send_event
from newsletter.campaign_services import CampaignSendNotAllowed, request_campaign_send
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticRequestNotSentError, TemporaryMauticError
from newsletter.mautic_diagnostics_services import _broadcast_send_status
from newsletter.models import (
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCategory,
)
from newsletter.tests.test_mautic_user_identity import MAUTIC_SETTINGS

User = get_user_model()

BASE = "https://mautic.example.test/api/"
SEND_URL = f"{BASE}emails/77/send"


def _response(status_code=200, payload=None):
    response = Mock(status_code=status_code)
    response.json.return_value = payload if payload is not None else {}
    response.text = json.dumps(payload or {})
    response.headers = {}
    return response


def _refused():
    """What requests raises when nothing is listening on the Mautic port."""
    return requests.ConnectionError(
        Mock(reason=NewConnectionError(None, "Connection refused"))
    )


def _dropped():
    """The connection broke after the request was sent."""
    return requests.ConnectionError(
        ProtocolError("Connection aborted.", ConnectionResetError())
    )


class FakeMautic:
    def __init__(self, send_outcome):
        self.send_outcome = send_outcome
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        if method == "PATCH" and url == f"{BASE}emails/77/edit":
            return _response(payload={"email": {"id": 77, "isPublished": True}})
        if method == "POST" and url == SEND_URL:
            if isinstance(self.send_outcome, Exception):
                raise self.send_outcome
            return self.send_outcome
        return _response(500, {"errors": [{"message": f"unexpected {method} {url}"}]})

    def send_calls(self):
        return [c for c in self.calls if c == ("POST", SEND_URL)]


@override_settings(**MAUTIC_SETTINGS, MAUTIC_SYNC_ENABLED=True)
class SendNowUncertainOutcomeTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            username="send-now-staff", email="send-now-staff@example.test",
            password="pw", is_staff=True, is_superuser=True,
        )
        category = NewsletterCategory.objects.create(
            name="Send Now List", slug="send-now-list", mautic_segment_id="31"
        )
        self.campaign = NewsletterCampaign.objects.create(
            name="Send Now Draft", subject="Hello", from_name="IMAA",
            from_email="newsletter@example.test", html_content="<p>Hi</p>",
            plain_text="Hi", mautic_email_id="77",
        )
        self.campaign.audiences.set([category])
        self.event = create_campaign_send_event(self.campaign, requested_by=self.staff)

    def run_send(self, outcome):
        mautic = FakeMautic(outcome)

        def factory(*args, **kwargs):
            kwargs["session"] = mautic
            return MauticClient(*args, **kwargs)

        with patch("newsletter.campaign_send_processor.MauticClient", side_effect=factory), patch(
            "newsletter.campaign_send_processor.sync_campaign_for_worker_delivery",
            side_effect=lambda campaign, actor=None: campaign,
        ):
            result = process_campaign_send_event(self.event.pk)
        self.event.refresh_from_db()
        self.campaign.refresh_from_db()
        return result, mautic

    def assert_uncertain(self, result):
        self.assertEqual(result["outcome"], "uncertain")
        self.assertFalse(result["retry_safe"])
        self.assertEqual(self.event.status, NewsletterCampaignSendEvent.Status.PROCESSING)
        self.assertIsNotNone(self.event.provider_send_started_at)
        self.assertIsNone(self.event.completed_at)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.SENDING)
        self.assertIsNone(self.campaign.sent_at)
        self.assertIn("did not confirm", self.campaign.last_error)
        self.assertIn("will not be retried", self.event.last_error)

    def assert_failed(self, result):
        self.assertFalse(result["retry_safe"])
        self.assertEqual(self.event.status, NewsletterCampaignSendEvent.Status.FAILED)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.FAILED)

    # --- classification ------------------------------------------------------

    def test_success_is_sent(self):
        result, mautic = self.run_send(
            _response(payload={"success": 1, "sentCount": 3, "failedRecipients": []})
        )

        self.assertEqual(self.event.status, NewsletterCampaignSendEvent.Status.SUCCEEDED)
        self.assertEqual(self.event.provider_sent_count, 3)
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.SENT)
        self.assertEqual(len(mautic.send_calls()), 1)

    def test_read_timeout_is_uncertain_not_failed(self):
        result, mautic = self.run_send(requests.ReadTimeout("read timed out"))

        self.assert_uncertain(result)
        self.assertEqual(len(mautic.send_calls()), 1)

    def test_connection_dropped_mid_response_is_uncertain(self):
        result, _ = self.run_send(_dropped())
        self.assert_uncertain(result)

    def test_server_error_after_send_started_is_uncertain(self):
        result, _ = self.run_send(_response(504, {"errors": [{"message": "Gateway Timeout"}]}))
        self.assert_uncertain(result)

    def test_unsuccessful_or_unreadable_response_is_uncertain(self):
        result, _ = self.run_send(_response(payload={"success": 0}))
        self.assert_uncertain(result)

    def test_unexpected_error_is_uncertain(self):
        with patch.object(MauticClient, "send_email_to_segments", side_effect=RuntimeError("boom")):
            result, _ = self.run_send(_response(payload={"success": 1}))
        self.assert_uncertain(result)

    def test_connection_refused_proves_nothing_was_sent_and_fails(self):
        result, _ = self.run_send(_refused())
        self.assert_failed(result)

    def test_connect_timeout_proves_nothing_was_sent_and_fails(self):
        result, _ = self.run_send(requests.ConnectTimeout("connect timed out"))
        self.assert_failed(result)

    def test_explicit_mautic_rejection_fails(self):
        result, _ = self.run_send(_response(404, {"errors": [{"message": "Item was not found."}]}))
        self.assert_failed(result)

    # --- never resent -----------------------------------------------------------

    def test_uncertain_send_is_never_retried_by_worker_recovery_or_send_now(self):
        _, mautic = self.run_send(requests.ReadTimeout("read timed out"))

        # Redelivered Celery task.
        again, _ = self.run_send(_response(payload={"success": 1, "sentCount": 1}))
        self.assertFalse(again["processed"])
        # Beat recovery, even long after the processing timeout.
        NewsletterCampaignSendEvent.objects.filter(pk=self.event.pk).update(
            processing_started_at=timezone.now() - timedelta(days=1)
        )
        self.assertNotIn(self.event.pk, due_campaign_send_event_ids())
        self.assertEqual(dispatch_due_campaign_send_events()["selected"], 0)
        # A second Send Now: reuses the event and dispatches nothing.
        with patch("newsletter.campaign_services.dispatch_campaign_send_event_safely") as dispatch:
            with self.captureOnCommitCallbacks(execute=True):
                reused = request_campaign_send(self.campaign, user=self.staff)
        self.assertEqual(reused.pk, self.event.pk)
        dispatch.assert_not_called()

        self.assertEqual(NewsletterCampaignSendEvent.objects.filter(campaign=self.campaign).count(), 1)
        self.assertEqual(len(mautic.send_calls()), 1)
        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.SENDING)

    def test_definitive_failure_after_boundary_still_blocks_send_now(self):
        self.run_send(_refused())

        with self.assertRaises(CampaignSendNotAllowed):
            request_campaign_send(self.campaign, user=self.staff)

    def test_uncertain_send_blocks_scheduling_and_editing_into_a_resend(self):
        self.run_send(requests.ReadTimeout("read timed out"))
        client = APIClient()
        client.force_authenticate(self.staff)

        with patch("newsletter.admin_views.HasMarketingHubAccess.has_permission", return_value=True):
            response = client.post(
                reverse("newsletter-admin-campaign-schedule", args=[self.campaign.uuid]),
                {"scheduled_at": (timezone.now() + timedelta(hours=1)).isoformat()},
                format="json",
            )
        self.assertEqual(response.status_code, 400)
        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.status, NewsletterCampaign.Status.SENDING)

    # --- operator visibility ----------------------------------------------------

    def test_uncertain_send_surfaces_in_diagnostics_after_processing_timeout(self):
        self.run_send(requests.ReadTimeout("read timed out"))
        self.assertEqual(_broadcast_send_status(), {"sending": 1, "needs_review": 0})

        NewsletterCampaign.objects.filter(pk=self.campaign.pk).update(
            send_started_at=timezone.now() - timedelta(hours=1)
        )
        self.assertEqual(_broadcast_send_status(), {"sending": 1, "needs_review": 1})


@override_settings(**MAUTIC_SETTINGS)
class TransportClassificationTests(TestCase):
    """The client marks only provably-unsent requests as not sent."""

    def classify(self, exc):
        session = Mock()
        session.request.side_effect = exc
        client = MauticClient(session=session)
        with self.assertRaises(TemporaryMauticError) as raised:
            client.get_email("77")
        return type(raised.exception)

    def test_refused_and_connect_timeout_are_not_sent(self):
        self.assertIs(self.classify(_refused()), MauticRequestNotSentError)
        self.assertIs(self.classify(requests.ConnectTimeout()), MauticRequestNotSentError)

    def test_read_timeout_and_dropped_connection_may_have_been_processed(self):
        self.assertIs(self.classify(requests.ReadTimeout()), TemporaryMauticError)
        self.assertIs(self.classify(_dropped()), TemporaryMauticError)

    def test_not_sent_is_still_a_temporary_error_for_existing_callers(self):
        self.assertTrue(issubclass(MauticRequestNotSentError, TemporaryMauticError))
