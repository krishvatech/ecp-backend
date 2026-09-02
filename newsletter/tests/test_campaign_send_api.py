from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.campaign_send_events import create_campaign_send_event
from newsletter.models import (
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCategory,
)
from newsletter.tasks import process_newsletter_campaign_send_event


User = get_user_model()


@override_settings(
    MAUTIC_SYNC_ENABLED=True,
    MAUTIC_BASE_URL="http://mautic.local",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="secret",
)
class NewsletterAdminCampaignSendAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.normal_user = User.objects.create_user(
            username="campaign-send-normal",
            email="campaign-send-normal@example.test",
            password="test-password",
        )
        self.staff = User.objects.create_user(
            username="campaign-send-staff",
            email="campaign-send-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.superuser = User.objects.create_superuser(
            username="campaign-send-super",
            email="campaign-send-super@example.test",
            password="test-password",
        )
        self.category = NewsletterCategory.objects.create(
            name="Campaign Send Audience",
            slug="campaign-send-audience",
            mautic_segment_id="71",
        )

    def campaign(self, *, name="Campaign Send Draft"):
        campaign = NewsletterCampaign.objects.create(
            name=name,
            subject="Campaign send subject",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            html_content="<p>Campaign send body</p>",
            plain_text="Campaign send body",
        )
        campaign.audiences.set([self.category])
        return campaign

    def send_url(self, campaign):
        return reverse(
            "newsletter-admin-campaign-send",
            args=[campaign.uuid],
        )

    def detail_url(self, campaign):
        return reverse(
            "newsletter-admin-campaign-detail",
            args=[campaign.uuid],
        )

    def test_guest_and_normal_user_are_denied(self):
        campaign = self.campaign()

        guest = self.client.post(self.send_url(campaign), format="json")
        self.assertIn(guest.status_code, (401, 403))

        self.client.force_authenticate(user=self.normal_user)
        normal = self.client.post(self.send_url(campaign), format="json")
        self.assertEqual(normal.status_code, 403)

        self.assertFalse(
            NewsletterCampaignSendEvent.objects.filter(
                campaign=campaign
            ).exists()
        )

    @patch("newsletter.campaign_services.dispatch_campaign_send_event_safely")
    def test_staff_and_superuser_create_one_pending_event(self, dispatch):
        for index, user in enumerate((self.staff, self.superuser), start=1):
            campaign = self.campaign(name=f"Role Send {index}")
            self.client.force_authenticate(user=user)

            with self.captureOnCommitCallbacks(execute=True):
                response = self.client.post(
                    self.send_url(campaign),
                    format="json",
                )

            self.assertEqual(response.status_code, 202)
            self.assertEqual(response.data["accepted"], True)
            self.assertEqual(response.data["status"], "pending")
            event = NewsletterCampaignSendEvent.objects.get(campaign=campaign)
            self.assertEqual(event.requested_by, user)
            dispatch.assert_any_call(event.pk)

        self.assertEqual(dispatch.call_count, 2)

    @patch("newsletter.campaign_services.dispatch_campaign_send_event_safely")
    def test_duplicate_send_request_reuses_same_event(self, dispatch):
        campaign = self.campaign()
        self.client.force_authenticate(user=self.staff)

        with self.captureOnCommitCallbacks(execute=True):
            first = self.client.post(self.send_url(campaign), format="json")
        event = NewsletterCampaignSendEvent.objects.get(campaign=campaign)

        with self.captureOnCommitCallbacks(execute=True):
            second = self.client.post(self.send_url(campaign), format="json")

        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 202)
        self.assertEqual(
            NewsletterCampaignSendEvent.objects.filter(
                campaign=campaign
            ).count(),
            1,
        )
        self.assertEqual(
            NewsletterCampaignSendEvent.objects.get(campaign=campaign).pk,
            event.pk,
        )
        self.assertEqual(dispatch.call_count, 2)

    @patch("newsletter.campaign_services.dispatch_campaign_send_event_safely")
    def test_invalid_campaign_returns_400_without_event(self, dispatch):
        campaign = self.campaign()
        campaign.subject = ""
        campaign.save(update_fields=["subject"])
        self.client.force_authenticate(user=self.staff)

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.send_url(campaign), format="json")

        self.assertEqual(response.status_code, 400)
        self.assertFalse(
            NewsletterCampaignSendEvent.objects.filter(
                campaign=campaign
            ).exists()
        )
        dispatch.assert_not_called()

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    @patch("newsletter.campaign_services.dispatch_campaign_send_event_safely")
    def test_disabled_sync_returns_503_without_event(self, dispatch):
        campaign = self.campaign()
        self.client.force_authenticate(user=self.staff)

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.send_url(campaign), format="json")

        self.assertEqual(response.status_code, 503)
        self.assertFalse(
            NewsletterCampaignSendEvent.objects.filter(
                campaign=campaign
            ).exists()
        )
        dispatch.assert_not_called()

    @patch("newsletter.campaign_services.dispatch_campaign_send_event_safely")
    def test_succeeded_event_cannot_be_requested_again(self, dispatch):
        campaign = self.campaign()
        event = create_campaign_send_event(
            campaign,
            requested_by=self.staff,
        )
        NewsletterCampaignSendEvent.objects.filter(pk=event.pk).update(
            status=NewsletterCampaignSendEvent.Status.SUCCEEDED,
            provider_send_started_at=timezone.now(),
            completed_at=timezone.now(),
        )
        NewsletterCampaign.objects.filter(pk=campaign.pk).update(
            status=NewsletterCampaign.Status.SENT,
            sent_at=timezone.now(),
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.post(self.send_url(campaign), format="json")

        self.assertEqual(response.status_code, 400)
        self.assertIn("already", str(response.data).lower())
        dispatch.assert_not_called()

    @patch("newsletter.campaign_services.dispatch_campaign_send_event_safely")
    def test_post_provider_failed_event_cannot_be_retried(self, dispatch):
        campaign = self.campaign()
        event = create_campaign_send_event(
            campaign,
            requested_by=self.staff,
        )
        boundary = timezone.now()
        NewsletterCampaignSendEvent.objects.filter(pk=event.pk).update(
            status=NewsletterCampaignSendEvent.Status.FAILED,
            provider_send_started_at=boundary,
            completed_at=boundary,
        )
        NewsletterCampaign.objects.filter(pk=campaign.pk).update(
            status=NewsletterCampaign.Status.FAILED,
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.post(self.send_url(campaign), format="json")

        self.assertEqual(response.status_code, 400)
        self.assertIn("cannot be retried", str(response.data).lower())
        dispatch.assert_not_called()

    @patch("newsletter.campaign_services.dispatch_campaign_send_event_safely")
    def test_pre_provider_failed_event_redispatches_same_event(self, dispatch):
        campaign = self.campaign()
        event = create_campaign_send_event(
            campaign,
            requested_by=self.staff,
        )
        NewsletterCampaignSendEvent.objects.filter(pk=event.pk).update(
            status=NewsletterCampaignSendEvent.Status.FAILED,
            last_error="Safe preparation failure",
        )
        self.client.force_authenticate(user=self.staff)

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.send_url(campaign), format="json")

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.data["status"], "failed")
        self.assertEqual(
            NewsletterCampaignSendEvent.objects.filter(
                campaign=campaign
            ).count(),
            1,
        )
        dispatch.assert_called_once_with(event.pk)

    @patch("newsletter.campaign_services.dispatch_campaign_send_event_safely")
    def test_post_provider_processing_event_is_not_redispatched(self, dispatch):
        campaign = self.campaign()
        event = create_campaign_send_event(
            campaign,
            requested_by=self.staff,
        )
        boundary = timezone.now()
        NewsletterCampaignSendEvent.objects.filter(pk=event.pk).update(
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            provider_send_started_at=boundary,
            processing_started_at=boundary,
        )
        NewsletterCampaign.objects.filter(pk=campaign.pk).update(
            status=NewsletterCampaign.Status.SENDING,
            send_started_at=boundary,
        )
        self.client.force_authenticate(user=self.staff)

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.send_url(campaign), format="json")

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.data["status"], "processing")
        dispatch.assert_not_called()

    @patch(
        "newsletter.tasks.process_newsletter_campaign_send_event.delay",
        side_effect=ConnectionError("broker unavailable"),
    )
    def test_broker_failure_keeps_durable_event_and_api_succeeds(self, delay):
        campaign = self.campaign()
        self.client.force_authenticate(user=self.staff)

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.send_url(campaign), format="json")

        self.assertEqual(response.status_code, 202)
        event = NewsletterCampaignSendEvent.objects.get(campaign=campaign)
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.PENDING)
        self.assertEqual(event.attempt_count, 0)
        delay.assert_called_once_with(event.pk)

    def test_send_request_freezes_campaign_edit_and_delete(self):
        campaign = self.campaign()
        create_campaign_send_event(
            campaign,
            requested_by=self.staff,
        )
        self.client.force_authenticate(user=self.staff)

        patch_response = self.client.patch(
            self.detail_url(campaign),
            {"name": "Must not change"},
            format="json",
        )
        delete_response = self.client.delete(self.detail_url(campaign))

        self.assertEqual(patch_response.status_code, 400)
        self.assertEqual(delete_response.status_code, 400)
        campaign.refresh_from_db()
        self.assertEqual(campaign.name, "Campaign Send Draft")
        self.assertTrue(
            NewsletterCampaign.objects.filter(pk=campaign.pk).exists()
        )

    @patch("newsletter.campaign_services.MauticClient")
    def test_send_request_freezes_manual_mautic_sync(self, client_cls):
        campaign = self.campaign()
        create_campaign_send_event(
            campaign,
            requested_by=self.staff,
        )
        self.client.force_authenticate(user=self.staff)
        url = reverse(
            "newsletter-admin-campaign-sync",
            args=[campaign.uuid],
        )

        response = self.client.post(url, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertIn("send has been requested", str(response.data).lower())
        client_cls.assert_not_called()

    @patch("newsletter.campaign_services.MauticClient")
    def test_send_request_freezes_test_email_sync(self, client_cls):
        campaign = self.campaign()
        create_campaign_send_event(
            campaign,
            requested_by=self.staff,
        )
        self.client.force_authenticate(user=self.staff)
        url = reverse(
            "newsletter-admin-campaign-test-email",
            args=[campaign.uuid],
        )

        response = self.client.post(
            url,
            {"email": "test-recipient@example.test"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("send has been requested", str(response.data).lower())
        client_cls.assert_not_called()


class NewsletterCampaignSendTaskTests(SimpleTestCase):
    @patch("newsletter.tasks.process_campaign_broadcast_event")
    def test_campaign_send_task_calls_processor_without_retry_wrapper(self, processor):
        processor.return_value = {
            "event_id": 123,
            "status": "succeeded",
            "processed": True,
        }

        result = process_newsletter_campaign_send_event.run(123)

        processor.assert_called_once_with(123)
        self.assertEqual(result["status"], "succeeded")

    def test_campaign_send_task_name_is_stable(self):
        self.assertEqual(
            process_newsletter_campaign_send_event.name,
            "newsletter.process_campaign_send_event",
        )
