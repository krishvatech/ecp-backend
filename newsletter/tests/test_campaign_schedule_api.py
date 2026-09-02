from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.campaign_send_events import create_scheduled_campaign_send_event
from newsletter.models import (
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCategory,
)


User = get_user_model()


class NewsletterAdminCampaignScheduleAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.normal_user = User.objects.create_user(
            username="schedule-normal",
            email="schedule-normal@example.test",
            password="test-password",
        )
        self.staff = User.objects.create_user(
            username="schedule-staff",
            email="schedule-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.category = NewsletterCategory.objects.create(
            name="Schedule Audience",
            slug="schedule-audience",
            mautic_segment_id="91",
        )

    def campaign(self, **kwargs):
        values = {
            "name": "Schedule Draft",
            "subject": "Schedule subject",
            "from_name": "IMAA Connect",
            "from_email": "newsletter@example.test",
            "html_content": "<p>Schedule body</p>",
            "plain_text": "Schedule body",
        }
        values.update(kwargs)
        campaign = NewsletterCampaign.objects.create(**values)
        campaign.audiences.set([self.category])
        return campaign

    def schedule_url(self, campaign):
        return reverse("newsletter-admin-campaign-schedule", args=[campaign.uuid])

    def cancel_url(self, campaign):
        return reverse("newsletter-admin-campaign-cancel", args=[campaign.uuid])

    def send_url(self, campaign):
        return reverse("newsletter-admin-campaign-send", args=[campaign.uuid])

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    @patch("newsletter.campaign_services.MauticClient")
    def test_staff_can_schedule_valid_draft_without_mautic(self, client_cls):
        campaign = self.campaign()
        scheduled_at = timezone.now() + timedelta(hours=2)
        self.client.force_authenticate(user=self.staff)

        response = self.client.post(
            self.schedule_url(campaign),
            {"scheduled_at": scheduled_at.isoformat()},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, NewsletterCampaign.Status.SCHEDULED)
        self.assertEqual(campaign.updated_by, self.staff)
        client_cls.assert_not_called()

    def test_non_staff_rejected(self):
        campaign = self.campaign()
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.post(
            self.schedule_url(campaign),
            {"scheduled_at": (timezone.now() + timedelta(hours=1)).isoformat()},
            format="json",
        )

        self.assertEqual(response.status_code, 403)

    def test_missing_and_past_timestamp_rejected(self):
        campaign = self.campaign()
        self.client.force_authenticate(user=self.staff)

        missing = self.client.post(self.schedule_url(campaign), {}, format="json")
        past = self.client.post(
            self.schedule_url(campaign),
            {"scheduled_at": (timezone.now() - timedelta(seconds=1)).isoformat()},
            format="json",
        )

        self.assertEqual(missing.status_code, 400)
        self.assertEqual(past.status_code, 400)

    def test_invalid_content_and_audience_rejected(self):
        self.client.force_authenticate(user=self.staff)
        scheduled_at = (timezone.now() + timedelta(hours=1)).isoformat()
        invalid = self.campaign(subject="")
        empty_audience = self.campaign(name="No Audience")
        empty_audience.audiences.clear()
        inactive = NewsletterCategory.objects.create(
            name="Inactive",
            slug="inactive",
            is_active=False,
            mautic_segment_id="92",
        )
        inactive_campaign = self.campaign(name="Inactive Audience")
        inactive_campaign.audiences.set([inactive])
        unmapped = NewsletterCategory.objects.create(
            name="Unmapped",
            slug="unmapped",
        )
        unmapped_campaign = self.campaign(name="Unmapped Audience")
        unmapped_campaign.audiences.set([unmapped])

        for campaign in (invalid, empty_audience, inactive_campaign, unmapped_campaign):
            response = self.client.post(
                self.schedule_url(campaign),
                {"scheduled_at": scheduled_at},
                format="json",
            )
            self.assertEqual(response.status_code, 400)

    def test_reschedule_allowed_before_event_and_blocked_after_event(self):
        campaign = self.campaign(status=NewsletterCampaign.Status.SCHEDULED)
        NewsletterCampaign.objects.filter(pk=campaign.pk).update(
            scheduled_at=timezone.now() + timedelta(hours=1)
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.post(
            self.schedule_url(campaign),
            {"scheduled_at": (timezone.now() + timedelta(hours=3)).isoformat()},
            format="json",
        )
        self.assertEqual(response.status_code, 200)

        campaign.refresh_from_db()
        create_scheduled_campaign_send_event(campaign, requested_by=self.staff)
        blocked = self.client.post(
            self.schedule_url(campaign),
            {"scheduled_at": (timezone.now() + timedelta(hours=4)).isoformat()},
            format="json",
        )
        self.assertEqual(blocked.status_code, 400)

    def test_non_eligible_statuses_rejected(self):
        self.client.force_authenticate(user=self.staff)
        scheduled_at = (timezone.now() + timedelta(hours=1)).isoformat()
        for status in (
            NewsletterCampaign.Status.SENDING,
            NewsletterCampaign.Status.SENT,
            NewsletterCampaign.Status.FAILED,
            NewsletterCampaign.Status.CANCELLED,
        ):
            campaign = self.campaign(name=f"Status {status}", status=status)
            response = self.client.post(
                self.schedule_url(campaign),
                {"scheduled_at": scheduled_at},
                format="json",
            )
            self.assertEqual(response.status_code, 400)

    @patch("newsletter.campaign_services.MauticClient")
    def test_cancel_scheduled_campaign_cases(self, client_cls):
        self.client.force_authenticate(user=self.staff)
        scheduled_at = timezone.now() + timedelta(hours=1)

        no_event = self.campaign(status=NewsletterCampaign.Status.SCHEDULED)
        NewsletterCampaign.objects.filter(pk=no_event.pk).update(
            scheduled_at=scheduled_at
        )
        response = self.client.post(self.cancel_url(no_event), format="json")
        self.assertEqual(response.status_code, 200)
        no_event.refresh_from_db()
        self.assertEqual(no_event.status, NewsletterCampaign.Status.CANCELLED)
        self.assertEqual(no_event.scheduled_at, scheduled_at)

        pending = self.campaign(
            name="Pending Cancel",
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at=scheduled_at,
        )
        event = create_scheduled_campaign_send_event(pending, requested_by=self.staff)
        response = self.client.post(self.cancel_url(pending), format="json")
        self.assertEqual(response.status_code, 200)
        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.FAILED)
        self.assertIsNone(event.provider_send_started_at)
        self.assertIsNotNone(event.completed_at)

        processing = self.campaign(
            name="Processing Cancel",
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at=scheduled_at,
        )
        processing_event = create_scheduled_campaign_send_event(
            processing,
            requested_by=self.staff,
        )
        NewsletterCampaignSendEvent.objects.filter(pk=processing_event.pk).update(
            status=NewsletterCampaignSendEvent.Status.PROCESSING,
            processing_started_at=timezone.now(),
        )
        response = self.client.post(self.cancel_url(processing), format="json")
        self.assertEqual(response.status_code, 200)

        post_provider = self.campaign(
            name="Post Provider Cancel",
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at=scheduled_at,
        )
        post_event = create_scheduled_campaign_send_event(
            post_provider,
            requested_by=self.staff,
        )
        NewsletterCampaignSendEvent.objects.filter(pk=post_event.pk).update(
            provider_send_started_at=timezone.now()
        )
        response = self.client.post(self.cancel_url(post_provider), format="json")
        self.assertEqual(response.status_code, 400)
        client_cls.assert_not_called()

    def test_cancel_rejects_other_campaign_statuses(self):
        self.client.force_authenticate(user=self.staff)
        for status in (
            NewsletterCampaign.Status.DRAFT,
            NewsletterCampaign.Status.SENDING,
            NewsletterCampaign.Status.SENT,
            NewsletterCampaign.Status.FAILED,
            NewsletterCampaign.Status.CANCELLED,
        ):
            campaign = self.campaign(name=f"Cancel {status}", status=status)
            response = self.client.post(self.cancel_url(campaign), format="json")
            self.assertEqual(response.status_code, 400)

    @patch("newsletter.campaign_services.dispatch_campaign_send_event_safely")
    def test_send_now_cannot_bypass_future_scheduled_campaign(self, dispatch):
        campaign = self.campaign(
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at=timezone.now() + timedelta(hours=1),
        )
        event = create_scheduled_campaign_send_event(
            campaign,
            requested_by=self.staff,
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.post(self.send_url(campaign), format="json")

        event.refresh_from_db()
        campaign.refresh_from_db()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(campaign.status, NewsletterCampaign.Status.SCHEDULED)
        self.assertEqual(event.status, NewsletterCampaignSendEvent.Status.PENDING)
        self.assertEqual(event.attempt_count, 0)
        self.assertIsNone(event.provider_send_started_at)
        dispatch.assert_not_called()
