from django.contrib.auth import get_user_model
from django.test import TestCase

from newsletter.campaign_send_events import (
    build_campaign_send_idempotency_key,
    create_campaign_send_event,
)
from newsletter.models import NewsletterCampaign, NewsletterCampaignSendEvent


class NewsletterCampaignSendEventCreationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.staff = User.objects.create_user(
            username="newsletter-send-event-staff",
            email="newsletter-send-event-staff@example.test",
            password="test-password",
            is_staff=True,
        )

    def campaign(self, *, name="Send Event Draft"):
        return NewsletterCampaign.objects.create(name=name)

    def test_builds_stable_campaign_send_key(self):
        campaign = self.campaign()

        key = build_campaign_send_idempotency_key(campaign)

        self.assertEqual(
            key,
            f"mautic:newsletter:campaign:{campaign.uuid}:send",
        )

    def test_creates_one_pending_send_event(self):
        campaign = self.campaign()

        event = create_campaign_send_event(
            campaign,
            requested_by=self.staff,
        )

        self.assertEqual(event.campaign, campaign)
        self.assertEqual(event.requested_by, self.staff)
        self.assertEqual(
            event.status,
            NewsletterCampaignSendEvent.Status.PENDING,
        )
        self.assertEqual(event.attempt_count, 0)
        self.assertIsNone(event.processing_started_at)
        self.assertIsNone(event.provider_send_started_at)
        self.assertIsNone(event.completed_at)
        self.assertEqual(event.last_error, "")

    def test_duplicate_send_request_reuses_same_event(self):
        campaign = self.campaign()

        first = create_campaign_send_event(campaign, requested_by=self.staff)
        second = create_campaign_send_event(campaign, requested_by=self.staff)

        self.assertEqual(second.pk, first.pk)
        self.assertEqual(
            NewsletterCampaignSendEvent.objects.filter(
                campaign=campaign
            ).count(),
            1,
        )

    def test_existing_failed_event_is_still_reused(self):
        campaign = self.campaign()
        first = create_campaign_send_event(campaign, requested_by=self.staff)
        NewsletterCampaignSendEvent.objects.filter(pk=first.pk).update(
            status=NewsletterCampaignSendEvent.Status.FAILED,
            last_error="Provider result was ambiguous",
        )

        second = create_campaign_send_event(campaign, requested_by=self.staff)

        self.assertEqual(second.pk, first.pk)
        self.assertEqual(
            NewsletterCampaignSendEvent.objects.filter(
                campaign=campaign
            ).count(),
            1,
        )

    def test_different_campaigns_get_different_events(self):
        first_campaign = self.campaign(name="First")
        second_campaign = self.campaign(name="Second")

        first = create_campaign_send_event(first_campaign)
        second = create_campaign_send_event(second_campaign)

        self.assertNotEqual(first.pk, second.pk)
        self.assertNotEqual(first.idempotency_key, second.idempotency_key)

    def test_non_draft_campaign_without_event_is_rejected(self):
        campaign = self.campaign()
        NewsletterCampaign.objects.filter(pk=campaign.pk).update(
            status=NewsletterCampaign.Status.SENT
        )

        with self.assertRaisesRegex(
            ValueError,
            "Only draft newsletter campaigns can request a send",
        ):
            create_campaign_send_event(campaign, requested_by=self.staff)

        self.assertFalse(
            NewsletterCampaignSendEvent.objects.filter(
                campaign=campaign
            ).exists()
        )

    def test_uses_database_campaign_state_not_stale_object_state(self):
        campaign = self.campaign()
        self.assertEqual(campaign.status, NewsletterCampaign.Status.DRAFT)
        NewsletterCampaign.objects.filter(pk=campaign.pk).update(
            status=NewsletterCampaign.Status.CANCELLED
        )

        with self.assertRaisesRegex(
            ValueError,
            "Only draft newsletter campaigns can request a send",
        ):
            create_campaign_send_event(campaign)

    def test_unsaved_campaign_is_rejected(self):
        unsaved = NewsletterCampaign(name="Unsaved")

        with self.assertRaisesRegex(
            ValueError,
            "Saved newsletter campaign is required",
        ):
            create_campaign_send_event(unsaved)
