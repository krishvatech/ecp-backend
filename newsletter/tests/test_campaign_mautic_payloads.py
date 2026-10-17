from datetime import datetime, timezone as datetime_timezone

from django.test import TestCase

from newsletter.mautic.payloads import (
    build_campaign_email_payload,
    build_cancelled_schedule_email_payload,
    build_scheduled_campaign_email_payload,
    build_test_email_payload,
)
from newsletter.models import NewsletterCampaign, NewsletterCategory


class CampaignMauticPayloadTests(TestCase):
    def setUp(self):
        self.campaign = NewsletterCampaign.objects.create(
            name="September Newsletter",
            subject="September updates",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
            preview_text="Deals of the month",
            html_content="<p>Hello</p>",
            plain_text="Hello",
        )
        self.category_b = NewsletterCategory.objects.create(
            name="Payload Segment B",
            slug="payload-segment-b",
            mautic_segment_id="22",
        )
        self.category_a = NewsletterCategory.objects.create(
            name="Payload Segment A",
            slug="payload-segment-a",
            mautic_segment_id="7",
        )
        self.campaign.audiences.set([self.category_b, self.category_a])

    def test_campaign_maps_to_mautic_list_email_payload(self):
        payload = build_campaign_email_payload(self.campaign)

        self.assertEqual(
            payload,
            {
                "name": "September Newsletter",
                "subject": "September updates",
                "preheaderText": "Deals of the month",
                "fromName": "IMAA Connect",
                "fromAddress": "newsletter@example.test",
                "plainText": "Hello",
                "customHtml": "<p>Hello</p>",
                "emailType": "list",
                "lists": [7, 22],
                "isPublished": False,
            },
        )

    def test_publish_flag_is_explicit(self):
        draft_payload = build_campaign_email_payload(self.campaign, publish=False)
        published_payload = build_campaign_email_payload(self.campaign, publish=True)

        self.assertIs(draft_payload["isPublished"], False)
        self.assertIs(published_payload["isPublished"], True)

    def test_payload_does_not_mutate_campaign(self):
        original_email_id = self.campaign.mautic_email_id

        build_campaign_email_payload(self.campaign)

        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.mautic_email_id, original_email_id)

    def test_test_email_payload_is_not_attached_to_segments(self):
        payload = build_test_email_payload(self.campaign)

        self.assertEqual(payload["name"], "September Newsletter - Test")
        self.assertEqual(payload["subject"], "September updates")
        self.assertEqual(payload["preheaderText"], "Deals of the month")
        self.assertEqual(payload["fromName"], "IMAA Connect")
        self.assertEqual(payload["fromAddress"], "newsletter@example.test")
        self.assertEqual(payload["plainText"], "Hello")
        self.assertEqual(payload["customHtml"], "<p>Hello</p>")
        self.assertEqual(payload["emailType"], "template")
        self.assertIs(payload["isPublished"], True)
        self.assertNotIn("lists", payload)

    def test_preheader_is_carried_by_every_broadcast_payload(self):
        scheduled = build_scheduled_campaign_email_payload(
            self.campaign,
            scheduled_at=datetime(2026, 11, 2, 9, 30, tzinfo=datetime_timezone.utc),
        )
        cancelled = build_cancelled_schedule_email_payload(self.campaign)

        self.assertEqual(scheduled["preheaderText"], "Deals of the month")
        self.assertEqual(cancelled["preheaderText"], "Deals of the month")

    def test_empty_preview_text_clears_the_mautic_preheader(self):
        self.campaign.preview_text = ""

        self.assertEqual(build_campaign_email_payload(self.campaign)["preheaderText"], "")
        self.assertEqual(build_test_email_payload(self.campaign)["preheaderText"], "")
