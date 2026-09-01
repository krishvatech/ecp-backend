from django.test import TestCase

from newsletter.mautic.payloads import build_campaign_email_payload
from newsletter.models import NewsletterCampaign, NewsletterCategory


class CampaignMauticPayloadTests(TestCase):
    def setUp(self):
        self.campaign = NewsletterCampaign.objects.create(
            name="September Newsletter",
            subject="September updates",
            from_name="IMAA Connect",
            from_email="newsletter@example.test",
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
