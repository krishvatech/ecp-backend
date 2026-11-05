"""Email Broadcasts go to any chosen Mautic segment (NewsletterCampaign.mautic_segments)."""

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.calendar_views import broadcast_items
from newsletter.campaign_services import duplicate_campaign
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.payloads import build_campaign_email_payload, campaign_segments
from newsletter.models import NewsletterCampaign, NewsletterCampaignSendEvent, NewsletterCategory
from newsletter.tests.marketing_actors import grant_marketing_access

User = get_user_model()


def draft(**extra):
    return NewsletterCampaign.objects.create(
        **{
            "name": "Monthly",
            "subject": "Monthly news",
            "from_name": "IMAA",
            "from_email": "sender@example.test",
            "html_content": "<p>Hello</p>",
            **extra,
        }
    )


class CampaignSegmentsTests(TestCase):
    def setUp(self):
        self.category = NewsletterCategory.objects.create(name="Old List", slug="old-list", mautic_segment_id="11")

    def test_chosen_segments_go_to_mautic(self):
        campaign = draft(mautic_segments=[{"id": 7, "name": "Investors"}, {"id": 9, "name": "Bankers"}])
        self.assertEqual(build_campaign_email_payload(campaign)["lists"], [7, 9])

    def test_older_broadcast_still_goes_to_its_subscription_list(self):
        campaign = draft()
        campaign.audiences.set([self.category])
        self.assertEqual(campaign_segments(campaign), [{"id": 11, "name": "Old List"}])
        self.assertEqual(build_campaign_email_payload(campaign)["lists"], [11])

    def test_chosen_segments_win_over_a_list(self):
        campaign = draft(mautic_segments=[{"id": 7, "name": "Investors"}])
        campaign.audiences.set([self.category])
        self.assertEqual(build_campaign_email_payload(campaign)["lists"], [7])

    def test_duplicate_keeps_the_chosen_segments_as_a_separate_copy(self):
        source = draft(mautic_segments=[{"id": 7, "name": "Investors"}], mautic_email_id="50")
        copy = duplicate_campaign(source, user=None)
        self.assertEqual(copy.mautic_segments, [{"id": 7, "name": "Investors"}])
        self.assertEqual(copy.mautic_email_id, "")
        copy.mautic_segments.append({"id": 8, "name": "Other"})
        copy.save()
        source.refresh_from_db()
        self.assertEqual(len(source.mautic_segments), 1)

    def test_calendar_names_the_chosen_segment(self):
        now = timezone.now()
        draft(
            mautic_segments=[{"id": 7, "name": "Investors"}],
            status=NewsletterCampaign.Status.SENT,
            sent_at=now,
        )
        items = broadcast_items(now.date() - timedelta(days=1), now.date() + timedelta(days=1))
        self.assertEqual([item["lists"] for item in items], [["Investors"]])


@override_settings(
    ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False,
    MAUTIC_SYNC_ENABLED=True,
    MAUTIC_BASE_URL="http://127.0.0.1:9",
)
class BroadcastSegmentApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="segment-admin",
            email="segment-admin@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        grant_marketing_access(self.user)
        self.api = APIClient()
        self.api.force_authenticate(user=self.user)
        self.list_url = reverse("newsletter-admin-campaign-list")
        self.category = NewsletterCategory.objects.create(name="Old List", slug="old-list", mautic_segment_id="11")
        patcher = patch("newsletter.campaign_services.MauticClient")
        self.addCleanup(patcher.stop)
        self.mautic = patcher.start().return_value
        self.mautic.get_segment.side_effect = lambda segment_id: {"id": segment_id, "name": f"Segment {segment_id}", "isPublished": True}
        self.mautic.create_email.return_value = {"id": 500}
        self.mautic.get_email.return_value = {"id": 500}

    def _detail(self, campaign):
        return reverse("newsletter-admin-campaign-detail", args=[campaign.uuid])

    def _sync(self, campaign):
        return self.api.post(reverse("newsletter-admin-campaign-sync", args=[campaign.uuid]), {}, format="json")

    def _send(self, campaign):
        return self.api.post(reverse("newsletter-admin-campaign-send", args=[campaign.uuid]), {}, format="json")

    def _body(self, **extra):
        return {
            "name": "Monthly",
            "subject": "Monthly news",
            "from_name": "IMAA",
            "from_email": "sender@example.test",
            "html_content": "<p>Hello</p>",
            **extra,
        }

    def test_create_stores_chosen_segments_without_calling_mautic(self):
        response = self.api.post(self.list_url, self._body(segment_ids=[7, 9, 7]), format="json")
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual([row["id"] for row in response.data["segments"]], ["7", "9"])
        self.assertEqual(response.data["audiences"], [])
        self.mautic.get_segment.assert_not_called()

    def test_bad_segment_ids_are_refused(self):
        for bad in ([0], [-1], ["abc"], list(range(1, 52))):
            response = self.api.post(self.list_url, self._body(segment_ids=bad), format="json")
            self.assertEqual(response.status_code, 400, bad)
            self.assertIn("segment_ids", response.data)

    def test_older_draft_reports_and_then_moves_off_its_list(self):
        campaign = draft()
        campaign.audiences.set([self.category])
        response = self.api.get(self._detail(campaign))
        self.assertEqual(response.data["segments"], [{"id": "11", "name": "Old List"}])

        response = self.api.patch(self._detail(campaign), {"segment_ids": [11]}, format="json")
        self.assertEqual(response.status_code, 200, response.content)
        campaign.refresh_from_db()
        self.assertEqual(campaign.mautic_segments, [{"id": 11, "name": ""}])
        self.assertEqual(campaign.audiences.count(), 0)

    def test_sending_a_list_again_clears_chosen_segments(self):
        campaign = draft(mautic_segments=[{"id": 7, "name": "Investors"}])
        response = self.api.patch(self._detail(campaign), {"audience_slugs": ["old-list"]}, format="json")
        self.assertEqual(response.status_code, 200, response.content)
        campaign.refresh_from_db()
        self.assertEqual(campaign.mautic_segments, [])
        self.assertEqual(list(campaign.audiences.values_list("slug", flat=True)), ["old-list"])

    def test_changing_segments_keeps_known_names(self):
        campaign = draft(mautic_segments=[{"id": 7, "name": "Investors"}])
        self.api.patch(self._detail(campaign), {"segment_ids": [9, 7]}, format="json")
        campaign.refresh_from_db()
        self.assertEqual(campaign.mautic_segments, [{"id": 9, "name": ""}, {"id": 7, "name": "Investors"}])

    def test_sync_targets_the_segments_and_refreshes_their_names(self):
        campaign = draft(mautic_segments=[{"id": 7, "name": ""}])
        response = self._sync(campaign)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(self.mautic.create_email.call_args.args[0]["lists"], [7])
        self.assertEqual(self.mautic.create_email.call_args.args[0]["emailType"], "list")
        campaign.refresh_from_db()
        self.assertEqual(campaign.mautic_segments, [{"id": 7, "name": "Segment 7"}])

    def test_sync_with_no_segment_is_refused(self):
        response = self._sync(draft())
        self.assertEqual(response.status_code, 400)
        self.assertIn("At least one segment", str(response.data))
        self.mautic.create_email.assert_not_called()

    def test_sync_refuses_a_deleted_segment_and_leaves_mautic_alone(self):
        self.mautic.get_segment.side_effect = PermanentMauticError("Mautic segment lookup failed: HTTP 404")
        response = self._sync(draft(mautic_segments=[{"id": 7, "name": "Investors"}]))
        self.assertEqual(response.status_code, 400)
        self.assertIn("'Investors' no longer exists", str(response.data))
        self.mautic.create_email.assert_not_called()

    def test_sync_refuses_an_unpublished_segment(self):
        self.mautic.get_segment.side_effect = None
        self.mautic.get_segment.return_value = {"id": 7, "name": "Investors", "isPublished": False}
        response = self._sync(draft(mautic_segments=[{"id": 7, "name": "Investors"}]))
        self.assertEqual(response.status_code, 400)
        self.assertIn("'Investors' is unpublished", str(response.data))
        self.mautic.create_email.assert_not_called()

    def test_sync_reports_mautic_being_down_rather_than_a_bad_segment(self):
        self.mautic.get_segment.side_effect = TemporaryMauticError("down")
        response = self._sync(draft(mautic_segments=[{"id": 7, "name": "Investors"}]))
        self.assertEqual(response.status_code, 503)

    def test_send_now_refuses_a_deleted_segment_before_the_broadcast_locks(self):
        campaign = draft(mautic_segments=[{"id": 7, "name": "Investors"}])
        self.mautic.get_segment.side_effect = PermanentMauticError("Mautic segment lookup failed: HTTP 404")
        response = self._send(campaign)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(NewsletterCampaignSendEvent.objects.filter(campaign=campaign).exists())
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, NewsletterCampaign.Status.DRAFT)

        # Still editable: the draft can be pointed at another segment.
        response = self.api.patch(self._detail(campaign), {"segment_ids": [9]}, format="json")
        self.assertEqual(response.status_code, 200, response.content)

    def test_schedule_refuses_an_unpublished_segment(self):
        campaign = draft(mautic_segments=[{"id": 7, "name": "Investors"}])
        self.mautic.get_segment.side_effect = None
        self.mautic.get_segment.return_value = {"id": 7, "name": "Investors", "isPublished": False}
        response = self.api.post(
            reverse("newsletter-admin-campaign-schedule", args=[campaign.uuid]),
            {"scheduled_at": (timezone.now() + timedelta(days=1)).isoformat()},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        campaign.refresh_from_db()
        self.assertEqual(campaign.status, NewsletterCampaign.Status.DRAFT)

    def test_broadcast_on_a_list_does_not_look_segments_up(self):
        campaign = draft()
        campaign.audiences.set([self.category])
        with patch("newsletter.campaign_services.dispatch_campaign_send_event_safely"):
            response = self._send(campaign)
        self.assertLess(response.status_code, 300, response.content)
        self.mautic.get_segment.assert_not_called()
