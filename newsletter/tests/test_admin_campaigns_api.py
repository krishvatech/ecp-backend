from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.models import (
    MauticContactMapping,
    NewsletterCampaign,
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterSyncEvent,
)


User = get_user_model()


class NewsletterAdminCampaignAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.normal_user = User.objects.create_user(
            username="newsletter-normal",
            email="newsletter-normal@example.test",
            password="test-password",
        )
        self.staff = User.objects.create_user(
            username="newsletter-staff",
            email="newsletter-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.superuser = User.objects.create_superuser(
            username="newsletter-superuser",
            email="newsletter-superuser@example.test",
            password="test-password",
        )
        self.category = NewsletterCategory.objects.get(slug="imaa-events")
        self.other_category = NewsletterCategory.objects.get(slug="imaa-deal-alert")
        self.inactive_category = NewsletterCategory.objects.create(
            name="Inactive Newsletter",
            slug="inactive-newsletter",
            is_active=False,
        )
        self.list_url = reverse("newsletter-admin-campaign-list")
        self.categories_url = reverse("newsletter-admin-category-list")

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def _campaign_detail_url(self, campaign):
        return reverse("newsletter-admin-campaign-detail", args=[campaign.uuid])

    def _campaign_payload(self, **overrides):
        payload = {
            "name": "September Deal Newsletter",
            "subject": "September deals",
            "preview_text": "A quick look at this month's deals.",
            "from_name": "IMAA Connect",
            "from_email": "newsletter@example.test",
            "html_content": "<p>Hello</p>",
            "plain_text": "Hello",
            "audience_slugs": ["imaa-events"],
        }
        payload.update(overrides)
        return payload

    def test_guest_and_normal_user_are_denied_for_admin_endpoints(self):
        campaign = NewsletterCampaign.objects.create(name="Draft")
        detail_url = self._campaign_detail_url(campaign)
        endpoints = [
            ("get", self.list_url, None),
            ("post", self.list_url, self._campaign_payload()),
            ("get", detail_url, None),
            ("patch", detail_url, {"name": "Updated"}),
            ("delete", detail_url, None),
            ("get", self.categories_url, None),
        ]

        for method, url, payload in endpoints:
            response = getattr(self.client, method)(url, payload, format="json")
            self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        for method, url, payload in endpoints:
            response = getattr(self.client, method)(url, payload, format="json")
            self.assertEqual(response.status_code, 403)

    def test_staff_and_superuser_can_access_list_and_categories(self):
        for user in (self.staff, self.superuser):
            self.client.force_authenticate(user=user)
            self.assertEqual(self.client.get(self.list_url).status_code, 200)
            self.assertEqual(self.client.get(self.categories_url).status_code, 200)

    def test_staff_can_create_draft_with_audiences_and_read_only_fields_ignored(self):
        self._authenticate(self.staff)
        response = self.client.post(
            self.list_url,
            self._campaign_payload(
                status="sent",
                mautic_email_id="999",
                audience_slugs=["imaa-events", "imaa-events", "imaa-deal-alert"],
            ),
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        campaign = NewsletterCampaign.objects.get(uuid=response.data["uuid"])
        self.assertEqual(campaign.status, NewsletterCampaign.Status.DRAFT)
        self.assertEqual(campaign.mautic_email_id, "")
        self.assertEqual(campaign.created_by, self.staff)
        self.assertEqual(campaign.updated_by, self.staff)
        self.assertEqual(
            set(campaign.audiences.values_list("slug", flat=True)),
            {"imaa-events", "imaa-deal-alert"},
        )
        self.assertEqual(response.data["status"], "draft")
        self.assertIsNone(response.data["mautic_email_id"])

    def test_staff_can_create_draft_with_empty_audiences(self):
        self._authenticate(self.staff)
        response = self.client.post(
            self.list_url,
            self._campaign_payload(audience_slugs=[]),
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        campaign = NewsletterCampaign.objects.get(uuid=response.data["uuid"])
        self.assertEqual(campaign.audiences.count(), 0)

    def test_unknown_and_inactive_audiences_are_rejected(self):
        self._authenticate(self.staff)

        unknown = self.client.post(
            self.list_url,
            self._campaign_payload(audience_slugs=["not-real"]),
            format="json",
        )
        self.assertEqual(unknown.status_code, 400)

        inactive = self.client.post(
            self.list_url,
            self._campaign_payload(audience_slugs=["inactive-newsletter"]),
            format="json",
        )
        self.assertEqual(inactive.status_code, 400)

    def test_staff_can_patch_draft_and_replace_audiences(self):
        campaign = NewsletterCampaign.objects.create(
            name="Original",
            created_by=self.normal_user,
            updated_by=self.normal_user,
        )
        campaign.audiences.set([self.category])
        self._authenticate(self.staff)

        response = self.client.patch(
            self._campaign_detail_url(campaign),
            {
                "name": "Updated",
                "subject": "Updated subject",
                "audience_slugs": ["imaa-deal-alert"],
                "status": "sent",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        campaign.refresh_from_db()
        self.assertEqual(campaign.name, "Updated")
        self.assertEqual(campaign.subject, "Updated subject")
        self.assertEqual(campaign.status, NewsletterCampaign.Status.DRAFT)
        self.assertEqual(campaign.updated_by, self.staff)
        self.assertEqual(
            list(campaign.audiences.values_list("slug", flat=True)),
            ["imaa-deal-alert"],
        )

    def test_patch_rejects_unknown_and_inactive_audiences(self):
        campaign = NewsletterCampaign.objects.create(name="Draft")
        self._authenticate(self.staff)

        unknown = self.client.patch(
            self._campaign_detail_url(campaign),
            {"audience_slugs": ["not-real"]},
            format="json",
        )
        self.assertEqual(unknown.status_code, 400)

        inactive = self.client.patch(
            self._campaign_detail_url(campaign),
            {"audience_slugs": ["inactive-newsletter"]},
            format="json",
        )
        self.assertEqual(inactive.status_code, 400)

    def test_non_draft_campaign_cannot_be_edited_or_deleted(self):
        campaign = NewsletterCampaign.objects.create(
            name="Scheduled",
            status=NewsletterCampaign.Status.SCHEDULED,
        )
        self._authenticate(self.staff)

        patch_response = self.client.patch(
            self._campaign_detail_url(campaign),
            {"name": "Nope"},
            format="json",
        )
        self.assertEqual(patch_response.status_code, 400)

        delete_response = self.client.delete(self._campaign_detail_url(campaign))
        self.assertEqual(delete_response.status_code, 400)
        self.assertTrue(NewsletterCampaign.objects.filter(pk=campaign.pk).exists())

    def test_draft_campaign_can_be_deleted(self):
        campaign = NewsletterCampaign.objects.create(name="Draft")
        self._authenticate(self.staff)

        response = self.client.delete(self._campaign_detail_url(campaign))

        self.assertEqual(response.status_code, 204)
        self.assertFalse(NewsletterCampaign.objects.filter(pk=campaign.pk).exists())

    def test_list_detail_response_shape_audiences_and_latest_ordering(self):
        older = NewsletterCampaign.objects.create(name="Older")
        older.audiences.set([self.category])
        newer = NewsletterCampaign.objects.create(name="Newer")
        newer.audiences.set([self.other_category])
        self._authenticate(self.staff)

        list_response = self.client.get(self.list_url)
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(list_response.data[0]["uuid"], str(newer.uuid))
        self.assertEqual(list_response.data[1]["uuid"], str(older.uuid))
        self.assertEqual(
            set(list_response.data[0]),
            {
                "uuid",
                "name",
                "subject",
                "preview_text",
                "from_name",
                "from_email",
                "html_content",
                "plain_text",
                "status",
                "audiences",
                "scheduled_at",
                "send_started_at",
                "sent_at",
                "mautic_email_id",
                "last_synced_to_mautic_at",
                "last_error",
                "created_at",
                "updated_at",
            },
        )
        self.assertEqual(
            list_response.data[0]["audiences"][0]["slug"],
            "imaa-deal-alert",
        )
        self.assertNotIn("mautic_segment_id", list_response.data[0]["audiences"][0])

        detail_response = self.client.get(self._campaign_detail_url(older))
        self.assertEqual(detail_response.status_code, 200)
        self.assertEqual(detail_response.data["audiences"][0]["slug"], "imaa-events")

    def test_categories_returns_only_active_without_mautic_internal_ids(self):
        self._authenticate(self.staff)
        response = self.client.get(self.categories_url)

        self.assertEqual(response.status_code, 200)
        slugs = {item["slug"] for item in response.data}
        self.assertIn("imaa-events", slugs)
        self.assertNotIn("inactive-newsletter", slugs)
        self.assertTrue(all("mautic_segment_id" not in item for item in response.data))

    def test_crud_has_no_mautic_or_preference_sync_side_effects(self):
        self._authenticate(self.staff)
        before = {
            "events": NewsletterSyncEvent.objects.count(),
            "subscriptions": NewsletterSubscription.objects.count(),
            "mappings": MauticContactMapping.objects.count(),
        }

        create_response = self.client.post(
            self.list_url,
            self._campaign_payload(),
            format="json",
        )
        campaign = NewsletterCampaign.objects.get(uuid=create_response.data["uuid"])
        self.client.patch(
            self._campaign_detail_url(campaign),
            {"name": "Updated"},
            format="json",
        )
        self.client.delete(self._campaign_detail_url(campaign))

        after = {
            "events": NewsletterSyncEvent.objects.count(),
            "subscriptions": NewsletterSubscription.objects.count(),
            "mappings": MauticContactMapping.objects.count(),
        }
        self.assertEqual(after, before)


class NewsletterCampaignModelTests(TestCase):
    def test_status_fields_exist_for_future_lifecycle(self):
        campaign = NewsletterCampaign.objects.create(name="Draft")

        self.assertEqual(campaign.status, NewsletterCampaign.Status.DRAFT)
        self.assertEqual(
            {choice[0] for choice in NewsletterCampaign.Status.choices},
            {"draft", "scheduled", "sending", "sent", "failed", "cancelled"},
        )
        self.assertIsNone(campaign.scheduled_at)
        self.assertIsNone(campaign.send_started_at)
        self.assertIsNone(campaign.sent_at)
        self.assertIsNone(campaign.last_synced_to_mautic_at)
        self.assertEqual(campaign.last_error, "")

    def test_non_draft_timestamps_can_be_stored_for_future_phases(self):
        now = timezone.now()
        campaign = NewsletterCampaign.objects.create(
            name="Sent",
            status=NewsletterCampaign.Status.SENT,
            scheduled_at=now,
            send_started_at=now,
            sent_at=now,
            mautic_email_id="123",
            last_synced_to_mautic_at=now,
        )

        campaign.refresh_from_db()
        self.assertEqual(campaign.mautic_email_id, "123")
        self.assertEqual(campaign.sent_at, now)
