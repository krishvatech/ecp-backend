from django.contrib.auth import get_user_model
from unittest.mock import call, patch

from django.test import TestCase, override_settings
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

    def _category_contacts_url(self, category=None):
        category = category or self.category
        return reverse(
            "newsletter-admin-category-contacts",
            args=[category.slug],
        )

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
            ("get", self._category_contacts_url(), None),
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
        self.assertTrue(all("mautic_segment_id" not in item for item in response.data))

    def test_admin_categories_returns_inactive_for_reactivation(self):
        self._authenticate(self.staff)

        response = self.client.get(self.categories_url)

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "inactive-newsletter",
            {item["slug"] for item in response.data},
        )

    def test_admin_categories_can_opt_into_mautic_internal_ids(self):
        self._authenticate(self.staff)
        self.category.mautic_segment_id = "1"
        self.category.save(update_fields=["mautic_segment_id"])

        response = self.client.get(self.categories_url, {"include_mautic": "true"})

        self.assertEqual(response.status_code, 200)
        by_slug = {item["slug"]: item for item in response.data}
        self.assertEqual(by_slug["imaa-events"]["mautic_segment_id"], "1")

    @patch("newsletter.admin_views.MauticClient")
    def test_category_contacts_returns_only_current_subscribers_without_provider_call(
        self,
        client_cls,
    ):
        subscribed = User.objects.create_user(
            username="segment-subscriber",
            email="segment-subscriber@example.test",
            first_name="Segment",
            last_name="Subscriber",
        )
        unsubscribed = User.objects.create_user(
            username="segment-unsubscribed",
            email="segment-unsubscribed@example.test",
            first_name="Former",
            last_name="Subscriber",
        )
        other_segment = User.objects.create_user(
            username="other-segment",
            email="other-segment@example.test",
        )
        NewsletterSubscription.objects.create(
            user=subscribed,
            category=self.category,
            is_subscribed=True,
            subscribed_at=timezone.now(),
        )
        NewsletterSubscription.objects.create(
            user=unsubscribed,
            category=self.category,
            is_subscribed=False,
            unsubscribed_at=timezone.now(),
        )
        NewsletterSubscription.objects.create(
            user=other_segment,
            category=self.other_category,
            is_subscribed=True,
            subscribed_at=timezone.now(),
        )
        mapping = MauticContactMapping.objects.create(
            user=subscribed,
            mautic_contact_id="321",
            last_synced_at=timezone.now(),
        )
        NewsletterSyncEvent.objects.create(
            idempotency_key="contacts:list:subscriber",
            user_id=str(subscribed.pk),
            category=self.category,
            desired_subscribed=True,
            status=NewsletterSyncEvent.Status.SUCCEEDED,
            completed_at=timezone.now(),
        )
        self.category.mautic_segment_id = "1"
        self.category.save(update_fields=["mautic_segment_id"])
        self._authenticate(self.staff)

        response = self.client.get(self._category_contacts_url())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["category"]["slug"], "imaa-events")
        self.assertEqual(response.data["category"]["mautic_segment_id"], "1")
        self.assertEqual(len(response.data["results"]), 1)
        contact = response.data["results"][0]
        self.assertEqual(contact["user_id"], subscribed.pk)
        self.assertEqual(contact["name"], "Segment Subscriber")
        self.assertEqual(contact["email"], "segment-subscriber@example.test")
        self.assertEqual(contact["mautic_contact_id"], "321")
        self.assertEqual(contact["last_synced_at"], mapping.last_synced_at)
        self.assertEqual(contact["sync_status"], NewsletterSyncEvent.Status.SUCCEEDED)
        client_cls.assert_not_called()

    def test_category_contacts_searches_name_email_and_username(self):
        matching = User.objects.create_user(
            username="special-handle",
            email="alice@example.test",
            first_name="Alice",
            last_name="Example",
        )
        nonmatching = User.objects.create_user(
            username="ordinary-handle",
            email="bob@example.test",
            first_name="Bob",
            last_name="Example",
        )
        for user in (matching, nonmatching):
            NewsletterSubscription.objects.create(
                user=user,
                category=self.category,
                is_subscribed=True,
                subscribed_at=timezone.now(),
            )
        self._authenticate(self.staff)

        by_name = self.client.get(
            self._category_contacts_url(),
            {"search": "Alice"},
        )
        self.assertEqual(by_name.status_code, 200)
        self.assertEqual(by_name.data["count"], 1)
        self.assertEqual(by_name.data["results"][0]["user_id"], matching.pk)

        by_username = self.client.get(
            self._category_contacts_url(),
            {"search": "special-handle"},
        )
        self.assertEqual(by_username.status_code, 200)
        self.assertEqual(by_username.data["count"], 1)
        self.assertEqual(by_username.data["results"][0]["user_id"], matching.pk)

    def test_category_contacts_is_paginated_and_page_size_is_bounded(self):
        for index in range(3):
            user = User.objects.create_user(
                username=f"page-subscriber-{index}",
                email=f"page-subscriber-{index}@example.test",
            )
            NewsletterSubscription.objects.create(
                user=user,
                category=self.category,
                is_subscribed=True,
                subscribed_at=timezone.now(),
            )
        self._authenticate(self.staff)

        response = self.client.get(
            self._category_contacts_url(),
            {"page": 1, "page_size": 2},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 3)
        self.assertEqual(response.data["page"], 1)
        self.assertEqual(response.data["page_size"], 2)
        self.assertEqual(response.data["num_pages"], 2)
        self.assertEqual(len(response.data["results"]), 2)

        bounded = self.client.get(
            self._category_contacts_url(),
            {"page_size": 1000},
        )
        self.assertEqual(bounded.status_code, 200)
        self.assertEqual(bounded.data["page_size"], 100)

    def test_category_contacts_unknown_category_returns_404(self):
        self._authenticate(self.staff)

        response = self.client.get(
            reverse(
                "newsletter-admin-category-contacts",
                args=["missing-newsletter"],
            )
        )

        self.assertEqual(response.status_code, 404)

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    def test_create_category_remains_local_only_when_mautic_disabled(self):
        self._authenticate(self.staff)

        response = self.client.post(
            self.categories_url,
            {"name": "Board Updates", "description": "Board news."},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        category = NewsletterCategory.objects.get(slug="board-updates")
        self.assertEqual(category.mautic_segment_id, "")

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_create_category_creates_static_mautic_segment(self, client_cls):
        client = client_cls.return_value
        client.list_segments.return_value = {"lists": {}}
        client.create_segment.return_value = {"id": 44}
        self._authenticate(self.staff)

        response = self.client.post(
            self.categories_url,
            {"name": "Board Updates", "description": "Board news."},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        category = NewsletterCategory.objects.get(slug="board-updates")
        self.assertEqual(category.mautic_segment_id, "44")
        client.create_segment.assert_called_once_with(
            {
                "name": "Board Updates",
                "description": "Board news.",
                "isPublished": True,
                "isPreferenceCenter": False,
                "filters": [],
                "alias": "board-updates",
            }
        )

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_create_category_reuses_static_segment_by_alias(self, client_cls):
        client = client_cls.return_value
        client.list_segments.return_value = {
            "lists": {"45": {"id": 45, "alias": "board-updates", "filters": []}}
        }
        client.update_segment.return_value = {"id": 45}
        self._authenticate(self.staff)

        response = self.client.post(
            self.categories_url,
            {"name": "Board Updates"},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            NewsletterCategory.objects.get(slug="board-updates").mautic_segment_id,
            "45",
        )
        client.create_segment.assert_not_called()

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_create_category_rejects_dynamic_segment_with_same_alias(self, client_cls):
        client = client_cls.return_value
        client.list_segments.return_value = {
            "lists": {
                "45": {
                    "id": 45,
                    "alias": "board-updates",
                    "filters": [{"field": "email"}],
                }
            }
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.categories_url,
            {"name": "Board Updates"},
            format="json",
        )

        self.assertEqual(response.status_code, 502)
        self.assertFalse(NewsletterCategory.objects.filter(slug="board-updates").exists())
        client.create_segment.assert_not_called()

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_create_category_rejects_same_alias_static_mapped_elsewhere(self, client_cls):
        NewsletterCategory.objects.create(
            name="Mapped Elsewhere",
            slug="mapped-elsewhere",
            mautic_segment_id="45",
        )
        client = client_cls.return_value
        client.list_segments.return_value = {
            "lists": {"45": {"id": 45, "alias": "board-updates", "filters": []}}
        }
        self._authenticate(self.staff)

        response = self.client.post(
            self.categories_url,
            {"name": "Board Updates"},
            format="json",
        )

        self.assertEqual(response.status_code, 502)
        self.assertFalse(NewsletterCategory.objects.filter(slug="board-updates").exists())
        client.create_segment.assert_not_called()

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_create_category_provider_failure_rolls_back_local_row(self, client_cls):
        from newsletter.mautic import TemporaryMauticError

        client = client_cls.return_value
        client.list_segments.side_effect = TemporaryMauticError("Mautic unavailable")
        self._authenticate(self.staff)

        response = self.client.post(
            self.categories_url,
            {"name": "Broken Updates"},
            format="json",
        )

        self.assertEqual(response.status_code, 502)
        self.assertFalse(
            NewsletterCategory.objects.filter(slug="broken-updates").exists()
        )

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_created_remote_segment_is_unpublished_if_local_mapping_save_fails(
        self,
        client_cls,
    ):
        original_save = NewsletterCategory.save
        client = client_cls.return_value
        client.list_segments.return_value = {"lists": {}}
        client.create_segment.return_value = {"id": 88}

        def save_with_mapping_failure(instance, *args, **kwargs):
            if (
                instance.slug == "broken-updates"
                and str(instance.mautic_segment_id) == "88"
            ):
                raise RuntimeError("local save failed")
            return original_save(instance, *args, **kwargs)

        self.client.raise_request_exception = False
        self._authenticate(self.staff)
        with patch.object(NewsletterCategory, "save", save_with_mapping_failure):
            response = self.client.post(
                self.categories_url,
                {"name": "Broken Updates"},
                format="json",
            )

        self.assertEqual(response.status_code, 500)
        client.update_segment.assert_called_with("88", {"isPublished": False})

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_reused_remote_segment_is_not_compensated_if_local_mapping_save_fails(
        self,
        client_cls,
    ):
        original_save = NewsletterCategory.save
        client = client_cls.return_value
        client.list_segments.return_value = {
            "lists": {"88": {"id": 88, "alias": "broken-updates", "filters": []}}
        }

        def save_with_mapping_failure(instance, *args, **kwargs):
            if (
                instance.slug == "broken-updates"
                and str(instance.mautic_segment_id) == "88"
            ):
                raise RuntimeError("local save failed")
            return original_save(instance, *args, **kwargs)

        self.client.raise_request_exception = False
        self._authenticate(self.staff)
        with patch.object(NewsletterCategory, "save", save_with_mapping_failure):
            response = self.client.post(
                self.categories_url,
                {"name": "Broken Updates"},
                format="json",
            )

        self.assertEqual(response.status_code, 500)
        self.assertNotIn(
            call("88", {"isPublished": False}),
            client.update_segment.call_args_list,
        )

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_patch_category_syncs_metadata_without_changing_slug(self, client_cls):
        self.category.mautic_segment_id = "1"
        self.category.save(update_fields=["mautic_segment_id"])
        client = client_cls.return_value
        client.get_segment.return_value = {"id": 1, "filters": []}
        client.update_segment.return_value = {"id": 1}
        self._authenticate(self.staff)

        response = self.client.patch(
            reverse("newsletter-admin-category-detail", args=[self.category.slug]),
            {"name": "IMAA Eventss Renamed", "description": "Updated."},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.category.refresh_from_db()
        self.assertEqual(self.category.slug, "imaa-events")
        client.update_segment.assert_called_once_with(
            "1",
            {
                "name": "IMAA Eventss Renamed",
                "description": "Updated.",
                "isPublished": True,
                "isPreferenceCenter": False,
                "filters": [],
            },
        )

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_patch_inactive_category_active_publishes_segment(self, client_cls):
        self.inactive_category.mautic_segment_id = "55"
        self.inactive_category.save(update_fields=["mautic_segment_id"])
        client = client_cls.return_value
        client.get_segment.return_value = {"id": 55, "filters": []}
        client.update_segment.return_value = {"id": 55}
        self._authenticate(self.staff)

        response = self.client.patch(
            reverse("newsletter-admin-category-detail", args=[self.inactive_category.slug]),
            {"is_active": True},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        client.update_segment.assert_called_once_with(
            "55",
            {
                "name": "Inactive Newsletter",
                "description": "",
                "isPublished": True,
                "isPreferenceCenter": False,
                "filters": [],
            },
        )

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_delete_category_unpublishes_segment(self, client_cls):
        self.category.mautic_segment_id = "1"
        self.category.save(update_fields=["mautic_segment_id"])
        client_cls.return_value.update_segment.return_value = {"id": 1}
        self._authenticate(self.staff)

        response = self.client.delete(
            reverse("newsletter-admin-category-detail", args=[self.category.slug])
        )

        self.assertEqual(response.status_code, 204)
        self.category.refresh_from_db()
        self.assertFalse(self.category.is_active)
        client_cls.return_value.update_segment.assert_called_once_with(
            "1",
            {"isPublished": False},
        )

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_link_existing_static_segment_queues_reconciliation(self, client_cls):
        client_cls.return_value.get_segment.return_value = {
            "id": 99,
            "name": "External",
            "filters": [],
        }
        subscriber = User.objects.create_user(
            username="subscriber",
            email="subscriber@example.test",
        )
        NewsletterSubscription.objects.create(
            user=subscriber,
            category=self.category,
            is_subscribed=True,
        )
        self.category.mautic_segment_id = ""
        self.category.save(update_fields=["mautic_segment_id"])
        self._authenticate(self.staff)

        response = self.client.post(
            reverse(
                "newsletter-admin-category-link-mautic-segment",
                args=[self.category.slug],
            ),
            {"mautic_segment_id": "99"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.category.refresh_from_db()
        self.assertEqual(self.category.mautic_segment_id, "99")
        self.assertEqual(response.data["reconciliation_queued"], 1)
        self.assertEqual(NewsletterSyncEvent.objects.count(), 1)

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_link_dynamic_segment_is_rejected(self, client_cls):
        client_cls.return_value.get_segment.return_value = {
            "id": 99,
            "filters": [{"field": "email", "operator": "like"}],
        }
        self._authenticate(self.staff)

        response = self.client.post(
            reverse(
                "newsletter-admin-category-link-mautic-segment",
                args=[self.category.slug],
            ),
            {"mautic_segment_id": "99"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_link_duplicate_segment_mapping_is_rejected(self, client_cls):
        self.other_category.mautic_segment_id = "99"
        self.other_category.save(update_fields=["mautic_segment_id"])
        client_cls.return_value.get_segment.return_value = {"id": 99, "filters": []}
        self._authenticate(self.staff)

        response = self.client.post(
            reverse(
                "newsletter-admin-category-link-mautic-segment",
                args=[self.category.slug],
            ),
            {"mautic_segment_id": "99"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)

    @patch("newsletter.admin_views.MauticClient")
    def test_admin_can_list_mautic_segments(self, client_cls):
        self.category.mautic_segment_id = "1"
        self.category.save(update_fields=["mautic_segment_id"])
        client_cls.return_value.list_segments.return_value = {
            "lists": {
                "1": {
                    "id": 1,
                    "name": "IMAA Events",
                    "alias": "imaa-events",
                    "description": "Events",
                    "isPublished": True,
                    "filters": [],
                },
                "2": {
                    "id": 2,
                    "name": "Dynamic",
                    "alias": "dynamic",
                    "filters": [{"field": "email"}],
                },
            }
        }
        self._authenticate(self.staff)

        response = self.client.get(reverse("newsletter-admin-mautic-segment-list"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data[0]["id"], "1")
        self.assertTrue(response.data[0]["is_static"])
        self.assertTrue(response.data[0]["mapped_in_ecp"])
        self.assertTrue(response.data[1]["is_dynamic"])

    @patch("newsletter.admin_views.MauticClient")
    def test_admin_mautic_segments_normalizes_provider_booleans(self, client_cls):
        client_cls.return_value.list_segments.return_value = {
            "lists": {
                "1": {"id": 1, "isPublished": "0", "filters": []},
                "2": {"id": 2, "isPublished": "1", "filters": []},
                "3": {"id": 3, "isPublished": "false", "filters": []},
                "4": {"id": 4, "isPublished": "true", "filters": []},
            }
        }
        self._authenticate(self.staff)

        response = self.client.get(reverse("newsletter-admin-mautic-segment-list"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [item["isPublished"] for item in response.data],
            [False, True, False, True],
        )

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_sync_mautic_repairs_missing_segment_and_queues_reconciliation(
        self,
        client_cls,
    ):
        from newsletter.mautic import PermanentMauticError

        client = client_cls.return_value
        client.get_segment.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        client.list_segments.return_value = {"lists": {}}
        client.create_segment.return_value = {"id": 77}
        subscriber = User.objects.create_user(
            username="repair-subscriber",
            email="repair@example.test",
        )
        NewsletterSubscription.objects.create(
            user=subscriber,
            category=self.category,
            is_subscribed=True,
        )
        self.category.mautic_segment_id = "404"
        self.category.save(update_fields=["mautic_segment_id"])
        self._authenticate(self.staff)

        response = self.client.post(
            reverse("newsletter-admin-category-sync-mautic", args=[self.category.slug])
        )

        self.assertEqual(response.status_code, 200)
        self.category.refresh_from_db()
        self.assertEqual(self.category.mautic_segment_id, "77")
        self.assertEqual(response.data["reconciliation_queued"], 1)

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_sync_mautic_rejects_dynamic_segment_with_same_alias(self, client_cls):
        self.category.mautic_segment_id = "404"
        self.category.save(update_fields=["mautic_segment_id"])
        from newsletter.mautic import PermanentMauticError

        client = client_cls.return_value
        client.get_segment.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        client.list_segments.return_value = {
            "lists": {
                "77": {
                    "id": 77,
                    "alias": self.category.slug,
                    "filters": [{"field": "email"}],
                }
            }
        }
        self._authenticate(self.staff)

        response = self.client.post(
            reverse("newsletter-admin-category-sync-mautic", args=[self.category.slug])
        )

        self.assertEqual(response.status_code, 502)
        client.create_segment.assert_not_called()

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_sync_mautic_auth_error_does_not_create_replacement(self, client_cls):
        self.category.mautic_segment_id = "1"
        self.category.save(update_fields=["mautic_segment_id"])
        from newsletter.mautic import PermanentMauticError

        client = client_cls.return_value
        client.get_segment.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 403)"
        )
        self._authenticate(self.staff)

        response = self.client.post(
            reverse("newsletter-admin-category-sync-mautic", args=[self.category.slug])
        )

        self.assertEqual(response.status_code, 502)
        client.create_segment.assert_not_called()

    @override_settings(MAUTIC_SYNC_ENABLED=True)
    @patch("newsletter.admin_views.MauticClient")
    def test_sync_mautic_temporary_error_does_not_create_replacement(self, client_cls):
        self.category.mautic_segment_id = "1"
        self.category.save(update_fields=["mautic_segment_id"])
        from newsletter.mautic import TemporaryMauticError

        client = client_cls.return_value
        client.get_segment.side_effect = TemporaryMauticError("Mautic unavailable")
        self._authenticate(self.staff)

        response = self.client.post(
            reverse("newsletter-admin-category-sync-mautic", args=[self.category.slug])
        )

        self.assertEqual(response.status_code, 502)
        client.create_segment.assert_not_called()

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
