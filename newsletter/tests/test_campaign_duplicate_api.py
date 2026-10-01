"""Broadcast Duplicate: a new editable Draft that shares no delivery state."""

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.forms.models import model_to_dict
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.models import (
    MauticIdentityAuditLog,
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCampaignTrackingEvent,
    NewsletterCategory,
)
from newsletter.tests.marketing_actors import grant_marketing_access


User = get_user_model()

CONTENT = {
    "subject": "September deals",
    "preview_text": "A quick look at this month's deals.",
    "from_name": "IMAA Connect",
    "from_email": "newsletter@example.test",
    "html_content": "<p>Hello {contactfield=firstname}</p>",
    "plain_text": "Hello",
}


@override_settings(ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False)
class NewsletterCampaignDuplicateAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.author = User.objects.create_superuser(
            username="broadcast-author",
            email="broadcast-author@example.test",
            password="test-password",
        )
        self.operator = User.objects.create_superuser(
            username="broadcast-operator",
            email="broadcast-operator@example.test",
            password="test-password",
        )
        grant_marketing_access(self.operator)
        self.normal_user = User.objects.create_user(
            username="broadcast-normal",
            email="broadcast-normal@example.test",
            password="test-password",
        )
        self.events = NewsletterCategory.objects.get(slug="imaa-events")
        self.deals = NewsletterCategory.objects.get(slug="imaa-deal-alert")
        self.retired = NewsletterCategory.objects.create(
            name="Retired Newsletter",
            slug="retired-newsletter",
            is_active=False,
        )
        self.client.force_authenticate(user=self.operator)

        # Provider clients are patched everywhere a Broadcast flow could build
        # one, so any Mautic call made by Duplicate would be visible here.
        for target in (
            "newsletter.campaign_services.MauticClient",
            "newsletter.admin_views.MauticClient",
        ):
            patcher = patch(target)
            self.addCleanup(patcher.stop)
            setattr(self, target.split(".")[1] + "_mautic", patcher.start())

    def _source(self, **overrides):
        fields = {
            "name": "September Deal Newsletter",
            **CONTENT,
            "status": NewsletterCampaign.Status.DRAFT,
            "created_by": self.author,
            "updated_by": self.author,
            **overrides,
        }
        source = NewsletterCampaign.objects.create(**fields)
        source.audiences.set([self.events, self.deals, self.retired])
        return source

    def _duplicate(self, source):
        return self.client.post(
            reverse("newsletter-admin-campaign-duplicate", args=[source.uuid]),
            {},
            format="json",
        )

    def _snapshot(self, campaign):
        campaign.refresh_from_db()
        return {
            **model_to_dict(campaign, exclude=["audiences"]),
            "uuid": campaign.uuid,
            "created_at": campaign.created_at,
            "updated_at": campaign.updated_at,
            "audiences": sorted(campaign.audiences.values_list("slug", flat=True)),
        }

    def assertCleanDraft(self, duplicate, source):
        self.assertNotEqual(duplicate.pk, source.pk)
        self.assertNotEqual(duplicate.uuid, source.uuid)
        self.assertEqual(duplicate.status, NewsletterCampaign.Status.DRAFT)
        self.assertIsNone(duplicate.scheduled_at)
        self.assertEqual(duplicate.schedule_owner, "")
        self.assertIsNone(duplicate.send_started_at)
        self.assertIsNone(duplicate.sent_at)
        self.assertEqual(duplicate.mautic_email_id, "")
        self.assertIsNone(duplicate.last_synced_to_mautic_at)
        self.assertEqual(duplicate.last_error, "")
        self.assertFalse(
            NewsletterCampaignSendEvent.objects.filter(campaign=duplicate).exists()
        )
        self.assertFalse(duplicate.tracking_events.exists())

    def assertNoProviderCall(self):
        self.campaign_services_mautic.assert_not_called()
        self.admin_views_mautic.assert_not_called()

    # --- 1. Draft source -------------------------------------------------------

    def test_draft_duplicate_copies_content_and_lists_into_an_operator_owned_draft(self):
        source = self._source()

        response = self._duplicate(source)

        self.assertEqual(response.status_code, 201)
        duplicate = NewsletterCampaign.objects.get(uuid=response.data["uuid"])
        self.assertCleanDraft(duplicate, source)
        self.assertEqual(duplicate.name, "September Deal Newsletter Copy")
        for field, value in CONTENT.items():
            self.assertEqual(getattr(duplicate, field), value, field)
        # Editable configuration: the active lists only, as create accepts.
        self.assertEqual(
            sorted(duplicate.audiences.values_list("slug", flat=True)),
            ["imaa-deal-alert", "imaa-events"],
        )
        self.assertEqual(duplicate.created_by, self.operator)
        self.assertEqual(duplicate.updated_by, self.operator)
        self.assertGreaterEqual(duplicate.created_at, source.created_at)
        self.assertNoProviderCall()

    def test_response_matches_the_broadcast_representation(self):
        response = self._duplicate(self._source())

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["status"], "draft")
        self.assertEqual(response.data["mautic_email_id"], None)
        self.assertEqual(
            sorted(item["slug"] for item in response.data["audiences"]),
            ["imaa-deal-alert", "imaa-events"],
        )

    def test_duplicate_is_an_editable_draft(self):
        response = self._duplicate(self._source())
        url = reverse("newsletter-admin-campaign-detail", args=[response.data["uuid"]])

        edited = self.client.patch(
            url,
            {"subject": "Edited subject", "audience_slugs": ["imaa-events"]},
            format="json",
        )

        self.assertEqual(edited.status_code, 200, edited.data)
        self.assertEqual(edited.data["subject"], "Edited subject")

    # --- 2. Scheduled sources --------------------------------------------------

    def test_scheduled_sources_do_not_pass_on_their_schedule(self):
        for owner in (
            NewsletterCampaign.ScheduleOwner.ECP,
            NewsletterCampaign.ScheduleOwner.MAUTIC,
        ):
            with self.subTest(owner=owner):
                source = self._source(
                    status=NewsletterCampaign.Status.SCHEDULED,
                    scheduled_at=timezone.now() + timedelta(days=1),
                    schedule_owner=owner,
                    mautic_email_id=f"{owner}-71",
                    last_synced_to_mautic_at=timezone.now(),
                )

                response = self._duplicate(source)

                self.assertEqual(response.status_code, 201)
                self.assertCleanDraft(
                    NewsletterCampaign.objects.get(uuid=response.data["uuid"]),
                    source,
                )

    # --- 3. Sent source --------------------------------------------------------

    def test_sent_source_does_not_pass_on_send_history_or_stats(self):
        sent_at = timezone.now() - timedelta(days=2)
        source = self._source(
            status=NewsletterCampaign.Status.SENT,
            schedule_owner=NewsletterCampaign.ScheduleOwner.MAUTIC,
            scheduled_at=sent_at,
            send_started_at=sent_at,
            sent_at=sent_at,
            mautic_email_id="88",
            last_synced_to_mautic_at=sent_at,
        )
        NewsletterCampaignSendEvent.objects.create(
            campaign=source,
            idempotency_key=f"send-{source.uuid}",
            requested_by=self.author,
            status=NewsletterCampaignSendEvent.Status.SUCCEEDED,
            provider_sent_count=120,
        )
        NewsletterCampaignTrackingEvent.objects.create(
            campaign=source,
            event_type=NewsletterCampaignTrackingEvent.EventType.OPENED,
            recipient_email="reader@example.test",
            occurred_at=sent_at,
        )

        response = self._duplicate(source)

        self.assertEqual(response.status_code, 201)
        duplicate = NewsletterCampaign.objects.get(uuid=response.data["uuid"])
        self.assertCleanDraft(duplicate, source)
        # The source keeps its history.
        self.assertEqual(source.send_event.provider_sent_count, 120)
        self.assertEqual(source.tracking_events.count(), 1)

    # --- 4/5. Provider identity and error state --------------------------------

    def test_duplicate_never_shares_the_source_mautic_email(self):
        source = self._source(mautic_email_id="91", last_synced_to_mautic_at=timezone.now())

        response = self._duplicate(source)

        duplicate = NewsletterCampaign.objects.get(uuid=response.data["uuid"])
        self.assertEqual(duplicate.mautic_email_id, "")
        self.assertNotEqual(duplicate.mautic_email_id, source.mautic_email_id)
        self.assertNoProviderCall()

    def test_failed_source_does_not_pass_on_its_error(self):
        source = self._source(
            status=NewsletterCampaign.Status.FAILED,
            send_started_at=timezone.now(),
            mautic_email_id="92",
            last_error="Mautic rejected the send (HTTP 422)",
        )

        response = self._duplicate(source)

        self.assertEqual(response.status_code, 201)
        self.assertCleanDraft(
            NewsletterCampaign.objects.get(uuid=response.data["uuid"]),
            source,
        )

    # --- 7. Source untouched ---------------------------------------------------

    def test_every_source_field_is_left_unchanged(self):
        source = self._source(
            status=NewsletterCampaign.Status.SENT,
            sent_at=timezone.now(),
            mautic_email_id="93",
            last_error="old error",
        )
        before = self._snapshot(source)

        self.assertEqual(self._duplicate(source).status_code, 201)

        self.assertEqual(self._snapshot(source), before)

    # --- 8/9. Not found and permissions ----------------------------------------

    def test_unknown_broadcast_is_not_found(self):
        source = self._source()
        url = reverse("newsletter-admin-campaign-duplicate", args=[source.uuid])
        source.delete()

        response = self.client.post(url, {}, format="json")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(NewsletterCampaign.objects.count(), 0)

    def test_duplicate_requires_marketing_hub_access(self):
        source = self._source()
        url = reverse("newsletter-admin-campaign-duplicate", args=[source.uuid])
        unmapped_superuser = User.objects.create_superuser(
            username="broadcast-unmapped",
            email="broadcast-unmapped@example.test",
            password="test-password",
        )

        self.client.force_authenticate(user=None)
        self.assertIn(self.client.post(url, {}, format="json").status_code, (401, 403))
        for user in (self.normal_user, unmapped_superuser):
            self.client.force_authenticate(user=user)
            self.assertEqual(self.client.post(url, {}, format="json").status_code, 403)

        self.assertEqual(NewsletterCampaign.objects.count(), 1)

    def test_only_post_is_allowed(self):
        source = self._source()
        url = reverse("newsletter-admin-campaign-duplicate", args=[source.uuid])

        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(NewsletterCampaign.objects.count(), 1)

    # --- 10. Repeated duplicates -----------------------------------------------

    def test_repeated_duplicates_are_independent_drafts(self):
        source = self._source(mautic_email_id="94")

        first = NewsletterCampaign.objects.get(uuid=self._duplicate(source).data["uuid"])
        second = NewsletterCampaign.objects.get(uuid=self._duplicate(source).data["uuid"])
        copy_of_copy = NewsletterCampaign.objects.get(
            uuid=self._duplicate(first).data["uuid"]
        )

        self.assertEqual(len({source.pk, first.pk, second.pk, copy_of_copy.pk}), 4)
        self.assertEqual(first.name, second.name)
        self.assertEqual(copy_of_copy.name, "September Deal Newsletter Copy Copy")
        for duplicate in (first, second, copy_of_copy):
            self.assertEqual(duplicate.mautic_email_id, "")
        # Each copy owns its own list relation rows.
        first.audiences.set([self.events])
        self.assertEqual(second.audiences.count(), 2)

    def test_name_stays_within_the_field_limit(self):
        source = self._source(name="N" * 180)

        response = self._duplicate(source)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(response.data["name"]), 180)
        self.assertTrue(response.data["name"].endswith(" Copy"))

    # --- Audit -----------------------------------------------------------------

    def test_duplicate_writes_no_mautic_audit_row(self):
        # The identity audit records Mautic operations; Duplicate, like
        # Broadcast create, never reaches Mautic.
        self._duplicate(self._source())

        self.assertFalse(MauticIdentityAuditLog.objects.exists())
