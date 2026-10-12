"""Permanent delete of a Subscription List (NewsletterCategory).

Delete is a separate one-way lifecycle from Deactivate. Only the Mautic HTTP
session is faked: the real client, identity resolution, signing, bridge routing,
audit helper, row locking and DRF permissions all run.
"""

import json
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

import jwt
import requests
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter import category_delete_services
from newsletter.category_segment_services import (
    ensure_category_segment,
    repair_campaign_audience_segments,
)
from newsletter.mautic import PermanentMauticError
from newsletter.mautic.client import ECP_IDENTITY_ASSERTION_HEADER, MauticClient
from newsletter.mautic.operations import SEGMENT_DELETE
from newsletter.models import (
    MauticContactMapping,
    MauticIdentityAuditLog,
    NewsletterCampaign,
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterSyncEvent,
)
from newsletter.processor import process_newsletter_sync_event
from newsletter.services import list_user_preferences
from newsletter.tests.marketing_actors import grant_marketing_access, marketing_mautic_user_id
from newsletter.tests.test_mautic_per_user_execution import PER_USER_OFF, PER_USER_ON
from newsletter.tests.test_mautic_user_identity import PUBLIC_KEY

User = get_user_model()

BASE = "https://mautic.example.test/api/"
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "category-delete-tests"}}


def _response(status_code=200, payload=None):
    response = Mock(status_code=status_code)
    response.json.return_value = payload if payload is not None else {}
    response.text = json.dumps(payload or {})
    response.headers = {}
    return response


class FakeMautic:
    """In-memory Mautic answering the calls a Subscription List delete makes."""

    def __init__(self, *, segments=None, campaigns=None, emails=None, delete_status=None, delete_raises=None):
        self.segments = {str(k): v for k, v in (segments or {}).items()}
        self.campaigns = campaigns or []
        self.emails = emails or []
        self.delete_status = delete_status
        self.delete_raises = delete_raises
        self.calls = []

    @staticmethod
    def _page(rows, params):
        params = params or {}
        start = int(params.get("start", 0))
        limit = int(params.get("limit", 30))
        return rows[start:start + limit]

    def request(self, method, url, **kwargs):
        path = urlsplit(url).path[len(urlsplit(BASE).path):]
        self.calls.append({"method": method, "path": path, **kwargs})
        params = kwargs.get("params")
        if method == "GET" and path == "segments":
            rows = self._page(list(self.segments.values()), params)
            return _response(payload={"total": len(self.segments), "lists": {str(r["id"]): r for r in rows}})
        if method == "GET" and path.startswith("segments/"):
            segment = self.segments.get(path.split("/")[1])
            if segment is None:
                return _response(404, {"errors": [{"message": "Item was not found."}]})
            return _response(payload={"list": segment})
        if method == "GET" and path == "campaigns":
            if self.campaigns is None:
                return _response(payload={"total": 1, "campaigns": "invalid"})
            rows = self._page(self.campaigns, params)
            return _response(payload={"total": len(self.campaigns), "campaigns": rows})
        if method == "GET" and path == "emails":
            rows = self._page(self.emails, params)
            return _response(payload={"total": len(self.emails), "emails": rows})
        if method == "DELETE" and path.endswith("/delete") and "segments/" in path:
            segment_id = path.rstrip("/").split("/")[-2]
            if self.delete_raises is not None:
                raise self.delete_raises
            if self.delete_status is not None:
                return _response(self.delete_status, {"errors": [{"message": "refused"}]})
            segment = self.segments.pop(segment_id, None)
            if segment is None:
                return _response(404, {"errors": [{"message": "Item was not found."}]})
            return _response(payload={"list": {**segment, "id": None}})
        return _response(500, {"errors": [{"message": f"unexpected {method} {path}"}]})

    def deletes(self):
        return [call for call in self.calls if call["method"] == "DELETE"]

    def writes(self):
        return [call for call in self.calls if call["method"] != "GET"]


def _segment(segment_id, name="Deal Alerts", filters=None):
    return {"id": int(segment_id), "name": name, "alias": name.lower().replace(" ", "-"), "filters": filters or []}


@override_settings(**PER_USER_OFF, MAUTIC_SYNC_ENABLED=True, CACHES=LOCMEM)
class _Fixtures(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.actor = User.objects.create_user(
            username="list-admin", email="list-admin@example.test", password="pw", is_staff=True, is_superuser=True
        )
        grant_marketing_access(self.actor)
        self.api.force_authenticate(user=self.actor)

        self.member = User.objects.create_user(username="member", email="member@example.test", password="pw")
        self.category = NewsletterCategory.objects.create(
            name="Deal Alerts", slug="deal-alerts", description="Weekly deals", mautic_segment_id="300"
        )
        self.other = NewsletterCategory.objects.create(
            name="Events", slug="events", description="Events", mautic_segment_id="301"
        )
        self.subscription = NewsletterSubscription.objects.create(
            user=self.member, category=self.category, is_subscribed=True
        )
        NewsletterSubscription.objects.create(user=self.member, category=self.other, is_subscribed=True)
        self.sync_event = NewsletterSyncEvent.objects.create(
            idempotency_key="evt-1",
            user_id=str(self.member.pk),
            category=self.category,
            desired_subscribed=True,
            status=NewsletterSyncEvent.Status.SUCCEEDED,
        )
        MauticContactMapping.objects.create(user=self.member, mautic_contact_id="77")

    def mautic(self, **kwargs):
        kwargs.setdefault("segments", {"300": _segment(300), "301": _segment(301, "Events")})
        return FakeMautic(**kwargs)

    def call(self, method="post", slug="deal-alerts", *, mautic=None, api=None):
        mautic = mautic or self.mautic()

        def factory(*args, **kwargs):
            kwargs["session"] = mautic
            return MauticClient(*args, **kwargs)

        url = reverse("newsletter-admin-category-delete", kwargs={"slug": slug})
        with patch("newsletter.category_delete_views.MauticClient", side_effect=factory), patch(
            "newsletter.category_delete_services.MauticClient", side_effect=factory
        ):
            response = getattr(api or self.api, method)(url, format="json")
        return response, mautic

    def reload(self):
        self.category.refresh_from_db()
        return self.category


class CategoryDeleteSuccessTests(_Fixtures):
    def test_superuser_deletes_list_and_its_segment(self):
        response, mautic = self.call()

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["deletion_state"], "deleted")
        self.assertTrue(response.data["mautic_segment_deleted"])
        self.assertFalse(response.data["mautic_segment_already_missing"])
        category = self.reload()
        self.assertTrue(category.is_deleted)
        self.assertFalse(category.is_active)
        self.assertIsNotNone(category.deleted_at)
        self.assertEqual(category.deleted_by, self.actor)
        # Exactly one write: the linked segment. No contact or other segment.
        self.assertEqual([c["path"] for c in mautic.writes()], ["segments/300/delete"])
        self.assertNotIn("300", mautic.segments)
        self.assertIn("301", mautic.segments)

    def test_history_users_contacts_and_unrelated_lists_are_preserved(self):
        self.call()

        self.assertTrue(NewsletterSubscription.objects.filter(pk=self.subscription.pk, is_subscribed=True).exists())
        self.assertTrue(NewsletterSyncEvent.objects.filter(pk=self.sync_event.pk).exists())
        self.assertTrue(User.objects.filter(pk=self.member.pk).exists())
        self.assertTrue(MauticContactMapping.objects.filter(user=self.member, mautic_contact_id="77").exists())
        self.other.refresh_from_db()
        self.assertTrue(self.other.is_active)
        self.assertEqual(self.other.deletion_state, "")
        self.assertEqual(self.reload().mautic_segment_id, "300")

    def test_historical_broadcast_audience_is_kept(self):
        sent = NewsletterCampaign.objects.create(name="Old", status=NewsletterCampaign.Status.SENT)
        sent.audiences.add(self.category)

        response, _ = self.call()

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(list(sent.audiences.values_list("slug", flat=True)), ["deal-alerts"])

    def test_repeat_delete_is_idempotent_and_skips_mautic(self):
        self.call()
        response, mautic = self.call()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["already_deleted"])
        self.assertEqual(mautic.calls, [])

    def test_segment_already_missing_in_mautic_still_completes(self):
        response, mautic = self.call(mautic=self.mautic(segments={"301": _segment(301)}))

        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data["mautic_segment_already_missing"])
        self.assertEqual(mautic.deletes(), [])
        self.assertTrue(self.reload().is_deleted)

    def test_unlinked_list_is_deleted_locally_without_mautic(self):
        self.category.mautic_segment_id = ""
        self.category.save()

        response, mautic = self.call()

        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(response.data["mautic_segment_deleted"])
        self.assertEqual(mautic.calls, [])
        self.assertTrue(self.reload().is_deleted)

    def test_deleted_name_can_be_reused_but_live_names_stay_unique(self):
        self.call()

        with override_settings(MAUTIC_SYNC_ENABLED=False):
            reused = self.api.post(reverse("newsletter-admin-category-list"), {"name": "Deal Alerts"}, format="json")
            duplicate = self.api.post(reverse("newsletter-admin-category-list"), {"name": "Events"}, format="json")

        self.assertEqual(reused.status_code, 201, reused.data)
        self.assertNotEqual(reused.data["slug"], "deal-alerts")
        self.assertEqual(duplicate.status_code, 400)
        self.assertIn("name", duplicate.data)


class CategoryDeletePermissionTests(_Fixtures):
    def test_unknown_list_is_404(self):
        response, _ = self.call(slug="nope")
        self.assertEqual(response.status_code, 404)

    def test_unauthenticated_is_rejected(self):
        response, mautic = self.call(api=APIClient())
        self.assertIn(response.status_code, (401, 403))
        self.assertEqual(mautic.calls, [])
        self.assertEqual(self.reload().deletion_state, "")

    def test_regular_user_is_rejected(self):
        api = APIClient()
        api.force_authenticate(user=self.member)
        response, mautic = self.call(api=api)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(mautic.calls, [])

    def test_staff_without_superuser_is_rejected(self):
        staff = User.objects.create_user(username="staff", email="staff@example.test", password="pw", is_staff=True)
        api = APIClient()
        api.force_authenticate(user=staff)
        response, _ = self.call(api=api)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.reload().deletion_state, "")

    def test_superuser_without_mautic_mapping_is_rejected(self):
        unmapped = User.objects.create_user(
            username="su", email="su@example.test", password="pw", is_staff=True, is_superuser=True
        )
        api = APIClient()
        api.force_authenticate(user=unmapped)
        response, _ = self.call(api=api)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.reload().deletion_state, "")


class CategoryDeleteDependencyTests(_Fixtures):
    def assertBlocked(self, response, mautic, kind):
        self.assertEqual(response.status_code, 409, response.data)
        self.assertEqual(response.data["code"], "dependency_conflict")
        self.assertIn(kind, [d["type"] for d in response.data["dependencies"]])
        self.assertEqual(mautic.deletes(), [])
        category = self.reload()
        self.assertEqual(category.deletion_state, "")
        self.assertTrue(category.is_active)

    def test_scheduled_broadcast_blocks(self):
        scheduled = NewsletterCampaign.objects.create(name="Next", status=NewsletterCampaign.Status.SCHEDULED)
        scheduled.audiences.add(self.category)
        response, mautic = self.call()
        self.assertBlocked(response, mautic, "broadcast")

    def test_draft_broadcast_is_only_a_warning(self):
        draft = NewsletterCampaign.objects.create(name="Draft", status=NewsletterCampaign.Status.DRAFT)
        draft.audiences.add(self.category)
        response, _ = self.call()
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual([w["name"] for w in response.data["warnings"]], ["Draft"])

    def test_mautic_campaign_source_blocks(self):
        mautic = self.mautic(campaigns=[{"id": 9, "name": "Nurture", "lists": [{"id": 300}], "events": []}])
        response, mautic = self.call(mautic=mautic)
        self.assertBlocked(response, mautic, "mautic_campaign")

    def test_mautic_campaign_event_reference_blocks(self):
        mautic = self.mautic(
            campaigns=[{"id": 9, "name": "Mover", "lists": [], "events": [
                {"type": "lead.changelist", "properties": {"addToLists": ["300"], "removeFromLists": []}}
            ]}]
        )
        response, mautic = self.call(mautic=mautic)
        self.assertBlocked(response, mautic, "mautic_campaign")

    def test_other_segment_filter_reference_blocks(self):
        dependent = _segment(
            302, "Engaged", filters=[{"type": "leadlist", "field": "leadlist", "operator": "in",
                                      "properties": {"filter": ["300"]}}]
        )
        mautic = self.mautic(segments={"300": _segment(300), "302": dependent})
        response, mautic = self.call(mautic=mautic)
        self.assertBlocked(response, mautic, "mautic_segment")

    def test_native_mautic_email_blocks_but_ecp_owned_email_does_not(self):
        sent = NewsletterCampaign.objects.create(
            name="Old", status=NewsletterCampaign.Status.SENT, mautic_email_id="40"
        )
        sent.audiences.add(self.category)
        mautic = self.mautic(emails=[{"id": 40, "name": "ECP old", "lists": [{"id": 300}]}])
        ok, _ = self.call(mautic=mautic)
        self.assertEqual(ok.status_code, 200, ok.data)

        self.other.mautic_segment_id = "301"
        self.other.save()
        mautic = self.mautic(emails=[{"id": 41, "name": "Native", "lists": [{"id": 301}]}])
        response, mautic = self.call(slug="events", mautic=mautic)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(mautic.deletes(), [])

    def test_shared_segment_mapping_blocks(self):
        NewsletterCategory.objects.create(name="Twin", slug="twin", mautic_segment_id="300")
        response, mautic = self.call()
        self.assertBlocked(response, mautic, "subscription_list")

    def test_dynamic_linked_segment_blocks(self):
        dynamic = _segment(300, filters=[{"type": "email", "field": "email", "operator": "like",
                                          "properties": {"filter": "x"}}])
        response, mautic = self.call(mautic=self.mautic(segments={"300": dynamic}))
        self.assertBlocked(response, mautic, "mautic_segment")

    def test_mautic_disabled_with_linked_segment_blocks(self):
        with override_settings(MAUTIC_SYNC_ENABLED=False):
            response, mautic = self.call()
        self.assertBlocked(response, mautic, "mautic_segment")

    def test_preflight_reports_counts_without_changing_anything(self):
        response, mautic = self.call("get")

        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data["can_delete"])
        self.assertEqual(response.data["subscriber_count"], 1)
        self.assertEqual(response.data["mautic_segment_id"], "300")
        self.assertEqual(mautic.writes(), [])
        self.assertEqual(self.reload().deletion_state, "")


class CategoryDeleteFailureTests(_Fixtures):
    def test_mautic_rejection_leaves_deletion_pending_and_retry_finishes(self):
        response, _ = self.call(mautic=self.mautic(delete_status=400))

        self.assertEqual(response.status_code, 502, response.data)
        self.assertEqual(response.data["deletion_state"], "deleting")
        category = self.reload()
        self.assertFalse(category.is_deleted)
        self.assertIsNone(category.deleted_at)
        self.assertFalse(category.is_active)

        retry, _ = self.call()
        self.assertEqual(retry.status_code, 200, retry.data)
        self.assertTrue(self.reload().is_deleted)

    def test_timeout_is_retryable_and_ambiguous_success_is_resolved_by_404(self):
        response, mautic = self.call(mautic=self.mautic(delete_raises=requests.ReadTimeout("slow")))

        self.assertEqual(response.status_code, 503, response.data)
        self.assertEqual(response.data["code"], "mautic_unavailable")
        self.assertEqual(self.reload().deletion_state, "deleting")

        # Mautic actually deleted it before the timeout: the retry sees a 404.
        retry, _ = self.call(mautic=self.mautic(segments={"301": _segment(301)}))
        self.assertEqual(retry.status_code, 200, retry.data)
        self.assertTrue(retry.data["mautic_segment_already_missing"])
        self.assertTrue(self.reload().is_deleted)

    def test_provider_outage_during_check_changes_nothing(self):
        mautic = self.mautic()
        mautic.campaigns = None  # the campaign list answers with an invalid body

        response, mautic = self.call(mautic=mautic)

        self.assertIn(response.status_code, (502, 503))
        self.assertEqual(mautic.deletes(), [])
        self.assertEqual(self.reload().deletion_state, "")

    def test_concurrent_request_is_refused_while_locked(self):
        self.assertTrue(category_delete_services.acquire_lock(self.category))
        try:
            response, mautic = self.call()
        finally:
            category_delete_services.release_lock(self.category)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["code"], "deletion_in_progress")
        self.assertEqual(mautic.calls, [])

    def test_begin_deletion_rechecks_broadcasts_under_lock(self):
        scheduled = NewsletterCampaign.objects.create(name="Race", status=NewsletterCampaign.Status.SCHEDULED)
        scheduled.audiences.add(self.category)
        with self.assertRaises(category_delete_services.CategoryDeleteError):
            category_delete_services.begin_deletion(self.category, actor=self.actor)
        self.assertEqual(self.reload().deletion_state, "")


class DeletedListVisibilityTests(_Fixtures):
    def _delete(self):
        response, _ = self.call()
        self.assertEqual(response.status_code, 200, response.data)

    def test_admin_list_hides_deleted_but_shows_pending(self):
        self._delete()
        slugs = [row["slug"] for row in self.api.get(reverse("newsletter-admin-category-list")).data]
        self.assertNotIn("deal-alerts", slugs)
        self.assertIn("events", slugs)

        self.other.deletion_state = NewsletterCategory.DeletionState.DELETING
        self.other.is_active = False
        self.other.save()
        rows = self.api.get(reverse("newsletter-admin-category-list"), {"include_mautic": "1"}).data
        states = {r["slug"]: r["deletion_state"] for r in rows}
        self.assertEqual(states["events"], "deleting")
        self.assertNotIn("deal-alerts", states)

    def test_member_preferences_hide_deleted_and_reject_subscribe(self):
        self._delete()
        visible = [row["slug"] for row in list_user_preferences(self.member)]
        self.assertNotIn("deal-alerts", visible)
        self.assertIn("events", visible)

        api = APIClient()
        api.force_authenticate(user=self.member)
        listed = api.get(reverse("newsletter-preferences"))
        self.assertNotIn("deal-alerts", json.dumps(listed.data))
        response = api.patch(
            reverse("newsletter-preferences"),
            {"preferences": [{"slug": "deal-alerts", "subscribed": False}]},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.subscription.refresh_from_db()
        self.assertTrue(self.subscription.is_subscribed)

    def test_new_broadcast_cannot_target_deleted_list(self):
        self._delete()
        response = self.api.post(
            reverse("newsletter-admin-campaign-list"),
            {"name": "New", "audience_slugs": ["deal-alerts"]},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("audience_slugs", response.data)

    def test_deactivate_reactivate_edit_link_and_sync_refuse_deleted_list(self):
        self._delete()
        detail = reverse("newsletter-admin-category-detail", kwargs={"slug": "deal-alerts"})
        self.assertEqual(self.api.patch(detail, {"is_active": True}, format="json").status_code, 404)
        self.assertEqual(self.api.delete(detail).status_code, 404)
        sync = reverse("newsletter-admin-category-sync-mautic", kwargs={"slug": "deal-alerts"})
        self.assertEqual(self.api.post(sync).status_code, 404)
        link = reverse("newsletter-admin-category-link-mautic-segment", kwargs={"slug": "deal-alerts"})
        self.assertEqual(self.api.post(link, {"mautic_segment_id": "300"}, format="json").status_code, 404)
        self.assertFalse(self.reload().is_active)

    def test_pending_list_refuses_reactivate_and_sync(self):
        self.call(mautic=self.mautic(delete_status=400))
        detail = reverse("newsletter-admin-category-detail", kwargs={"slug": "deal-alerts"})

        response = self.api.patch(detail, {"is_active": True}, format="json")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["code"], "deletion_pending")
        sync = reverse("newsletter-admin-category-sync-mautic", kwargs={"slug": "deal-alerts"})
        self.assertEqual(self.api.post(sync).status_code, 409)
        self.assertFalse(self.reload().is_active)


class DeactivateReactivateRegressionTests(_Fixtures):
    def test_deactivate_and_reactivate_still_work_for_live_lists(self):
        detail = reverse("newsletter-admin-category-detail", kwargs={"slug": "deal-alerts"})
        with override_settings(MAUTIC_SYNC_ENABLED=False):
            self.assertEqual(self.api.delete(detail).status_code, 204)
            category = self.reload()
            self.assertFalse(category.is_active)
            self.assertEqual(category.deletion_state, "")

            response = self.api.patch(detail, {"is_active": True}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(self.reload().is_active)

    def test_deactivated_list_can_still_be_deleted(self):
        self.category.is_active = False
        self.category.save()
        response, _ = self.call()
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(self.reload().is_deleted)


@override_settings(MAUTIC_SYNC_ENABLED=True)
class BackgroundRecreationTests(_Fixtures):
    def test_segment_ensure_refuses_deleted_or_pending_list(self):
        for state in ("deleting", "deleted"):
            self.category.deletion_state = state
            client = Mock()
            with self.assertRaises(PermanentMauticError):
                ensure_category_segment(self.category, client=client)
            client.create_segment.assert_not_called()

    def test_broadcast_segment_repair_skips_deleted_list(self):
        self.call()
        campaign = NewsletterCampaign.objects.create(name="Old", status=NewsletterCampaign.Status.DRAFT)
        campaign.audiences.add(self.category)
        client = Mock()
        self.assertEqual(repair_campaign_audience_segments(campaign, client=client), 0)
        client.create_segment.assert_not_called()
        client.get_segment.assert_not_called()

    def test_queued_sync_event_for_deleted_list_is_skipped(self):
        self.call()
        event = NewsletterSyncEvent.objects.create(
            idempotency_key="evt-late",
            user_id=str(self.member.pk),
            category=self.category,
            desired_subscribed=True,
        )
        with patch("newsletter.processor.MauticClient") as client:
            result = process_newsletter_sync_event(event.pk)
        self.assertEqual(result["status"], NewsletterSyncEvent.Status.SKIPPED)
        client.assert_not_called()

    def test_deleted_segment_id_no_longer_marks_native_segment_as_managed(self):
        from newsletter.category_segment_services import mapped_category_for_segment

        self.assertEqual(mapped_category_for_segment("300"), self.category)
        self.call()
        self.assertIsNone(mapped_category_for_segment("300"))


@override_settings(**PER_USER_ON, MAUTIC_SYNC_ENABLED=True, CACHES=LOCMEM)
class CategoryDeleteAssertedIdentityTests(_Fixtures):
    def test_segment_delete_runs_through_bridge_as_acting_user_and_is_audited(self):
        response, mautic = self.call()

        self.assertEqual(response.status_code, 200, response.data)
        (delete,) = mautic.deletes()
        self.assertEqual(delete["path"], "ecp/bridge/segments/300/delete")
        claims = jwt.decode(
            delete["headers"][ECP_IDENTITY_ASSERTION_HEADER], PUBLIC_KEY, algorithms=["RS256"], audience="ecp-mautic"
        )
        self.assertEqual(claims["operation"], SEGMENT_DELETE)
        self.assertEqual(claims["mautic_user_id"], marketing_mautic_user_id(self.actor))
        self.assertEqual(claims["sub"], str(self.actor.pk))
        audit = MauticIdentityAuditLog.objects.filter(resource="newsletter_category").latest("id")
        self.assertEqual((audit.action, audit.status, audit.resource_id), (SEGMENT_DELETE, "succeeded", "deal-alerts"))

    def test_bridge_refusal_is_not_retried_as_service_account(self):
        response, mautic = self.call(mautic=self.mautic(delete_status=403))

        self.assertNotEqual(response.status_code, 200)
        self.assertEqual([c["path"] for c in mautic.deletes()], ["ecp/bridge/segments/300/delete"])
        self.assertFalse(self.reload().is_deleted)
        audit = MauticIdentityAuditLog.objects.filter(resource="newsletter_category").latest("id")
        self.assertEqual(audit.status, "denied")
