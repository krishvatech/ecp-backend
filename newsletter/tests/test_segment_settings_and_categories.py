"""Batch 2 (1-2): segment settings, usage, safe delete and duplicate; the
Mautic Categories manager and the shared category picker check."""

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, CATEGORY_CREATE, CATEGORY_DELETE, CATEGORY_UPDATE
from newsletter.mautic_category_services import alias_for, category_choice
from newsletter.models import MauticIdentityAuditLog, NewsletterCampaign, NewsletterCategory
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_admin_forms_api import PER_USER_ON

User = get_user_model()

CATEGORIES = {"categories": {
    "1": {"id": 1, "title": "Board", "alias": "board", "bundle": "segment", "color": "4E5D9D"},
    "2": {"id": 2, "title": "Everything", "alias": "everything", "bundle": "global"},
    "3": {"id": 3, "title": "Newsletters", "alias": "newsletters", "bundle": "email"},
    "4": {"id": 4, "title": "ECP Subscription Lists", "alias": "ecp-subscription-lists", "bundle": "segment"},
    "5": {"id": 5, "title": "Old", "alias": "old", "bundle": "segment"},
}, "total": 5}
OVERVIEW = {
    "usage": {1: {"items": {"lead_lists": 2, "emails": 1}}, 4: {"items": {"lead_lists": 3}}, 3: {"contact_preferences": {"lead_categories": 7}}},
    "published": {1: True, 2: True, 3: True, 4: True, 5: False},
}
NO_USAGE = {"segment_id": 9, "total": 0, "usage": {"campaigns": [], "emails": [], "segments": [], "forms": [], "reports": [], "point_triggers": []}}


def mock_client():
    client = Mock(name="mautic")
    client._uses_asserted_user.return_value = False
    client.list_categories.return_value = CATEGORIES
    client.get_category_overview.return_value = OVERVIEW
    client.get_segment_filter_metadata.return_value = {"fields": [{"object": "lead", "alias": "city", "type": "text",
                                                                 "operators": ["=", "!="]}],
                                                       "operators": [{"value": "="}, {"value": "!="}]}
    return client


def segment(**overrides):
    row = {"id": 9, "name": "Board Targeting", "alias": "board-targeting", "description": "d", "publicName": "Board",
           "isGlobal": True, "isPreferenceCenter": True, "isPublished": True, "category": None, "filters": []}
    row.update(overrides)
    return row


class CategoryChoiceTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client_mock = mock_client()

    def test_picker_rules(self):
        self.assertIsNone(category_choice("", "segment", client=self.client_mock))
        self.assertEqual(category_choice("1", "segment", client=self.client_mock), 1)
        self.assertEqual(category_choice(2, "segment", client=self.client_mock), 2)  # global
        for value, message in ((3, "segments"), (4, "managed by ECP"), (5, "unpublished"), (99, "no longer exists"), ("x", "from the list")):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, message):
                category_choice(value, "segment", client=self.client_mock)
        self.assertEqual(alias_for("ECP  Subscription-Lists!"), "ecp-subscription-lists")
        self.assertTrue({CATEGORY_CREATE, CATEGORY_UPDATE, CATEGORY_DELETE} <= ASSERTABLE_OPERATIONS)


@override_settings(ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False)
class CategoryManagerTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="cat-admin", email="cat-admin@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api.force_authenticate(self.admin)
        self.client_mock = mock_client()
        for target in ("newsletter.mautic_category_views.MauticClient", "newsletter.mautic_category_services.MauticClient",
                       "newsletter.mautic_identity_execution.MauticClient"):
            patcher = patch(target, return_value=self.client_mock)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.url = reverse("newsletter-admin-mautic-category-list")

    def detail(self, category_id):
        return reverse("newsletter-admin-mautic-category-detail", args=[category_id])

    def test_list_marks_the_consent_category_and_reports_usage(self):
        body = self.api.get(self.url).json()
        rows = {row["id"]: row for row in body["results"]}
        self.assertTrue(rows[4]["protected"])
        self.assertFalse(rows[1]["protected"])
        self.assertEqual((rows[1]["usage"]["items"], rows[3]["usage"]["contact_preferences"]), (3, 7))
        self.assertEqual((rows[5]["isPublished"], rows[1]["isPublished"]), (False, True))

    def test_picker_offers_published_categories_of_the_type_and_global_only(self):
        body = self.api.get(self.url, {"bundle": "segment"}).json()
        self.assertEqual(sorted(row["id"] for row in body["results"]), [1, 2])

    def test_create_refuses_reserved_and_duplicate_titles(self):
        for title, code in (("ECP Subscription Lists", 400), ("board", 409), ("", 400)):
            with self.subTest(title=title):
                self.assertEqual(self.api.post(self.url, {"title": title, "bundle": "segment"}, format="json").status_code, code)
        self.assertEqual(self.api.post(self.url, {"title": "X", "bundle": "nope"}, format="json").status_code, 400)
        self.assertEqual(self.api.post(self.url, {"title": "X", "bundle": "email", "color": "zz"}, format="json").status_code, 400)
        self.client_mock.create_category.assert_not_called()

    def test_create_sends_only_checked_fields(self):
        self.client_mock.create_category.return_value = {"id": 8, "title": "Webinars", "alias": "webinars", "bundle": "email"}
        response = self.api.post(self.url, {"title": " Webinars ", "bundle": "email", "color": "#aabbcc"}, format="json")
        self.assertEqual(response.status_code, 201, response.json())
        self.client_mock.create_category.assert_called_once_with({"title": "Webinars", "bundle": "email", "color": "aabbcc", "isPublished": 1})

    def test_edit_rules(self):
        self.assertEqual(self.api.patch(self.detail(4), {"title": "Mine"}, format="json").status_code, 409)
        self.assertEqual(self.api.patch(self.detail(1), {"bundle": "email"}, format="json").status_code, 400)
        self.assertEqual(self.api.patch(self.detail(1), {"title": "OLD"}, format="json").status_code, 409)
        self.assertEqual(self.api.patch(self.detail(99), {"title": "X"}, format="json").status_code, 404)
        self.client_mock.update_category.return_value = {"id": 1, "title": "Board 2", "alias": "board", "bundle": "segment"}
        response = self.api.patch(self.detail(1), {"title": "Board 2", "isPublished": False}, format="json")
        self.assertEqual(response.status_code, 200, response.json())
        self.client_mock.update_category.assert_called_once_with(1, {"title": "Board 2", "isPublished": 0})

    def test_delete_rules(self):
        self.assertEqual(self.api.delete(self.detail(4)).status_code, 409)
        # Items use it: never deleted, confirmed or not (Mautic refuses too).
        for url in (self.detail(1), self.detail(1) + "?confirm=1"):
            in_use = self.api.delete(url)
            self.assertEqual((in_use.status_code, in_use.json()["code"], in_use.json()["usage"]["items"]), (409, "category_in_use", 3))
        # Only contact preferences: deleted after confirmation.
        prefs = self.api.delete(self.detail(3))
        self.assertEqual((prefs.status_code, prefs.json()["code"]), (409, "category_has_preferences"))
        self.client_mock.delete_category.assert_not_called()
        self.assertEqual(self.api.delete(self.detail(3) + "?confirm=1").status_code, 204)
        self.assertEqual(self.api.delete(self.detail(5)).status_code, 204)  # unused: no confirmation needed
        # Came into use between the check and the delete: reported as in use.
        overviews = iter([OVERVIEW, {**OVERVIEW, "usage": {2: {"items": {"emails": 1}}}}])
        self.client_mock.get_category_overview.side_effect = lambda: next(overviews)
        self.client_mock.delete_category.side_effect = PermanentMauticError("Mautic API request failed (HTTP 500)")
        raced = self.api.delete(self.detail(2))
        self.assertEqual((raced.status_code, raced.json()["code"]), (409, "category_in_use"))
        self.client_mock.get_category_overview.side_effect = PermanentMauticError("Mautic API request failed (HTTP 404)")
        self.assertEqual(self.api.delete(self.detail(2) + "?confirm=1").status_code, 502)

    def test_refused_to_non_marketing_users(self):
        other = APIClient()
        other.force_authenticate(User.objects.create_user(username="cat-normal", email="cn@example.test", password="x"))
        self.assertEqual(other.get(self.url).status_code, 403)
        self.assertEqual(other.post(self.url, {"title": "X", "bundle": "email"}, format="json").status_code, 403)


@override_settings(**PER_USER_ON)
class CategoryAssertedWriteTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="cat-asserted", email="cat-asserted@example.test", password="x")
        grant_marketing_access(self.admin, mautic_user_id=6)
        self.api.force_authenticate(self.admin)
        self.service = mock_client()
        self.asserted = Mock(name="asserted")
        self.asserted._uses_asserted_user.return_value = True
        self.asserted.last_assertion_jti = "jti"
        self.asserted.create_category.return_value = {"id": 8, "title": "Webinars", "alias": "webinars", "bundle": "email"}

        def factory(*args, **kwargs):
            if kwargs.get("assertion_provider") is not None:
                self.asserted.execution_identity = kwargs["execution_identity"]
                return self.asserted
            return self.service

        for target in ("newsletter.mautic_category_views.MauticClient", "newsletter.mautic_category_services.MauticClient"):
            patcher = patch(target, side_effect=factory)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_create_runs_as_the_admin_and_is_audited(self):
        response = self.api.post(reverse("newsletter-admin-mautic-category-list"), {"title": "Webinars", "bundle": "email"}, format="json")
        self.assertEqual(response.status_code, 201, response.json())
        self.asserted.create_category.assert_called_once()
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual((entry.action, entry.resource_id, entry.status, entry.mautic_user_id), (CATEGORY_CREATE, "8", "succeeded", 6))


@override_settings(ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False)
class SegmentSettingsTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="seg-admin", email="seg-admin@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api.force_authenticate(self.admin)
        self.client_mock = mock_client()
        for target in ("newsletter.admin_views.MauticClient", "newsletter.mautic_category_services.MauticClient",
                       "newsletter.mautic_identity_execution.MauticClient"):
            patcher = patch(target, return_value=self.client_mock)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client_mock.get_segment.return_value = segment()
        self.client_mock.get_segment_usage.return_value = NO_USAGE

    def detail(self, segment_id=9):
        return reverse("newsletter-admin-mautic-segment-detail", args=[segment_id])

    def test_detail_shows_the_new_settings(self):
        self.client_mock.get_segment.return_value = segment(category={"id": 1, "title": "Board", "alias": "board", "color": "4E5D9D"})
        body = self.api.get(self.detail()).json()
        self.assertEqual((body["publicName"], body["isGlobal"], body["isPreferenceCenter"], body["category"]["id"], body["protected"]),
                         ("Board", True, True, 1, False))

    def test_settings_are_checked_and_saved(self):
        self.client_mock.update_segment.return_value = segment()
        response = self.api.patch(self.detail(), {"publicName": " Public ", "isGlobal": False, "isPreferenceCenter": True, "category": 1},
                                  format="json")
        self.assertEqual(response.status_code, 200, response.json())
        self.client_mock.update_segment.assert_called_once_with("9", {"publicName": "Public", "isGlobal": False,
                                                                      "isPreferenceCenter": True, "category": 1})
        for category in (4, 3, 5):
            with self.subTest(category=category):
                self.assertEqual(self.api.patch(self.detail(), {"category": category}, format="json").status_code, 400)
        cleared = self.api.patch(self.detail(), {"category": None}, format="json")
        self.assertEqual(cleared.status_code, 200)
        self.assertIsNone(self.client_mock.update_segment.call_args.args[1]["category"])

    def test_consent_gate_and_subscription_list_segments_stay_protected(self):
        self.client_mock.get_segment.return_value = segment(category={"id": 4, "title": "x", "alias": "ecp-subscription-lists"})
        self.assertTrue(self.api.get(self.detail()).json()["protected"])
        for call in (lambda: self.api.patch(self.detail(), {"name": "x"}, format="json"), lambda: self.api.delete(self.detail()),
                     lambda: self.api.post(reverse("newsletter-admin-mautic-segment-duplicate", args=[9]), {}, format="json")):
            self.assertEqual(call().status_code, 409)
        NewsletterCategory.objects.create(name="News", slug="news", mautic_segment_id="9")
        self.client_mock.get_segment.return_value = segment()
        self.assertEqual(self.api.post(reverse("newsletter-admin-mautic-segment-duplicate", args=[9]), {}, format="json").status_code, 409)
        self.client_mock.update_segment.assert_not_called()
        self.client_mock.delete_segment.assert_not_called()
        self.client_mock.create_segment.assert_not_called()

    def test_a_segment_in_use_is_not_deleted(self):
        used = {"total": 2, "usage": {**NO_USAGE["usage"], "campaigns": [{"id": 3, "name": "Welcome", "roles": ["condition"]}],
                                      "emails": [{"id": 5, "name": "News", "roles": ["excludes"]}]}}
        self.client_mock.get_segment_usage.return_value = used
        response = self.api.delete(self.detail())
        self.assertEqual((response.status_code, response.json()["code"]), (409, "segment_in_use"))
        self.assertEqual(response.json()["usage"]["campaigns"][0]["roles"], ["condition"])
        self.client_mock.delete_segment.assert_not_called()
        self.client_mock.get_segment_usage.return_value = NO_USAGE
        self.client_mock.delete_segment.return_value = {}
        self.assertEqual(self.api.delete(self.detail()).status_code, 204)

    def test_usage_links_emails_to_their_broadcast(self):
        broadcast = NewsletterCampaign.objects.create(name="Nov news", mautic_email_id="5")
        self.client_mock.get_segment_usage.return_value = {"total": 1, "usage": {**NO_USAGE["usage"],
                                                                                 "emails": [{"id": 5, "name": "News", "roles": ["sends_to"]}]}}
        body = self.api.get(reverse("newsletter-admin-mautic-segment-usage", args=[9])).json()
        self.assertEqual(body["usage"]["emails"][0]["broadcast_uuid"], str(broadcast.uuid))

    def test_duplicate_copies_like_native_clone(self):
        filters = [{"glue": "and", "field": "city", "object": "lead", "type": "text", "operator": "=", "properties": {"filter": "Bonn"}}]
        self.client_mock.get_segment.return_value = segment(filters=filters, category={"id": 1, "title": "Board", "alias": "board"})
        self.client_mock.create_segment.return_value = segment(id=10, name="Copy")
        response = self.api.post(reverse("newsletter-admin-mautic-segment-duplicate", args=[9]), {"name": "Board copy"}, format="json")
        self.assertEqual(response.status_code, 201, response.json())
        payload = self.client_mock.create_segment.call_args.args[0]
        self.assertEqual((payload["name"], payload["publicName"], payload["isPublished"], payload["isPreferenceCenter"], payload["category"]),
                         ("Board copy", "Board copy", False, False, 1))
        self.assertEqual(payload["filters"][0]["properties"]["filter"], "Bonn")
        self.assertNotIn("alias", payload)
        # A static source gives a static copy; the default name says it is a copy.
        self.client_mock.get_segment.return_value = segment()
        self.api.post(reverse("newsletter-admin-mautic-segment-duplicate", args=[9]), {}, format="json")
        payload = self.client_mock.create_segment.call_args.args[0]
        self.assertEqual((payload["name"], payload["filters"]), ("Copy of Board Targeting", []))
