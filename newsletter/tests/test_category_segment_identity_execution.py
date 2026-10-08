"""Asserted-user execution for Subscription List (NewsletterCategory) segment writes.

Creating, editing, archiving and syncing a Subscription List are human actions
in the Marketing Hub. With per-user execution on, the Mautic segment writes they
cause must run as the acting user's mapped Mautic user, through the bridge, bound
to the right operation, and be audited. A refusal must never be retried as the
service account.

Only the HTTP session is faked: identity resolution, RS256 signing, the client's
bridge routing and the audit helper all run for real.
"""

import json
from unittest.mock import Mock, patch

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic.client import ECP_IDENTITY_ASSERTION_HEADER, MauticClient
from newsletter.mautic.operations import SEGMENT_CREATE, SEGMENT_UPDATE
from newsletter.models import MauticIdentityAuditLog, MauticUserConnection, NewsletterCategory
from newsletter.tests.test_mautic_per_user_execution import PER_USER_OFF, PER_USER_ON
from newsletter.tests.test_mautic_user_identity import PUBLIC_KEY

User = get_user_model()

MAUTIC_USER_ID = 23
BASE = "https://mautic.example.test/api/"


def _form(payload):
    """The exact form encoding the client sends for a segment payload."""
    return MauticClient._segment_form_data(payload)


def _response(status_code=200, payload=None):
    response = Mock(status_code=status_code)
    response.json.return_value = payload if payload is not None else {}
    response.text = json.dumps(payload or {})
    response.headers = {}
    return response


class FakeMautic:
    """Answers the Mautic REST/bridge calls a Subscription List makes."""

    def __init__(self, *, existing=None, bridge_status=200):
        self.calls = []
        self.existing = existing or {}
        self.bridge_status = bridge_status

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        path = url[len(BASE):]
        if method == "GET" and path == "segments":
            return _response(payload={"lists": {}})
        if method == "GET" and path.startswith("segments/"):
            segment_id = path.split("/")[1]
            if segment_id in self.existing:
                return _response(payload={"list": self.existing[segment_id]})
            return _response(404, {"errors": [{"message": "Item was not found."}]})
        bridged = path.startswith("ecp/bridge/segments/")
        if bridged or path == "segments/new" or (path.startswith("segments/") and path.endswith("/edit")):
            if bridged and self.bridge_status != 200:
                return _response(self.bridge_status, {"errors": [{"message": "Access denied."}]})
            segment_id = 501 if path.endswith("/new") else int(path.rstrip("/").split("/")[-2])
            return _response(payload={"list": {"id": segment_id, "filters": []}})
        return _response(500, {"errors": [{"message": f"unexpected {method} {path}"}]})

    def writes(self):
        return [call for call in self.calls if call["method"] != "GET"]


class _CategoryFixtures:
    def setUp(self):
        self.client = APIClient()
        self.actor = User.objects.create_user(
            username="list-actor",
            email="list-actor@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        self.connection = MauticUserConnection.objects.create(
            user=self.actor,
            mautic_user_id=MAUTIC_USER_ID,
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
        )
        self.client.force_authenticate(user=self.actor)
        self.category = NewsletterCategory.objects.create(
            name="Deal Alerts",
            slug="deal-alerts",
            description="Weekly deals",
            is_active=True,
            mautic_segment_id="300",
        )
        self.existing_segment = {"id": 300, "name": "Deal Alerts", "alias": "deal-alerts", "filters": []}

    def _run(self, method, url, data=None, *, mautic=None):
        mautic = mautic or FakeMautic(existing={"300": self.existing_segment})

        def factory(*args, **kwargs):
            kwargs["session"] = mautic
            return MauticClient(*args, **kwargs)

        with patch("newsletter.admin_views.MauticClient", side_effect=factory):
            response = getattr(self.client, method)(url, data=data or {}, format="json")
        return response, mautic

    def _assert_asserted_write(self, call, *, method, path, operation):
        self.assertEqual(call["method"], method)
        self.assertEqual(call["url"], f"{BASE}{path}")
        token = call["headers"][ECP_IDENTITY_ASSERTION_HEADER]
        claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], audience="ecp-mautic")
        self.assertEqual(claims["operation"], operation)
        self.assertEqual(claims["mautic_user_id"], MAUTIC_USER_ID)
        self.assertEqual(claims["sub"], str(self.actor.pk))

    def _audit(self):
        return MauticIdentityAuditLog.objects.filter(resource="newsletter_category").latest("id")


@override_settings(**PER_USER_ON, MAUTIC_SYNC_ENABLED=True)
class CategorySegmentAssertedExecutionTests(_CategoryFixtures, TestCase):
    def test_create_writes_the_segment_as_the_mapped_user(self):
        response, mautic = self._run(
            "post", reverse("newsletter-admin-category-list"), {"name": "Pipeline Weekly"}
        )

        self.assertEqual(response.status_code, 201, response.data)
        writes = mautic.writes()
        self.assertEqual(len(writes), 1)
        self._assert_asserted_write(
            writes[0], method="POST", path="ecp/bridge/segments/new", operation=SEGMENT_CREATE
        )
        self.assertIn(("alias", "pipeline-weekly"), writes[0]["data"])
        category = NewsletterCategory.objects.get(slug="pipeline-weekly")
        self.assertEqual(category.mautic_segment_id, "501")

        entry = self._audit()
        self.assertEqual(entry.action, SEGMENT_CREATE)
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.SUCCEEDED)
        self.assertEqual(entry.ecp_user, self.actor)
        self.assertEqual(entry.mautic_user_id, MAUTIC_USER_ID)
        self.assertEqual(entry.auth_mode, "asserted_user")
        self.assertEqual(entry.resource_id, "pipeline-weekly")
        self.assertTrue(entry.assertion_jti)

    def test_edit_updates_the_segment_as_the_mapped_user(self):
        response, mautic = self._run(
            "patch",
            reverse("newsletter-admin-category-detail", args=[self.category.slug]),
            {"name": "Deal Alerts Weekly"},
        )

        self.assertEqual(response.status_code, 200, response.data)
        writes = mautic.writes()
        self.assertEqual(len(writes), 1)
        self._assert_asserted_write(
            writes[0], method="PATCH", path="ecp/bridge/segments/300/edit", operation=SEGMENT_UPDATE
        )
        self.assertIn(("name", "Deal Alerts Weekly"), writes[0]["data"])
        entry = self._audit()
        self.assertEqual((entry.action, entry.status, entry.auth_mode), (SEGMENT_UPDATE, "succeeded", "asserted_user"))

    def test_archive_unpublishes_the_segment_as_the_mapped_user(self):
        response, mautic = self._run(
            "delete", reverse("newsletter-admin-category-detail", args=[self.category.slug])
        )

        self.assertEqual(response.status_code, 204)
        writes = mautic.writes()
        self.assertEqual(len(writes), 1)
        self._assert_asserted_write(
            writes[0], method="PATCH", path="ecp/bridge/segments/300/edit", operation=SEGMENT_UPDATE
        )
        self.assertEqual(writes[0]["data"], _form({"isPublished": False}))
        self.category.refresh_from_db()
        self.assertFalse(self.category.is_active)
        self.assertEqual(self._audit().action, SEGMENT_UPDATE)

    def test_sync_of_a_mapped_list_updates_the_segment_as_the_mapped_user(self):
        response, mautic = self._run(
            "post", reverse("newsletter-admin-category-sync-mautic", args=[self.category.slug])
        )

        self.assertEqual(response.status_code, 200, response.data)
        writes = mautic.writes()
        self.assertEqual(len(writes), 1)
        self._assert_asserted_write(
            writes[0], method="PATCH", path="ecp/bridge/segments/300/edit", operation=SEGMENT_UPDATE
        )
        self.assertEqual(self._audit().action, SEGMENT_UPDATE)

    def test_sync_of_an_unmapped_list_creates_the_segment_as_the_mapped_user(self):
        self.category.mautic_segment_id = ""
        self.category.save(update_fields=["mautic_segment_id"])

        response, mautic = self._run(
            "post", reverse("newsletter-admin-category-sync-mautic", args=[self.category.slug])
        )

        self.assertEqual(response.status_code, 200, response.data)
        writes = mautic.writes()
        self.assertEqual(len(writes), 1)
        self._assert_asserted_write(
            writes[0], method="POST", path="ecp/bridge/segments/new", operation=SEGMENT_CREATE
        )
        self.category.refresh_from_db()
        self.assertEqual(self.category.mautic_segment_id, "501")
        self.assertEqual(self._audit().action, SEGMENT_CREATE)

    def test_mautic_permission_denial_rolls_back_and_never_falls_back(self):
        response, mautic = self._run(
            "post",
            reverse("newsletter-admin-category-list"),
            {"name": "Denied List"},
            mautic=FakeMautic(bridge_status=403),
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["code"], "mautic_permission_denied")
        # One bridge attempt, no service-account retry, no local row left behind.
        writes = mautic.writes()
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["url"], f"{BASE}ecp/bridge/segments/new")
        self.assertFalse(NewsletterCategory.objects.filter(slug="denied-list").exists())
        entry = self._audit()
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.DENIED)
        self.assertEqual(entry.mautic_user_id, MAUTIC_USER_ID)
        self.assertEqual(entry.auth_mode, "asserted_user")
        self.assertEqual(entry.error_code, "mautic_permission_denied")

    def test_denied_archive_keeps_the_list_active(self):
        response, _ = self._run(
            "delete",
            reverse("newsletter-admin-category-detail", args=[self.category.slug]),
            mautic=FakeMautic(existing={"300": self.existing_segment}, bridge_status=403),
        )

        self.assertEqual(response.status_code, 403)
        self.category.refresh_from_db()
        self.assertTrue(self.category.is_active)

    def test_inactive_mapping_is_refused_before_any_mautic_write(self):
        self.connection.is_active = False
        self.connection.status = MauticUserConnection.Status.DISABLED
        self.connection.save(update_fields=["is_active", "status"])

        response, mautic = self._run(
            "post", reverse("newsletter-admin-category-list"), {"name": "No Mapping"}
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(mautic.calls, [])
        self.assertFalse(NewsletterCategory.objects.filter(slug="no-mapping").exists())

    @override_settings(ECP_MAUTIC_IDENTITY_PRIVATE_KEY="")
    def test_missing_signing_configuration_fails_closed(self):
        response, mautic = self._run(
            "post", reverse("newsletter-admin-category-list"), {"name": "Unsigned"}
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data["code"], "mautic_identity_not_configured")
        self.assertEqual(mautic.calls, [])
        self.assertFalse(NewsletterCategory.objects.filter(slug="unsigned").exists())
        self.assertEqual(self._audit().error_code, "mautic_identity_not_configured")


@override_settings(**PER_USER_OFF, MAUTIC_SYNC_ENABLED=True)
class CategorySegmentServiceAccountWhenFlagOffTests(_CategoryFixtures, TestCase):
    def test_flag_off_keeps_the_plain_service_account_routes(self):
        response, mautic = self._run(
            "post", reverse("newsletter-admin-category-list"), {"name": "Flag Off"}
        )

        self.assertEqual(response.status_code, 201, response.data)
        writes = mautic.writes()
        self.assertEqual([(w["method"], w["url"]) for w in writes], [("POST", f"{BASE}segments/new")])
        self.assertNotIn(ECP_IDENTITY_ASSERTION_HEADER, writes[0].get("headers") or {})
        self.assertEqual(self._audit().auth_mode, "service_account")
