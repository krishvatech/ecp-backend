"""Phase 3: mapping management, error classification, audit trail, diagnostics."""

import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status as http_status
from rest_framework.test import APIClient

from newsletter.mautic.exceptions import (
    MauticActorRequiredError,
    MauticBridgeRejectedError,
    MauticIdentityAssertionError,
    MauticIdentityConfigurationError,
    MauticIdentityError,
    MauticUserConnectionInactiveError,
    MauticUserConnectionMissingError,
)
from newsletter.mautic.client import ECP_CORRELATION_HEADER, ECP_IDENTITY_ASSERTION_HEADER
from newsletter.mautic.identity import MauticExecutionContext, get_mautic_client
from newsletter.mautic_identity_audit import (
    CORRELATION_HEADER,
    correlation_id_for_request,
    record_identity_audit,
)
from newsletter.mautic_identity_errors import classify_identity_error
from newsletter.mautic_identity_services import (
    VerifiedMauticUser,
    activate_mautic_user_connection,
    deactivate_mautic_user_connection,
)
from newsletter.models import MauticIdentityAuditLog, MauticUserConnection
from newsletter.tests.test_mautic_per_user_execution import (
    PER_USER_OFF,
    PER_USER_ON,
    _SessionRecorder,
)
from newsletter.tests.test_mautic_user_identity import MAUTIC_SETTINGS, _IdentityFixtures

User = get_user_model()


def _campaign_fixtures():
    from newsletter.tests.test_admin_mautic_campaigns_api import (
        NewsletterAdminMauticCampaignsAPITests as fixtures,
    )

    return fixtures._create_payload(), fixtures._builder_capabilities()


def _verified_mautic_user(
    mautic_user_id=21,
    username="canonical-ravi",
    email="canonical-ravi@mautic.test",
    display_name="Canonical Ravi",
    role_name="Marketing Admin",
):
    return VerifiedMauticUser(
        mautic_user_id=mautic_user_id,
        username=username,
        email=email,
        display_name=display_name,
        role_name=role_name,
        is_active=True,
    )


class MauticConnectionManagementApiTests(_IdentityFixtures, TestCase):
    def setUp(self):
        super().setUp()
        self.superuser = User.objects.create_superuser(
            username="identity-superuser",
            email="identity-superuser@example.test",
            password="test-password",
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        self.list_url = reverse("newsletter-admin-mautic-connection-list")

    def _detail_url(self, name, connection):
        return reverse(name, kwargs={"connection_id": connection.pk})

    def test_admin_endpoints_require_superuser(self):
        anonymous = APIClient()
        connection = self._active_connection(mautic_user_id=17)
        urls = [
            (self.list_url, "get"),
            (self.list_url, "post"),
            (self._detail_url("newsletter-admin-mautic-connection-detail", connection), "get"),
            (self._detail_url("newsletter-admin-mautic-connection-activate", connection), "post"),
            (self._detail_url("newsletter-admin-mautic-connection-deactivate", connection), "post"),
            (reverse("newsletter-admin-mautic-identity-audit"), "get"),
        ]

        for url, method in urls:
            with self.subTest(url=url):
                self.assertIn(getattr(anonymous, method)(url).status_code, (401, 403))

        self.client.force_authenticate(user=self.normal_user)
        for url, method in urls:
            with self.subTest(url=url, user="non-staff"):
                self.assertEqual(getattr(self.client, method)(url).status_code, 403)

        self.client.force_authenticate(user=self.staff)
        for url, method in urls:
            with self.subTest(url=url, user="staff"):
                self.assertEqual(getattr(self.client, method)(url).status_code, 403)

        self.client.force_authenticate(user=self.superuser)
        self.assertEqual(self.client.get(self.list_url).status_code, 200)

    @patch("newsletter.mautic_identity_services.verify_mautic_user")
    def test_create_connection(self, verify):
        verify.return_value = _verified_mautic_user(mautic_user_id=21)
        response = self.client.post(
            self.list_url,
            {
                "ecp_user_id": self.other_staff.pk,
                "mautic_user_id": 21,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["mautic_user_id"], 21)
        self.assertEqual(response.data["ecp_user_id"], self.other_staff.pk)
        self.assertEqual(response.data["mautic_username"], "canonical-ravi")
        self.assertEqual(response.data["mautic_display_name"], "Canonical Ravi")
        self.assertEqual(response.data["mautic_role_name"], "Marketing Admin")
        self.assertEqual(response.data["status"], "active")
        self.assertTrue(response.data["is_active"])
        self.assertIsNotNone(response.data["connected_at"])
        self.assertIsNotNone(response.data["last_verified_at"])

    def test_create_connection_rejects_caller_supplied_mautic_metadata(self):
        response = self.client.post(
            self.list_url,
            {
                "ecp_user_id": self.other_staff.pk,
                "mautic_user_id": 21,
                "mautic_username": "fake-admin",
                "mautic_role_name": "Super Administrator",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(MauticUserConnection.objects.exists())

    def test_create_connection_rejects_unknown_ecp_user(self):
        response = self.client.post(
            self.list_url,
            {"ecp_user_id": 999999, "mautic_user_id": 21},
            format="json",
        )

        self.assertEqual(response.status_code, 400)

    def test_create_connection_rejects_invalid_mautic_user_id(self):
        for value in (0, -3, 2147483648):
            with self.subTest(value=value):
                response = self.client.post(
                    self.list_url,
                    {"ecp_user_id": self.other_staff.pk, "mautic_user_id": value},
                    format="json",
                )
                self.assertEqual(response.status_code, 400)

    def test_create_connection_rejects_non_staff_target(self):
        response = self.client.post(
            self.list_url,
            {"ecp_user_id": self.normal_user.pk, "mautic_user_id": 21},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "mautic_identity_error")

    @patch("newsletter.mautic_identity_services.verify_mautic_user")
    def test_mautic_user_already_connected_elsewhere_is_reported(self, verify):
        verify.return_value = _verified_mautic_user(mautic_user_id=17)
        self._active_connection(user=self.staff, mautic_user_id=17)

        response = self.client.post(
            self.list_url,
            {"ecp_user_id": self.other_staff.pk, "mautic_user_id": 17},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "mautic_identity_error")
        self.assertIn("already connected to another ECP user", response.data["detail"])

    def test_list_and_filter_connections(self):
        active = self._active_connection(user=self.staff, mautic_user_id=17)
        MauticUserConnection.objects.create(
            user=self.other_staff,
            mautic_user_id=18,
            status=MauticUserConnection.Status.DISABLED,
        )

        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 2)

        filtered = self.client.get(self.list_url, {"is_active": "true"})
        self.assertEqual(filtered.data["count"], 1)
        self.assertEqual(filtered.data["results"][0]["id"], active.pk)

        by_user = self.client.get(self.list_url, {"ecp_user_id": self.other_staff.pk})
        self.assertEqual(by_user.data["count"], 1)

    def test_detail_view(self):
        connection = self._active_connection(mautic_user_id=17)

        response = self.client.get(
            self._detail_url("newsletter-admin-mautic-connection-detail", connection)
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["id"], connection.pk)

    def test_detail_view_missing_connection(self):
        response = self.client.get(
            reverse("newsletter-admin-mautic-connection-detail", kwargs={"connection_id": 999999})
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["code"], "mautic_user_not_connected")

    @patch("newsletter.mautic_identity_services.verify_mautic_user")
    def test_deactivate_then_activate_roundtrip(self, verify):
        verify.return_value = _verified_mautic_user(mautic_user_id=17, username="fresh")
        connection = self._active_connection(mautic_user_id=17)

        deactivated = self.client.post(
            self._detail_url("newsletter-admin-mautic-connection-deactivate", connection),
            {"reason": "offboarded"},
            format="json",
        )
        self.assertEqual(deactivated.status_code, 200)
        self.assertFalse(deactivated.data["is_active"])
        self.assertEqual(deactivated.data["status"], "disabled")

        activated = self.client.post(
            self._detail_url("newsletter-admin-mautic-connection-activate", connection)
        )
        self.assertEqual(activated.status_code, 200)
        self.assertTrue(activated.data["is_active"])
        self.assertEqual(activated.data["status"], "active")

        connection.refresh_from_db()
        self.assertTrue(connection.is_usable)
        self.assertIsNone(connection.disabled_at)
        self.assertEqual(connection.mautic_username, "fresh")
        self.assertIsNotNone(connection.last_verified_at)

    @patch("newsletter.mautic_identity_services.verify_mautic_user")
    def test_activate_is_refused_when_the_user_already_has_another_active_mapping(self, verify):
        verify.return_value = _verified_mautic_user(mautic_user_id=18)
        old = MauticUserConnection.objects.create(
            user=self.staff,
            mautic_user_id=18,
            status=MauticUserConnection.Status.DISABLED,
        )
        self._active_connection(user=self.staff, mautic_user_id=17)

        response = self.client.post(
            self._detail_url("newsletter-admin-mautic-connection-activate", old)
        )

        self.assertEqual(response.status_code, 400)
        old.refresh_from_db()
        self.assertFalse(old.is_active)

    @patch("newsletter.mautic_identity_services.verify_mautic_user")
    def test_activate_is_refused_when_mautic_user_belongs_to_another_ecp_user(self, verify):
        verify.return_value = _verified_mautic_user(mautic_user_id=17)
        disabled = MauticUserConnection.objects.create(
            user=self.other_staff,
            mautic_user_id=17,
            status=MauticUserConnection.Status.DISABLED,
        )
        self._active_connection(user=self.staff, mautic_user_id=17)

        response = self.client.post(
            self._detail_url("newsletter-admin-mautic-connection-activate", disabled)
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("already connected to another ECP user", response.data["detail"])

    def test_responses_never_expose_credentials(self):
        connection = self._active_connection(mautic_user_id=17, mautic_email="ravi@mautic.test")

        body = json.dumps(
            self.client.get(
                self._detail_url("newsletter-admin-mautic-connection-detail", connection)
            ).json()
        )

        for forbidden in ("password", "token", "assertion", "PRIVATE", "ravi@mautic.test"):
            self.assertNotIn(forbidden, body)


class IdentityErrorClassificationTests(TestCase):
    def test_each_condition_has_a_distinct_status_and_code(self):
        cases = {
            MauticUserConnectionMissingError("x"): (409, "mautic_user_not_connected"),
            MauticUserConnectionInactiveError("x"): (409, "mautic_user_connection_inactive"),
            MauticActorRequiredError("x"): (403, "mautic_actor_required"),
            MauticBridgeRejectedError("x"): (403, "mautic_permission_denied"),
            MauticIdentityConfigurationError("x"): (503, "mautic_identity_not_configured"),
            MauticIdentityAssertionError("x"): (503, "mautic_identity_assertion_failed"),
            MauticIdentityError("x"): (400, "mautic_identity_error"),
        }

        for exc, (expected_status, expected_code) in cases.items():
            with self.subTest(exc=type(exc).__name__):
                status_code, code, detail = classify_identity_error(exc)
                self.assertEqual((status_code, code), (expected_status, expected_code))
                self.assertTrue(detail)

    def test_messages_never_echo_provider_internals(self):
        exc = MauticBridgeRejectedError("Mautic API request failed (HTTP 403): secret-detail")

        _, _, detail = classify_identity_error(exc)

        self.assertNotIn("403", detail)
        self.assertNotIn("secret-detail", detail)


@override_settings(**PER_USER_ON)
class CampaignAuditTrailTests(_IdentityFixtures, TestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.staff)
        self.create_url = reverse("newsletter-admin-mautic-campaign-list")
        self.payload, self.capabilities = _campaign_fixtures()

    def _patched_factory(self):
        factory = patch("newsletter.native_campaign_views.get_mautic_client").start()
        self.addCleanup(patch.stopall)
        factory.return_value.get_campaign_builder_capabilities.return_value = self.capabilities
        factory.return_value.execution_identity = Mock(
            mautic_user_id=17,
            auth_mode=Mock(value="asserted_user"),
        )
        return factory

    def test_successful_create_is_audited(self):
        self._active_connection(mautic_user_id=17)
        factory = self._patched_factory()
        factory.return_value.create_campaign.return_value = {"id": 5, "name": "Launch"}

        response = self.client.post(self.create_url, self.payload, format="json")

        self.assertEqual(response.status_code, 201)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.action, MauticIdentityAuditLog.Action.CAMPAIGN_CREATE)
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.SUCCEEDED)
        self.assertEqual(entry.ecp_user, self.staff)
        self.assertEqual(entry.ecp_user_label, self.staff.get_username())
        self.assertEqual(entry.mautic_user_id, 17)
        self.assertEqual(entry.resource, "campaign")
        self.assertEqual(entry.resource_id, "5")
        self.assertEqual(entry.auth_mode, "asserted_user")
        self.assertTrue(entry.correlation_id)

    def test_denied_operation_is_audited(self):
        self._active_connection(mautic_user_id=17)
        factory = self._patched_factory()
        factory.return_value.create_campaign.side_effect = MauticBridgeRejectedError(
            "Mautic API request failed (HTTP 403): Access denied."
        )

        response = self.client.post(self.create_url, self.payload, format="json")

        self.assertEqual(response.status_code, 403)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.DENIED)
        self.assertEqual(entry.error_code, "mautic_permission_denied")
        self.assertEqual(entry.detail, "MauticBridgeRejectedError")

    def test_unmapped_user_is_audited_and_reported_clearly(self):
        response = self.client.post(self.create_url, self.payload, format="json")

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["code"], "mautic_user_not_connected")
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.status, MauticIdentityAuditLog.Status.DENIED)
        self.assertEqual(entry.error_code, "mautic_user_not_connected")
        self.assertIsNone(entry.mautic_user_id)

    def test_audit_records_hold_no_assertion_material(self):
        self._active_connection(mautic_user_id=17)
        factory = self._patched_factory()
        factory.return_value.create_campaign.return_value = {"id": 5}

        self.client.post(self.create_url, self.payload, format="json")

        entry = MauticIdentityAuditLog.objects.get()
        serialized = json.dumps(
            {
                field.name: str(getattr(entry, field.name))
                for field in MauticIdentityAuditLog._meta.fields
            }
        )
        for forbidden in ("eyJ", "PRIVATE", "password", "super-secret"):
            self.assertNotIn(forbidden, serialized)

    @override_settings(**PER_USER_OFF)
    def test_service_account_path_is_still_audited(self):
        factory = self._patched_factory()
        factory.return_value.execution_identity = Mock(
            mautic_user_id=None,
            auth_mode=Mock(value="service_account"),
        )
        factory.return_value.create_campaign.return_value = {"id": 9}

        response = self.client.post(self.create_url, self.payload, format="json")

        self.assertEqual(response.status_code, 201)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual(entry.auth_mode, "service_account")
        self.assertIsNone(entry.mautic_user_id)


class IdentityAuditApiTests(_IdentityFixtures, TestCase):
    def setUp(self):
        super().setUp()
        self.superuser = User.objects.create_superuser(
            username="identity-audit-superuser",
            email="identity-audit-superuser@example.test",
            password="test-password",
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        self.url = reverse("newsletter-admin-mautic-identity-audit")

        record_identity_audit(
            action=MauticIdentityAuditLog.Action.CAMPAIGN_CREATE,
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            actor=self.staff,
            mautic_user_id=17,
            resource="campaign",
            resource_id="5",
            correlation_id="corr-one",
        )
        record_identity_audit(
            action=MauticIdentityAuditLog.Action.CAMPAIGN_UPDATE,
            status=MauticIdentityAuditLog.Status.DENIED,
            actor=self.other_staff,
            mautic_user_id=21,
            resource="campaign",
            resource_id="9",
            correlation_id="corr-two",
            error_code="mautic_permission_denied",
        )

    def test_list_is_newest_first(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 2)
        self.assertEqual(response.data["results"][0]["correlation_id"], "corr-two")

    def test_filters(self):
        for params, expected in (
            ({"ecp_user_id": self.staff.pk}, 1),
            ({"mautic_user_id": 21}, 1),
            ({"action": "campaign.create"}, 1),
            ({"status": "denied"}, 1),
            ({"correlation_id": "corr-one"}, 1),
            ({"correlation_id": "nope"}, 0),
        ):
            with self.subTest(params=params):
                self.assertEqual(self.client.get(self.url, params).data["count"], expected)

    def test_audit_endpoint_is_read_only(self):
        self.assertEqual(self.client.post(self.url, {}, format="json").status_code, 405)
        self.assertEqual(self.client.delete(self.url).status_code, 405)

    def test_audit_write_failure_never_breaks_the_operation(self):
        with patch(
            "newsletter.mautic_identity_audit.MauticIdentityAuditLog.objects.create",
            side_effect=RuntimeError("db down"),
        ):
            entry = record_identity_audit(
                action=MauticIdentityAuditLog.Action.CAMPAIGN_CREATE,
                status=MauticIdentityAuditLog.Status.SUCCEEDED,
                actor=self.staff,
            )

        self.assertIsNone(entry)


class CorrelationIdTests(_IdentityFixtures, TestCase):
    def test_inbound_correlation_id_is_reused_and_sanitised(self):
        request = Mock(headers={CORRELATION_HEADER: "abc-123_XYZ"})
        self.assertEqual(correlation_id_for_request(request), "abc-123_XYZ")

        # Only alphanumerics, "-" and "_" survive sanitising.
        dirty = Mock(headers={CORRELATION_HEADER: "bad/../value;drop"})
        self.assertEqual(correlation_id_for_request(dirty), "badvaluedrop")

        long_value = Mock(headers={CORRELATION_HEADER: "x" * 200})
        self.assertEqual(len(correlation_id_for_request(long_value)), 64)

    def test_missing_correlation_id_is_generated(self):
        generated = correlation_id_for_request(Mock(headers={}))

        self.assertEqual(len(generated), 32)
        self.assertNotEqual(generated, correlation_id_for_request(Mock(headers={})))

    @override_settings(**PER_USER_ON)
    def test_correlation_id_is_sent_on_bridge_requests_only(self):
        self._active_connection(mautic_user_id=17)
        session = _SessionRecorder()

        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=session,
            correlation_id="corr-abc",
        )
        client.create_campaign({"name": "Launch"})
        bridge_call = session.last

        native_session = _SessionRecorder(payload={"campaigns": [], "total": 0})
        native_client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=native_session,
            correlation_id="corr-abc",
        )
        native_client.list_campaigns(limit=1)
        native_call = native_session.last

        self.assertEqual(bridge_call["headers"][ECP_CORRELATION_HEADER], "corr-abc")
        self.assertIn(ECP_IDENTITY_ASSERTION_HEADER, bridge_call["headers"])
        self.assertNotIn(ECP_CORRELATION_HEADER, dict(native_call.get("headers") or {}))


@override_settings(**MAUTIC_SETTINGS)
class IdentityDiagnosticsTests(_IdentityFixtures, TestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.staff)
        self.url = reverse("newsletter-admin-mautic-diagnostics")

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_identity_section_reports_readiness(self, client_cls):
        client_cls.return_value.health_check.return_value = True
        client_cls.return_value.get_marketing_bridge_capabilities.return_value = {
            "capabilities": [],
            "identity": {"ready": True, "publicKeyConfigured": True},
        }
        client_cls.return_value.get_campaign_builder_capabilities.return_value = {
            "actions": [],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }
        self._active_connection(mautic_user_id=17)

        identity = self.client.get(self.url).data["identity"]

        self.assertFalse(identity["per_user_execution_enabled"])
        self.assertFalse(identity["signing_configured"])
        self.assertEqual(identity["active_connections"], 1)
        self.assertTrue(identity["current_user_connected"])
        self.assertEqual(identity["mautic_identity"], {"ready": True, "publicKeyConfigured": True})

    @override_settings(**PER_USER_ON)
    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_warnings_when_flag_is_on_without_connections(self, client_cls):
        client_cls.return_value.health_check.return_value = True
        client_cls.return_value.get_marketing_bridge_capabilities.return_value = {"capabilities": []}
        client_cls.return_value.get_campaign_builder_capabilities.return_value = {
            "actions": [],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }

        response = self.client.get(self.url)
        identity = response.data["identity"]

        self.assertTrue(identity["per_user_execution_enabled"])
        self.assertEqual(identity["active_connections"], 0)
        self.assertEqual(identity["status"], "Degraded")
        self.assertTrue(any("no Mautic user connections" in w for w in identity["warnings"]))
        self.assertIn(identity["warnings"][0], response.data["diagnostics"]["warnings"])

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_diagnostics_never_expose_key_material(self, client_cls):
        client_cls.return_value.health_check.return_value = True
        client_cls.return_value.get_marketing_bridge_capabilities.return_value = {"capabilities": []}
        client_cls.return_value.get_campaign_builder_capabilities.return_value = {
            "actions": [],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }

        body = json.dumps(self.client.get(self.url).json())

        for forbidden in ("PRIVATE KEY", "super-secret", "BEGIN", "eyJ"):
            self.assertNotIn(forbidden, body)


class ConnectionServiceTests(_IdentityFixtures, TestCase):
    def _verified(self, mautic_user_id=17, username="verified"):
        return VerifiedMauticUser(
            mautic_user_id=mautic_user_id,
            username=username,
            email=f"{username}@mautic.test",
            display_name="Verified User",
            role_name="Marketing",
            is_active=True,
        )

    def test_activate_is_idempotent(self):
        connection = self._active_connection(mautic_user_id=17)

        again = activate_mautic_user_connection(connection)

        self.assertTrue(again.is_usable)

    def test_deactivate_is_idempotent(self):
        connection = self._active_connection(mautic_user_id=17)

        deactivate_mautic_user_connection(connection, reason="first")
        second = deactivate_mautic_user_connection(connection, reason="second")

        self.assertFalse(second.is_active)
        self.assertEqual(second.last_error, "first")

    def test_activate_requires_marketing_hub_access(self):
        connection = MauticUserConnection.objects.create(
            user=self.staff,
            mautic_user_id=17,
            status=MauticUserConnection.Status.DISABLED,
        )
        self.staff.is_staff = False
        self.staff.save(update_fields=["is_staff"])
        connection.refresh_from_db()

        with patch(
            "newsletter.mautic_identity_services.verify_mautic_user",
            return_value=self._verified(),
        ):
            with self.assertRaises(MauticIdentityError):
                activate_mautic_user_connection(connection)

    def test_missing_connection_raises_identity_error(self):
        connection = self._active_connection(mautic_user_id=17)
        MauticUserConnection.objects.filter(pk=connection.pk).delete()

        with self.assertRaises(MauticUserConnectionMissingError):
            activate_mautic_user_connection(connection)


class IdentityStatusTruthfulnessTests(_IdentityFixtures, TestCase):
    """The status endpoint must describe the live decision, not Phase 1 defaults."""

    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.staff)
        self.url = reverse("newsletter-admin-mautic-identity-status")

    @override_settings(**PER_USER_OFF)
    def test_flag_off_reports_the_service_account(self):
        self._active_connection(mautic_user_id=17)

        data = self.client.get(self.url).data

        self.assertFalse(data["per_user_execution_enabled"])
        self.assertEqual(data["auth_mode"], "service_account")
        self.assertEqual(data["interactive_blocked_code"], "")

    @override_settings(**PER_USER_ON)
    def test_flag_on_with_a_mapping_reports_asserted_user(self):
        self._active_connection(mautic_user_id=17)

        data = self.client.get(self.url).data

        self.assertTrue(data["per_user_execution_enabled"])
        self.assertEqual(data["auth_mode"], "asserted_user")
        self.assertEqual(data["interactive_blocked_code"], "")

    @override_settings(**PER_USER_ON)
    def test_flag_on_without_a_mapping_reports_the_blocking_reason(self):
        data = self.client.get(self.url).data

        self.assertTrue(data["per_user_execution_enabled"])
        # Fail closed: there is no auth mode this user could act under.
        self.assertIsNone(data["auth_mode"])
        self.assertEqual(data["interactive_blocked_code"], "mautic_user_not_connected")

    @override_settings(**PER_USER_ON)
    def test_flag_on_with_a_disabled_mapping_is_distinguishable(self):
        connection = self._active_connection(mautic_user_id=17)
        deactivate_mautic_user_connection(connection, reason="revoked")

        data = self.client.get(self.url).data

        self.assertIsNone(data["auth_mode"])
        self.assertEqual(
            data["interactive_blocked_code"],
            "mautic_user_connection_inactive",
        )

    @override_settings(**{**PER_USER_ON, "ECP_MAUTIC_IDENTITY_PRIVATE_KEY": ""})
    def test_flag_on_without_signing_reports_a_configuration_problem(self):
        self._active_connection(mautic_user_id=17)

        data = self.client.get(self.url).data

        self.assertFalse(data["identity_signing_configured"])
        self.assertIsNone(data["auth_mode"])
        self.assertEqual(
            data["interactive_blocked_code"],
            "mautic_identity_not_configured",
        )
