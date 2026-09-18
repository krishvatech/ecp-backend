"""Phase 2: per-user interactive Mautic execution (feature flagged)."""

import logging
from unittest.mock import Mock, patch

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import MauticClient, get_mautic_client
from newsletter.mautic.client import ECP_IDENTITY_ASSERTION_HEADER
from newsletter.mautic.exceptions import (
    MauticBridgeRejectedError,
    MauticIdentityConfigurationError,
    MauticUserConnectionInactiveError,
    MauticUserConnectionMissingError,
    PermanentMauticError,
    TemporaryMauticError,
)
from newsletter.mautic.identity import (
    MauticAuthMode,
    MauticExecutionContext,
    _auth_mode_for,
    per_user_execution_enabled,
    resolve_mautic_execution_identity,
)
from newsletter.mautic_identity_audit import CORRELATION_HEADER
from newsletter.models import MauticIdentityAuditLog, MauticUserConnection
from newsletter.tests.test_mautic_user_identity import (
    IDENTITY_SETTINGS,
    MAUTIC_SETTINGS,
    PUBLIC_KEY,
    SIGNING_KEY_PEM,
    _IdentityFixtures,
)


User = get_user_model()

PER_USER_ON = {**IDENTITY_SETTINGS, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": True}
PER_USER_OFF = {**IDENTITY_SETTINGS, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": False}


def _campaign_fixtures():
    from newsletter.tests.test_admin_mautic_campaigns_api import (
        NewsletterAdminMauticCampaignsAPITests as fixtures,
    )

    return fixtures._create_payload(), fixtures._builder_capabilities()


def _response(status_code=200, payload=None):
    response = Mock(status_code=status_code)
    response.json.return_value = payload if payload is not None else {"campaign": {"id": 5}}
    return response


class _SessionRecorder:
    """Minimal requests.Session stand-in that records outbound calls."""

    def __init__(self, status_code=200, payload=None):
        self.calls = []
        self._status_code = status_code
        self._payload = payload

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return _response(self._status_code, self._payload)

    @property
    def last(self):
        return self.calls[-1]


class MauticAuthModeResolutionTests(_IdentityFixtures, TestCase):
    @override_settings(**PER_USER_OFF)
    def test_flag_defaults_and_reads_from_settings(self):
        self.assertFalse(per_user_execution_enabled())

        with override_settings(**PER_USER_ON):
            self.assertTrue(per_user_execution_enabled())

    @override_settings(**PER_USER_OFF)
    def test_flag_off_keeps_service_account_for_mapped_interactive_user(self):
        self._active_connection(mautic_user_id=17)

        identity = resolve_mautic_execution_identity(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
        )

        self.assertIs(identity.auth_mode, MauticAuthMode.SERVICE_ACCOUNT)
        self.assertEqual(identity.mautic_user_id, 17)

    @override_settings(**PER_USER_ON)
    def test_flag_on_with_mapping_resolves_asserted_user(self):
        self._active_connection(mautic_user_id=17)

        identity = resolve_mautic_execution_identity(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
        )

        self.assertIs(identity.auth_mode, MauticAuthMode.ASSERTED_USER)
        self.assertEqual(identity.mautic_user_id, 17)

    @override_settings(**PER_USER_ON)
    def test_flag_on_without_mapping_fails_closed(self):
        """A human action must never silently run as the service account."""
        with self.assertLogs("newsletter.mautic.identity", level="WARNING") as captured:
            with self.assertRaises(MauticUserConnectionMissingError):
                resolve_mautic_execution_identity(
                    actor=self.staff,
                    purpose=MauticExecutionContext.INTERACTIVE,
                )

        self.assertIn("refusing", "\n".join(captured.output))

    @override_settings(**PER_USER_ON)
    def test_flag_on_with_inactive_mapping_fails_closed(self):
        MauticUserConnection.objects.create(
            user=self.staff,
            mautic_user_id=17,
            status=MauticUserConnection.Status.DISABLED,
        )

        with self.assertRaises(MauticUserConnectionInactiveError):
            resolve_mautic_execution_identity(
                actor=self.staff,
                purpose=MauticExecutionContext.INTERACTIVE,
            )

    @override_settings(**{**PER_USER_ON, "ECP_MAUTIC_IDENTITY_PRIVATE_KEY": ""})
    def test_flag_on_without_signing_configuration_fails_closed(self):
        self._active_connection(mautic_user_id=17)

        with self.assertLogs("newsletter.mautic.identity", level="ERROR") as captured:
            with self.assertRaises(MauticIdentityConfigurationError):
                resolve_mautic_execution_identity(
                    actor=self.staff,
                    purpose=MauticExecutionContext.INTERACTIVE,
                )

        self.assertIn("identity signing is not configured", "\n".join(captured.output))

    @override_settings(**PER_USER_ON)
    def test_client_factory_also_fails_closed_for_unmapped_interactive_user(self):
        with self.assertRaises(MauticUserConnectionMissingError):
            get_mautic_client(actor=self.staff, purpose=MauticExecutionContext.INTERACTIVE)

    @override_settings(**PER_USER_ON)
    def test_auth_mode_decision_point_requires_a_mapped_user(self):
        # Direct guard for callers that bypass resolve().
        with self.assertRaises(MauticUserConnectionMissingError):
            _auth_mode_for(MauticExecutionContext.INTERACTIVE, mautic_user_id=None)

        self.assertIs(
            _auth_mode_for(MauticExecutionContext.INTERACTIVE, mautic_user_id=17),
            MauticAuthMode.ASSERTED_USER,
        )

    @override_settings(**PER_USER_OFF)
    def test_flag_off_keeps_working_without_a_mapping(self):
        identity = resolve_mautic_execution_identity(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
        )

        self.assertIs(identity.auth_mode, MauticAuthMode.SERVICE_ACCOUNT)
        self.assertIsNone(identity.mautic_user_id)

    @override_settings(**{**PER_USER_OFF, "ECP_MAUTIC_IDENTITY_PRIVATE_KEY": ""})
    def test_flag_off_ignores_missing_signing_configuration(self):
        MauticUserConnection.objects.create(
            user=self.staff,
            mautic_user_id=17,
            status=MauticUserConnection.Status.DISABLED,
        )

        identity = resolve_mautic_execution_identity(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
        )

        self.assertIs(identity.auth_mode, MauticAuthMode.SERVICE_ACCOUNT)

    @override_settings(**PER_USER_ON)
    def test_background_system_and_readonly_never_assert_even_when_mapped(self):
        self._active_connection(mautic_user_id=17)

        for purpose in ("system", "background", "readonly"):
            with self.subTest(purpose=purpose):
                identity = resolve_mautic_execution_identity(actor=self.staff, purpose=purpose)

                self.assertIs(identity.auth_mode, MauticAuthMode.SERVICE_ACCOUNT)
                self.assertIsNone(identity.mautic_user_id)
                self.assertEqual(identity.actor_id, self.staff.pk)

    @override_settings(**PER_USER_ON)
    def test_background_contexts_are_unaffected_by_missing_mapping(self):
        """Fail-closed applies to human work only; jobs must keep running."""
        for purpose in ("system", "background", "readonly"):
            with self.subTest(purpose=purpose):
                identity = resolve_mautic_execution_identity(actor=self.staff, purpose=purpose)

                self.assertIs(identity.auth_mode, MauticAuthMode.SERVICE_ACCOUNT)


class AssertedUserClientTests(_IdentityFixtures, TestCase):
    def _decode(self, token):
        return jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience="ecp-mautic",
            issuer="ecp",
        )

    @override_settings(**PER_USER_ON)
    def test_campaign_create_uses_bridge_with_service_auth_and_assertion(self):
        self._active_connection(mautic_user_id=17)
        session = _SessionRecorder()

        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=session,
        )
        client.create_campaign({"name": "Launch"})

        call = session.last
        self.assertEqual(call["method"], "POST")
        self.assertTrue(call["url"].endswith("/api/ecp/bridge/campaigns/new"))
        # Service credentials are still the transport authentication.
        self.assertEqual(
            (call["auth"].username, call["auth"].password),
            ("api-user", "super-secret"),
        )
        claims = self._decode(call["headers"][ECP_IDENTITY_ASSERTION_HEADER])
        self.assertEqual(claims["sub"], str(self.staff.pk))
        self.assertEqual(claims["mautic_user_id"], 17)
        self.assertEqual(claims["purpose"], "interactive")
        self.assertEqual(claims["operation"], "campaign.create")

    @override_settings(**PER_USER_ON)
    def test_client_exposes_the_jti_of_the_assertion_it_just_sent(self):
        self._active_connection(mautic_user_id=17)
        session = _SessionRecorder()

        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=session,
        )
        self.assertEqual(client.last_assertion_jti, "")

        client.create_campaign({"name": "Launch"})
        first = client.last_assertion_jti
        sent = self._decode(session.last["headers"][ECP_IDENTITY_ASSERTION_HEADER])
        self.assertEqual(first, sent["jti"])

        # Each bridge call mints its own assertion, so the tracked id moves on.
        client.create_campaign({"name": "Second"})
        self.assertNotEqual(client.last_assertion_jti, first)

    @override_settings(**PER_USER_OFF)
    def test_service_account_client_exposes_no_assertion_id(self):
        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=_SessionRecorder(),
        )

        self.assertEqual(client.last_assertion_jti, "")

    @override_settings(**PER_USER_ON)
    def test_campaign_update_uses_bridge_edit_path(self):
        self._active_connection(mautic_user_id=17)
        session = _SessionRecorder()

        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=session,
        )
        client.update_campaign(9, {"name": "Renamed"})

        call = session.last
        self.assertEqual(call["method"], "PATCH")
        self.assertTrue(call["url"].endswith("/api/ecp/bridge/campaigns/9/edit"))
        claims = self._decode(call["headers"][ECP_IDENTITY_ASSERTION_HEADER])
        # Bound to update, so it cannot be replayed against the create route.
        self.assertEqual(claims["operation"], "campaign.update")

    @override_settings(**PER_USER_ON)
    def test_campaign_delete_uses_bridge_delete_path(self):
        self._active_connection(mautic_user_id=17)
        session = _SessionRecorder(payload={"campaign": {"id": None}})

        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=session,
        )
        client.delete_campaign(9)

        call = session.last
        self.assertEqual(call["method"], "DELETE")
        self.assertTrue(call["url"].endswith("/api/ecp/bridge/campaigns/9/delete"))
        claims = self._decode(call["headers"][ECP_IDENTITY_ASSERTION_HEADER])
        self.assertEqual(claims["operation"], "campaign.delete")

    @override_settings(**PER_USER_ON)
    def test_campaign_builder_event_delete_uses_bridge_path(self):
        self._active_connection(mautic_user_id=17)
        session = _SessionRecorder(payload={"deleted": {"id": 26, "campaignId": 7}})

        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=session,
        )
        client.delete_campaign_event(7, 26)

        call = session.last
        self.assertEqual(call["method"], "DELETE")
        self.assertTrue(
            call["url"].endswith("/api/ecp/campaign-builder/campaigns/7/events/26")
        )
        claims = self._decode(call["headers"][ECP_IDENTITY_ASSERTION_HEADER])
        self.assertEqual(claims["operation"], "campaign.event.delete")

    @override_settings(**PER_USER_ON)
    def test_each_bridge_call_mints_a_fresh_single_use_assertion(self):
        self._active_connection(mautic_user_id=17)
        session = _SessionRecorder()

        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=session,
        )
        client.create_campaign({"name": "One"})
        client.create_campaign({"name": "Two"})

        jtis = {
            self._decode(call["headers"][ECP_IDENTITY_ASSERTION_HEADER])["jti"]
            for call in session.calls
        }
        self.assertEqual(len(jtis), 2)

    @override_settings(**PER_USER_ON)
    def test_assertion_is_not_attached_to_other_mautic_endpoints(self):
        self._active_connection(mautic_user_id=17)
        session = _SessionRecorder(payload={"campaigns": [], "total": 0})

        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=session,
        )
        client.list_campaigns(limit=5)

        for call in session.calls:
            self.assertNotIn("/ecp/bridge/", call["url"])
            self.assertNotIn(ECP_IDENTITY_ASSERTION_HEADER, dict(call.get("headers") or {}))

    @override_settings(**PER_USER_OFF)
    def test_flag_off_campaign_create_uses_native_endpoint_without_assertion(self):
        self._active_connection(mautic_user_id=17)
        session = _SessionRecorder()

        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=session,
        )
        client.create_campaign({"name": "Launch"})

        call = session.last
        self.assertTrue(call["url"].endswith("/api/campaigns/new"))
        self.assertNotIn(ECP_IDENTITY_ASSERTION_HEADER, dict(call.get("headers") or {}))

    @override_settings(**PER_USER_OFF)
    def test_direct_client_never_sends_an_assertion(self):
        session = _SessionRecorder()

        MauticClient(session=session).create_campaign({"name": "Launch"})

        self.assertTrue(session.last["url"].endswith("/api/campaigns/new"))
        self.assertIsNone(session.last.get("headers"))

    @override_settings(**PER_USER_ON)
    def test_bridge_rejection_is_raised_as_bridge_error(self):
        self._active_connection(mautic_user_id=17)

        for status_code in (401, 403):
            with self.subTest(status_code=status_code):
                session = _SessionRecorder(
                    status_code=status_code,
                    payload={"errors": [{"message": "Access denied."}]},
                )
                client = get_mautic_client(
                    actor=self.staff,
                    purpose=MauticExecutionContext.INTERACTIVE,
                    session=session,
                )

                with self.assertRaises(MauticBridgeRejectedError):
                    client.create_campaign({"name": "Launch"})

    @override_settings(**PER_USER_ON)
    def test_bridge_unavailable_stays_a_retryable_provider_error(self):
        self._active_connection(mautic_user_id=17)
        session = _SessionRecorder(status_code=503, payload={"errors": [{"message": "unavailable"}]})
        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=session,
        )

        # A bridge outage is provider downtime, not an identity rejection.
        with self.assertRaises(TemporaryMauticError) as ctx:
            client.create_campaign({"name": "Launch"})
        self.assertNotIsInstance(ctx.exception, MauticBridgeRejectedError)

    @override_settings(**PER_USER_ON)
    def test_assertion_and_key_are_never_logged(self):
        self._active_connection(mautic_user_id=17)
        session = _SessionRecorder()

        with self.assertLogs(logging.getLogger(), level="DEBUG") as captured:
            logging.getLogger("newsletter").debug("capture start")
            client = get_mautic_client(
                actor=self.staff,
                purpose=MauticExecutionContext.INTERACTIVE,
                session=session,
            )
            client.create_campaign({"name": "Launch"})

        token = session.last["headers"][ECP_IDENTITY_ASSERTION_HEADER]
        output = "\n".join(captured.output)
        self.assertNotIn(token, output)
        self.assertNotIn(token.split(".")[2], output)
        self.assertNotIn("PRIVATE KEY", output)
        self.assertNotIn(SIGNING_KEY_PEM.splitlines()[1], output)
        self.assertNotIn("super-secret", output)


@override_settings(**PER_USER_ON)
class InteractiveCampaignApiTests(_IdentityFixtures, TestCase):
    # Reuse the payload/capability shapes the existing campaign API tests use,
    # so this suite exercises the real validator. Imported lazily so pytest does
    # not collect the other module's TestCase here.
    CREATE_PAYLOAD, BUILDER_CAPABILITIES = _campaign_fixtures()

    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.staff)
        self.create_url = reverse("newsletter-admin-mautic-campaign-list")
        self.detail_url = reverse(
            "newsletter-admin-mautic-campaign-detail",
            kwargs={"campaign_id": "9"},
        )

    def test_campaign_create_passes_request_user_as_actor(self):
        self._active_connection(mautic_user_id=17)

        with patch("newsletter.native_campaign_views.get_mautic_client") as factory:
            factory.return_value.get_campaign_builder_capabilities.return_value = (
                self.BUILDER_CAPABILITIES
            )
            factory.return_value.create_campaign.return_value = {"id": 5, "name": "Launch"}

            response = self.client.post(self.create_url, self.CREATE_PAYLOAD, format="json")

        self.assertEqual(response.status_code, 201)
        self.assertEqual(factory.call_args.kwargs["actor"], self.staff)
        self.assertIs(
            factory.call_args.kwargs["purpose"],
            MauticExecutionContext.INTERACTIVE,
        )

    def test_campaign_update_passes_request_user_as_actor(self):
        self._active_connection(mautic_user_id=17)

        with patch("newsletter.native_campaign_views.get_mautic_client") as factory:
            factory.return_value.update_campaign.return_value = {"id": 9, "name": "Renamed"}

            response = self.client.patch(self.detail_url, {"name": "Renamed"}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(factory.call_args.kwargs["actor"], self.staff)
        self.assertIs(
            factory.call_args.kwargs["purpose"],
            MauticExecutionContext.INTERACTIVE,
        )

    def test_bridge_rejection_is_reported_as_forbidden(self):
        self._active_connection(mautic_user_id=17)

        with patch("newsletter.native_campaign_views.get_mautic_client") as factory:
            factory.return_value.get_campaign_builder_capabilities.return_value = (
                self.BUILDER_CAPABILITIES
            )
            factory.return_value.create_campaign.side_effect = MauticBridgeRejectedError(
                "Mautic API request failed (HTTP 403): Access denied."
            )

            response = self.client.post(self.create_url, self.CREATE_PAYLOAD, format="json")

        self.assertEqual(response.status_code, 403)
        self.assertNotIn("403", response.data["detail"])
        self.assertNotIn("api-user", str(response.data))

    def test_identity_configuration_failure_is_reported_as_unavailable(self):
        self._active_connection(mautic_user_id=17)

        with patch("newsletter.native_campaign_views.get_mautic_client") as factory:
            factory.side_effect = MauticIdentityConfigurationError("key missing")

            response = self.client.post(self.create_url, self.CREATE_PAYLOAD, format="json")

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("key", response.data["detail"].lower())

    def test_campaign_read_remains_on_the_service_account_but_delete_is_interactive(self):
        self._active_connection(mautic_user_id=17)

        with patch("newsletter.native_campaign_views.MauticClient") as direct_client, patch(
            "newsletter.native_campaign_views.get_mautic_client"
        ) as factory:
            direct_client.return_value.get_campaign.return_value = {"id": 9}
            factory.return_value.delete_campaign.return_value = {}

            self.assertEqual(self.client.get(self.detail_url).status_code, 200)
            self.client.delete(self.detail_url)

        self.assertTrue(direct_client.called)
        self.assertEqual(factory.call_args.kwargs["actor"], self.staff)
        self.assertIs(
            factory.call_args.kwargs["purpose"],
            MauticExecutionContext.INTERACTIVE,
        )

    def test_non_staff_user_is_still_rejected_before_any_identity_work(self):
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.post(self.create_url, self.CREATE_PAYLOAD, format="json")

        self.assertEqual(response.status_code, 403)

    def test_successful_response_echoes_the_inbound_correlation_id(self):
        self._active_connection(mautic_user_id=17)

        with patch("newsletter.native_campaign_views.get_mautic_client") as factory:
            factory.return_value.get_campaign_builder_capabilities.return_value = (
                self.BUILDER_CAPABILITIES
            )
            factory.return_value.create_campaign.return_value = {"id": 5, "name": "Launch"}

            response = self.client.post(
                self.create_url,
                self.CREATE_PAYLOAD,
                format="json",
                headers={CORRELATION_HEADER: "trace-123"},
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response[CORRELATION_HEADER], "trace-123")

    def test_identity_failure_response_also_carries_the_correlation_id(self):
        # The actor holds Marketing access, so the request reaches the view; the
        # identity layer then fails closed and the refusal is still correlatable
        # with the Mautic-side logs.
        self._active_connection(mautic_user_id=17)
        with patch("newsletter.native_campaign_views.get_mautic_client") as factory:
            factory.side_effect = MauticUserConnectionMissingError("not connected")

            response = self.client.post(
                self.create_url,
                self.CREATE_PAYLOAD,
                format="json",
                headers={CORRELATION_HEADER: "trace-456"},
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response[CORRELATION_HEADER], "trace-456")

    def test_audit_row_records_which_assertion_authorised_the_call(self):
        self._active_connection(mautic_user_id=17)

        with patch("newsletter.native_campaign_views.get_mautic_client") as factory:
            client = factory.return_value
            client.get_campaign_builder_capabilities.return_value = self.BUILDER_CAPABILITIES
            client.create_campaign.return_value = {"id": 5, "name": "Launch"}
            client.last_assertion_jti = "jti-abc123"

            response = self.client.post(self.create_url, self.CREATE_PAYLOAD, format="json")

        self.assertEqual(response.status_code, 201)
        entry = MauticIdentityAuditLog.objects.latest("id")
        self.assertEqual(entry.assertion_jti, "jti-abc123")

    def test_audit_row_omits_a_jti_when_no_assertion_was_minted(self):
        self._active_connection(mautic_user_id=17)

        with patch("newsletter.native_campaign_views.get_mautic_client") as factory:
            client = factory.return_value
            client.get_campaign_builder_capabilities.return_value = self.BUILDER_CAPABILITIES
            client.create_campaign.return_value = {"id": 5, "name": "Launch"}
            # A client with no assertion tracking must not leak a Mock repr.
            del client.last_assertion_jti

            response = self.client.post(self.create_url, self.CREATE_PAYLOAD, format="json")

        self.assertEqual(response.status_code, 201)
        self.assertEqual(MauticIdentityAuditLog.objects.latest("id").assertion_jti, "")


@override_settings(**PER_USER_ON)
class BackgroundIsolationTests(_IdentityFixtures, TestCase):
    """Background work must never mint an assertion, even with a mapped actor."""

    def setUp(self):
        super().setUp()
        self._active_connection(mautic_user_id=17)

    def test_background_client_has_no_assertion_provider(self):
        session = _SessionRecorder()

        for purpose in ("background", "system", "readonly"):
            with self.subTest(purpose=purpose):
                client = get_mautic_client(
                    actor=self.staff,
                    purpose=purpose,
                    session=session,
                )
                client.create_campaign({"name": "Queued"})

                self.assertFalse(client._uses_asserted_user())
                self.assertTrue(session.last["url"].endswith("/api/campaigns/new"))
                self.assertNotIn(
                    ECP_IDENTITY_ASSERTION_HEADER,
                    dict(session.last.get("headers") or {}),
                )

    def test_background_modules_do_not_mint_assertions(self):
        with patch("newsletter.mautic.identity_assertion.issue_identity_assertion") as signer:
            for module, target in (
                ("newsletter.processor", "MauticClient"),
                ("newsletter.campaign_send_processor", "MauticClient"),
                ("newsletter.mautic_diagnostics_services", "MauticClient"),
            ):
                with self.subTest(module=module):
                    with patch(f"{module}.{target}") as direct_client:
                        direct_client.return_value.health_check.return_value = True
                        __import__(module)

            signer.assert_not_called()

    def test_background_processors_still_construct_service_clients_directly(self):
        import newsletter.campaign_send_processor as send_processor
        import newsletter.processor as processor
        import newsletter.tasks  # noqa: F401  (imported to prove wiring is untouched)

        for module in (processor, send_processor):
            source = open(module.__file__).read()
            self.assertIn("MauticClient()", source)
            self.assertNotIn("get_mautic_client", source)
            self.assertNotIn("issue_identity_assertion", source)
