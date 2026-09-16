import json
import logging
from datetime import datetime, timezone as dt_timezone
from unittest.mock import Mock, patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import MauticClient, get_mautic_client
from newsletter.mautic.exceptions import (
    MauticActorRequiredError,
    MauticIdentityAssertionError,
    MauticIdentityConfigurationError,
    MauticIdentityError,
    MauticUserConnectionInactiveError,
    MauticUserConnectionMissingError,
)
from newsletter.mautic.identity import (
    MauticAuthMode,
    MauticExecutionContext,
    get_active_mautic_user_connection,
    resolve_mautic_execution_identity,
)
from newsletter.mautic.identity_assertion import (
    ASSERTION_TYPE,
    issue_identity_assertion,
    load_identity_assertion_settings,
)
from newsletter.mautic.operations import CAMPAIGN_CREATE, CAMPAIGN_UPDATE
from newsletter.mautic_identity_services import (
    connect_mautic_user,
    disable_mautic_user_connection,
)
from newsletter.models import MauticUserConnection


User = get_user_model()


def _pem(private_key) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


# Generated per test run; no key material is committed.
_SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SIGNING_KEY_PEM = _pem(_SIGNING_KEY)
PUBLIC_KEY = _SIGNING_KEY.public_key()

MAUTIC_SETTINGS = {
    "MAUTIC_BASE_URL": "https://mautic.example.test",
    "MAUTIC_USERNAME": "api-user",
    "MAUTIC_PASSWORD": "super-secret",
    "MAUTIC_REQUEST_TIMEOUT": 3,
    # Pinned so these suites assert "dormant, unsigned" behaviour
    # deterministically, whatever the developer's own environment configures.
    # IDENTITY_SETTINGS and PER_USER_ON override these where signing and
    # per-user execution are the subject under test.
    "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": False,
    "ECP_MAUTIC_IDENTITY_PRIVATE_KEY": "",
    "ECP_MAUTIC_IDENTITY_KEY_ID": "",
}
IDENTITY_SETTINGS = {
    **MAUTIC_SETTINGS,
    "ECP_MAUTIC_IDENTITY_PRIVATE_KEY": SIGNING_KEY_PEM,
    "ECP_MAUTIC_IDENTITY_KEY_ID": "ecp-test-key-1",
    "ECP_MAUTIC_IDENTITY_ISSUER": "ecp",
    "ECP_MAUTIC_IDENTITY_AUDIENCE": "ecp-mautic",
    "ECP_MAUTIC_IDENTITY_TTL_SECONDS": "90",
}


class _IdentityFixtures:
    def setUp(self):
        self.staff = User.objects.create_user(
            username="identity-staff",
            email="identity-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.other_staff = User.objects.create_user(
            username="identity-staff-2",
            email="identity-staff-2@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="identity-normal",
            email="identity-normal@example.test",
            password="test-password",
        )

    def _active_connection(self, user=None, mautic_user_id=17, **kwargs):
        return MauticUserConnection.objects.create(
            user=user or self.staff,
            mautic_user_id=mautic_user_id,
            mautic_username=kwargs.pop("mautic_username", "ravi"),
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
            **kwargs,
        )


class MauticUserConnectionModelTests(_IdentityFixtures, TestCase):
    def test_create_active_connection(self):
        connection = self._active_connection()

        self.assertTrue(connection.is_usable)
        self.assertEqual(connection.mautic_user_id, 17)
        self.assertEqual(str(connection), f"user:{self.staff.pk} -> mautic-user:17 [active]")

    def test_default_connection_is_pending_and_unusable(self):
        connection = MauticUserConnection.objects.create(user=self.staff, mautic_user_id=5)

        self.assertEqual(connection.status, MauticUserConnection.Status.PENDING)
        self.assertFalse(connection.is_active)
        self.assertFalse(connection.is_usable)

    def test_only_one_active_connection_per_ecp_user(self):
        self._active_connection(mautic_user_id=17)

        with self.assertRaises(IntegrityError), transaction.atomic():
            self._active_connection(mautic_user_id=18)

    def test_only_one_active_connection_per_mautic_user(self):
        self._active_connection(user=self.staff, mautic_user_id=17)

        with self.assertRaises(IntegrityError), transaction.atomic():
            self._active_connection(user=self.other_staff, mautic_user_id=17)

    def test_inactive_history_rows_do_not_conflict(self):
        for mautic_user_id in (17, 17, 18):
            MauticUserConnection.objects.create(
                user=self.staff,
                mautic_user_id=mautic_user_id,
                status=MauticUserConnection.Status.DISABLED,
                is_active=False,
            )
        self._active_connection(mautic_user_id=17)

        self.assertEqual(MauticUserConnection.objects.filter(user=self.staff).count(), 4)

    def test_active_flag_requires_active_status(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            MauticUserConnection.objects.create(
                user=self.staff,
                mautic_user_id=17,
                status=MauticUserConnection.Status.DISABLED,
                is_active=True,
            )

    def test_mautic_user_id_must_be_positive(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            MauticUserConnection.objects.create(user=self.staff, mautic_user_id=0)


class MauticUserConnectionServiceTests(_IdentityFixtures, TestCase):
    def test_connect_creates_active_connection(self):
        connection = connect_mautic_user(
            self.staff,
            mautic_user_id=17,
            mautic_username="ravi",
            mautic_email="ravi@mautic.example.test",
            created_by=self.other_staff,
        )

        self.assertTrue(connection.is_usable)
        self.assertEqual(connection.created_by, self.other_staff)
        self.assertIsNotNone(connection.connected_at)

    def test_reconnect_to_different_mautic_user_disables_previous_row(self):
        first = connect_mautic_user(self.staff, mautic_user_id=17)
        second = connect_mautic_user(self.staff, mautic_user_id=18)

        first.refresh_from_db()
        self.assertFalse(first.is_active)
        self.assertEqual(first.status, MauticUserConnection.Status.DISABLED)
        self.assertIsNotNone(first.disabled_at)
        self.assertTrue(second.is_usable)
        self.assertEqual(get_active_mautic_user_connection(self.staff).pk, second.pk)

    def test_reconnect_same_mautic_user_updates_metadata_only(self):
        first = connect_mautic_user(self.staff, mautic_user_id=17, mautic_username="old")
        again = connect_mautic_user(self.staff, mautic_user_id=17, mautic_username="new")

        self.assertEqual(first.pk, again.pk)
        self.assertEqual(again.mautic_username, "new")
        self.assertEqual(MauticUserConnection.objects.count(), 1)

    def test_mautic_user_connected_elsewhere_is_rejected(self):
        connect_mautic_user(self.staff, mautic_user_id=17)

        with self.assertRaises(MauticIdentityError):
            connect_mautic_user(self.other_staff, mautic_user_id=17)
        self.assertFalse(MauticUserConnection.objects.filter(user=self.other_staff).exists())

    def test_non_staff_user_cannot_be_connected(self):
        with self.assertRaises(MauticIdentityError):
            connect_mautic_user(self.normal_user, mautic_user_id=17)

    def test_invalid_mautic_user_ids_are_rejected(self):
        for value in (0, -1, True, "abc", "17.0", None, 1.5):
            with self.subTest(value=value), self.assertRaises(MauticIdentityError):
                connect_mautic_user(self.staff, mautic_user_id=value)

    def test_disable_connection(self):
        connect_mautic_user(self.staff, mautic_user_id=17)

        self.assertEqual(disable_mautic_user_connection(self.staff, reason="offboarded"), 1)
        with self.assertRaises(MauticUserConnectionInactiveError):
            get_active_mautic_user_connection(self.staff)


@override_settings(**MAUTIC_SETTINGS)
class MauticActorResolutionTests(_IdentityFixtures, TestCase):
    def test_active_mapping_resolves(self):
        connection = self._active_connection()

        self.assertEqual(get_active_mautic_user_connection(self.staff).pk, connection.pk)

    def test_missing_mapping_is_rejected(self):
        with self.assertRaises(MauticUserConnectionMissingError):
            get_active_mautic_user_connection(self.staff)

    def test_inactive_mapping_is_rejected(self):
        MauticUserConnection.objects.create(
            user=self.staff,
            mautic_user_id=17,
            status=MauticUserConnection.Status.DISABLED,
        )

        with self.assertRaises(MauticUserConnectionInactiveError):
            get_active_mautic_user_connection(self.staff)

    def test_actor_must_have_marketing_hub_access(self):
        self._active_connection(user=self.normal_user)
        self.staff.is_active = False

        for actor in (None, Mock(is_authenticated=False), self.normal_user, self.staff):
            with self.subTest(actor=actor), self.assertRaises(MauticActorRequiredError):
                get_active_mautic_user_connection(actor)

    def test_mapping_is_never_resolved_by_email(self):
        self._active_connection(user=self.staff, mautic_email="shared@example.test")
        lookalike = User.objects.create_user(
            username="lookalike",
            email="shared@example.test",
            password="test-password",
            is_staff=True,
        )

        with self.assertRaises(MauticUserConnectionMissingError):
            get_active_mautic_user_connection(lookalike)


@override_settings(**MAUTIC_SETTINGS)
class MauticClientFactoryTests(_IdentityFixtures, TestCase):
    def _assert_service_account(self, client):
        self.assertIsInstance(client, MauticClient)
        self.assertEqual(client.username, "api-user")
        self.assertEqual(client.password, "super-secret")
        self.assertIs(client.execution_identity.auth_mode, MauticAuthMode.SERVICE_ACCOUNT)

    def test_direct_client_construction_is_unchanged(self):
        client = MauticClient()

        self.assertIsNone(client.execution_identity)
        self.assertEqual(client.username, "api-user")

    def test_default_is_system_service_account(self):
        client = get_mautic_client()

        self._assert_service_account(client)
        self.assertIs(client.execution_identity.context, MauticExecutionContext.SYSTEM)
        self.assertIsNone(client.execution_identity.actor_id)

    def test_system_and_background_contexts_never_resolve_human_mapping(self):
        self._active_connection()

        for purpose in ("system", "background", "readonly"):
            with self.subTest(purpose=purpose), self.assertNumQueries(0):
                client = get_mautic_client(actor=self.staff, purpose=purpose)
            self._assert_service_account(client)
            self.assertEqual(client.execution_identity.actor_id, self.staff.pk)
            self.assertIsNone(client.execution_identity.mautic_user_id)
            self.assertFalse(client.execution_identity.is_human)

    def test_interactive_mapped_user_still_uses_service_credentials_on_the_wire(self):
        self._active_connection(mautic_user_id=17)
        session = Mock()
        session.request.return_value = Mock(status_code=200)

        client = get_mautic_client(
            actor=self.staff,
            purpose=MauticExecutionContext.INTERACTIVE,
            session=session,
        )
        client.health_check()

        self._assert_service_account(client)
        self.assertEqual(client.execution_identity.mautic_user_id, 17)
        self.assertTrue(client.execution_identity.is_human)
        auth = session.request.call_args.kwargs["auth"]
        self.assertEqual((auth.username, auth.password), ("api-user", "super-secret"))
        headers = session.request.call_args.kwargs.get("headers") or {}
        self.assertFalse(any("ecp" in str(name).lower() for name in headers))

    def test_interactive_unmapped_user_keeps_working_in_phase_1(self):
        client = get_mautic_client(actor=self.staff, purpose="interactive")

        self._assert_service_account(client)
        self.assertIsNone(client.execution_identity.mautic_user_id)

    def test_interactive_requires_marketing_hub_actor(self):
        for actor in (None, self.normal_user):
            with self.subTest(actor=actor), self.assertRaises(MauticActorRequiredError):
                get_mautic_client(actor=actor, purpose="interactive")

    def test_unknown_purpose_is_rejected(self):
        with self.assertRaises(MauticIdentityError):
            resolve_mautic_execution_identity(purpose="impersonate")


@override_settings(**IDENTITY_SETTINGS)
class MauticIdentityAssertionTests(_IdentityFixtures, TestCase):
    NOW = datetime(2026, 9, 15, 10, 0, 0, tzinfo=dt_timezone.utc)

    def _decode(self, token, **kwargs):
        return jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience="ecp-mautic",
            issuer="ecp",
            options={"verify_exp": False},
            **kwargs,
        )

    def test_assertion_contains_only_required_claims(self):
        self._active_connection(mautic_user_id=17)

        issued = issue_identity_assertion(self.staff, operation=CAMPAIGN_CREATE, now=self.NOW)
        claims = self._decode(issued.token)
        header = jwt.get_unverified_header(issued.token)

        self.assertEqual(
            set(claims),
            {"iss", "aud", "sub", "mautic_user_id", "purpose", "operation", "iat", "exp", "jti"},
        )
        self.assertEqual(claims["operation"], CAMPAIGN_CREATE)
        self.assertEqual(issued.operation, CAMPAIGN_CREATE)
        self.assertEqual(claims["iss"], "ecp")
        self.assertEqual(claims["aud"], "ecp-mautic")
        self.assertEqual(claims["sub"], str(self.staff.pk))
        self.assertEqual(claims["mautic_user_id"], 17)
        self.assertEqual(claims["purpose"], "interactive")
        self.assertEqual(claims["jti"], issued.jti)
        self.assertEqual(header, {"alg": "RS256", "typ": ASSERTION_TYPE, "kid": "ecp-test-key-1"})
        self.assertNotIn(self.staff.email, issued.token)

    def test_assertion_ttl(self):
        self._active_connection()

        issued = issue_identity_assertion(self.staff, operation=CAMPAIGN_CREATE, now=self.NOW)
        claims = self._decode(issued.token)

        self.assertEqual(claims["iat"], int(self.NOW.timestamp()))
        self.assertEqual(claims["exp"] - claims["iat"], 90)
        self.assertEqual((issued.expires_at - issued.issued_at).total_seconds(), 90)

    def test_expired_assertion_fails_standard_verification(self):
        self._active_connection()
        issued = issue_identity_assertion(self.staff, operation=CAMPAIGN_CREATE, now=self.NOW)

        with self.assertRaises(jwt.ExpiredSignatureError):
            jwt.decode(issued.token, PUBLIC_KEY, algorithms=["RS256"], audience="ecp-mautic")

    def test_ttl_outside_allowed_window_is_rejected(self):
        self._active_connection()
        for ttl in ("0", "9", "121", "3600", "abc"):
            with self.subTest(ttl=ttl), override_settings(ECP_MAUTIC_IDENTITY_TTL_SECONDS=ttl):
                with self.assertRaises(MauticIdentityConfigurationError):
                    issue_identity_assertion(self.staff, operation=CAMPAIGN_CREATE)

    def test_each_assertion_has_unique_jti(self):
        self._active_connection()

        jtis = {issue_identity_assertion(self.staff, operation=CAMPAIGN_CREATE, now=self.NOW).jti for _ in range(25)}

        self.assertEqual(len(jtis), 25)
        self.assertTrue(all(len(jti) >= 32 for jti in jtis))

    def test_each_operation_is_signed_into_its_own_assertion(self):
        self._active_connection()

        for operation in (CAMPAIGN_CREATE, CAMPAIGN_UPDATE):
            with self.subTest(operation=operation):
                issued = issue_identity_assertion(self.staff, operation=operation, now=self.NOW)
                self.assertEqual(self._decode(issued.token)["operation"], operation)

    def test_operation_is_required(self):
        self._active_connection()

        with self.assertRaises(TypeError):
            issue_identity_assertion(self.staff)

    def test_unknown_operation_is_refused_before_signing(self):
        self._active_connection()

        for operation in ("", "campaign.delete", "CAMPAIGN.CREATE", "campaign.create ", None, 1):
            with self.subTest(operation=operation), self.assertRaises(MauticIdentityAssertionError):
                issue_identity_assertion(self.staff, operation=operation)

    def test_missing_mapping_is_rejected(self):
        with self.assertRaises(MauticUserConnectionMissingError):
            issue_identity_assertion(self.staff, operation=CAMPAIGN_CREATE)

    def test_inactive_mapping_is_rejected(self):
        connect_mautic_user(self.staff, mautic_user_id=17)
        disable_mautic_user_connection(self.staff)

        with self.assertRaises(MauticUserConnectionInactiveError):
            issue_identity_assertion(self.staff, operation=CAMPAIGN_CREATE)

    def test_non_staff_actor_is_rejected(self):
        self._active_connection(user=self.normal_user)

        with self.assertRaises(MauticActorRequiredError):
            issue_identity_assertion(self.normal_user, operation=CAMPAIGN_CREATE)

    def test_background_and_system_purposes_cannot_mint_human_assertions(self):
        self._active_connection()

        for purpose in ("system", "background", "readonly", "anything"):
            with self.subTest(purpose=purpose), self.assertRaises(MauticIdentityAssertionError):
                issue_identity_assertion(self.staff, operation=CAMPAIGN_CREATE, purpose=purpose)

    def test_escaped_newline_pem_is_accepted(self):
        self._active_connection()
        escaped = SIGNING_KEY_PEM.replace("\n", "\\n")

        with override_settings(ECP_MAUTIC_IDENTITY_PRIVATE_KEY=escaped):
            issued = issue_identity_assertion(self.staff, operation=CAMPAIGN_CREATE, now=self.NOW)

        self._decode(issued.token)

    def test_invalid_signing_configuration_is_rejected(self):
        self._active_connection()
        weak_rsa = _pem(rsa.generate_private_key(public_exponent=65537, key_size=1024))
        ec_key = _pem(ec.generate_private_key(ec.SECP256R1()))
        cases = {
            "missing key": {"ECP_MAUTIC_IDENTITY_PRIVATE_KEY": ""},
            "garbage key": {"ECP_MAUTIC_IDENTITY_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"},
            "weak rsa": {"ECP_MAUTIC_IDENTITY_PRIVATE_KEY": weak_rsa},
            "non-rsa": {"ECP_MAUTIC_IDENTITY_PRIVATE_KEY": ec_key},
            "missing kid": {"ECP_MAUTIC_IDENTITY_KEY_ID": ""},
            "missing issuer": {"ECP_MAUTIC_IDENTITY_ISSUER": ""},
            "missing audience": {"ECP_MAUTIC_IDENTITY_AUDIENCE": ""},
        }
        for name, overrides in cases.items():
            with self.subTest(name), override_settings(**overrides):
                with self.assertRaises(MauticIdentityConfigurationError) as ctx:
                    issue_identity_assertion(self.staff, operation=CAMPAIGN_CREATE)
                self.assertIsNone(ctx.exception.__cause__)
                self.assertNotIn("PRIVATE KEY", str(ctx.exception))

    def test_private_key_and_token_are_never_logged_or_repr(self):
        self._active_connection()
        root = logging.getLogger()
        with self.assertLogs(root, level="DEBUG") as captured:
            logging.getLogger("newsletter").debug("capture start")
            issued = issue_identity_assertion(self.staff, operation=CAMPAIGN_CREATE, now=self.NOW)

        output = "\n".join(captured.output)
        self.assertIn(issued.jti, output)
        self.assertNotIn(issued.token, output)
        self.assertNotIn(issued.token.split(".")[2], output)
        self.assertNotIn("PRIVATE KEY", output)
        self.assertNotIn(SIGNING_KEY_PEM.splitlines()[1], output)
        self.assertNotIn(issued.token, repr(issued))
        self.assertNotIn("PRIVATE", repr(load_identity_assertion_settings()))


@override_settings(**MAUTIC_SETTINGS)
class NewsletterAdminMauticIdentityStatusAPITests(_IdentityFixtures, TestCase):
    EXPECTED_KEYS = {
        "connected",
        "status",
        "mautic_user_id",
        "mautic_username",
        "last_verified_at",
        "auth_mode",
        "per_user_execution_enabled",
        "identity_signing_configured",
        "interactive_blocked_code",
    }

    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.url = reverse("newsletter-admin-mautic-identity-status")

    def test_route_is_in_marketing_hub_settings_namespace(self):
        self.assertEqual(self.url, "/api/newsletter/admin/settings/mautic-identity/status/")

    def test_requires_marketing_hub_staff(self):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, (401, 403))

        self.client.force_authenticate(user=self.normal_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_not_connected(self):
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.data), self.EXPECTED_KEYS)
        self.assertFalse(response.data["connected"])
        self.assertEqual(response.data["status"], "not_connected")
        self.assertIsNone(response.data["mautic_user_id"])
        self.assertEqual(response.data["auth_mode"], "service_account")
        self.assertFalse(response.data["per_user_execution_enabled"])
        self.assertFalse(response.data["identity_signing_configured"])

    def test_connected_reports_only_the_current_users_mapping(self):
        self._active_connection(user=self.staff, mautic_user_id=17, mautic_username="ravi")
        self._active_connection(user=self.other_staff, mautic_user_id=99, mautic_username="other")
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["connected"])
        self.assertEqual(response.data["status"], "active")
        self.assertEqual(response.data["mautic_user_id"], 17)
        self.assertEqual(response.data["mautic_username"], "ravi")

    def test_disabled_connection_is_not_connected(self):
        connect_mautic_user(self.staff, mautic_user_id=17, mautic_username="ravi")
        disable_mautic_user_connection(self.staff)
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url)

        self.assertFalse(response.data["connected"])
        self.assertEqual(response.data["status"], "disabled")
        self.assertIsNone(response.data["mautic_user_id"])
        self.assertIsNone(response.data["mautic_username"])

    @override_settings(**IDENTITY_SETTINGS)
    @patch("newsletter.mautic.client.MauticClient._request")
    def test_response_exposes_no_secrets_and_calls_no_provider(self, request_mock):
        self._active_connection(mautic_email="ravi@mautic.example.test")
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url)
        body = json.dumps(response.json())

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["identity_signing_configured"])
        request_mock.assert_not_called()
        for forbidden in (
            "super-secret",
            "api-user",
            "PRIVATE KEY",
            SIGNING_KEY_PEM.splitlines()[1],
            "ecp-test-key-1",
            "ravi@mautic.example.test",
            "password",
            "token",
        ):
            self.assertNotIn(forbidden, body)
