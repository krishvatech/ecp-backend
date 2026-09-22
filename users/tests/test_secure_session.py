"""
Tests for the Phase 1 secure Cognito session endpoints.

All AWS access is mocked: boto3.client is patched for every test (profile
signals also call Cognito), and Cognito tokens are signed with a throwaway RSA
key that stands in for the pool's JWKS.
"""

import hashlib
import time
import uuid
from datetime import timedelta
from unittest import mock

import jwt
from botocore.exceptions import ClientError, EndpointConnectionError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from users import secure_session as svc
from users.models import CognitoIdentity, CognitoSecureSession, UserProfile

ORIGIN = "https://connect.imaa-institute.org"
REGION = "eu-central-1"
POOL_ID = "eu-central-1_TESTPOOL"
CLIENT_ID = "test-client-id"
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{POOL_ID}"
COOKIE = "__Host-ecp_secure_session"
FERNET_KEY = Fernet.generate_key().decode()

ESTABLISH = "/api/auth/secure-session/establish/"
REFRESH = "/api/auth/secure-session/refresh/"
LOGOUT = "/api/auth/secure-session/logout/"

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def make_cognito_token(sub, token_use="id", key=_PRIVATE_KEY, exp_in=7200, **extra):
    now = int(time.time())
    claims = {
        "sub": sub,
        "iss": ISSUER,
        "token_use": token_use,
        "iat": now,
        "exp": now + exp_in,
        "cognito:username": f"user-{sub[:8]}",
        "email": f"{sub[:8]}@example.com",
        "email_verified": True,
    }
    if token_use == "id":
        claims["aud"] = CLIENT_ID
    else:
        claims["client_id"] = CLIENT_ID
    claims.update(extra)
    return jwt.encode(claims, _pem(key), algorithm="RS256", headers={"kid": "test-kid"})


def cognito_error(code):
    return ClientError({"Error": {"Code": code, "Message": "mocked"}}, "InitiateAuth")


SECURE_SETTINGS = dict(
    SECURE_AUTH_SESSION_ENABLED=True,
    SECURE_AUTH_TOKEN_ENCRYPTION_KEY=FERNET_KEY,
    SECURE_AUTH_SESSION_TTL_DAYS=30,
    SECURE_AUTH_COOKIE_NAME=COOKIE,
    SECURE_AUTH_COOKIE_SECURE=True,
    SECURE_AUTH_COOKIE_SAMESITE="Strict",
    SECURE_AUTH_ALLOWED_ORIGINS=[ORIGIN],
    SECURE_AUTH_SESSION_THROTTLE_RATE=None,
    COGNITO_REGION=REGION,
    COGNITO_USER_POOL_ID=POOL_ID,
    COGNITO_APP_CLIENT_ID=CLIENT_ID,
    COGNITO_CLIENT_ID=CLIENT_ID,
    COGNITO_APP_CLIENT_SECRET="",
)


@override_settings(**SECURE_SETTINGS)
class SecureSessionTestBase(TestCase):
    def setUp(self):
        # No test may reach AWS: profile signals and the service both use boto3.
        boto_patch = mock.patch("boto3.client", return_value=mock.MagicMock())
        boto_patch.start()
        self.addCleanup(boto_patch.stop)

        saleor_patch = mock.patch("users.tasks.sync_user_to_saleor_async.delay")
        saleor_patch.start()
        self.addCleanup(saleor_patch.stop)

        key_patch_auth = mock.patch("users.cognito_auth._get_public_key", return_value=_PRIVATE_KEY.public_key())
        key_patch_auth.start()
        self.addCleanup(key_patch_auth.stop)
        key_patch_svc = mock.patch("users.secure_session._get_public_key", return_value=_PRIVATE_KEY.public_key())
        key_patch_svc.start()
        self.addCleanup(key_patch_svc.stop)

        self.cognito = mock.MagicMock()
        client_patch = mock.patch("users.secure_session._cognito_client", return_value=self.cognito)
        client_patch.start()
        self.addCleanup(client_patch.stop)

        self.client = APIClient()
        self.sub = str(uuid.uuid4())
        self.user = User.objects.create_user(
            username=f"member-{self.sub[:8]}", email=f"{self.sub[:8]}@example.com", password="x-Unused-123"
        )
        # ensure_profile runs in transaction.on_commit, which never fires inside TestCase.
        UserProfile.objects.get_or_create(user=self.user)
        CognitoIdentity.objects.create(user=self.user, cognito_sub=self.sub, email=self.user.email, provider="cognito")
        self.refresh_token = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIn0." + "r" * 400 + ".cognito-refresh-token"
        self.new_id_token = make_cognito_token(self.sub)
        self.cognito.initiate_auth.return_value = {
            "AuthenticationResult": {"IdToken": self.new_id_token, "AccessToken": "unused", "ExpiresIn": 7200}
        }

    def headers(self, origin=ORIGIN, secure_header=True, bearer=None):
        h = {}
        if origin is not None:
            h["HTTP_ORIGIN"] = origin
        if secure_header:
            h["HTTP_X_ECP_SECURE_AUTH"] = "1"
        if bearer:
            h["HTTP_AUTHORIZATION"] = f"Bearer {bearer}"
        return h

    def establish(self, refresh_token=None, bearer=None, **header_kwargs):
        body = {} if refresh_token is False else {"refresh_token": refresh_token or self.refresh_token}
        return self.client.post(
            ESTABLISH,
            body,
            format="json",
            **self.headers(bearer=bearer or make_cognito_token(self.sub), **header_kwargs),
        )

    def make_session(self, handle="handle-" + "a" * 40, expires_in_days=30, revoked=False, user=None):
        session = CognitoSecureSession.objects.create(
            user=user or self.user,
            handle_hash=svc.hash_session_handle(handle),
            encrypted_refresh_token=Fernet(FERNET_KEY.encode()).encrypt(self.refresh_token.encode()).decode(),
            cognito_sub=self.sub,
            expires_at=timezone.now() + timedelta(days=expires_in_days),
            revoked_at=timezone.now() if revoked else None,
        )
        self.client.cookies[COOKIE] = handle
        return session

    def assert_cookie_cleared(self, response):
        morsel = response.cookies.get(COOKIE)
        self.assertIsNotNone(morsel, "expected the session cookie to be cleared")
        self.assertEqual(morsel.value, "")
        self.assertEqual(str(morsel["max-age"]), "0")


# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------

@override_settings(SECURE_AUTH_SESSION_ENABLED=False)
class SecureSessionDisabledTests(SecureSessionTestBase):
    def test_all_endpoints_return_404_when_disabled(self):
        self.client.cookies[COOKIE] = "some-handle"
        with mock.patch("users.cognito_auth.CognitoJWTAuthentication.authenticate") as auth_spy:
            for url in (ESTABLISH, REFRESH, LOGOUT):
                response = self.client.post(
                    url,
                    {"refresh_token": self.refresh_token},
                    format="json",
                    **self.headers(bearer=make_cognito_token(self.sub)),
                )
                self.assertEqual(response.status_code, 404, url)
        # Disabled means no authentication work, no Cognito calls, no side effects.
        auth_spy.assert_not_called()
        self.cognito.initiate_auth.assert_not_called()
        self.cognito.revoke_token.assert_not_called()

    def test_disabled_creates_no_row_and_no_cookie(self):
        for url in (ESTABLISH, REFRESH, LOGOUT):
            response = self.client.post(url, {"refresh_token": self.refresh_token}, format="json", **self.headers())
            self.assertNotIn(COOKIE, response.cookies, url)
        self.assertEqual(CognitoSecureSession.objects.count(), 0)

    def test_disabled_ignores_missing_encryption_key(self):
        with override_settings(SECURE_AUTH_TOKEN_ENCRYPTION_KEY=""):
            self.assertEqual(self.client.post(REFRESH, **self.headers()).status_code, 404)
            self.assertEqual(svc.check_secure_session_configuration(), [])


class SecureSessionConfigurationTests(SecureSessionTestBase):
    def test_missing_key_fails_safely_when_enabled(self):
        with override_settings(SECURE_AUTH_TOKEN_ENCRYPTION_KEY=""):
            response = self.establish()
            self.assertEqual(response.status_code, 503)
            self.assertEqual([e.id for e in svc.check_secure_session_configuration()], ["users.E901"])
        self.assertEqual(CognitoSecureSession.objects.count(), 0)
        self.cognito.initiate_auth.assert_not_called()

    def test_invalid_key_fails_safely_and_is_not_echoed(self):
        bad_key = "not-a-fernet-key-SECRET-MATERIAL"
        with override_settings(SECURE_AUTH_TOKEN_ENCRYPTION_KEY=bad_key):
            response = self.client.post(REFRESH, **self.headers())
            self.assertEqual(response.status_code, 503)
            self.assertNotIn(bad_key, response.content.decode())
            errors = svc.check_secure_session_configuration()
            self.assertEqual(len(errors), 1)
            self.assertNotIn(bad_key, errors[0].msg)

    def test_host_prefixed_cookie_requires_secure(self):
        with override_settings(SECURE_AUTH_COOKIE_SECURE=False):
            self.assertEqual(self.client.post(LOGOUT, **self.headers()).status_code, 503)

    def test_valid_configuration_has_no_check_errors(self):
        self.assertEqual(svc.check_secure_session_configuration(), [])


# ---------------------------------------------------------------------------
# Establish
# ---------------------------------------------------------------------------

class SecureSessionEstablishTests(SecureSessionTestBase):
    def test_anonymous_request_rejected(self):
        response = self.client.post(ESTABLISH, {"refresh_token": self.refresh_token}, format="json", **self.headers())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(CognitoSecureSession.objects.count(), 0)
        self.cognito.initiate_auth.assert_not_called()

    def test_guest_jwt_rejected(self):
        guest_token = jwt.encode(
            {"token_type": "guest", "guest_id": 1, "jti": "x", "exp": int(time.time()) + 3600},
            "any-secret",
            algorithm="HS256",
        )
        response = self.establish(bearer=guest_token)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(CognitoSecureSession.objects.count(), 0)
        self.cognito.initiate_auth.assert_not_called()

    def test_simplejwt_style_token_rejected(self):
        simple = jwt.encode({"user_id": self.user.id, "token_type": "access", "exp": int(time.time()) + 600}, "k", algorithm="HS256")
        self.assertEqual(self.establish(bearer=simple).status_code, 401)
        self.assertEqual(CognitoSecureSession.objects.count(), 0)

    def test_invalid_cognito_bearer_rejected(self):
        forged = make_cognito_token(self.sub, key=_OTHER_PRIVATE_KEY)
        response = self.establish(bearer=forged)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(CognitoSecureSession.objects.count(), 0)
        self.cognito.initiate_auth.assert_not_called()

    def test_missing_refresh_token_rejected(self):
        response = self.establish(refresh_token=False)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "refresh_token_required")
        self.cognito.initiate_auth.assert_not_called()

    def test_invalid_cognito_refresh_token_rejected(self):
        self.cognito.initiate_auth.side_effect = cognito_error("NotAuthorizedException")
        response = self.establish()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "refresh_token_rejected")
        self.assertEqual(CognitoSecureSession.objects.count(), 0)
        self.assertNotIn(COOKIE, response.cookies)

    def test_mismatched_cognito_subject_rejected(self):
        other_sub = str(uuid.uuid4())
        self.cognito.initiate_auth.return_value = {
            "AuthenticationResult": {"IdToken": make_cognito_token(other_sub)}
        }
        response = self.establish()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["code"], "identity_mismatch")
        self.assertEqual(CognitoSecureSession.objects.count(), 0)
        self.assertNotIn(COOKIE, response.cookies)

    def test_refreshed_token_signed_by_unknown_key_rejected(self):
        self.cognito.initiate_auth.return_value = {
            "AuthenticationResult": {"IdToken": make_cognito_token(self.sub, key=_OTHER_PRIVATE_KEY)}
        }
        response = self.establish()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(CognitoSecureSession.objects.count(), 0)

    def test_cognito_unavailable_returns_502_without_session(self):
        self.cognito.initiate_auth.side_effect = EndpointConnectionError(endpoint_url="https://cognito")
        self.assertEqual(self.establish().status_code, 502)
        self.assertEqual(CognitoSecureSession.objects.count(), 0)

    def test_successful_establish(self):
        response = self.establish()
        self.assertEqual(response.status_code, 200, response.content)

        # Exactly one session, bound to the authenticated user and subject.
        self.assertEqual(CognitoSecureSession.objects.count(), 1)
        session = CognitoSecureSession.objects.get()
        self.assertEqual(session.user_id, self.user.id)
        self.assertEqual(session.cognito_sub, self.sub)
        self.assertIsNone(session.revoked_at)
        self.assertGreater(session.expires_at, timezone.now() + timedelta(days=29))

        # Cookie: opaque handle, hashed at rest, secure attributes, host-only.
        morsel = response.cookies[COOKIE]
        handle = morsel.value
        self.assertTrue(handle)
        self.assertNotEqual(session.handle_hash, handle)
        self.assertEqual(session.handle_hash, hashlib.sha256(handle.encode()).hexdigest())
        self.assertTrue(morsel["httponly"])
        self.assertTrue(morsel["secure"])
        self.assertEqual(morsel["samesite"], "Strict")
        self.assertEqual(morsel["path"], "/")
        self.assertEqual(morsel["domain"], "")

        # Refresh token encrypted, never plaintext.
        self.assertNotEqual(session.encrypted_refresh_token, self.refresh_token)
        self.assertEqual(svc.decrypt_refresh_token(session.encrypted_refresh_token), self.refresh_token)

        # Response: fresh ID token as access_token; no refresh credential.
        self.assertEqual(response.data["access_token"], self.new_id_token)
        self.assertTrue(response.data["session_established"])
        self.assertGreater(response.data["expires_in"], 0)
        self.assertNotIn("refresh_token", response.data)
        self.assertNotIn(self.refresh_token, response.content.decode())
        self.assertEqual(response["Cache-Control"], "no-store")

        # Cognito called exactly once with REFRESH_TOKEN_AUTH and no secret hash.
        self.cognito.initiate_auth.assert_called_once()
        kwargs = self.cognito.initiate_auth.call_args.kwargs
        self.assertEqual(kwargs["AuthFlow"], "REFRESH_TOKEN_AUTH")
        self.assertEqual(kwargs["ClientId"], CLIENT_ID)
        self.assertEqual(kwargs["AuthParameters"], {"REFRESH_TOKEN": self.refresh_token})

    def test_access_token_bearer_is_accepted(self):
        response = self.establish(bearer=make_cognito_token(self.sub, token_use="access"))
        self.assertEqual(response.status_code, 200, response.content)

    def test_local_cookie_configuration_is_respected(self):
        with override_settings(SECURE_AUTH_COOKIE_NAME="ecp_secure_session_local", SECURE_AUTH_COOKIE_SECURE=False, SECURE_AUTH_COOKIE_SAMESITE="Lax"):
            response = self.establish()
            self.assertEqual(response.status_code, 200, response.content)
            morsel = response.cookies["ecp_secure_session_local"]
            self.assertFalse(morsel["secure"])
            self.assertTrue(morsel["httponly"])
            self.assertEqual(morsel["samesite"], "Lax")


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

class SecureSessionRefreshTests(SecureSessionTestBase):
    def test_missing_cookie_rejected(self):
        response = self.client.post(REFRESH, **self.headers())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "session_missing")
        self.cognito.initiate_auth.assert_not_called()

    def test_unknown_handle_rejected_and_cookie_cleared(self):
        self.client.cookies[COOKIE] = "unknown-handle"
        response = self.client.post(REFRESH, **self.headers())
        self.assertEqual(response.status_code, 401)
        self.assert_cookie_cleared(response)
        self.cognito.initiate_auth.assert_not_called()

    def test_revoked_session_rejected(self):
        self.make_session(revoked=True)
        response = self.client.post(REFRESH, **self.headers())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "session_revoked")
        self.assert_cookie_cleared(response)
        self.cognito.initiate_auth.assert_not_called()

    def test_expired_session_rejected(self):
        session = self.make_session(expires_in_days=-1)
        response = self.client.post(REFRESH, **self.headers())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "session_expired")
        self.assert_cookie_cleared(response)
        session.refresh_from_db()
        self.assertIsNotNone(session.revoked_at)
        self.assertEqual(session.encrypted_refresh_token, "")
        self.cognito.initiate_auth.assert_not_called()

    def test_inactive_user_rejected(self):
        session = self.make_session()
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        response = self.client.post(REFRESH, **self.headers())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "account_unavailable")
        session.refresh_from_db()
        self.assertIsNotNone(session.revoked_at)
        self.cognito.initiate_auth.assert_not_called()

    def test_suspended_user_rejected(self):
        self.make_session()
        UserProfile.objects.filter(user=self.user).update(profile_status=UserProfile.PROFILE_STATUS_SUSPENDED)
        response = self.client.post(REFRESH, **self.headers())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "account_unavailable")
        self.cognito.initiate_auth.assert_not_called()

    def test_cognito_rejection_revokes_session(self):
        session = self.make_session()
        self.cognito.initiate_auth.side_effect = cognito_error("NotAuthorizedException")
        response = self.client.post(REFRESH, **self.headers())
        self.assertEqual(response.status_code, 401)
        self.assert_cookie_cleared(response)
        session.refresh_from_db()
        self.assertIsNotNone(session.revoked_at)

    def test_cognito_unavailable_keeps_session(self):
        session = self.make_session()
        self.cognito.initiate_auth.side_effect = EndpointConnectionError(endpoint_url="https://cognito")
        response = self.client.post(REFRESH, **self.headers())
        self.assertEqual(response.status_code, 502)
        self.assertNotIn(COOKIE, response.cookies)
        session.refresh_from_db()
        self.assertIsNone(session.revoked_at)

    def test_subject_mismatch_revokes_session(self):
        session = self.make_session()
        self.cognito.initiate_auth.return_value = {
            "AuthenticationResult": {"IdToken": make_cognito_token(str(uuid.uuid4()))}
        }
        response = self.client.post(REFRESH, **self.headers())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "identity_mismatch")
        session.refresh_from_db()
        self.assertIsNotNone(session.revoked_at)

    def test_successful_refresh(self):
        session = self.make_session()
        stored_ciphertext = session.encrypted_refresh_token
        self.assertIsNone(session.last_used_at)

        response = self.client.post(REFRESH, **self.headers())

        self.assertEqual(response.status_code, 200, response.content)
        self.cognito.initiate_auth.assert_called_once()
        self.assertEqual(
            self.cognito.initiate_auth.call_args.kwargs["AuthParameters"], {"REFRESH_TOKEN": self.refresh_token}
        )
        self.assertEqual(response.data["access_token"], self.new_id_token)
        self.assertNotIn("refresh_token", response.data)
        self.assertNotIn(self.refresh_token, response.content.decode())
        self.assertNotIn(COOKIE, response.cookies)
        session.refresh_from_db()
        self.assertIsNotNone(session.last_used_at)
        self.assertEqual(session.encrypted_refresh_token, stored_ciphertext)

    def test_rotated_refresh_token_replaces_encrypted_value(self):
        session = self.make_session()
        old_ciphertext = session.encrypted_refresh_token
        rotated = "rotated-" + "z" * 300
        self.cognito.initiate_auth.return_value = {
            "AuthenticationResult": {"IdToken": self.new_id_token, "RefreshToken": rotated}
        }

        response = self.client.post(REFRESH, **self.headers())

        self.assertEqual(response.status_code, 200, response.content)
        session.refresh_from_db()
        self.assertNotEqual(session.encrypted_refresh_token, old_ciphertext)
        self.assertNotEqual(session.encrypted_refresh_token, rotated)
        self.assertEqual(svc.decrypt_refresh_token(session.encrypted_refresh_token), rotated)
        body = response.content.decode()
        self.assertNotIn(rotated, body)
        self.assertNotIn(self.refresh_token, body)
        self.assertNotIn("refresh_token", response.data)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

class SecureSessionLogoutTests(SecureSessionTestBase):
    def test_successful_logout_revokes_everything(self):
        session = self.make_session()
        response = self.client.post(LOGOUT, **self.headers())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["logged_out"])
        self.cognito.revoke_token.assert_called_once_with(Token=self.refresh_token, ClientId=CLIENT_ID)
        session.refresh_from_db()
        self.assertIsNotNone(session.revoked_at)
        self.assertEqual(session.encrypted_refresh_token, "")
        self.assert_cookie_cleared(response)
        morsel = response.cookies[COOKIE]
        self.assertTrue(morsel["secure"])
        self.assertTrue(morsel["httponly"])
        self.assertEqual(morsel["path"], "/")

        # The revoked handle can no longer refresh.
        self.client.cookies[COOKIE] = "handle-" + "a" * 40
        self.assertEqual(self.client.post(REFRESH, **self.headers()).status_code, 401)

    def test_logout_without_session_is_idempotent(self):
        response = self.client.post(LOGOUT, **self.headers())
        self.assertEqual(response.status_code, 200)
        self.assert_cookie_cleared(response)
        self.cognito.revoke_token.assert_not_called()

    def test_repeated_logout_does_not_error(self):
        self.make_session()
        first = self.client.post(LOGOUT, **self.headers())
        self.client.cookies[COOKIE] = "handle-" + "a" * 40
        second = self.client.post(LOGOUT, **self.headers())
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(self.cognito.revoke_token.call_count, 1)

    def test_cognito_revocation_failure_still_revokes_locally(self):
        session = self.make_session()
        self.cognito.revoke_token.side_effect = cognito_error("UnsupportedTokenTypeException")
        response = self.client.post(LOGOUT, **self.headers())
        self.assertEqual(response.status_code, 200)
        session.refresh_from_db()
        self.assertIsNotNone(session.revoked_at)
        self.assertEqual(session.encrypted_refresh_token, "")


# ---------------------------------------------------------------------------
# Origin / CSRF protection
# ---------------------------------------------------------------------------

class SecureSessionOriginTests(SecureSessionTestBase):
    def test_missing_custom_header_rejected(self):
        self.make_session()
        for url in (ESTABLISH, REFRESH, LOGOUT):
            response = self.client.post(url, **self.headers(secure_header=False, bearer=make_cognito_token(self.sub)))
            self.assertEqual(response.status_code, 403, url)
        self.cognito.initiate_auth.assert_not_called()
        self.cognito.revoke_token.assert_not_called()

    def test_wrong_origin_rejected(self):
        self.make_session()
        for origin in ("https://imaa-institute.org", "https://evil.example", "null", "https://connect.imaa-institute.org.evil.example"):
            for url in (ESTABLISH, REFRESH, LOGOUT):
                response = self.client.post(url, **self.headers(origin=origin, bearer=make_cognito_token(self.sub)))
                self.assertEqual(response.status_code, 403, (url, origin))
        self.cognito.initiate_auth.assert_not_called()
        self.cognito.revoke_token.assert_not_called()

    def test_missing_origin_rejected(self):
        self.make_session()
        for url in (ESTABLISH, REFRESH, LOGOUT):
            response = self.client.post(url, **self.headers(origin=None, bearer=make_cognito_token(self.sub)))
            self.assertEqual(response.status_code, 403, url)

    def test_rejected_origin_skips_authentication(self):
        with mock.patch("users.cognito_auth.CognitoJWTAuthentication.authenticate") as auth_spy:
            self.establish(origin="https://evil.example")
        auth_spy.assert_not_called()

    def test_connect_origin_accepted(self):
        self.make_session()
        response = self.client.post(REFRESH, **self.headers(origin=ORIGIN))
        self.assertEqual(response.status_code, 200)


# ---------------------------------------------------------------------------
# Credential exposure
# ---------------------------------------------------------------------------

class SecureSessionExposureTests(SecureSessionTestBase):
    def test_plaintext_refresh_token_not_in_any_db_field(self):
        self.assertEqual(self.establish().status_code, 200)
        session = CognitoSecureSession.objects.get()
        for field in CognitoSecureSession._meta.concrete_fields:
            value = str(field.value_from_object(session))
            self.assertNotIn(self.refresh_token, value, field.name)
            self.assertNotIn(self.new_id_token, value, field.name)

    def test_cookie_contains_no_jwt_or_refresh_token(self):
        response = self.establish()
        handle = response.cookies[COOKIE].value
        self.assertNotEqual(handle, self.refresh_token)
        self.assertNotIn(self.refresh_token, handle)
        self.assertNotIn(self.new_id_token, handle)
        self.assertNotEqual(handle.count("."), 2, "cookie must not look like a JWT")
        self.assertNotIn(str(self.user.id), handle.split("-"))
        self.assertNotIn(self.user.email, handle)
        self.assertNotIn(self.sub, handle)

    def test_responses_never_include_refresh_token(self):
        establish = self.establish()
        self.client.cookies[COOKIE] = establish.cookies[COOKIE].value
        refresh = self.client.post(REFRESH, **self.headers())
        logout = self.client.post(LOGOUT, **self.headers())
        for response in (establish, refresh, logout):
            self.assertNotIn(self.refresh_token, response.content.decode())
            self.assertNotIn("refresh_token", getattr(response, "data", {}) or {})


# ---------------------------------------------------------------------------
# Throttle identity (must not trust client-supplied X-Forwarded-For)
# ---------------------------------------------------------------------------

_LOCMEM_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "secure-session-throttle"}}


@override_settings(CACHES=_LOCMEM_CACHE, SECURE_AUTH_SESSION_THROTTLE_RATE="2/min")
class SecureSessionThrottleTests(SecureSessionTestBase):
    def setUp(self):
        super().setUp()
        from django.core.cache import cache

        cache.clear()  # isolated locmem cache, never the shared Redis cache

    def _post(self, url, xff, **kwargs):
        return self.client.post(url, HTTP_X_FORWARDED_FOR=xff, REMOTE_ADDR="10.0.0.9", **self.headers(**kwargs))

    def test_identity_ignores_x_forwarded_for(self):
        from rest_framework.test import APIRequestFactory

        factory = APIRequestFactory()
        idents = set()
        for xff in ("1.1.1.1", "2.2.2.2, 3.3.3.3", "spoofed", ""):
            request = factory.post(REFRESH, HTTP_X_FORWARDED_FOR=xff, REMOTE_ADDR="10.0.0.9")
            idents.add(svc.throttle_identity(request))
        self.assertEqual(idents, {"addr:10.0.0.9"})

    def test_session_identity_is_hash_not_raw_handle(self):
        from rest_framework.test import APIRequestFactory

        handle = "raw-handle-value-" + "x" * 30
        self.make_session(handle=handle)
        request = APIRequestFactory().post(REFRESH, REMOTE_ADDR="10.0.0.9")
        request.COOKIES[COOKIE] = handle
        ident = svc.throttle_identity(request)
        self.assertEqual(ident, "session:" + svc.hash_session_handle(handle))
        self.assertNotIn("raw-handle-value", ident)

    def test_unknown_cookie_does_not_create_attacker_selected_throttle_bucket(self):
        from rest_framework.test import APIRequestFactory

        factory = APIRequestFactory()
        idents = set()
        for i in range(5):
            request = factory.post(REFRESH, REMOTE_ADDR="10.0.0.9")
            request.COOKIES[COOKIE] = f"attacker-selected-handle-{i}-" + "x" * 32
            idents.add(svc.throttle_identity(request))
        self.assertEqual(idents, {"addr:10.0.0.9"})

    def test_rotating_xff_cannot_bypass_establish_user_throttle(self):
        statuses = [
            self.client.post(
                ESTABLISH, {"refresh_token": self.refresh_token}, format="json",
                HTTP_X_FORWARDED_FOR=f"203.0.113.{i}",
                **self.headers(bearer=make_cognito_token(self.sub)),
            ).status_code
            for i in range(3)
        ]
        self.assertEqual(statuses, [200, 200, 429])

    def test_establish_is_keyed_per_user(self):
        for i in range(2):
            self.client.post(ESTABLISH, {"refresh_token": self.refresh_token}, format="json",
                             **self.headers(bearer=make_cognito_token(self.sub)))
        other_sub = str(uuid.uuid4())
        other = User.objects.create_user(username=f"other-{other_sub[:8]}", email=f"{other_sub[:8]}@example.com", password="x-Unused-123")
        UserProfile.objects.get_or_create(user=other)
        CognitoIdentity.objects.create(user=other, cognito_sub=other_sub, email=other.email, provider="cognito")
        self.cognito.initiate_auth.return_value = {"AuthenticationResult": {"IdToken": make_cognito_token(other_sub)}}
        response = self.client.post(ESTABLISH, {"refresh_token": self.refresh_token}, format="json",
                                    **self.headers(bearer=make_cognito_token(other_sub)))
        self.assertEqual(response.status_code, 200, response.content)

    def test_rotating_xff_cannot_bypass_refresh_session_throttle(self):
        self.make_session()
        statuses = [self._post(REFRESH, f"198.51.100.{i}").status_code for i in range(3)]
        self.assertEqual(statuses, [200, 200, 429])

    def test_rotating_unknown_cookie_values_cannot_bypass_refresh_throttle(self):
        statuses = []
        for i in range(3):
            self.client.cookies[COOKIE] = f"unknown-handle-{i}-" + "x" * 40
            statuses.append(self._post(REFRESH, f"198.51.100.{i}").status_code)
        self.assertEqual(statuses, [401, 401, 429])

    def test_refresh_is_keyed_per_session(self):
        self.make_session(handle="first-handle-" + "a" * 40)
        self._post(REFRESH, "1.1.1.1")
        self._post(REFRESH, "1.1.1.1")
        self.assertEqual(self._post(REFRESH, "1.1.1.1").status_code, 429)
        self.make_session(handle="second-handle-" + "b" * 40)  # also switches the client cookie
        self.assertEqual(self._post(REFRESH, "1.1.1.1").status_code, 200)

    def test_logout_uses_session_identity(self):
        handle = "handle-" + "a" * 40
        self.make_session(handle=handle)
        statuses = []
        for i in range(3):
            # Logout clears the cookie; replay the same handle each time.
            self.client.cookies[COOKIE] = handle
            statuses.append(self._post(LOGOUT, f"192.0.2.{i}").status_code)
        self.assertEqual(statuses, [200, 200, 429])

    def test_identity_less_requests_share_remote_addr_bucket(self):
        statuses = [self._post(REFRESH, f"192.0.2.{i}").status_code for i in range(3)]
        self.assertEqual(statuses, [401, 401, 429])

    def test_malformed_or_huge_cookie_is_handled(self):
        with override_settings(SECURE_AUTH_SESSION_THROTTLE_RATE=None):
            for value in ("", " ", "éè-not-ascii", "x" * 8000, "a;b=c", "null"):
                self.client.cookies[COOKIE] = value
                for url in (REFRESH, LOGOUT):
                    response = self.client.post(url, **self.headers())
                    self.assertIn(response.status_code, (200, 401), (url, value[:20]))

    def test_global_drf_throttling_unchanged(self):
        from rest_framework.settings import api_settings
        from rest_framework.throttling import AnonRateThrottle
        from rest_framework.test import APIRequestFactory

        names = [f"{c.__module__}.{c.__name__}" for c in api_settings.DEFAULT_THROTTLE_CLASSES]
        self.assertEqual(names, ["rest_framework.throttling.AnonRateThrottle", "rest_framework.throttling.UserRateThrottle"])
        # Global get_ident behaviour is untouched (still reads X-Forwarded-For).
        request = APIRequestFactory().get("/", HTTP_X_FORWARDED_FOR="7.7.7.7", REMOTE_ADDR="10.0.0.9")
        self.assertEqual(AnonRateThrottle().get_ident(request), "7.7.7.7")


@override_settings(SECURE_AUTH_SESSION_ENABLED=False)
class SecureSessionDisabledNoWorkTests(SecureSessionTestBase):
    def test_disabled_does_no_throttle_sentry_or_db_work(self):
        self.client.cookies[COOKIE] = "some-handle"
        with mock.patch("users.secure_session_views.SecureSessionThrottle.allow_request") as throttle_spy, \
                mock.patch("users.secure_session_views.protect_current_request") as protect_spy, \
                self.assertNumQueries(0):
            for url in (ESTABLISH, REFRESH, LOGOUT):
                response = self.client.post(url, {"refresh_token": self.refresh_token}, format="json",
                                            **self.headers(bearer=make_cognito_token(self.sub)))
                self.assertEqual(response.status_code, 404)
        throttle_spy.assert_not_called()
        protect_spy.assert_not_called()
        self.cognito.initiate_auth.assert_not_called()
