"""
Secure Cognito session service (Phase 1 foundation, disabled by default).

Keeps the long-lived Cognito refresh token on the server instead of in browser
storage:

    browser  -> opaque random handle in an HttpOnly cookie
    database -> SHA-256(handle) + Fernet-encrypted Cognito refresh token

Nothing in the existing authentication stack imports this module; it is used
only by users/secure_session_views.py. Never log tokens, handles or keys here.
"""

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

import boto3
import jwt
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
from django.views.decorators.debug import sensitive_variables

from .cognito_auth import _get_public_key, _issuer

BLOCKED_PROFILE_STATUSES = ("suspended", "fake", "deceased", "deleted")
SECURE_AUTH_HEADER = "X-ECP-Secure-Auth"
SECURE_AUTH_HEADER_META = "HTTP_X_ECP_SECURE_AUTH"
SECURE_AUTH_HEADER_VALUE = "1"
MAX_REFRESH_TOKEN_LENGTH = 8192


class SecureSessionError(Exception):
    """Base error; `code` is safe to return to clients and to log."""

    code = "secure_session_error"

    def __init__(self, code: Optional[str] = None):
        super().__init__(code or self.code)
        if code:
            self.code = code


class CognitoRefreshRejected(SecureSessionError):
    """Cognito refused the refresh token (invalid, expired or revoked)."""

    code = "refresh_token_rejected"


class CognitoUnavailable(SecureSessionError):
    """Cognito could not be reached or returned an unexpected error."""

    code = "cognito_unavailable"


class TokenVerificationFailed(SecureSessionError):
    code = "token_verification_failed"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def is_enabled() -> bool:
    return bool(getattr(settings, "SECURE_AUTH_SESSION_ENABLED", False))


def _cognito_client_id() -> str:
    return getattr(settings, "COGNITO_APP_CLIENT_ID", "") or getattr(settings, "COGNITO_CLIENT_ID", "") or ""


def _fernet() -> MultiFernet:
    raw = getattr(settings, "SECURE_AUTH_TOKEN_ENCRYPTION_KEY", "") or ""
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if not keys:
        raise ImproperlyConfigured("SECURE_AUTH_TOKEN_ENCRYPTION_KEY is not configured.")
    try:
        return MultiFernet([Fernet(k.encode("utf-8")) for k in keys])
    except (ValueError, TypeError):
        # Do not chain the original exception: its message may echo key material.
        raise ImproperlyConfigured("SECURE_AUTH_TOKEN_ENCRYPTION_KEY is not a valid Fernet key.") from None


def check_secure_session_configuration(app_configs=None, **kwargs):
    """Django system check; silent unless SECURE_AUTH_SESSION_ENABLED=True."""
    from django.core.checks import Error

    if not is_enabled():
        return []
    try:
        validate_configuration()
    except ImproperlyConfigured as exc:
        return [Error(str(exc), id="users.E901")]
    return []


def validate_configuration() -> None:
    """Raise ImproperlyConfigured if the enabled feature cannot run safely."""
    _fernet()
    if not getattr(settings, "COGNITO_REGION", "") or not getattr(settings, "COGNITO_USER_POOL_ID", ""):
        raise ImproperlyConfigured("COGNITO_REGION and COGNITO_USER_POOL_ID are required for secure sessions.")
    if not _cognito_client_id():
        raise ImproperlyConfigured("COGNITO_APP_CLIENT_ID is required for secure sessions.")
    if not getattr(settings, "SECURE_AUTH_ALLOWED_ORIGINS", None):
        raise ImproperlyConfigured("SECURE_AUTH_ALLOWED_ORIGINS must list at least one origin.")
    if getattr(settings, "SECURE_AUTH_SESSION_TTL_DAYS", 0) <= 0:
        raise ImproperlyConfigured("SECURE_AUTH_SESSION_TTL_DAYS must be positive.")
    name = cookie_name()
    if name.startswith("__Host-") and not getattr(settings, "SECURE_AUTH_COOKIE_SECURE", True):
        raise ImproperlyConfigured("A __Host- cookie requires SECURE_AUTH_COOKIE_SECURE=True.")
    if name.startswith("__Secure-") and not getattr(settings, "SECURE_AUTH_COOKIE_SECURE", True):
        raise ImproperlyConfigured("A __Secure- cookie requires SECURE_AUTH_COOKIE_SECURE=True.")


# ---------------------------------------------------------------------------
# Encryption and handles
# ---------------------------------------------------------------------------

@sensitive_variables()
def encrypt_refresh_token(refresh_token: str) -> str:
    return _fernet().encrypt(refresh_token.encode("utf-8")).decode("utf-8")


@sensitive_variables()
def decrypt_refresh_token(ciphertext: str) -> str:
    if not ciphertext:
        raise SecureSessionError("session_credential_missing")
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise SecureSessionError("session_credential_undecryptable") from None


def new_session_handle() -> str:
    """256-bit random opaque handle for the browser cookie."""
    return secrets.token_urlsafe(32)


def hash_session_handle(handle: str) -> str:
    # A plain SHA-256 is sufficient: the handle is 256 bits of randomness, so
    # the hash cannot be brute-forced back into a usable cookie value.
    return hashlib.sha256(handle.encode("utf-8")).hexdigest()


def throttle_identity(request) -> str:
    """
    Throttle key for the secure-session endpoints. Never derived from
    client-supplied X-Forwarded-For:

    1. authenticated member (establish)   -> "user:<id>"
    2. secure-session cookie (refresh/logout) -> "session:<sha256(handle)>"
    3. otherwise -> "addr:<REMOTE_ADDR>", the immediate TCP peer as seen by
       Django. Behind nginx/ALB this is the proxy, so identity-less requests
       share one conservative bucket; those requests do no DB or Cognito work.
    """
    user = getattr(request, "user", None)
    if getattr(user, "is_authenticated", False) and not getattr(user, "is_guest", False) and getattr(user, "pk", None):
        return f"user:{user.pk}"
    handle = request.COOKIES.get(cookie_name(), "")
    if handle:
        # A caller can invent arbitrary Cookie values.  Keying the throttle on
        # hash(handle) without first proving that the handle belongs to a stored
        # session lets an attacker rotate fake cookie values and obtain a fresh
        # bucket on every request.  Only a handle that resolves to one of our
        # server-side sessions gets a per-session bucket; unknown handles fall
        # back to the conservative immediate-peer bucket below.
        handle_hash = hash_session_handle(handle)
        from .models import CognitoSecureSession

        if CognitoSecureSession.objects.filter(handle_hash=handle_hash).exists():
            return f"session:{handle_hash}"
    return f"addr:{request.META.get('REMOTE_ADDR') or 'unknown'}"


def session_expiry():
    return timezone.now() + timedelta(days=settings.SECURE_AUTH_SESSION_TTL_DAYS)


# ---------------------------------------------------------------------------
# Cookie
# ---------------------------------------------------------------------------

def cookie_name() -> str:
    return getattr(settings, "SECURE_AUTH_COOKIE_NAME", "__Host-ecp_secure_session")


def set_session_cookie(response, handle: str, expires_at) -> None:
    max_age = max(0, int((expires_at - timezone.now()).total_seconds()))
    response.set_cookie(
        cookie_name(),
        handle,
        max_age=max_age,
        path="/",
        domain=None,
        secure=settings.SECURE_AUTH_COOKIE_SECURE,
        httponly=True,
        samesite=settings.SECURE_AUTH_COOKIE_SAMESITE,
    )


def clear_session_cookie(response) -> None:
    # Same attributes as when set, so browsers (and __Host- rules) accept the overwrite.
    response.set_cookie(
        cookie_name(),
        "",
        max_age=0,
        expires="Thu, 01 Jan 1970 00:00:00 GMT",
        path="/",
        domain=None,
        secure=settings.SECURE_AUTH_COOKIE_SECURE,
        httponly=True,
        samesite=settings.SECURE_AUTH_COOKIE_SAMESITE,
    )


# ---------------------------------------------------------------------------
# Request origin protection (all three endpoints)
# ---------------------------------------------------------------------------

def request_origin_problem(request) -> Optional[str]:
    """Return a reason code if Origin / custom header checks fail, else None."""
    if request.META.get(SECURE_AUTH_HEADER_META, "") != SECURE_AUTH_HEADER_VALUE:
        return "missing_secure_auth_header"
    origin = (request.META.get("HTTP_ORIGIN") or "").strip().rstrip("/")
    if not origin:
        return "missing_origin"
    allowed = {o.rstrip("/").lower() for o in settings.SECURE_AUTH_ALLOWED_ORIGINS}
    if origin.lower() not in allowed:
        return "origin_not_allowed"
    return None


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def user_can_hold_session(user) -> bool:
    if not user or not getattr(user, "is_active", False):
        return False
    profile = getattr(user, "profile", None)
    return not (profile and profile.profile_status in BLOCKED_PROFILE_STATUSES)


def user_id_for_cognito_sub(sub: str) -> Optional[int]:
    from .models import CognitoIdentity

    return (
        CognitoIdentity.objects.filter(cognito_sub=sub).values_list("user_id", flat=True).first()
    )


# ---------------------------------------------------------------------------
# Cognito
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RefreshResult:
    # repr=False keeps tokens out of reprs (logs, Sentry frame variables).
    id_token: str = field(repr=False)
    # Present only if Cognito rotates the refresh token (rotation is not
    # configured on the production client today).
    rotated_refresh_token: Optional[str] = field(default=None, repr=False)


def _cognito_client():
    return boto3.client("cognito-idp", region_name=settings.COGNITO_REGION)


def _client_secret() -> str:
    return getattr(settings, "COGNITO_APP_CLIENT_SECRET", "") or ""


def _secret_hash(username: str) -> str:
    message = (username + _cognito_client_id()).encode("utf-8")
    digest = hmac.new(_client_secret().encode("utf-8"), message, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


@sensitive_variables()
def cognito_refresh(refresh_token: str, cognito_username: str = "") -> RefreshResult:
    """Exchange a refresh token for fresh tokens via REFRESH_TOKEN_AUTH."""
    params = {"REFRESH_TOKEN": refresh_token}
    if _client_secret():
        # The production client has no secret; this keeps the flow correct if one
        # is added later. The secret itself is never sent or logged.
        params["SECRET_HASH"] = _secret_hash(cognito_username)
    try:
        response = _cognito_client().initiate_auth(
            ClientId=_cognito_client_id(),
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters=params,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NotAuthorizedException", "UserNotFoundException", "InvalidParameterException"):
            raise CognitoRefreshRejected() from None
        raise CognitoUnavailable() from None
    except BotoCoreError:
        raise CognitoUnavailable() from None

    result = response.get("AuthenticationResult") or {}
    id_token = result.get("IdToken") or ""
    if not id_token:
        raise CognitoUnavailable("cognito_missing_id_token")
    return RefreshResult(id_token=id_token, rotated_refresh_token=result.get("RefreshToken") or None)


@sensitive_variables()
def cognito_revoke(refresh_token: str) -> bool:
    """Revoke a refresh token (and tokens minted from it). Returns success."""
    kwargs = {"Token": refresh_token, "ClientId": _cognito_client_id()}
    if _client_secret():
        kwargs["ClientSecret"] = _client_secret()
    try:
        _cognito_client().revoke_token(**kwargs)
        return True
    except (ClientError, BotoCoreError):
        return False


@sensitive_variables()
def verify_id_token(id_token: str) -> dict:
    """
    Verify a Cognito ID token for this pool and app client without the side
    effects of CognitoJWTAuthentication (user creation, profile/Saleor sync).
    Uses the same JWKS cache, issuer and leeway as that class.
    """
    try:
        header = jwt.get_unverified_header(id_token)
        kid = header.get("kid")
        if not kid:
            raise TokenVerificationFailed()
        claims = jwt.decode(
            id_token,
            _get_public_key(kid),
            algorithms=["RS256"],
            audience=_cognito_client_id(),
            issuer=_issuer(),
            leeway=60,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except TokenVerificationFailed:
        raise
    except Exception:
        raise TokenVerificationFailed() from None
    if claims.get("token_use") != "id" or not (claims.get("sub") or "").strip():
        raise TokenVerificationFailed()
    return claims


def seconds_until_expiry(claims: dict) -> int:
    return max(0, int(claims.get("exp", 0)) - int(timezone.now().timestamp()))
