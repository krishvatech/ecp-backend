"""Short-lived signed ECP identity assertions for the ECP Mautic bridge.

ECP signs with an RSA private key (RS256); Mautic verifies with the matching
public key only, so Mautic never holds material that can mint assertions.

The assertion carries only what the bridge needs to authorize a request:
issuer, audience, the immutable ECP user id (``sub``), the mapped Mautic user
id, the execution purpose, timestamps, and a unique ``jti`` for replay
protection. It never contains Cognito tokens, Mautic credentials, passwords,
or email addresses.

PHASE 1: nothing sends these assertions to Mautic yet.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone as dt_timezone

import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from django.conf import settings
from django.utils import timezone

from .exceptions import MauticIdentityAssertionError, MauticIdentityConfigurationError
from .identity import MauticExecutionContext, get_active_mautic_user_connection

logger = logging.getLogger(__name__)

ASSERTION_ALGORITHM = "RS256"
# Explicit JWT type (RFC 8725 §3.11) so this token cannot be confused with any
# other JWT the platform issues or accepts.
ASSERTION_TYPE = "ecp-identity+jwt"
MIN_RSA_KEY_BITS = 2048
MIN_TTL_SECONDS = 10
MAX_TTL_SECONDS = 120
DEFAULT_TTL_SECONDS = 90
MAX_KEY_ID_LENGTH = 128


@dataclass(frozen=True)
class IdentityAssertionSettings:
    private_key: RSAPrivateKey = field(repr=False)
    key_id: str
    issuer: str
    audience: str
    ttl_seconds: int


@dataclass(frozen=True)
class IssuedIdentityAssertion:
    token: str = field(repr=False)
    jti: str
    key_id: str
    subject: str
    mautic_user_id: int
    issued_at: datetime
    expires_at: datetime


def _setting_str(name: str, default: str = "") -> str:
    return str(getattr(settings, name, default) or "").strip()


def _load_private_key(raw_pem: str) -> RSAPrivateKey:
    if not raw_pem:
        raise MauticIdentityConfigurationError("ECP Mautic identity private key is not configured")
    # Environment files commonly store PEM newlines as literal "\n".
    pem = raw_pem.replace("\\n", "\n").encode("utf-8")
    try:
        key = load_pem_private_key(pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        # Suppress chaining so no key-derived detail reaches tracebacks/logs.
        raise MauticIdentityConfigurationError(
            "ECP Mautic identity private key could not be loaded"
        ) from None
    if not isinstance(key, RSAPrivateKey):
        raise MauticIdentityConfigurationError("ECP Mautic identity private key must be an RSA key")
    if key.key_size < MIN_RSA_KEY_BITS:
        raise MauticIdentityConfigurationError(
            f"ECP Mautic identity private key must be at least {MIN_RSA_KEY_BITS} bits"
        )
    return key


def _load_ttl_seconds() -> int:
    raw = getattr(settings, "ECP_MAUTIC_IDENTITY_TTL_SECONDS", DEFAULT_TTL_SECONDS)
    try:
        ttl = int(str(raw).strip())
    except (TypeError, ValueError):
        raise MauticIdentityConfigurationError("ECP Mautic identity TTL must be an integer") from None
    if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
        raise MauticIdentityConfigurationError(
            f"ECP Mautic identity TTL must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS} seconds"
        )
    return ttl


def load_identity_assertion_settings() -> IdentityAssertionSettings:
    key_id = _setting_str("ECP_MAUTIC_IDENTITY_KEY_ID")
    issuer = _setting_str("ECP_MAUTIC_IDENTITY_ISSUER")
    audience = _setting_str("ECP_MAUTIC_IDENTITY_AUDIENCE")
    if not key_id or len(key_id) > MAX_KEY_ID_LENGTH:
        raise MauticIdentityConfigurationError("ECP Mautic identity key id is not configured")
    if not issuer:
        raise MauticIdentityConfigurationError("ECP Mautic identity issuer is not configured")
    if not audience:
        raise MauticIdentityConfigurationError("ECP Mautic identity audience is not configured")

    return IdentityAssertionSettings(
        private_key=_load_private_key(str(getattr(settings, "ECP_MAUTIC_IDENTITY_PRIVATE_KEY", "") or "")),
        key_id=key_id,
        issuer=issuer,
        audience=audience,
        ttl_seconds=_load_ttl_seconds(),
    )


def is_identity_assertion_configured() -> bool:
    try:
        load_identity_assertion_settings()
    except MauticIdentityConfigurationError:
        return False
    return True


def issue_identity_assertion(
    actor,
    *,
    purpose=MauticExecutionContext.INTERACTIVE,
    now: datetime | None = None,
) -> IssuedIdentityAssertion:
    """Sign an identity assertion for a mapped, active Marketing Hub user.

    Raises ``MauticActorRequiredError``, ``MauticUserConnectionMissingError``,
    ``MauticUserConnectionInactiveError``, ``MauticIdentityAssertionError`` or
    ``MauticIdentityConfigurationError``.
    """
    try:
        context = MauticExecutionContext(purpose)
    except ValueError:
        raise MauticIdentityAssertionError("Unknown identity assertion purpose") from None
    if context is not MauticExecutionContext.INTERACTIVE:
        # Background/system work must use the service identity, never a human's.
        raise MauticIdentityAssertionError(
            "Identity assertions may only be issued for interactive operations"
        )

    connection = get_active_mautic_user_connection(actor)
    config = load_identity_assertion_settings()

    issued_at = (now or timezone.now()).astimezone(dt_timezone.utc).replace(microsecond=0)
    iat = int(issued_at.timestamp())
    exp = iat + config.ttl_seconds
    jti = secrets.token_urlsafe(32)
    subject = str(actor.pk)

    claims = {
        "iss": config.issuer,
        "aud": config.audience,
        "sub": subject,
        "mautic_user_id": int(connection.mautic_user_id),
        "purpose": context.value,
        "iat": iat,
        "exp": exp,
        "jti": jti,
    }
    token = jwt.encode(
        claims,
        config.private_key,
        algorithm=ASSERTION_ALGORITHM,
        headers={"kid": config.key_id, "typ": ASSERTION_TYPE},
    )

    logger.info(
        "Issued ECP Mautic identity assertion jti=%s ecp_user_id=%s mautic_user_id=%s kid=%s exp=%s",
        jti,
        subject,
        connection.mautic_user_id,
        config.key_id,
        exp,
    )
    return IssuedIdentityAssertion(
        token=token,
        jti=jti,
        key_id=config.key_id,
        subject=subject,
        mautic_user_id=int(connection.mautic_user_id),
        issued_at=issued_at,
        expires_at=datetime.fromtimestamp(exp, tz=dt_timezone.utc),
    )
