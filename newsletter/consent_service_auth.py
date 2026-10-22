"""Service authentication for Mautic -> ECP marketing-consent verification.

The ECP Marketing Bridge plugin in Mautic signs every consent-verification
request with its own Ed25519 key (a compact JWS, ``alg=EdDSA``); ECP holds only
the matching public keys. This is a separate trust relationship from every
other ECP <-> Mautic credential: it is not the per-administrator identity
assertion (ECP -> Mautic), not the webhook HMAC secret and not the Mautic API
service account, and it grants nothing but a read-only consent decision.

A request is accepted only when all of these hold:

* the token is an EdDSA JWS signed by a configured, non-revoked key, chosen by
  ``kid`` from ECP's own configuration (``kid`` is only a dictionary key);
* ``iss``/``aud``/``purpose`` are the fixed values below;
* it is current (``iat``/``exp``, at most 60 seconds of validity, a bounded
  clock skew) and its ``jti`` has never been seen before (shared Redis,
  ``cache.add`` is atomic across ECP instances);
* it is bound to the exact request: HTTP method, path and a SHA-256 digest of
  the raw body.

Anything else fails. A missing configuration or an unavailable replay store is
"unavailable" (HTTP 503), never an accepted request.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.core.cache import cache

ISSUER = "mautic-consent-client"
AUDIENCE = "ecp-consent-read"
PURPOSE = "marketing-consent-verify"
ALGORITHM = "EdDSA"
HEADER = "X-ECP-Consent-Signature"
MAX_TOKEN_BYTES = 4096
MAX_VALIDITY_SECONDS = 60
MAX_CLOCK_SKEW_SECONDS = 30
REPLAY_KEY = "ecp-consent-replay:{kid}:{jti}"
RATE_KEY = "ecp-consent-rate:{kid}:{window}"

_KID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_JTI = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_REQUIRED = ["iss", "aud", "iat", "exp", "jti", "purpose", "htm", "htu", "bdh"]


class ConsentAuthError(Exception):
    """The request is not an authentic, current, unused consent request (401)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ConsentAuthUnavailable(Exception):
    """Authentication cannot be completed right now (503): no keys configured,
    no shared replay store. The caller must treat this as UNAVAILABLE."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ConsentCaller:
    key_id: str
    jti: str


def _b64decode(value: str) -> bytes:
    value = value.strip()
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def body_digest(body: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()


def verification_keys() -> dict[str, Ed25519PublicKey]:
    """Configured Ed25519 public keys by key id, minus revoked ids.

    ``ECP_CONSENT_VERIFY_KEYS`` is JSON ``{"<kid>": "<base64 raw 32-byte key>"}``;
    several keys overlap during rotation. ``ECP_CONSENT_REVOKED_KEY_IDS`` is a
    comma-separated list that always wins."""
    raw = getattr(settings, "ECP_CONSENT_VERIFY_KEYS", "") or ""
    if isinstance(raw, str) and not raw.strip():
        return {}
    try:
        configured = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except (TypeError, ValueError) as exc:
        raise ConsentAuthUnavailable("verification_keys_invalid") from exc
    if not isinstance(configured, dict):
        raise ConsentAuthUnavailable("verification_keys_invalid")
    revoked = {kid.strip() for kid in str(getattr(settings, "ECP_CONSENT_REVOKED_KEY_IDS", "") or "").split(",") if kid.strip()}
    keys = {}
    for kid, encoded in configured.items():
        if not isinstance(kid, str) or not _KID.match(kid) or kid in revoked:
            continue
        try:
            material = _b64decode(str(encoded))
            if len(material) != 32:
                raise ValueError("Ed25519 public keys are 32 bytes")
            keys[kid] = Ed25519PublicKey.from_public_bytes(material)
        except ValueError as exc:
            raise ConsentAuthUnavailable("verification_keys_invalid") from exc
    return keys


def _clock_skew() -> int:
    try:
        skew = int(getattr(settings, "ECP_CONSENT_CLOCK_SKEW_SECONDS", MAX_CLOCK_SKEW_SECONDS))
    except (TypeError, ValueError):
        skew = MAX_CLOCK_SKEW_SECONDS
    return max(0, min(skew, MAX_CLOCK_SKEW_SECONDS))


def _require_shared_replay_store() -> None:
    """Replay protection only works when every ECP process sees the same store."""
    backend = str(settings.CACHES.get("default", {}).get("BACKEND", ""))
    local = any(name in backend for name in ("LocMemCache", "DummyCache"))
    if local and not getattr(settings, "ECP_CONSENT_ALLOW_PROCESS_LOCAL_REPLAY_STORE", False):
        raise ConsentAuthUnavailable("replay_store_not_shared")


def authenticate(*, method: str, path: str, body: bytes, token: str | None) -> ConsentCaller:
    if not token:
        raise ConsentAuthError("missing_signature")
    if len(token) > MAX_TOKEN_BYTES:
        raise ConsentAuthError("malformed_signature")
    keys = verification_keys()
    if not keys:
        raise ConsentAuthUnavailable("not_configured")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise ConsentAuthError("malformed_signature") from exc
    if header.get("alg") != ALGORITHM:
        raise ConsentAuthError("unsupported_algorithm")
    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in keys:
        raise ConsentAuthError("unknown_key")

    skew = _clock_skew()
    try:
        claims = jwt.decode(
            token,
            keys[kid],
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
            leeway=skew,
            options={"require": _REQUIRED},
        )
    except jwt.ExpiredSignatureError as exc:
        raise ConsentAuthError("expired") from exc
    except jwt.ImmatureSignatureError as exc:
        raise ConsentAuthError("not_yet_valid") from exc
    except jwt.InvalidAudienceError as exc:
        raise ConsentAuthError("wrong_audience") from exc
    except jwt.InvalidIssuerError as exc:
        raise ConsentAuthError("wrong_issuer") from exc
    except jwt.InvalidSignatureError as exc:
        raise ConsentAuthError("invalid_signature") from exc
    except jwt.InvalidTokenError as exc:
        raise ConsentAuthError("invalid_claims") from exc

    iat, exp = claims["iat"], claims["exp"]
    if not isinstance(iat, int) or not isinstance(exp, int) or exp <= iat or exp - iat > MAX_VALIDITY_SECONDS:
        raise ConsentAuthError("invalid_validity")
    jti = claims["jti"]
    if not isinstance(jti, str) or not _JTI.match(jti):
        raise ConsentAuthError("invalid_claims")
    if claims["purpose"] != PURPOSE:
        raise ConsentAuthError("wrong_purpose")
    if claims["htm"] != method.upper():
        raise ConsentAuthError("wrong_method")
    if claims["htu"] != path:
        raise ConsentAuthError("wrong_path")
    if not isinstance(claims["bdh"], str) or not hmac.compare_digest(claims["bdh"], body_digest(body)):
        raise ConsentAuthError("body_mismatch")

    _require_shared_replay_store()
    ttl = max(1, exp + skew - int(time.time()) + 1)
    try:
        first_use = cache.add(REPLAY_KEY.format(kid=kid, jti=jti), 1, timeout=ttl)
    except Exception as exc:  # the store itself is down: never accept unchecked
        raise ConsentAuthUnavailable("replay_store_unavailable") from exc
    if not first_use:
        raise ConsentAuthError("replayed")
    _enforce_rate_limit(kid)
    return ConsentCaller(key_id=kid, jti=jti)


def _enforce_rate_limit(kid: str) -> None:
    """Fixed one-minute window per signing key; protects ECP from a runaway caller."""
    try:
        limit = int(getattr(settings, "ECP_CONSENT_MAX_REQUESTS_PER_MINUTE", 1200))
    except (TypeError, ValueError):
        limit = 1200
    key = RATE_KEY.format(kid=kid, window=int(time.time() // 60))
    try:
        cache.add(key, 0, timeout=70)
        count = cache.incr(key)
    except Exception as exc:
        raise ConsentAuthUnavailable("replay_store_unavailable") from exc
    if count > limit:
        raise ConsentAuthUnavailable("rate_limited")
