"""Saleor webhook signature verification.

Modern Saleor signs each webhook with a *detached* JWS (RS256) carried in the
``Saleor-Signature`` header and verifiable against the app's public JWKS
(``<saleor-host>/.well-known/jwks.json``). The legacy HMAC-SHA256 shared secret
is deprecated.

This module:
  * verifies the detached JWS against Saleor's published public keys (with a
    short JWKS cache and a single forced refresh to tolerate key rotation),
  * falls back to legacy HMAC-SHA256 when a shared secret is configured and the
    incoming signature is an HMAC hex digest rather than a JWS,
  * optionally allows unverified requests when
    ``SALEOR_WEBHOOK_VERIFICATION_OPTIONAL`` is true (defaults to DEBUG) so local
    development keeps working even if JWKS cannot be reached.
"""
import base64
import hashlib
import hmac
import json
import logging
from urllib.parse import urlparse

import jwt
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger("saleor.webhook")

_JWKS_CACHE_KEY = "saleor:webhook:jwks"
_JWKS_TTL = 60 * 60  # 1 hour


def _b64url_decode(segment: str) -> bytes:
    padding_chars = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding_chars)


def _jwks_url() -> str:
    explicit = getattr(settings, "SALEOR_JWKS_URL", "") or ""
    if explicit:
        return explicit
    api_url = getattr(settings, "SALEOR_API_URL", "") or ""
    parsed = urlparse(api_url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}/.well-known/jwks.json"


def _get_jwks(force_refresh=False):
    if not force_refresh:
        cached = cache.get(_JWKS_CACHE_KEY)
        if cached:
            return cached
    url = _jwks_url()
    if not url:
        return None
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        jwks = resp.json()
    except Exception:
        logger.warning("Could not fetch Saleor JWKS from %s", url, exc_info=True)
        return None
    cache.set(_JWKS_CACHE_KEY, jwks, _JWKS_TTL)
    return jwks


def _public_key_for_kid(kid, force_refresh=False):
    jwks = _get_jwks(force_refresh=force_refresh)
    if not jwks:
        return None
    for key in jwks.get("keys", []):
        if not kid or key.get("kid") == kid:
            try:
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
            except Exception:
                logger.warning("Invalid JWK in Saleor JWKS", exc_info=True)
                return None
    return None


def _verify_jws(body: bytes, signature_header: str) -> bool:
    """Verify a Saleor detached JWS (``<protected>..<signature>``)."""
    parts = signature_header.split(".")
    if len(parts) != 3:
        return False
    protected_b64, _payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(protected_b64))
    except Exception:
        return False

    if header.get("alg") != "RS256":
        logger.warning("Unsupported Saleor JWS alg=%s", header.get("alg"))
        return False
    kid = header.get("kid")

    # Detached JWS signing input: protected_b64 + "." + base64url(body)
    payload_b64 = base64.urlsafe_b64encode(body).rstrip(b"=").decode()
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    try:
        signature = _b64url_decode(sig_b64)
    except Exception:
        return False

    # Try cached keys first, then force a JWKS refresh once (handles rotation).
    for force_refresh in (False, True):
        public_key = _public_key_for_kid(kid, force_refresh=force_refresh)
        if public_key is None:
            continue
        try:
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return True
        except InvalidSignature:
            continue
        except Exception:
            logger.warning("Saleor JWS verification error", exc_info=True)
            return False
    return False


def verify_saleor_webhook(request) -> bool:
    """Return True if the Saleor webhook request is authentic (or explicitly allowed)."""
    signature = (
        request.headers.get("Saleor-Signature")
        or request.headers.get("X-Saleor-Signature")
        or ""
    ).strip()
    body = request.body

    verified = False
    if signature.count(".") == 2:
        verified = _verify_jws(body, signature)
        if not verified:
            logger.warning("Saleor JWS signature verification failed.")
    else:
        secret = getattr(settings, "SALEOR_WEBHOOK_SECRET", "") or ""
        if secret and signature:
            expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            verified = hmac.compare_digest(signature, expected)
            if not verified:
                logger.warning("Saleor HMAC signature mismatch.")

    if verified:
        return True

    optional = getattr(settings, "SALEOR_WEBHOOK_VERIFICATION_OPTIONAL", getattr(settings, "DEBUG", False))
    if optional:
        logger.warning("Saleor webhook signature NOT verified; allowed because verification is optional.")
        return True

    return False
