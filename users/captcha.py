"""IPDT-773 — Cloudflare Turnstile server-side verification (prototype).

Verifies a Turnstile token against the provider's Siteverify endpoint. The
secret stays backend-only and is never logged; tokens are never logged in
full. Callers decide when verification is required; this helper fails closed
(returns a failure result) on any network/provider error so an outage can
never be mistaken for a pass.

Nothing here is wired into live signup or event-application submission in
Phase 1 — see CAPTCHA_PROTOTYPE_ENABLED.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TurnstileResult:
    success: bool
    # Machine-readable reason for a failure; never contains the token/secret.
    reason: str = ""
    hostname: str = ""


def _token_marker(token: str) -> str:
    """A log-safe marker that contains NO substring of the token itself —
    only whether one was present and its length. Never the token's bytes,
    prefix, or suffix, and never the secret."""
    if not token:
        return "absent"
    return f"present(len={len(token)})"


def verify_turnstile(token: str, *, remoteip: str | None = None) -> TurnstileResult:
    """Validate a Turnstile token with Cloudflare Siteverify.

    Returns TurnstileResult(success=...). Fails closed on misconfiguration,
    timeout, or any provider error.
    """
    secret = getattr(settings, "TURNSTILE_SECRET", "") or ""
    if not secret:
        logger.warning("Turnstile not configured (no TURNSTILE_SECRET); failing closed.")
        return TurnstileResult(False, reason="not_configured")

    if not token or not isinstance(token, str):
        return TurnstileResult(False, reason="missing_token")

    data = {"secret": secret, "response": token}
    if remoteip:
        data["remoteip"] = remoteip

    try:
        resp = requests.post(
            getattr(settings, "TURNSTILE_VERIFY_URL",
                    "https://challenges.cloudflare.com/turnstile/v0/siteverify"),
            data=data,
            timeout=getattr(settings, "TURNSTILE_TIMEOUT_SECONDS", 5),
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception as e:  # network error, timeout, non-2xx, bad JSON
        logger.warning("Turnstile verify failed (%s) token=%s", e.__class__.__name__, _token_marker(token))
        return TurnstileResult(False, reason="provider_error")

    if not payload.get("success"):
        # Cloudflare returns machine codes in "error-codes"; safe to log (no secrets).
        logger.info("Turnstile rejected token=%s codes=%s", _token_marker(token), payload.get("error-codes"))
        return TurnstileResult(False, reason="rejected", hostname=payload.get("hostname", ""))

    expected_host = getattr(settings, "TURNSTILE_EXPECTED_HOSTNAME", "") or ""
    host = payload.get("hostname", "") or ""
    if expected_host and host != expected_host:
        logger.warning("Turnstile hostname mismatch: got=%s", host)
        return TurnstileResult(False, reason="hostname_mismatch", hostname=host)

    return TurnstileResult(True, hostname=host)
