"""IPDT-773 — short-lived signed "signup proof" (prototype).

The future enforcement design is:

    React Turnstile -> Django Siteverify -> Django signed signup proof
    -> Cognito signup ClientMetadata -> Pre Sign-up Lambda verifies the proof.

This module mints and verifies that proof. It is a deliberately portable,
versioned HMAC-SHA256 token (not Django-specific `signing`) so the Pre Sign-up
Lambda — which may be written in Python or Node — can reproduce the exact
verification with the same shared secret.

Proof string format (all dot-separated, base64url, no padding):

    v1.<b64url(payload_json)>.<b64url(hmac_sha256(payload_json))>

payload_json canonical fields:
    v   : format version ("1")
    em  : normalized (lower/trim) email
    op  : intended operation, e.g. "signup"
    cid : Cognito app client id the proof is bound to
    iat : issued-at (unix seconds)
    exp : expiry (unix seconds)
    jti : unique nonce (uuid4 hex) for replay prevention

REPLAY PREVENTION (NOT fully implemented in Phase 1): a short `exp` limits the
window but does NOT make the proof single-use. True single-use requires the
VERIFIER (the Pre Sign-up Lambda) to atomically consume `jti` in a shared store
— e.g. a DynamoDB table with a conditional PutItem on `jti` (ConditionExpression
attribute_not_exists(jti)) and a TTL attribute set to `exp`. First use succeeds,
any replay hits the condition and is rejected; TTL auto-expires spent nonces.
`verify_signup_proof` exposes a `consume_nonce` hook for that store; until a
store is wired, it validates signature + binding + expiry only, and callers must
treat replay protection as PENDING.
"""
from __future__ import annotations

import base64
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from hashlib import sha256

from django.conf import settings

_VERSION = "1"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _secret() -> bytes:
    return (getattr(settings, "SIGNUP_PROOF_SECRET", "") or "").encode("utf-8")


def _sign(payload_b64: str) -> str:
    mac = hmac.new(_secret(), payload_b64.encode("ascii"), sha256).digest()
    return _b64url_encode(mac)


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


class SignupProofConfigError(RuntimeError):
    """Raised when proof issuance is attempted without a dedicated secret."""


def issue_signup_proof(email: str, *, operation: str = "signup", client_id: str = "",
                       ttl_seconds: int | None = None) -> str:
    """Create a signed, short-lived proof bound to email/operation/client.

    Requires a dedicated SIGNUP_PROOF_SECRET; it never falls back to
    SECRET_KEY. Fails closed (raises) when the secret is absent.
    """
    if not _secret():
        raise SignupProofConfigError("SIGNUP_PROOF_SECRET is not configured")
    now = int(time.time())
    ttl = ttl_seconds if ttl_seconds is not None else getattr(settings, "SIGNUP_PROOF_TTL_SECONDS", 300)
    payload = {
        "v": _VERSION,
        "em": normalize_email(email),
        "op": operation,
        "cid": client_id or "",
        "iat": now,
        "exp": now + int(ttl),
        "jti": uuid.uuid4().hex,
    }
    # Canonical JSON: sorted keys, no spaces — the Lambda must serialize the same way.
    payload_b64 = _b64url_encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return f"v{_VERSION}.{payload_b64}.{_sign(payload_b64)}"


@dataclass(frozen=True)
class ProofResult:
    valid: bool
    reason: str = ""
    payload: dict | None = None


def verify_signup_proof(proof: str, *, email: str, operation: str = "signup",
                        client_id: str = "", consume_nonce=None, now: int | None = None) -> ProofResult:
    """Verify a proof's signature, binding, and expiry.

    `consume_nonce(jti, exp) -> bool` is the atomic single-use hook for the
    shared replay store; when omitted, replay protection is PENDING (signature
    + binding + expiry only). Returns ProofResult.
    """
    if not proof or not isinstance(proof, str):
        return ProofResult(False, "missing_proof")

    parts = proof.split(".")
    if len(parts) != 3 or parts[0] != f"v{_VERSION}":
        return ProofResult(False, "malformed")
    _, payload_b64, sig = parts

    # Constant-time signature check before trusting any payload bytes.
    if not hmac.compare_digest(sig, _sign(payload_b64)):
        return ProofResult(False, "bad_signature")

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        return ProofResult(False, "malformed_payload")

    ts = int(now if now is not None else time.time())
    if int(payload.get("exp", 0)) < ts:
        return ProofResult(False, "expired", payload)
    # Reject proofs issued in the future beyond small clock skew (tamper / bad clock).
    if int(payload.get("iat", 0)) > ts + 60:
        return ProofResult(False, "future_issued", payload)
    if payload.get("op") != operation:
        return ProofResult(False, "op_mismatch", payload)
    if normalize_email(email) != payload.get("em"):
        return ProofResult(False, "email_mismatch", payload)
    if client_id and payload.get("cid") != client_id:
        return ProofResult(False, "client_mismatch", payload)

    if consume_nonce is not None:
        try:
            if not consume_nonce(payload.get("jti", ""), int(payload.get("exp", 0))):
                return ProofResult(False, "replayed", payload)
        except Exception:
            # Fail closed if the replay store is required but unavailable.
            return ProofResult(False, "nonce_store_error", payload)

    return ProofResult(True, "ok", payload)
