"""POST /api/marketing/internal/consent/verify/ — read-only consent decisions for
the ECP Marketing Bridge plugin in Mautic (see consent_service_auth and
authoritative_consent).

Machine-to-machine only: no session, no cookies, no browser. The signature over
method, path and the exact body is mandatory on every request, including on an
internal network; CSRF protection does not apply to a cookie-less signed
request, so the view is exempt. Request bodies are bounded and validated
strictly; decisions carry low-cardinality reason codes and never subscription
details or personal data.
"""

from __future__ import annotations

import json
import logging
import time

from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .authoritative_consent import MAX_CONTACTS, MAX_MERGED_IDS, ConsentLookupUnavailable, decide
from .consent_service_auth import HEADER, ISSUER, ConsentAuthError, ConsentAuthUnavailable, authenticate
from .mautic_identity_audit import record_identity_audit
from .models import MauticIdentityAuditLog

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 32 * 1024
AUDIT_ACTION = "consent.verify"
#: Unauthenticated failures are written to the audit table at most this many
#: times per minute per reason code (shared Redis counter); the rest are logged.
AUTH_FAILURE_AUDIT_PER_MINUTE = 30
AUTH_FAILURE_COUNTER = "ecp-consent-auth-failure-audit:{code}:{window}"
_TOP_LEVEL = {"campaign_id", "event_id", "contacts"}
_CONTACT = {"id", "merged_ids"}


class RequestInvalid(ValueError):
    pass


def _positive_int(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 2**53:
        raise RequestInvalid(f"{field} must be a positive integer")
    return value


def parse_request(body: bytes) -> dict:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RequestInvalid("invalid JSON") from exc
    if not isinstance(data, dict) or set(data) != _TOP_LEVEL:
        raise RequestInvalid("unexpected fields")
    contacts = data["contacts"]
    if not isinstance(contacts, list) or not 1 <= len(contacts) <= MAX_CONTACTS:
        raise RequestInvalid(f"contacts must hold 1 to {MAX_CONTACTS} entries")
    parsed, seen = [], set()
    for entry in contacts:
        if not isinstance(entry, dict) or not set(entry) <= _CONTACT or "id" not in entry:
            raise RequestInvalid("malformed contact")
        contact_id = _positive_int(entry["id"], "contact id")
        if contact_id in seen:
            raise RequestInvalid("duplicate contact")
        seen.add(contact_id)
        merged = entry.get("merged_ids", [])
        if not isinstance(merged, list) or len(merged) > MAX_MERGED_IDS:
            raise RequestInvalid(f"merged_ids must hold at most {MAX_MERGED_IDS} entries")
        merged = [_positive_int(m, "merged id") for m in merged]
        if len(set(merged)) != len(merged) or contact_id in merged:
            raise RequestInvalid("ambiguous merged_ids")
        parsed.append({"id": contact_id, "merged_ids": merged})
    return {
        "campaign_id": _positive_int(data["campaign_id"], "campaign_id"),
        "event_id": _positive_int(data["event_id"], "event_id"),
        "contacts": parsed,
    }


def _audit_auth_failure(code: str) -> None:
    """A refused, unauthenticated request. Anyone can send these, so the audit
    table only takes a bounded number per minute; every one is logged with its
    fixed reason code (never the token, key id or body)."""
    logger.warning("Consent verification refused: unauthenticated (%s)", code)
    try:
        budget = int(getattr(settings, "ECP_CONSENT_AUTH_FAILURE_AUDIT_PER_MINUTE", AUTH_FAILURE_AUDIT_PER_MINUTE))
    except (TypeError, ValueError):
        budget = AUTH_FAILURE_AUDIT_PER_MINUTE
    key = AUTH_FAILURE_COUNTER.format(code=code, window=int(time.time() // 60))
    try:
        cache.add(key, 0, timeout=70)
        count = cache.incr(key)
    except Exception:  # no shared counter: do not let unauthenticated traffic write rows
        logger.warning("Consent verification: auth-failure audit budget unavailable; not recorded in the audit table")
        return
    if count <= budget:
        _audit(MauticIdentityAuditLog.Status.DENIED, error_code=f"auth:{code}"[:64])
    elif count == budget + 1:
        logger.warning("Consent verification: more than %s unauthenticated refusals this minute (%s); further ones are logged only", budget, code)


def _error(status: int, code: str) -> JsonResponse:
    return JsonResponse({"error": code}, status=status)


def _audit(status: str, *, caller=None, resource_id="", error_code="", detail=""):
    record_identity_audit(
        action=AUDIT_ACTION,
        status=status,
        resource="consent",
        resource_id=resource_id,
        auth_mode=f"service:{ISSUER}"[:32],
        assertion_jti=getattr(caller, "jti", ""),
        error_code=error_code,
        detail=detail,
    )


@csrf_exempt  # cookie-less, signed service request; see module docstring
@require_POST
def consent_verify_view(request):
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        return _error(400, "invalid_request")
    if length > MAX_BODY_BYTES:
        return _error(413, "request_too_large")
    body = request.body
    if len(body) > MAX_BODY_BYTES:
        return _error(413, "request_too_large")

    try:
        caller = authenticate(method=request.method, path=request.path, body=body, token=request.headers.get(HEADER))
    except ConsentAuthError as exc:
        _audit_auth_failure(exc.code)
        return _error(401, exc.code)
    except ConsentAuthUnavailable as exc:
        logger.error("Consent verification unavailable: %s", exc.code)
        return _error(503, exc.code)

    try:
        payload = parse_request(body)
    except RequestInvalid:
        _audit(MauticIdentityAuditLog.Status.DENIED, caller=caller, error_code="invalid_request")
        return _error(400, "invalid_request")

    resource_id = f"{payload['campaign_id']}:{payload['event_id']}"
    try:
        decisions = decide(payload["campaign_id"], payload["event_id"], payload["contacts"])
    except ConsentLookupUnavailable as exc:
        logger.warning("Consent verification could not read Mautic: %s", exc)
        _audit(MauticIdentityAuditLog.Status.FAILED, caller=caller, resource_id=resource_id, error_code=str(exc)[:64])
        return _error(503, "upstream_unavailable")

    counts = {}
    for decision in decisions:
        counts[(decision["decision"], decision["reason"])] = counts.get((decision["decision"], decision["reason"]), 0) + 1
    summary = " ".join(f"{d}:{r}={n}" for (d, r), n in sorted(counts.items()))[:255]
    logger.info("Consent verification campaign_event=%s %s", resource_id, summary)
    if any(d["decision"] != "ALLOW" for d in decisions):
        # Refusals are audited (ids and reason codes only); allows are counted in logs.
        _audit(MauticIdentityAuditLog.Status.SUCCEEDED, caller=caller, resource_id=resource_id, detail=summary)
    return JsonResponse({"decisions": decisions})
