"""Audit trail for user-attributed Mautic operations.

Every asserted-user attempt is recorded, successful or not, so an operator can
answer "who did this in Mautic, and on whose behalf". Records are append-only
and never contain assertions, signatures, keys or credentials.
"""

from __future__ import annotations

import logging
import uuid

from .mautic_identity_errors import classify_identity_error
from .models import MauticIdentityAuditLog

logger = logging.getLogger(__name__)

CORRELATION_HEADER = "X-ECP-Correlation-Id"
_MAX_CORRELATION_LENGTH = 64


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def correlation_id_for_request(request) -> str:
    """Reuse an inbound correlation id when present, otherwise mint one.

    The inbound value is untrusted, so it is length-capped and restricted to
    characters that are safe to log and forward as a header.
    """
    raw = ""
    if request is not None:
        raw = str(request.headers.get(CORRELATION_HEADER, "") or "").strip()

    cleaned = "".join(char for char in raw if char.isalnum() or char in "-_")[
        :_MAX_CORRELATION_LENGTH
    ]
    return cleaned or new_correlation_id()


def _positive_int_or_none(value):
    """Audit input is defensive: a non-numeric value is dropped, never stored."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def record_identity_audit(
    *,
    action: str,
    status: str,
    actor=None,
    mautic_user_id=None,
    resource: str = "",
    resource_id="",
    auth_mode: str = "",
    correlation_id: str = "",
    assertion_jti: str = "",
    error_code: str = "",
    detail: str = "",
) -> MauticIdentityAuditLog | None:
    """Append one audit record. Never raises: auditing must not break an operation."""
    try:
        entry = MauticIdentityAuditLog.objects.create(
            ecp_user=actor if getattr(actor, "pk", None) else None,
            ecp_user_label=(actor.get_username() if getattr(actor, "pk", None) else "")[:191],
            mautic_user_id=_positive_int_or_none(mautic_user_id),
            action=action,
            resource=str(resource or "")[:64],
            resource_id=str(resource_id or "")[:64],
            status=status,
            auth_mode=str(auth_mode or "")[:32],
            correlation_id=str(correlation_id or "")[:64],
            assertion_jti=str(assertion_jti or "")[:128],
            error_code=str(error_code or "")[:64],
            detail=str(detail or "")[:255],
        )
    except Exception:
        logger.exception(
            "Failed to write Mautic identity audit record action=%s status=%s",
            action,
            status,
        )
        return None

    logger.info(
        "Mautic identity audit action=%s status=%s ecp_user_id=%s mautic_user_id=%s "
        "resource=%s resource_id=%s correlation_id=%s",
        action,
        status,
        entry.ecp_user_id,
        entry.mautic_user_id,
        entry.resource,
        entry.resource_id,
        entry.correlation_id,
    )
    return entry


def record_identity_failure(
    *,
    action: str,
    exc,
    actor=None,
    mautic_user_id=None,
    resource: str = "",
    resource_id="",
    auth_mode: str = "",
    correlation_id: str = "",
    assertion_jti: str = "",
) -> MauticIdentityAuditLog | None:
    """Audit a failure, classifying it with the shared error mapping."""
    http_status, code, _ = classify_identity_error(exc)
    status = (
        MauticIdentityAuditLog.Status.DENIED
        if http_status in (401, 403, 409)
        else MauticIdentityAuditLog.Status.FAILED
    )
    return record_identity_audit(
        action=action,
        status=status,
        actor=actor,
        mautic_user_id=mautic_user_id,
        resource=resource,
        resource_id=resource_id,
        auth_mode=auth_mode,
        correlation_id=correlation_id,
        assertion_jti=assertion_jti,
        error_code=code,
        # The exception type only: provider text may echo request content.
        detail=type(exc).__name__,
    )
