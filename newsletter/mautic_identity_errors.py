"""Distinct, actionable responses for Mautic identity failures.

Phase 2 collapsed every identity problem into one generic 503, so an operator
could not tell "this user is not connected" from "the bridge is down". Each
condition now maps to its own status and stable machine-readable code.

Messages are safe to show: they never contain assertions, keys, credentials or
provider internals.
"""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response

from .mautic.exceptions import (
    MauticActorRequiredError,
    MauticBridgeRejectedError,
    MauticIdentityAssertionError,
    MauticIdentityConfigurationError,
    MauticIdentityError,
    MauticUserConnectionInactiveError,
    MauticUserConnectionMissingError,
    MauticUserVerificationInvalidError,
    MauticUserVerificationUnavailableError,
)

# Checked most-specific first; subclasses must precede their base.
_IDENTITY_ERROR_MAP = (
    (
        MauticUserConnectionMissingError,
        status.HTTP_409_CONFLICT,
        "mautic_user_not_connected",
        "Your ECP account is not connected to a Mautic user. Ask an administrator "
        "to connect it before performing this action.",
    ),
    (
        MauticUserConnectionInactiveError,
        status.HTTP_409_CONFLICT,
        "mautic_user_connection_inactive",
        "Your Mautic user connection is disabled. Ask an administrator to "
        "reactivate it before performing this action.",
    ),
    (
        MauticActorRequiredError,
        status.HTTP_403_FORBIDDEN,
        "mautic_actor_required",
        "An active Marketing Hub staff account is required for this action.",
    ),
    (
        MauticBridgeRejectedError,
        status.HTTP_403_FORBIDDEN,
        "mautic_permission_denied",
        "Your Mautic user is not allowed to perform this operation.",
    ),
    (
        MauticIdentityConfigurationError,
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "mautic_identity_not_configured",
        "Mautic identity signing is not configured. Contact an administrator.",
    ),
    (
        MauticIdentityAssertionError,
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "mautic_identity_assertion_failed",
        "A Mautic identity assertion could not be issued for this action.",
    ),
    (
        MauticUserVerificationInvalidError,
        status.HTTP_400_BAD_REQUEST,
        "mautic_user_verification_invalid",
        "The requested Mautic user could not be verified as an active usable user.",
    ),
    (
        MauticUserVerificationUnavailableError,
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "mautic_user_verification_unavailable",
        "Mautic user verification is temporarily unavailable. Try again later.",
    ),
)

_FALLBACK = (
    status.HTTP_400_BAD_REQUEST,
    "mautic_identity_error",
    "This Mautic identity request could not be completed.",
)


def classify_identity_error(exc) -> tuple[int, str, str]:
    """Return ``(http_status, code, detail)`` for an identity failure."""
    for error_type, http_status, code, detail in _IDENTITY_ERROR_MAP:
        if isinstance(exc, error_type):
            return http_status, code, detail

    # Base MauticIdentityError carries a curated validation message written in
    # our own services (for example "already connected to another ECP user"),
    # so it is surfaced instead of a generic string. Provider text never
    # reaches here: those cases are matched above.
    http_status, code, fallback_detail = _FALLBACK
    detail = str(exc).strip()[:255] if isinstance(exc, MauticIdentityError) else ""

    return http_status, code, detail or fallback_detail


def identity_error_response(exc) -> Response:
    http_status, code, detail = classify_identity_error(exc)
    return Response({"detail": detail, "code": code}, status=http_status)


def is_identity_error(exc) -> bool:
    return isinstance(exc, (MauticIdentityError, MauticBridgeRejectedError))
