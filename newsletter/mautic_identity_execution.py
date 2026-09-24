"""Shared asserted-user execution helpers for interactive Mautic mutations."""

from __future__ import annotations

from typing import Any, Callable

from .mautic import MauticClient
from .mautic.exceptions import MauticBridgeRejectedError, MauticIdentityError
from .mautic.identity import MauticExecutionContext, get_mautic_client
from .mautic_identity_audit import (
    correlation_id_for_request,
    record_identity_audit,
    record_identity_failure,
)
from .mautic_identity_errors import identity_error_response
from .models import MauticIdentityAuditLog


def interactive_mautic_client(request, correlation_id, *, client_factory=MauticClient):
    return get_mautic_client(
        actor=request.user,
        purpose=MauticExecutionContext.INTERACTIVE,
        client_factory=client_factory,
        correlation_id=correlation_id,
    )


def asserted_client_or_none(client):
    """Return the client only when it carries a human identity.

    In SERVICE_ACCOUNT mode the interactive factory still hands back a perfectly
    usable client, but injecting it would move where the service layer gets its
    client from. Returning None instead lets the service build its own, so the
    flag-off path stays exactly what it was before asserted execution existed.
    """
    return client if getattr(client, "_uses_asserted_user", lambda: False)() else None


def asserted_user_id(client):
    identity = getattr(client, "execution_identity", None)
    try:
        value = int(getattr(identity, "mautic_user_id", None))
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def auth_mode_label(client) -> str:
    identity = getattr(client, "execution_identity", None)
    mode = getattr(identity, "auth_mode", None)
    value = getattr(mode, "value", mode)
    return value if isinstance(value, str) else ""


def assertion_jti(client) -> str:
    value = getattr(client, "last_assertion_jti", "")
    return value if isinstance(value, str) else ""


def with_correlation(response, correlation_id):
    if correlation_id:
        response["X-ECP-Correlation-Id"] = str(correlation_id)
    return response


def run_interactive_mutation(
    request,
    *,
    action: str,
    resource: str,
    resource_id: Any = "",
    mutate: Callable[[MauticClient], Any],
    client_factory=MauticClient,
    audit_and_reraise: tuple = (),
):
    """Run one interactive Mautic mutation and audit who did it.

    ``audit_and_reraise`` names provider/service exception classes that should
    also produce a failed audit row before propagating unchanged. It defaults to
    an empty tuple, which never matches, so every existing caller keeps its
    current behaviour and unrelated application errors are not reclassified as
    identity failures. Callers opt in explicitly for the provider errors their
    own service layer raises.
    """
    correlation_id = correlation_id_for_request(request)
    try:
        client = interactive_mautic_client(
            request,
            correlation_id,
            client_factory=client_factory,
        )
    except MauticIdentityError as exc:
        record_identity_failure(
            action=action,
            exc=exc,
            actor=request.user,
            resource=resource,
            resource_id=resource_id,
            correlation_id=correlation_id,
        )
        return None, with_correlation(identity_error_response(exc), correlation_id)

    try:
        result = mutate(client)
    except (MauticBridgeRejectedError, MauticIdentityError) as exc:
        record_identity_failure(
            action=action,
            exc=exc,
            actor=request.user,
            mautic_user_id=asserted_user_id(client),
            resource=resource,
            resource_id=resource_id,
            auth_mode=auth_mode_label(client),
            correlation_id=correlation_id,
            assertion_jti=assertion_jti(client),
        )
        return None, with_correlation(identity_error_response(exc), correlation_id)
    except audit_and_reraise as exc:
        # The provider refused the operation. Record who attempted it, then let
        # the original exception through so the view's status code and body are
        # untouched. Listed after the identity branch above, so an identity or
        # bridge failure can never be audited twice.
        record_identity_failure(
            action=action,
            exc=exc,
            actor=request.user,
            mautic_user_id=asserted_user_id(client),
            resource=resource,
            resource_id=resource_id,
            auth_mode=auth_mode_label(client),
            correlation_id=correlation_id,
            assertion_jti=assertion_jti(client),
        )
        raise

    record_identity_audit(
        action=action,
        status=MauticIdentityAuditLog.Status.SUCCEEDED,
        actor=request.user,
        mautic_user_id=asserted_user_id(client),
        resource=resource,
        resource_id=resource_id,
        auth_mode=auth_mode_label(client),
        correlation_id=correlation_id,
        assertion_jti=assertion_jti(client),
    )
    return result, None
