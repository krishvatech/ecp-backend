"""High-level Marketing Access endpoints for the Users admin area.

The frontend expresses intent ("give this ECP user Marketing access") and never
supplies a ``mautic_user_id``: provisioning and identity resolution belong to
the backend. The low-level connection endpoints stay available for explicit
administrator linking and diagnostics.

Audit distinguishes the *manager* performing the action (``actor``) from the
*target* whose mapping changes (``resource_id`` / ``detail``).
"""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .mautic.exceptions import MauticIdentityError
from .mautic_identity_audit import correlation_id_for_request, record_identity_audit
from .mautic_identity_errors import classify_identity_error, identity_error_response
from .marketing_access_services import (
    MarketingGrantResult,
    describe_marketing_access,
    grant_marketing_access,
    latest_connection_for,
    list_marketing_access,
    marketing_status_for_actor,
    revoke_marketing_access,
)
from .marketing_permissions import CanManageMarketingAccess
from .models import MauticIdentityAuditLog

User = get_user_model()


def _target_or_404(ecp_user_id):
    return User.objects.filter(pk=ecp_user_id).first()


def _audit_failure(*, action, exc, actor, target_id, connection, correlation_id):
    http_status, code, _ = classify_identity_error(exc)
    record_identity_audit(
        action=action,
        status=(
            MauticIdentityAuditLog.Status.DENIED
            if http_status in (401, 403, 409)
            else MauticIdentityAuditLog.Status.FAILED
        ),
        actor=actor,
        mautic_user_id=connection.mautic_user_id if connection else None,
        resource="mautic_user_connection",
        resource_id=connection.pk if connection else "",
        correlation_id=correlation_id,
        error_code=code,
        detail=f"target_ecp_user_id={target_id}",
    )


class NewsletterAdminMarketingAccessListView(APIView):
    """Everyone who may hold Marketing access, plus their current state."""

    permission_classes = [CanManageMarketingAccess]

    def get(self, request):
        results = list_marketing_access()
        return Response(
            {
                "count": len(results),
                "results": results,
                "per_user_execution_enabled": marketing_status_for_actor(request.user)[
                    "per_user_execution_enabled"
                ],
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminMarketingAccessGrantView(APIView):
    """Add (or re-enable) Marketing access for one ECP superuser."""

    permission_classes = [CanManageMarketingAccess]

    def post(self, request, ecp_user_id):
        target = _target_or_404(ecp_user_id)
        if target is None:
            return Response(
                {"detail": "ECP user does not exist.", "code": "target_not_found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        correlation_id = correlation_id_for_request(request)
        try:
            result = grant_marketing_access(target, actor=request.user)
        except MauticIdentityError as exc:
            _audit_failure(
                action=MauticIdentityAuditLog.Action.CONNECTION_CREATE,
                exc=exc,
                actor=request.user,
                target_id=target.pk,
                connection=latest_connection_for(target),
                correlation_id=correlation_id,
            )
            return identity_error_response(exc)

        connection = result.connection
        record_identity_audit(
            action=(
                MauticIdentityAuditLog.Action.CONNECTION_ACTIVATE
                if result.outcome == MarketingGrantResult.REACTIVATED
                else MauticIdentityAuditLog.Action.CONNECTION_CREATE
            ),
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            actor=request.user,
            mautic_user_id=connection.mautic_user_id,
            resource="mautic_user_connection",
            resource_id=connection.pk,
            correlation_id=correlation_id,
            detail=f"target_ecp_user_id={target.pk} outcome={result.outcome}",
        )
        return Response(
            {
                "outcome": result.outcome,
                **describe_marketing_access(target, connection),
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminMarketingAccessRevokeView(APIView):
    """Remove Marketing access. History and the provider identity are kept."""

    permission_classes = [CanManageMarketingAccess]

    def post(self, request, ecp_user_id):
        target = _target_or_404(ecp_user_id)
        if target is None:
            return Response(
                {"detail": "ECP user does not exist.", "code": "target_not_found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        correlation_id = correlation_id_for_request(request)
        reason = str(request.data.get("reason") or "").strip()[:255]
        try:
            connection = revoke_marketing_access(target, actor=request.user, reason=reason)
        except MauticIdentityError as exc:
            _audit_failure(
                action=MauticIdentityAuditLog.Action.CONNECTION_DEACTIVATE,
                exc=exc,
                actor=request.user,
                target_id=target.pk,
                connection=latest_connection_for(target),
                correlation_id=correlation_id,
            )
            return identity_error_response(exc)

        record_identity_audit(
            action=MauticIdentityAuditLog.Action.CONNECTION_DEACTIVATE,
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            actor=request.user,
            mautic_user_id=connection.mautic_user_id,
            resource="mautic_user_connection",
            resource_id=connection.pk,
            correlation_id=correlation_id,
            detail=f"target_ecp_user_id={target.pk}",
        )
        return Response(
            describe_marketing_access(target, connection),
            status=status.HTTP_200_OK,
        )


class NewsletterMarketingAccessMeView(APIView):
    """Authoritative Marketing status for the authenticated user.

    Any authenticated user may read their own status: a non-eligible user gets
    ``eligible: false`` rather than a 403, so the frontend can hide Marketing
    Hub without guessing from ``is_superuser``.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(
            marketing_status_for_actor(request.user),
            status=status.HTTP_200_OK,
        )
