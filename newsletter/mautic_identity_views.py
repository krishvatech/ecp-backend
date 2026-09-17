"""Staff-only Marketing Hub Mautic identity endpoints.

Covers the mapping lifecycle (create / activate / deactivate / view) and the
audit trail. No endpoint here accepts or returns credentials, tokens or keys.
"""

from django.contrib.auth import get_user_model
from django.core.paginator import Paginator
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser, IsSuperuser

from .mautic.exceptions import MauticIdentityError
from .mautic_identity_audit import correlation_id_for_request, record_identity_audit
from .mautic_identity_errors import identity_error_response
from .mautic_identity_serializers import (
    MauticIdentityAuditLogSerializer,
    MauticUserConnectionCreateSerializer,
    MauticUserConnectionDeactivateSerializer,
)
from .mautic_identity_services import (
    activate_mautic_user_connection,
    connect_mautic_user,
    deactivate_mautic_user_connection,
    describe_mautic_user_connection,
    get_mautic_identity_connection_status,
    get_mautic_user_connection_or_raise,
)
from .models import MauticIdentityAuditLog, MauticUserConnection

User = get_user_model()

MAX_PAGE_SIZE = 100


def _page_params(request, default_size=25):
    try:
        page = max(1, int(request.query_params.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = int(request.query_params.get("page_size", default_size))
    except (TypeError, ValueError):
        page_size = default_size
    return page, max(1, min(page_size, MAX_PAGE_SIZE))


class NewsletterAdminMauticIdentityStatusView(APIView):
    """Connection state for the authenticated user."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        return Response(
            get_mautic_identity_connection_status(request.user),
            status=status.HTTP_200_OK,
        )


class NewsletterAdminMauticConnectionListCreateView(APIView):
    """List every Mautic user connection, or create/refresh one."""

    permission_classes = [IsSuperuser]

    def get(self, request):
        connections = MauticUserConnection.objects.select_related("user").all()

        active = str(request.query_params.get("is_active", "") or "").strip().lower()
        if active in {"true", "1", "yes"}:
            connections = connections.filter(is_active=True)
        elif active in {"false", "0", "no"}:
            connections = connections.filter(is_active=False)

        ecp_user_id = str(request.query_params.get("ecp_user_id", "") or "").strip()
        if ecp_user_id.isdigit():
            connections = connections.filter(user_id=int(ecp_user_id))

        page, page_size = _page_params(request)
        paginator = Paginator(connections, page_size)
        rows = paginator.get_page(page)

        return Response(
            {
                "count": paginator.count,
                "page": rows.number,
                "page_size": page_size,
                "num_pages": paginator.num_pages,
                "results": [describe_mautic_user_connection(row) for row in rows],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        serializer = MauticUserConnectionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        target = serializer.target_user

        correlation_id = correlation_id_for_request(request)
        try:
            connection = connect_mautic_user(
                target,
                mautic_user_id=data["mautic_user_id"],
                created_by=request.user,
            )
        except MauticIdentityError as exc:
            return identity_error_response(exc)

        record_identity_audit(
            action=MauticIdentityAuditLog.Action.CONNECTION_CREATE,
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            actor=request.user,
            mautic_user_id=connection.mautic_user_id,
            resource="mautic_user_connection",
            resource_id=connection.pk,
            correlation_id=correlation_id,
            detail=f"ecp_user_id={connection.user_id}",
        )
        return Response(
            describe_mautic_user_connection(connection),
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminMauticConnectionDetailView(APIView):
    permission_classes = [IsSuperuser]

    def get(self, request, connection_id):
        try:
            connection = get_mautic_user_connection_or_raise(connection_id)
        except MauticIdentityError as exc:
            return identity_error_response(exc)
        return Response(
            describe_mautic_user_connection(connection),
            status=status.HTTP_200_OK,
        )


class NewsletterAdminMauticConnectionActivateView(APIView):
    permission_classes = [IsSuperuser]

    def post(self, request, connection_id):
        correlation_id = correlation_id_for_request(request)
        try:
            connection = activate_mautic_user_connection(
                get_mautic_user_connection_or_raise(connection_id),
                actor=request.user,
            )
        except MauticIdentityError as exc:
            return identity_error_response(exc)

        record_identity_audit(
            action=MauticIdentityAuditLog.Action.CONNECTION_ACTIVATE,
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            actor=request.user,
            mautic_user_id=connection.mautic_user_id,
            resource="mautic_user_connection",
            resource_id=connection.pk,
            correlation_id=correlation_id,
            detail=f"ecp_user_id={connection.user_id}",
        )
        return Response(
            describe_mautic_user_connection(connection),
            status=status.HTTP_200_OK,
        )


class NewsletterAdminMauticConnectionDeactivateView(APIView):
    permission_classes = [IsSuperuser]

    def post(self, request, connection_id):
        serializer = MauticUserConnectionDeactivateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        correlation_id = correlation_id_for_request(request)
        try:
            connection = deactivate_mautic_user_connection(
                get_mautic_user_connection_or_raise(connection_id),
                reason=serializer.validated_data.get("reason", ""),
            )
        except MauticIdentityError as exc:
            return identity_error_response(exc)

        record_identity_audit(
            action=MauticIdentityAuditLog.Action.CONNECTION_DEACTIVATE,
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            actor=request.user,
            mautic_user_id=connection.mautic_user_id,
            resource="mautic_user_connection",
            resource_id=connection.pk,
            correlation_id=correlation_id,
            detail=f"ecp_user_id={connection.user_id}",
        )
        return Response(
            describe_mautic_user_connection(connection),
            status=status.HTTP_200_OK,
        )


class NewsletterAdminMauticIdentityAuditView(APIView):
    """Read-only, queryable audit trail. Records are never mutated here."""

    permission_classes = [IsSuperuser]

    def get(self, request):
        entries = MauticIdentityAuditLog.objects.all()

        ecp_user_id = str(request.query_params.get("ecp_user_id", "") or "").strip()
        if ecp_user_id.isdigit():
            entries = entries.filter(ecp_user_id=int(ecp_user_id))

        mautic_user_id = str(request.query_params.get("mautic_user_id", "") or "").strip()
        if mautic_user_id.isdigit():
            entries = entries.filter(mautic_user_id=int(mautic_user_id))

        action = str(request.query_params.get("action", "") or "").strip()
        if action:
            entries = entries.filter(action=action)

        audit_status = str(request.query_params.get("status", "") or "").strip()
        if audit_status:
            entries = entries.filter(status=audit_status)

        correlation_id = str(request.query_params.get("correlation_id", "") or "").strip()
        if correlation_id:
            entries = entries.filter(correlation_id=correlation_id)

        page, page_size = _page_params(request)
        paginator = Paginator(entries, page_size)
        rows = paginator.get_page(page)

        return Response(
            {
                "count": paginator.count,
                "page": rows.number,
                "page_size": page_size,
                "num_pages": paginator.num_pages,
                "results": MauticIdentityAuditLogSerializer(rows, many=True).data,
            },
            status=status.HTTP_200_OK,
        )
