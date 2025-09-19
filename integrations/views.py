"""
Views for the integrations app.

Provides endpoints to manage integration configurations for
organizations and to test the connection with HubSpot.  Only
authenticated organization owners or admins may create or modify
integration configs.  Secrets remain write-only.
"""
from __future__ import annotations

import requests
from django.conf import settings
from django.http import JsonResponse
from rest_framework import viewsets, permissions, status, views
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied, NotFound, ValidationError

from organizations.models import Organization
from .models import IntegrationConfig, SyncLog
from .serializers import IntegrationConfigSerializer, SyncLogSerializer


class IsOrgAdminPermission(permissions.BasePermission):
    """Ensures the requesting user is an admin/owner of the organization."""

    def has_object_permission(self, request, view, obj):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        return (
            user.is_staff
            or user.is_superuser
            or user.organizations.filter(id=obj.id).exists()
            or user.owned_organizations.filter(id=obj.id).exists()
        )


class IntegrationConfigViewSet(viewsets.ModelViewSet):
    """CRUD endpoints for IntegrationConfig objects."""

    queryset = IntegrationConfig.objects.all().select_related("organization")
    serializer_class = IntegrationConfigSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "id"

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        if user.is_staff or user.is_superuser:
            return qs
        # Only configs belonging to organizations where the user is a member/owner
        return qs.filter(
            organization__in=list(user.organizations.all())
        ) | qs.filter(
            organization__in=list(user.owned_organizations.all())
        )

    def perform_create(self, serializer):
        org = serializer.validated_data["organization"]
        user = self.request.user
        if not (
            user.is_staff
            or user.is_superuser
            or user.organizations.filter(id=org.id).exists()
            or user.owned_organizations.filter(id=org.id).exists()
        ):
            raise PermissionDenied("You do not have permission to configure integrations for this organization.")
        return serializer.save()

    def perform_update(self, serializer):
        instance = self.get_object()
        org = instance.organization
        user = self.request.user
        if not (
            user.is_staff
            or user.is_superuser
            or user.organizations.filter(id=org.id).exists()
            or user.owned_organizations.filter(id=org.id).exists()
        ):
            raise PermissionDenied("You do not have permission to update this integration config.")
        return serializer.save()


class TestConnectionView(views.APIView):
    """Test the connection to HubSpot for a given integration config."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Accept config ID or organization & type
        config_id = request.data.get("config_id")
        org_id = request.data.get("organization_id")
        integration_type = request.data.get("type", IntegrationConfig.TYPE_HUBSPOT)
        if config_id:
            try:
                config = IntegrationConfig.objects.get(pk=config_id)
            except IntegrationConfig.DoesNotExist:
                raise NotFound("Integration config not found.")
        else:
            if not org_id:
                raise ValidationError({"organization_id": "This field is required if config_id is not provided."})
            try:
                config = IntegrationConfig.objects.get(
                    organization_id=org_id, type=integration_type
                )
            except IntegrationConfig.DoesNotExist:
                raise NotFound("Integration config not found for organization.")
        user = request.user
        org = config.organization
        # Permission check
        if not (
            user.is_staff
            or user.is_superuser
            or user.organizations.filter(id=org.id).exists()
            or user.owned_organizations.filter(id=org.id).exists()
        ):
            raise PermissionDenied("You do not have permission to test this integration.")
        if config.type != IntegrationConfig.TYPE_HUBSPOT:
            return Response({"detail": "Unsupported integration type."}, status=status.HTTP_400_BAD_REQUEST)
        token = config.secrets.get("token")
        if not token:
            SyncLog.objects.create(
                organization_id=config.organization_id,
                integration_type=config.type,
                status="failure",
                payload_snippet=f"test-connection config_id={config.id}",
                error="Missing token",
            )
            return Response({"detail": "Missing token."}, status=status.HTTP_400_BAD_REQUEST)
        # Attempt to hit HubSpot authentication/health endpoint
        url = "https://api.hubapi.com/integrations/v1/me"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code < 300:
                SyncLog.objects.create(
                    organization_id=config.organization_id,
                    integration_type=config.type,
                    status="success",
                    payload_snippet=f"test-connection config_id={config.id}",
                    error="",
                )
                return Response({"status": "success"})
            else:
                detail = (resp.text or "")[:512]
                SyncLog.objects.create(
                    organization_id=config.organization_id,
                    integration_type=config.type,
                    status="failure",
                    payload_snippet=f"test-connection config_id={config.id}",
                    error=detail,
                )
                return Response({"status": "failed", "detail": detail}, status=status.HTTP_502_BAD_GATEWAY)
        except requests.RequestException as exc:
            SyncLog.objects.create(
                organization_id=config.organization_id,
                integration_type=config.type,
                status="failure",
                payload_snippet=f"test-connection config_id={config.id}",
                error=str(exc),
            )
            return Response({"status": "failed", "detail": str(exc)}, status=status.HTTP_502_BAD_GATEWAY)