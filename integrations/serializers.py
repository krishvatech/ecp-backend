"""
Serializers for the integrations app.

Expose integration configurations and sync logs via the API while
ensuring that sensitive secrets are never exposed in responses.
"""
from __future__ import annotations

from rest_framework import serializers
from organizations.models import Organization
from .models import IntegrationConfig, SyncLog


class IntegrationConfigSerializer(serializers.ModelSerializer):
    """Serializer for IntegrationConfig.

    Secrets are write-only to avoid leaking sensitive tokens.  The
    serializer accepts a plain dict for secrets on creation and
    update.  Organization ID must be provided explicitly.
    """

    organization_id = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(), source="organization"
    )
    secrets = serializers.JSONField(write_only=True, required=False)

    class Meta:
        model = IntegrationConfig
        fields = [
            "id",
            "organization_id",
            "type",
            "enabled",
            "secrets",
            "settings",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        # Remove secrets from representation
        rep.pop("secrets", None)
        return rep


class SyncLogSerializer(serializers.ModelSerializer):
    """Read-only serializer for SyncLog records."""

    organization_id = serializers.IntegerField(source="organization.id", read_only=True)

    class Meta:
        model = SyncLog
        fields = [
            "id",
            "organization_id",
            "integration_type",
            "status",
            "payload_snippet",
            "error",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields
