"""
Serializers for the analytics app.

Expose the MetricDaily model to the API.  Fields are read-only.
"""
from __future__ import annotations

from rest_framework import serializers
from .models import MetricDaily


class MetricDailySerializer(serializers.ModelSerializer):
    """Serializer for MetricDaily records."""

    organization_id = serializers.IntegerField(source="organization.id", allow_null=True, read_only=True)
    event_id = serializers.IntegerField(source="event.id", allow_null=True, read_only=True)

    class Meta:
        model = MetricDaily
        fields = [
            "id",
            "date",
            "organization_id",
            "event_id",
            "message_count",
            "resource_count",
            "registrations_count",
            "purchases_count",
            "revenue_cents",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields
