"""
Serializers for the events app.

Provides a serializer for creating and updating events.  The
`organization_id` is required in the request body for creation.
"""
from rest_framework import serializers

from .models import Event


class EventSerializer(serializers.ModelSerializer):
    """Serializer for Event objects."""
    organization_id = serializers.IntegerField()
    created_by_id = serializers.IntegerField(read_only=True)

    class Meta:
        model = Event
        fields = [
            "id",
            "organization_id",
            "title",
            "slug",
            "description",
            "start_time",
            "end_time",
            "status",
            "is_live",
            "recording_url",
            "created_by_id",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "slug", "created_by_id", "created_at", "updated_at"]

    def create(self, validated_data):
        # Assign the creator automatically
        validated_data["created_by_id"] = self.context["request"].user.id
        return super().create(validated_data)