"""
Serializers for the organizations app.

Provides a serializer that returns organization details including a
read-only `owner_id` and computed `members_count`.  On creation, the
requesting user is set as the owner automatically.
"""
from rest_framework import serializers

from .models import Organization


class OrganizationSerializer(serializers.ModelSerializer):
    """Serializer for the Organization model."""
    owner_id = serializers.IntegerField(read_only=True)
    members_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Organization
        fields = [
            "id",
            "name",
            "slug",
            "description",
            "owner_id",
            "members",
            "members_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "slug", "owner_id", "members_count", "created_at", "updated_at"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["members_count"] = instance.members.count()
        data["owner_id"] = instance.owner_id
        return data

    def create(self, validated_data):
        user = self.context["request"].user
        org = Organization.objects.create(owner=user, **validated_data)
        return org