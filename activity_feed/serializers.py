"""
Serializers for the activity_feed app.

The ``FeedItemSerializer`` exposes read‑only representations of feed
entries.  It returns primary key IDs for the organization, event,
actor and target objects to minimize payload size.  Clients may use
the metadata field for display purposes without needing to resolve
generic relations on the backend.
"""
from rest_framework import serializers
from .models import FeedItem

class FeedItemSerializer(serializers.ModelSerializer):
    organization_id = serializers.IntegerField(read_only=True)
    event_id = serializers.IntegerField(read_only=True)
    actor_id = serializers.IntegerField(read_only=True)
    target_content_type_id = serializers.IntegerField(read_only=True)
    target_object_id = serializers.IntegerField(read_only=True)

    class Meta:
        model = FeedItem
        fields = [
            "id",
            "organization_id",
            "event_id",
            "actor_id",
            "verb",
            "target_content_type_id",
            "target_object_id",
            "metadata",
            "created_at",
        ]
        read_only_fields = fields
