"""
Serializers for the content app.

The ``ResourceSerializer`` exposes all fields on the ``Resource`` model
and enforces that the appropriate source field is provided based on the
resource type.  It also automatically sets the ``uploaded_by`` field
from the authenticated request user during creation.
"""
from rest_framework import serializers
from .models import Resource
from community.models import Community
from events.models import Event
from django.utils import timezone

class ResourceSerializer(serializers.ModelSerializer):
    # map request keys → actual FK fields via `source`
    community_id = serializers.PrimaryKeyRelatedField(
        source="community", queryset=Community.objects.all(),
        required=False, allow_null=True
    )
    event_id = serializers.PrimaryKeyRelatedField(
        source="event", queryset=Event.objects.all(),
        required=False, allow_null=True
    )
    uploaded_by_id = serializers.IntegerField(read_only=True)
    event_title = serializers.CharField(source="event.title", read_only=True)

    class Meta:
        model = Resource
        fields = [
            "id",
            "community_id", "event_id",
            "title", "description", "type",
            "file", "link_url", "video_url",
            "tags", "is_published", "publish_at",
            "uploaded_by_id", "created_at", "updated_at",
            "event_title",
        ]
        read_only_fields = ["id", "uploaded_by_id", "created_at", "updated_at"]

    def validate(self, data):
        # For creation, ensure event_id or community_id is provided
        if not self.instance:
            event = data.get("event")
            community = data.get("community")
            if not event and not community:
                raise serializers.ValidationError(
                    "Either event_id or community_id must be provided."
                )
            if event and not event.community:
                raise serializers.ValidationError(
                    "The selected event does not have a community."
                )

        rtype = data.get("type") or getattr(self.instance, "type", None)
        file = data.get("file")
        link = data.get("link_url")
        video = data.get("video_url")
        existing_file = getattr(self.instance, "file", None) if self.instance else None
        existing_link = getattr(self.instance, "link_url", None) if self.instance else None
        existing_video = getattr(self.instance, "video_url", None) if self.instance else None

        if rtype == Resource.TYPE_FILE:
            if not (file or existing_file):
                raise serializers.ValidationError({"file": "This field is required for file resources."})
        elif rtype == Resource.TYPE_LINK:
            if not (link or existing_link):
                raise serializers.ValidationError({"link_url": "This field is required for link resources."})
        elif rtype == Resource.TYPE_VIDEO:
            if not (video or existing_video):
                raise serializers.ValidationError({"video_url": "This field is required for video resources."})
        else:
            raise serializers.ValidationError({"type": "Invalid resource type."})

        if data.get("publish_at") and data["publish_at"] <= timezone.now():
            data["is_published"] = True
        return data

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # return raw ids for your UI
        data["community_id"] = instance.community_id
        data["event_id"] = instance.event_id
        return data

    def create(self, validated_data):
        user = self.context["request"].user
        validated_data.setdefault("uploaded_by", user)
        return Resource.objects.create(**validated_data)