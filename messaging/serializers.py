from __future__ import annotations
from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Conversation, Message

User = get_user_model()


class ConversationSerializer(serializers.ModelSerializer):
    # existing computed fields
    participant_ids = serializers.SerializerMethodField()
    last_message = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()

    # explicitly bind method names so DRF never looks for get_<field>
    chat_type = serializers.SerializerMethodField(method_name="compute_chat_type")
    display_title = serializers.SerializerMethodField(method_name="compute_display_title")

    # handy pass-throughs for FE if you want them
    event_title = serializers.CharField(source="event.title", read_only=True, default=None)
    group_name = serializers.CharField(source="group.name", read_only=True, default=None)

    class Meta:
        model = Conversation
        fields = [
            "id",
            "is_group",
            "is_event_group",
            "group",
            "event",
            "room_key",
            "title",          # keep for compatibility; UI should not use this
            "display_title",  # UI: use this
            "event_title",
            "group_name",
            "chat_type",
            "participant_ids",
            "last_message",
            "unread_count",
            "updated_at",
            "created_at",
            "created_by",
        ]
        read_only_fields = fields

    # ---------- backing methods ----------
    def compute_chat_type(self, obj):
        if obj.is_event_group:
            return "event"
        if obj.is_group:
            return "group"
        return "dm"

    def compute_display_title(self, obj):
        # Event chat → Event.title
        if obj.is_event_group:
            return (getattr(obj.event, "title", "") or "Event").strip()
        # Group chat → Group.name (optionally fall back to Conversation.title if FK missing)
        if obj.is_group:
            return (
                getattr(obj.group, "name", "")
                or "Group"
            )

        # --- DM label (other user's name) ---
        req = self.context.get("request")
        me_id = getattr(getattr(req, "user", None), "id", None)
        other_id = None
        if obj.user1_id and obj.user2_id:
            other_id = obj.user2_id if obj.user1_id == me_id else obj.user1_id
        if other_id:
            try:
                other = User.objects.select_related("profile").get(pk=other_id)
                prof = getattr(other, "profile", None)
                full = (getattr(prof, "full_name", "") or other.get_full_name() or other.username or "").strip()
                return full or "Direct Message"
            except User.DoesNotExist:
                pass
        return "Direct Message"

    def get_participant_ids(self, obj: Conversation) -> list[int]:
        if obj.is_group or obj.is_event_group:
            return []
        return [obj.user1_id, obj.user2_id]

    def get_last_message(self, obj: Conversation) -> str:
        msg = (
            obj.messages.filter(is_hidden=False, is_deleted=False)
            .order_by("-created_at")
            .first()
        )
        return msg.body[:80] if msg else ""

    def get_unread_count(self, obj: Conversation) -> int:
        user = self.context.get("request").user if self.context.get("request") else None
        if not user or not user.is_authenticated:
            return 0
        return (
            obj.messages.filter(is_hidden=False, is_deleted=False, is_read=False)
            .exclude(sender_id=user.id)
            .count()
        )


class MessageSerializer(serializers.ModelSerializer):
    sender_id = serializers.IntegerField(read_only=True)
    conversation_id = serializers.IntegerField(read_only=True)
    sender_name = serializers.SerializerMethodField()
    sender_display = serializers.SerializerMethodField()
    mine = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "id",
            "conversation_id",
            "sender_id",
            "sender_name",
            "sender_display",
            "mine",
            "body",
            "attachments",
            "is_read",
            "is_hidden",
            "is_deleted",
            "deleted_at",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "conversation_id",
            "sender_id",
            "is_read",
            "is_hidden",
            "is_deleted",
            "deleted_at",
            "created_at",
        ]

    def get_sender_name(self, obj):
        u = getattr(obj, "sender", None)
        if not u:
            return ""
        prof = getattr(u, "profile", None)
        full = (getattr(prof, "full_name", "") or u.get_full_name() or u.username or "").strip()
        return full

    def get_sender_display(self, obj):
        return self.get_sender_name(obj)

    def get_mine(self, obj):
        req = self.context.get("request")
        user = getattr(req, "user", None)
        return bool(user and user.is_authenticated and obj.sender_id == user.id)

    def validate_attachments(self, value):
        if not value:
            return []
        if not isinstance(value, list):
            raise serializers.ValidationError("Attachments must be a list of objects.")
        for item in value:
            if not isinstance(item, dict):
                raise serializers.ValidationError("Each attachment must be an object.")
            url = item.get("url")
            if url is not None and not isinstance(url, str):
                raise serializers.ValidationError("Attachment 'url' must be a string.")
        return value
