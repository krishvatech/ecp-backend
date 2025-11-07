"""
Serializers for the messaging app.

Define representations for Conversation and Message objects, as well as
validation logic for creating new messages. Conversations include
participant identifiers (for DMs), a snippet of the most recent message
and the unread message count for the requesting user.
"""
from __future__ import annotations

from rest_framework import serializers
from .models import Conversation, Message
from django.contrib.auth import get_user_model
User = get_user_model()

class ConversationSerializer(serializers.ModelSerializer):
    """Serializer for listing and retrieving conversations."""

    participant_ids = serializers.SerializerMethodField()
    last_message = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()

    # NEW:
    chat_type = serializers.SerializerMethodField()
    display_title = serializers.SerializerMethodField()

    class Meta:
        model = Conversation
        fields = [
            "id",
            "is_group",
            "is_event_group",      # <- include, FE may want it
            "group",               # optional: useful IDs for headers
            "event",
            "room_key",
            "title",
            "display_title",       # <- NEW
            "chat_type",           # <- NEW
            "participant_ids",
            "last_message",
            "unread_count",
            "updated_at",
            "created_at",
            "created_by",
        ]
        read_only_fields = fields

    def get_chat_type(self, obj):
        if obj.is_group:
            return "group"
        if obj.is_event_group:
            return "event"
        return "dm"

    def get_display_title(self, obj: Conversation) -> str:
        # For DMs: show other user. For Group/Event: fallback to title/name.
        if obj.is_group:
            return obj.title or getattr(obj.group, "name", "") or "Group"
        if obj.is_event_group:
            return obj.title or getattr(obj.event, "title", "") or "Event chat"
        # DM:
        req = self.context.get("request")
        me_id = getattr(getattr(req, "user", None), "id", None)
        other_id = None
        if obj.user1_id and obj.user2_id:
            other_id = obj.user2_id if obj.user1_id == me_id else obj.user1_id
        if other_id:
            try:
                other = User.objects.select_related("profile").get(pk=other_id)
                prof = getattr(other, "profile", None)
                if prof and getattr(prof, "full_name", ""):
                    return prof.full_name.strip()
                full = (other.get_full_name() or "").strip()
                return full or other.username
            except User.DoesNotExist:
                pass
        return "Direct Message"

    def get_participant_ids(self, obj: Conversation) -> list[int]:
        if obj.is_group or obj.is_event_group:
            return []
        return [obj.user1_id, obj.user2_id]

    def get_last_message(self, obj: Conversation) -> str:
        msg = (
            obj.messages
              .filter(is_hidden=False, is_deleted=False)
              .order_by("-created_at")
              .first()
        )
        return msg.body[:80] if msg else ""

    def get_unread_count(self, obj: Conversation) -> int:
        user = self.context.get("request").user if self.context.get("request") else None
        if not user or not user.is_authenticated:
            return 0
        # global is_read (not per-user receipts); exclude my own
        return obj.messages.filter(is_hidden=False, is_deleted=False, is_read=False).exclude(sender_id=user.id).count()

class MessageSerializer(serializers.ModelSerializer):
    sender_id = serializers.IntegerField(read_only=True)
    conversation_id = serializers.IntegerField(read_only=True)
    sender_name = serializers.SerializerMethodField()

    # NEW:
    mine = serializers.SerializerMethodField()
    sender_display = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "id",
            "conversation_id",
            "sender_id",
            "sender_name",      # keep for backward-compat
            "sender_display",   # NEW (same value; FE will use this)
            "mine",             # NEW
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
        # unchanged
        u = getattr(obj, "sender", None)
        if not u:
            return ""
        prof = getattr(u, "profile", None)
        full_name = ""
        if prof:
            full_name = (getattr(prof, "full_name", "") or "").strip()
        if full_name:
            return full_name
        full = (u.get_full_name() or "").strip()
        return full or u.username

    def get_sender_display(self, obj):
        # same as sender_name; FE will decide visibility based on chat_type
        return self.get_sender_name(obj)

    def get_mine(self, obj):
        req = self.context.get("request")
        user = getattr(req, "user", None)
        return bool(user and user.is_authenticated and obj.sender_id == user.id)

    def validate_attachments(self, value):
        """Ensure attachments is a list of objects with optional url fields."""
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
