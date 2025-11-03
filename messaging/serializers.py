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


class ConversationSerializer(serializers.ModelSerializer):
    """Serializer for listing and retrieving conversations."""

    participant_ids = serializers.SerializerMethodField()
    last_message = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()

    class Meta:
        model = Conversation
        fields = [
            "id",
            "is_group",
            "room_key",
            "title",
            "participant_ids",
            "last_message",
            "unread_count",
            "updated_at",
            "created_at",
            "created_by",
        ]
        read_only_fields = fields

    def get_participant_ids(self, obj: Conversation) -> list[int]:
        if obj.is_group:
            return []
        return [obj.user1_id, obj.user2_id]

    def get_last_message(self, obj: Conversation) -> str:
        msg = obj.messages.first()
        return msg.body[:80] if msg else ""

    def get_unread_count(self, obj: Conversation) -> int:
        user = self.context.get("request").user if self.context.get("request") else None
        if not user or not user.is_authenticated:
            return 0
        # NOTE: "is_read" is global here; for real per-user read receipts you’d need a join table.
        return obj.messages.filter(is_read=False).exclude(sender_id=user.id).count()


class MessageSerializer(serializers.ModelSerializer):
    sender_id = serializers.IntegerField(read_only=True)
    conversation_id = serializers.IntegerField(read_only=True)
    sender_name = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "id",
            "conversation_id",
            "sender_id",
            "sender_name",
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
        """
        Best human-friendly name:
        1) User.profile.full_name (your OneToOne related_name="profile")
        2) user.get_full_name()
        3) username
        """
        u = getattr(obj, "sender", None)
        if not u:
            return ""
        # Try profile.full_name
        prof = getattr(u, "profile", None)
        full_name = ""
        if prof:
            full_name = (getattr(prof, "full_name", "") or "").strip()
        if full_name:
            return full_name

        # Fallbacks
        full = (u.get_full_name() or "").strip()
        return full or u.username

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
