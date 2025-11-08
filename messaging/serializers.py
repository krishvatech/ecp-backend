from __future__ import annotations
from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Conversation, Message

User = get_user_model()


class ConversationSerializer(serializers.ModelSerializer):
    # computed additions
    is_group = serializers.SerializerMethodField()
    is_event_group = serializers.SerializerMethodField()
    participant_ids = serializers.SerializerMethodField()
    last_message = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()
    context_cover = serializers.SerializerMethodField()
    group_cover   = serializers.SerializerMethodField()
    event_cover   = serializers.SerializerMethodField()
    context_logo  = serializers.SerializerMethodField()
    chat_type = serializers.SerializerMethodField(method_name="compute_chat_type")
    display_title = serializers.SerializerMethodField(method_name="compute_display_title")

    event_title = serializers.CharField(source="event.title", read_only=True, default=None)
    group_name  = serializers.CharField(source="group.name", read_only=True, default=None)

    class Meta:
        model = Conversation
        fields = [
            "id",
            "is_group", "is_event_group",
            "group", "event",
            "room_key",
            "title",
            "display_title", "context_cover", "context_logo", "group_cover", "event_cover",
            "event_title", "group_name",
            "chat_type",
            "participant_ids",
            "last_message",
            "unread_count",
            "updated_at", "created_at", "created_by",
        ]
        read_only_fields = fields

    # --- new getters for the flags ---
    def get_is_group(self, obj):         # noqa
        return bool(obj.group_id and not obj.event_id)

    def get_is_event_group(self, obj):   # noqa
        return bool(obj.event_id and not obj.group_id)

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
    
    def _urlish(self, v):
        try:
            url = getattr(v, "url", "") or str(v) or ""
        except Exception:
            url = str(v) if v else ""
        # build absolute URL when possible
        req = self.context.get("request")
        if req and url and url.startswith("/"):
            return req.build_absolute_uri(url)
        return url

    def get_group_cover(self, obj):
        if not obj.group_id:
            return ""
        g = getattr(obj, "group", None)
        if not g:
            return ""
        # Try common field names safely
        for name in ("cover_image", "banner", "banner_url", "cover", "header_image", "hero_image", "logo_url"):
            if hasattr(g, name):
                val = getattr(g, name)
                if isinstance(val, str):
                    if val:
                        return val
                else:
                    url = self._urlish(val)
                    if url:
                        return url
        return ""

    def get_event_cover(self, obj):
        if not obj.event_id:
            return ""
        e = getattr(obj, "event", None)
        if not e:
            return ""
        # Try common field names safely
        for name in ("banner_url", "cover_image", "poster", "thumbnail", "banner", "cover", "header_image", "hero_image"):
            if hasattr(e, name):
                val = getattr(e, name)
                if isinstance(val, str):
                    if val:
                        return val
                else:
                    url = self._urlish(val)
                    if url:
                        return url
        return ""

    def get_context_cover(self, obj):
        if obj.is_event_group:
            return self.get_event_cover(obj)
        if obj.is_group:
            return self.get_group_cover(obj)
        return ""

    def get_context_logo(self, obj):
        # Prefer a smaller emblem if present
        if obj.is_group:
            g = getattr(obj, "group", None)
            if g:
                for name in ("logo_url", "logo", "avatar", "image"):
                    if hasattr(g, name):
                        val = getattr(g, name)
                        if isinstance(val, str) and val:
                            return val
                        url = self._urlish(val)
                        if url:
                            return url
        if obj.is_event_group:
            e = getattr(obj, "event", None)
            if e:
                for name in ("thumbnail", "poster", "logo_url", "cover_image"):
                    if hasattr(e, name):
                        val = getattr(e, name)
                        if isinstance(val, str) and val:
                            return val
                        url = self._urlish(val)
                        if url:
                            return url
        return ""


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


# serializers.py
class MessageSerializer(serializers.ModelSerializer):
    sender_id = serializers.IntegerField(read_only=True)
    conversation_id = serializers.IntegerField(read_only=True)
    sender_name = serializers.SerializerMethodField()
    sender_display = serializers.SerializerMethodField()
    sender_avatar = serializers.SerializerMethodField()
    mine = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "id",
            "conversation_id",
            "sender_id",
            "sender_name",
            "sender_display",
            "sender_avatar",         
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
            "id", "conversation_id", "sender_id",
            "is_read", "is_hidden", "is_deleted",
            "deleted_at", "created_at",
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

    def get_sender_avatar(self, obj):
        u = getattr(obj, "sender", None)
        if not u:
            return ""
        prof = getattr(u, "profile", None)
        # prefer user_image / avatar from profile
        if prof:
            img = getattr(prof, "user_image", None) or getattr(prof, "avatar", None)
            if img:
                try:
                    url = getattr(img, "url", "") or str(img)
                except Exception:
                    url = str(img)
                # make absolute
                req = self.context.get("request")
                if req and url and url.startswith("/"):
                    return req.build_absolute_uri(url)
                return url
        li = getattr(u, "linkedin", None)
        return getattr(li, "picture_url", "") or ""


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
