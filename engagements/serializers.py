from django.contrib.contenttypes.models import ContentType 
from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import Comment, Reaction, Share
from activity_feed.models import FeedItem
from groups.models import Group
from users.serializers import UserMiniSerializer  # ← use mini user with avatar_url

User = get_user_model()


def get_ct(value: str) -> ContentType:
    """
    Accepts either a ContentType id (string/int) or 'app_label.ModelName' (case-insensitive).
    """
    # numeric id
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        return ContentType.objects.get(id=int(value))
    # 'app_label.ModelName'
    try:
        app_label, model = value.split(".", 1)
        return ContentType.objects.get(app_label=app_label.lower(), model=model.lower())
    except Exception:
        raise serializers.ValidationError("Invalid target_type. Use CT id or 'app_label.ModelName'.")


# Small user projection (kept in case used elsewhere)
class MiniUserSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    avatar_url = serializers.SerializerMethodField()

    def get_avatar_url(self, obj):
        for attr in ("avatar_url", "profile_image", "photo", "image"):
            val = getattr(obj, attr, None)
            if val:
                return str(val)
        return ""


# ---------- Comments ----------
class CommentSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField(read_only=True)
    likes_count = serializers.SerializerMethodField(read_only=True)
    has_liked = serializers.SerializerMethodField(read_only=True)

    # write-only generic target
    target_type = serializers.CharField(write_only=True, required=False, allow_blank=True, allow_null=True)
    target_id = serializers.IntegerField(write_only=True, required=False)
    feed_item = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = Comment
        fields = [
            "id",
            "user",
            "text",
            "parent",
            "likes_count",
            "has_liked",
            "created_at",
            "updated_at",
            # write-only:
            "target_type",
            "target_id",
            "feed_item",
        ]
        read_only_fields = ["user", "likes_count", "has_liked", "created_at", "updated_at"]

    def _mini_user_payload(self, user):
        """
        Build: {id, name, avatar_url} using central avatar logic from UserMiniSerializer.
        """
        mini = UserMiniSerializer(user, context=self.context)
        mini_data = mini.data
        # Prefer first_name, else username, else string representation
        name = (user.first_name or user.username or "").strip() or str(user)
        return {
            "id": user.id,
            "name": name,
            "avatar_url": mini_data.get("avatar_url") or "",
        }

    def get_user(self, obj):
        return self._mini_user_payload(obj.user)

    def get_likes_count(self, obj):
        ct = ContentType.objects.get_for_model(Comment)
        return Reaction.objects.filter(content_type=ct, object_id=obj.id).count()

    def get_has_liked(self, obj):
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return False
        ct = ContentType.objects.get_for_model(Comment)
        return Reaction.objects.filter(content_type=ct, object_id=obj.id, user=request.user).exists()

    def create(self, validated_data):
        # pop helpers (may be missing)
        ttype = validated_data.pop("target_type", None)
        tid = validated_data.pop("target_id", None)
        feed_item = validated_data.pop("feed_item", None)
        parent = validated_data.get("parent")  # keep in validated_data so save() sets it

        # 1) explicit target_type -> parse ('comment', numeric id, or 'app.Model')
        if ttype:
            if str(ttype).lower() == "comment":
                ct = ContentType.objects.get_for_model(Comment)
            elif str(ttype).isdigit():
                ct = ContentType.objects.get(id=int(ttype))
            else:
                app_label, model = str(ttype).split(".", 1)
                ct = ContentType.objects.get(app_label=app_label.lower(), model=model.lower())
            if tid is None:
                raise serializers.ValidationError({"target_id": ["This field is required with target_type."]})
            oid = tid
        # 2) if parent provided and no explicit target -> inherit parent’s target
        elif parent:
            ct = parent.content_type
            oid = parent.object_id
        # 3) if target_id or feed_item provided -> default to FeedItem
        elif (tid is not None) or (feed_item is not None):
            ct = ContentType.objects.get_for_model(FeedItem)
            oid = tid if tid is not None else feed_item
        else:
            raise serializers.ValidationError({
                "target_id": ["Provide target_id or feed_item, or pass parent, or include target_type+target_id."]
            })

        return Comment.objects.create(
            content_type=ct,
            object_id=oid,
            user=self.context["request"].user,
            **validated_data,
        )


# ---------- Reactions ----------
class ReactionToggleSerializer(serializers.Serializer):
    # Accept "comment" OR a generic 'app_label.ModelName' for non-comment targets
    target_type = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    target_id = serializers.IntegerField()
    reaction = serializers.ChoiceField(choices=["like"], default="like")


class ReactionUserSerializer(serializers.ModelSerializer):
    """
    Used for the "liked by X and N others" list.
    Returns: {id, name, avatar_url} for user.
    """
    user = serializers.SerializerMethodField()

    class Meta:
        model = Reaction
        fields = ["id", "user", "reaction", "created_at"]

    def _mini_user_payload(self, user):
        mini = UserMiniSerializer(user, context=self.context)
        mini_data = mini.data
        name = (user.first_name or user.username or "").strip() or str(user)
        return {
            "id": user.id,
            "name": name,
            "avatar_url": mini_data.get("avatar_url") or "",
        }

    def get_user(self, obj):
        return self._mini_user_payload(obj.user)


# ---------- Shares ----------
# ---------- Share (READ) ----------
class ShareReadSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    recipient = serializers.SerializerMethodField()
    target = serializers.SerializerMethodField()

    class Meta:
        model = Share
        fields = ["id", "user", "recipient", "note", "target", "created_at"]

    def get_user(self, obj):
        u = obj.user
        return {"id": u.id, "name": str(u)}

    def get_recipient(self, obj):
        if obj.to_user_id:
            return {"type": "user", "id": obj.to_user_id}
        return {"type": "group", "id": obj.to_group_id}

    def get_target(self, obj):
        # minimal projection
        return {
            "content_type_id": obj.content_type_id,
            "object_id": obj.object_id,
        }


# ---------- Share (WRITE) ----------
class ShareWriteSerializer(serializers.Serializer):
    note = serializers.CharField(required=False, allow_blank=True, default="")

    # multiple recipients
    to_users = serializers.ListField(
        child=serializers.IntegerField(), required=False, allow_empty=True
    )
    to_groups = serializers.ListField(
        child=serializers.IntegerField(), required=False, allow_empty=True
    )

    # what to share (defaults to FeedItem if target_type missing)
    target_type = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    target_id = serializers.IntegerField(required=False)
    feed_item = serializers.IntegerField(required=False)

    def validate(self, attrs):
        users = attrs.get("to_users") or []
        groups = attrs.get("to_groups") or []
        if not users and not groups:
            raise serializers.ValidationError("Pick at least one friend (to_users) or one group (to_groups).")
        return attrs

    def _resolve_target(self, ttype, tid, feed_item):
        if ttype:
            t = str(ttype).strip()
            if t.lower() == "comment":
                ct = ContentType.objects.get_for_model(Comment)
            elif t.isdigit():
                ct = ContentType.objects.get(id=int(t))
            else:
                app_label, model = t.split(".", 1)
                ct = ContentType.objects.get(app_label=app_label.lower(), model=model.lower())
            if tid is None and feed_item is None:
                raise serializers.ValidationError({"target_id": ["This field is required with target_type."]})
            oid = tid if tid is not None else feed_item
        else:
            ct = ContentType.objects.get_for_model(FeedItem)
            oid = tid if tid is not None else feed_item
        if oid is None:
            raise serializers.ValidationError({"target_id": ["Provide target_id or feed_item."]})
        return ct, oid

    def create(self, validated_data):
        request = self.context["request"]
        note = validated_data.get("note", "")
        to_users = list(dict.fromkeys(validated_data.get("to_users") or []))   # de-dup
        to_groups = list(dict.fromkeys(validated_data.get("to_groups") or [])) # de-dup

        ttype = validated_data.get("target_type")
        tid = validated_data.get("target_id")
        feed_item = validated_data.get("feed_item")
        ct, oid = self._resolve_target(ttype, tid, feed_item)

        rows = []
        for uid in to_users:
            rows.append(Share(
                content_type=ct, object_id=oid, user=request.user,
                to_user_id=uid, note=note
            ))
        for gid in to_groups:
            rows.append(Share(
                content_type=ct, object_id=oid, user=request.user,
                to_group_id=gid, note=note
            ))

        # Use bulk_create with ignore_conflicts=True to skip duplicates silently
        Share.objects.bulk_create(rows, ignore_conflicts=True)

        # Load whatever actually exists now (created or previously existing) for response
        q = Share.objects.filter(user=request.user, content_type=ct, object_id=oid)
        if to_users:
            q = q.filter(to_user_id__in=to_users) | q
        if to_groups:
            q = Share.objects.filter(
                user=request.user,
                content_type=ct,
                object_id=oid,
                to_group_id__in=to_groups,
            ) | q

        return list(q.distinct())
