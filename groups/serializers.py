# groups/serializers.py
from rest_framework import serializers
from django.db.models import Count
from community.models import Community
from django.contrib.auth import get_user_model
from .models import Group, GroupMembership, PromotionRequest, GroupPinnedMessage, GroupPoll, GroupPollOption, GroupPollVote
User = get_user_model()


class GroupSerializer(serializers.ModelSerializer):
    member_count = serializers.IntegerField(read_only=True)
    created_by = serializers.SerializerMethodField(read_only=True)
    remove_cover_image = serializers.BooleanField(write_only=True, required=False, default=False)
    current_user_role = serializers.SerializerMethodField(read_only=True)

    # NEW ↓
    membership_status = serializers.SerializerMethodField(read_only=True)
    invited = serializers.SerializerMethodField(read_only=True)

    community_id = serializers.PrimaryKeyRelatedField(
        source="community", queryset=Community.objects.all(), required=False
    )
    parent_id = serializers.PrimaryKeyRelatedField(
        source="parent", queryset=Group.objects.all(), required=False, allow_null=True
    )

    class Meta:
        model = Group
        fields = [
            "id", "name", "slug", "description",
            "visibility", "join_policy",
            "cover_image", "remove_cover_image",
            "member_count", "created_by",
            "created_at", "updated_at",
            "current_user_role",
            "membership_status",  # NEW
            "invited",            # NEW
            "community_id",
            "parent_id",
        ]
    read_only_fields = ["id", "slug", "member_count", "created_by", "created_at", "updated_at"]

    def validate(self, attrs):
        """
        Enforce the matrix:
          - public  => join_policy in {open, approval}
          - private => join_policy in {invite, approval}
        Also handle partial updates by falling back to instance values.
        """
        vis = attrs.get("visibility", getattr(self.instance, "visibility", None))
        jp  = attrs.get("join_policy", getattr(self.instance, "join_policy", None))

        if vis == Group.VISIBILITY_PUBLIC and jp not in {Group.JOIN_OPEN, Group.JOIN_APPROVAL}:
            raise serializers.ValidationError({"join_policy": "Public groups must be 'open' or 'approval'."})

        if vis == Group.VISIBILITY_PRIVATE and jp not in {Group.JOIN_INVITE, Group.JOIN_APPROVAL}:
            raise serializers.ValidationError({"join_policy": "Private groups must be 'invite' or 'approval'."})

        # ⬇️ NEW: keep sub-group in same community as parent (server will also enforce)
        parent = attrs.get("parent", getattr(self.instance, "parent", None))
        community = attrs.get("community", getattr(self.instance, "community", None))
        if parent:
            # prefer parent's community
            attrs["community"] = parent.community

        return attrs

    def get_created_by(self, obj):
        u = getattr(obj, "created_by", None)
        if not u:
            return None
        name = getattr(u, "get_full_name", lambda: "")() or getattr(u, "username", "") or getattr(u, "email", None)
        return {"id": u.pk, "email": getattr(u, "email", None), "name": name}

    def create(self, validated_data):
        # ensure created_by comes from request
        request = self.context.get("request")
        if request and request.user and request.user.is_authenticated:
            validated_data.setdefault("created_by", request.user)

        remove = validated_data.pop("remove_cover_image", False)
        obj = super().create(validated_data)

        if remove and obj.cover_image:
            obj.cover_image.delete(save=True)
        return obj

    def update(self, instance, validated_data):
        request = self.context.get("request")
        remove_flag = validated_data.pop("remove_cover_image", None)
        if remove_flag is None and request is not None:
            remove_flag = str(request.data.get("remove_cover_image", "")).lower() in ("1", "true", "on")

        old_file = instance.cover_image if instance.cover_image else None
        obj = super().update(instance, validated_data)

        if remove_flag and old_file:
            try:
                old_file.delete(save=False)
            except Exception:
                pass
            obj.cover_image = None
            obj.save(update_fields=["cover_image"])
        return obj
    
    def get_current_user_role(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        uid = getattr(user, "id", None)
        if not uid:
            return None
        # treat creator/owner as "owner"
        if obj.created_by_id == uid or getattr(obj, "owner_id", None) == uid:
            return "owner"
        try:
            m = GroupMembership.objects.get(group=obj, user_id=uid)
            return m.role
        except GroupMembership.DoesNotExist:
            return None
    
    def get_membership_status(self, obj):
        request = self.context.get("request")
        uid = getattr(getattr(request, "user", None), "id", None)
        if not uid:
            return None
        m = GroupMembership.objects.filter(group=obj, user_id=uid).only("status").first()
        return getattr(m, "status", None) if m else None

    # NEW ↓
    def get_invited(self, obj):
        request = self.context.get("request")
        uid = getattr(getattr(request, "user", None), "id", None)
        if not uid:
            return False
        m = GroupMembership.objects.filter(group=obj, user_id=uid).only("invited_by_id", "status").first()
        return bool(m and m.status == GroupMembership.STATUS_PENDING and getattr(m, "invited_by_id", None))

class GroupSettingsSerializer(serializers.ModelSerializer):
    """
    API takes/returns a boolean, DB stays enum.
    POST body can be:
      { "admins_only": true }     # preferred simple API
    or
      { "message_mode": "admins_only" }  # advanced console / back-compat
    """
    admins_only = serializers.BooleanField(write_only=True, required=False)
    admins_only_effective = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Group
        fields = ["message_mode", "admins_only", "admins_only_effective"]
        extra_kwargs = {"message_mode": {"required": False}}

    def get_admins_only_effective(self, obj):
        return obj.message_mode == Group.MSG_MODE_ADMINS

    def update(self, instance, validated):
        # boolean mapping → enum
        if "admins_only" in validated:
            instance.message_mode = (
                Group.MSG_MODE_ADMINS if validated.pop("admins_only") else Group.MSG_MODE_ALL
            )
        # allow direct enum too
        if "message_mode" in validated:
            instance.message_mode = validated["message_mode"]
        instance.save(update_fields=["message_mode"])
        return instance
    
class GroupMemberOutSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = GroupMembership
        fields = ["user", "role", "joined_at", "status"]

    def get_user(self, obj):
        u = obj.user
        name = getattr(u, "get_full_name", lambda: "")() or getattr(u, "username", "") or getattr(u, "email", "")
        avatar = getattr(u, "avatar", None)
        if not avatar and hasattr(u, "profile") and hasattr(u.profile, "avatar"):
            avatar = getattr(u.profile, "avatar", None)
        if hasattr(avatar, "url"):
            avatar = avatar.url
        return {"id": u.pk, "name": name or None, "email": getattr(u, "email", None), "avatar": avatar}

# ---- Pinned messages ----
class GroupPinnedMessageOutSerializer(serializers.ModelSerializer):
    message = serializers.SerializerMethodField()
    pinned_by = serializers.SerializerMethodField()
    scope = serializers.SerializerMethodField()  # NEW

    class Meta:
        model = GroupPinnedMessage
        fields = ["id", "pinned_at", "pinned_by", "scope", "message"]

    def get_scope(self, obj):
        return "global" if obj.is_global else "personal"

    def get_pinned_by(self, obj):
        u = obj.pinned_by
        if not u:
            return None
        name = getattr(u, "get_full_name", lambda: "")() or getattr(u, "username", "") or getattr(u, "email", "")
        return {"id": u.id, "name": name, "email": getattr(u, "email", None)}

    def get_message(self, obj):
        m = obj.message
        return {
            "id": getattr(m, "id", None),
            "body": (getattr(m, "body", "") or "")[:500],
            "created_at": getattr(m, "created_at", None),
            "sender_id": getattr(m, "sender_id", None),
            "is_hidden": getattr(m, "is_hidden", False),
            "is_deleted": getattr(m, "is_deleted", False),
        }



# ---- Polls ----
class GroupPollOptionOutSerializer(serializers.ModelSerializer):
    vote_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = GroupPollOption
        fields = ["id", "text", "index", "vote_count"]


class GroupPollOutSerializer(serializers.ModelSerializer):
    options = GroupPollOptionOutSerializer(many=True, read_only=True)
    total_votes = serializers.IntegerField(read_only=True)
    user_votes = serializers.SerializerMethodField()

    class Meta:
        model = GroupPoll
        fields = [
            "id", "question", "allows_multiple", "is_anonymous", "is_closed",
            "ends_at", "created_by", "created_at", "updated_at",
            "options", "total_votes", "user_votes",
        ]
        read_only_fields = ["created_by", "created_at", "updated_at", "total_votes", "user_votes"]

    def get_user_votes(self, obj):
        request = self.context.get("request")
        uid = getattr(getattr(request, "user", None), "id", None)
        if not uid:
            return []
        return list(GroupPollVote.objects.filter(poll=obj, user_id=uid).values_list("option_id", flat=True))


class GroupPollCreateSerializer(serializers.Serializer):
    question = serializers.CharField(max_length=500)
    options = serializers.ListField(
        child=serializers.CharField(max_length=300), allow_empty=False, min_length=2
    )
    allows_multiple = serializers.BooleanField(required=False, default=False)
    is_anonymous = serializers.BooleanField(required=False, default=False)
    ends_at = serializers.DateTimeField(required=False, allow_null=True)


class GroupPollVoteInSerializer(serializers.Serializer):
    option_ids = serializers.ListField(child=serializers.IntegerField(), allow_empty=False, min_length=1)

class CreatePollSerializer(serializers.Serializer):
    question = serializers.CharField(max_length=500)
    options  = serializers.ListField(
        child=serializers.CharField(max_length=200),
        min_length=2, max_length=20
    )
    multi_select = serializers.BooleanField(required=False, default=False)
    closes_at = serializers.DateTimeField(required=False, allow_null=True)
    
class VotePollSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text="FeedItem id of the poll")
    choices = serializers.ListField(
        child=serializers.IntegerField(min_value=0),
        min_length=1
    )

# ===== Feed Posts stored as activity_feed.FeedItem =====
class CreateFeedPostSerializer(serializers.Serializer):
    content = serializers.CharField(max_length=4000)


class FeedItemIdSerializer(serializers.Serializer):
    id = serializers.IntegerField()


# ===== Promotion requests =====
class PromotionRequestCreateSerializer(serializers.Serializer):
    role_requested = serializers.ChoiceField(choices=GroupMembership.ROLE_CHOICES, required=False)
    reason = serializers.CharField(max_length=500, required=False, allow_blank=True)


class PromotionRequestOutSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = PromotionRequest
        fields = ["id", "user", "role_requested", "reason", "status", "created_at", "reviewed_by", "reviewed_at"]

    def get_user(self, obj):
        u = obj.user
        name = getattr(u, "get_full_name", lambda: "")() or getattr(u, "username", "") or getattr(u, "email", "")
        return {"id": u.pk, "name": name, "email": getattr(u, "email", None)}# groups/serializers.py

class GroupCreateUpdateSerializer(serializers.ModelSerializer):
    parent_id = serializers.IntegerField(required=False, allow_null=True, write_only=True)
    remove_cover_image = serializers.BooleanField(required=False, write_only=True)

    class Meta:
        model = Group
        fields = [
            'id', 'name', 'slug', 'description', 'visibility',
            'cover_image', 'parent_id', 'community', 'remove_cover_image'
        ]
        extra_kwargs = {
            'community': {'required': False, 'allow_null': True},
            'slug': {'required': False},
        }

    def validate(self, attrs):
        parent_id = attrs.pop('parent_id', None)
        if parent_id is not None:
            try:
                parent = Group.objects.get(pk=int(parent_id))
            except (ValueError, Group.DoesNotExist):
                raise serializers.ValidationError({'detail': 'Invalid parent_id'})
            # inherit community if not provided
            if not attrs.get('community'):
                attrs['community'] = parent.community
            attrs['parent'] = parent
        return attrs

    def update(self, instance, validated):
        # handle remove_cover_image
        if validated.pop('remove_cover_image', False):
            if instance.cover_image:
                instance.cover_image.delete(save=False)
            instance.cover_image = None
        return super().update(instance, validated)