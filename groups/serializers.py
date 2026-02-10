# groups/serializers.py
from rest_framework import serializers
from django.db.models import Count
from community.models import Community
from django.contrib.auth import get_user_model
from users.serializers import UserMiniSerializer
from users.models import Experience
from .models import Group, GroupMembership, PromotionRequest, GroupNotification

User = get_user_model()



class GroupSerializer(serializers.ModelSerializer):
    member_count = serializers.IntegerField(read_only=True)
    created_by = serializers.SerializerMethodField(read_only=True)
    remove_cover_image = serializers.BooleanField(write_only=True, required=False, default=False)
    remove_logo = serializers.BooleanField(write_only=True, required=False, default=False)
    current_user_role = serializers.SerializerMethodField(read_only=True)

    # NEW ↓
    membership_status = serializers.SerializerMethodField(read_only=True)
    invited = serializers.SerializerMethodField(read_only=True)
    parent_group = serializers.SerializerMethodField(read_only=True)

    community_id = serializers.PrimaryKeyRelatedField(
        source="community", queryset=Community.objects.all(), required=False
    )
    parent_id = serializers.PrimaryKeyRelatedField(
        source="parent", queryset=Group.objects.all(), required=False, allow_null=True
    )

    owner = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Group
        fields = [
            "id", "name", "slug", "description",
            "visibility", "join_policy",
            "cover_image", "remove_cover_image",
            "logo", "remove_logo",
            "member_count", "created_by", "owner",
            "created_at", "updated_at",
            "current_user_role",
            "membership_status",  # NEW
            "invited",            # NEW
            "community_id",
            "parent_id",
            "parent_group",       # NEW
            "message_mode",
            "posts_comments_enabled",
            "posts_creation_restricted",
            "forum_enabled",
        ]
    read_only_fields = ["id", "slug", "member_count", "created_by", "owner", "created_at", "updated_at", "parent_group"]

    def validate(self, attrs):
        """
        Enforce the matrix:
          - public  => join_policy in {open, approval, invite}
          - private => join_policy = invite only
          - sub-group public can be OPEN only if parent is (public + open)
        Also handle partial updates by falling back to instance values.
        """
        vis = attrs.get("visibility", getattr(self.instance, "visibility", None))
        jp = attrs.get("join_policy", getattr(self.instance, "join_policy", None))
        parent = attrs.get("parent", getattr(self.instance, "parent", None))

        # Private groups must be invite-only
        if vis == Group.VISIBILITY_PRIVATE and jp != Group.JOIN_INVITE:
            raise serializers.ValidationError({"join_policy": "Private groups must be 'invite'."})

        # Public groups allow open/approval/invite
        if vis == Group.VISIBILITY_PUBLIC and jp not in {Group.JOIN_OPEN, Group.JOIN_APPROVAL, Group.JOIN_INVITE}:
            raise serializers.ValidationError({"join_policy": "Public groups must be 'open', 'approval', or 'invite'."})

        # Sub-group rules (parent-dependent)
        if parent:
            if vis == Group.VISIBILITY_PUBLIC and jp == Group.JOIN_OPEN:
                parent_is_open = (
                    parent.visibility == Group.VISIBILITY_PUBLIC
                    and parent.join_policy == Group.JOIN_OPEN
                )
                if not parent_is_open:
                    raise serializers.ValidationError(
                        {"join_policy": "Subgroups under non-open parents cannot be 'open'."}
                    )

        # Parent update behavior (safer): block if it would invalidate existing sub-groups.
        # We do NOT auto-downgrade sub-groups to avoid silent policy changes.
        if self.instance and not getattr(self.instance, "parent_id", None):
            parent_target_open = (
                vis == Group.VISIBILITY_PUBLIC and jp == Group.JOIN_OPEN
            )
            if not parent_target_open:
                has_open_public_subgroups = Group.objects.filter(
                    parent=self.instance,
                    visibility=Group.VISIBILITY_PUBLIC,
                    join_policy=Group.JOIN_OPEN,
                ).exists()
                if has_open_public_subgroups:
                    raise serializers.ValidationError(
                        {
                            "join_policy": (
                                "Parent groups with public subgroups set to 'open' "
                                "cannot be changed to non-open. Update subgroups first."
                            )
                        }
                    )

        # ⬇️ keep sub-group in same community as parent (server will also enforce)
        if parent:
            attrs["community"] = parent.community

        return attrs

    def get_created_by(self, obj):
        u = getattr(obj, "created_by", None)
        if not u:
            return None
        name = getattr(u, "get_full_name", lambda: "")() or getattr(u, "username", "") or getattr(u, "email", None)
        return {"id": u.pk, "email": getattr(u, "email", None), "name": name}

    def get_owner(self, obj):
        u = getattr(obj, "owner", None)
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
        remove_logo = validated_data.pop("remove_logo", False)
        obj = super().create(validated_data)

        if remove and obj.cover_image:
            obj.cover_image.delete(save=True)
        if remove_logo and obj.logo:
            obj.logo.delete(save=True)
        return obj

    def update(self, instance, validated_data):
        request = self.context.get("request")
        remove_flag = validated_data.pop("remove_cover_image", None)
        if remove_flag is None and request is not None:
            remove_flag = str(request.data.get("remove_cover_image", "")).lower() in ("1", "true", "on")

        remove_logo_flag = validated_data.pop("remove_logo", None)
        if remove_logo_flag is None and request is not None:
            remove_logo_flag = str(request.data.get("remove_logo", "")).lower() in ("1", "true", "on")

        old_file = instance.cover_image if instance.cover_image else None
        old_logo = instance.logo if instance.logo else None
        
        obj = super().update(instance, validated_data)

        if remove_flag and old_file:
            try:
                old_file.delete(save=False)
            except Exception:
                pass
            obj.cover_image = None
            obj.save(update_fields=["cover_image"])

        if remove_logo_flag and old_logo:
            try:
                old_logo.delete(save=False)
            except Exception:
                pass
            obj.logo = None
            obj.save(update_fields=["logo"])
            
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

    def get_parent_group(self, obj):
        if not obj.parent_id:
            return None
        # obj.parent might hit DB if not select_related, but typically safe for list views if optimized
        p = obj.parent
        return {
            "id": p.id,
            "name": p.name,
            "slug": p.slug,
            "visibility": p.visibility,
            "join_policy": p.join_policy,
        }

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


class CommunicationSettingsSerializer(serializers.ModelSerializer):
    """
    Handles all communication settings for a group:
    - posts_comments_enabled: Toggle On/Off for posts & comments
    - posts_creation_restricted: If True, only admins/mods can create posts
    - forum_enabled: Toggle On/Off for forum feature
    """

    class Meta:
        model = Group
        fields = [
            "posts_comments_enabled",
            "posts_creation_restricted",
            "forum_enabled",
            "message_mode",
        ]

    def update(self, instance, validated_data):
        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()
        return instance


class GroupMemberOutSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = GroupMembership
        fields = ["user", "role", "joined_at", "status"]

    def _best_experience(self, user):
        qs = getattr(user, "experiences", None)
        if hasattr(qs, "all"):
            qs = qs.all()
        else:
            qs = Experience.objects.filter(user=user)
        return qs.order_by("-currently_work_here", "-end_date", "-start_date", "-id").first()

    def get_user(self, obj):
        u = obj.user
        name = getattr(u, "get_full_name", lambda: "")() or getattr(u, "username", "") or getattr(u, "email", "")
        avatar = getattr(u, "avatar", None)
        if not avatar and hasattr(u, "profile"):
            # Check user_image (the actual field in UserProfile model)
            avatar = getattr(u.profile, "user_image", None)
            # Fallback to avatar if user_image doesn't exist
            if not avatar:
                avatar = getattr(u.profile, "avatar", None)
        if hasattr(avatar, "url"):
            avatar = avatar.url
        
        kyc_status = "not_started"
        if hasattr(u, "profile"):
            kyc_status = getattr(u.profile, "kyc_status", "not_started")

        ex = self._best_experience(u)
        location = ""
        if hasattr(u, "profile"):
            location = getattr(u.profile, "location", "") or ""
        location = location or getattr(u, "location", "") or ""

        return {
            "id": u.pk,
            "name": name or None,
            "email": getattr(u, "email", None),
            "avatar": avatar,
            "kyc_status": kyc_status,
            "company_from_experience": ex.community_name if ex else "",
            "position_from_experience": ex.position if ex else "",
            "industry_from_experience": ex.industry if ex else "",
            "number_of_employees_from_experience": ex.number_of_employees if ex else "",
            "location": location,
        }

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
    remove_logo = serializers.BooleanField(required=False, write_only=True)

    class Meta:
        model = Group
        fields = [
            'id', 'name', 'slug', 'description', 'visibility',
            'cover_image', 'logo', 'parent_id', 'community', 
            'remove_cover_image', 'remove_logo'
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
            
        if validated.pop('remove_logo', False):
            if instance.logo:
                instance.logo.delete(save=False)
            instance.logo = None
            
        return super().update(instance, validated)
    

class GroupNotificationSerializer(serializers.ModelSerializer):
    actor = UserMiniSerializer(read_only=True)

    class Meta:
        model = GroupNotification
        fields = (
            "id",
            "group",
            "kind",
            "title",
            "description",
            "state",
            "is_read",
            "created_at",
            "actor",
            "data",
        )
        read_only_fields = fields

class SuggestedGroupSerializer(serializers.ModelSerializer):
    member_count = serializers.IntegerField(read_only=True)
    mutuals = serializers.IntegerField(read_only=True)
    mutual_members = serializers.SerializerMethodField()

    # keep ids simple (frontend can filter)
    community_id = serializers.IntegerField(read_only=True)
    parent_id = serializers.IntegerField(read_only=True)

    class Meta:
        model = Group
        fields = (
            "id",
            "name",
            "slug",
            "description",
            "visibility",
            "join_policy",
            "join_policy",
            "cover_image",
            "logo",
            "member_count",
            "mutuals",
            "mutual_members",
            "community_id",
            "parent_id",
        )

    def get_mutual_members(self, obj):
        # map provided by the view: { group_id: [User, User, ...] }
        m = (self.context.get("mutual_members_map") or {})
        users = m.get(obj.id, [])
        return UserMiniSerializer(users, many=True, context=self.context).data
