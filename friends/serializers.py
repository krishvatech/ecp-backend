from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Friendship, FriendRequest,Notification

User = get_user_model()


class UserTinySerializer(serializers.ModelSerializer):
    """Tiny projection of a user suitable for friend lists."""
    display_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ("id", "username", "email", "display_name")
        read_only_fields = fields

    def get_display_name(self, obj):
        for attr in ("name", "full_name", "get_full_name"):
            if hasattr(obj, attr):
                v = getattr(obj, attr)
                return v() if callable(v) else v
        return obj.username or obj.email


class friendserializer(serializers.ModelSerializer):
    friend = serializers.SerializerMethodField()

    class Meta:
        model = Friendship
        fields = ("id", "friend", "created_at")
        read_only_fields = fields

    def get_friend(self, obj):
        # When listing "friends of X", we pass perspective_id in context.
        me_id = self.context.get("perspective_id")
        if me_id is None:
            request = self.context.get("request")
            me_id = getattr(getattr(request, "user", None), "id", None)

        other = obj.user2 if obj.user1_id == me_id else obj.user1
        return UserTinySerializer(other).data


class FriendshipCreateSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()

    def validate(self, attrs):
        request = self.context["request"]
        me_id = request.user.id
        target_id = attrs["user_id"]
        if me_id == target_id:
            raise serializers.ValidationError("You cannot friend yourself.")
        if Friendship.are_friends(me_id, target_id):
            raise serializers.ValidationError("You are already friends.")
        return attrs

    def create(self, validated_data):
        request = self.context["request"]
        me_id = request.user.id
        target_id = validated_data["user_id"]
        u1, u2 = (me_id, target_id) if me_id < target_id else (target_id, me_id)
        friendship, _ = Friendship.objects.get_or_create(user1_id=u1, user2_id=u2)
        return friendship


class NotificationActorSerializer(serializers.ModelSerializer):
    display_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ("id", "username", "email", "display_name")

    def get_display_name(self, obj):
        for attr in ("name", "full_name", "get_full_name"):
            if hasattr(obj, attr):
                v = getattr(obj, attr)
                return v() if callable(v) else v
        return obj.username or obj.email

class NotificationSerializer(serializers.ModelSerializer):
    actor = NotificationActorSerializer(read_only=True)

    class Meta:
        model = Notification
        fields = (
            "id", "kind", "title", "description", "state",
            "is_read", "created_at", "actor", "data",
        )
        read_only_fields = fields

class FriendRequestSerializer(serializers.ModelSerializer):
    from_user = UserTinySerializer(read_only=True)
    to_user = UserTinySerializer(read_only=True)

    class Meta:
        model = FriendRequest
        fields = (
            "id",
            "from_user",
            "to_user",
            "status",
            "created_at",
            "responded_at",
        )
        read_only_fields = fields


class FriendRequestCreateSerializer(serializers.ModelSerializer):
    to_user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = FriendRequest
        fields = ("to_user",)

    def validate(self, attrs):
        request = self.context["request"]
        me = request.user
        to_user = attrs["to_user"]
        if me.id == to_user.id:
            raise serializers.ValidationError("You cannot send a request to yourself.")
        if Friendship.are_friends(me.id, to_user.id):
            raise serializers.ValidationError("You are already friends.")
        return attrs

    def create(self, validated_data):
        request = self.context["request"]
        fr = FriendRequest.objects.create(
            from_user=request.user, to_user=validated_data["to_user"]
        )
        from .models import notify_friend_request_created
        notify_friend_request_created(fr)
        return fr
