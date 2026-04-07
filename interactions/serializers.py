# interactions/serializers.py
from rest_framework import serializers
from .models import Question


class QuestionSerializer(serializers.ModelSerializer):
    user_display = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Question
        fields = [
            "id",
            "event",
            "user",
            "guest_asker",
            "user_display",
            "content",
            "created_at",
            "updated_at",
            "is_hidden",
            "hidden_by",
            "hidden_at",
            "lounge_table",
            "moderation_status",
            "rejection_reason",
        ]
        read_only_fields = ["user", "guest_asker", "created_at", "updated_at", "is_hidden", "hidden_by", "hidden_at", "moderation_status", "rejection_reason"]

    def get_user_display(self, obj):
        if getattr(obj, "guest_asker", None):
            return obj.guest_asker.get_display_name()
        user = obj.user
        if not user:
            return "Audience"
        full = getattr(user, "get_full_name", lambda: "")()
        if full:
            return full
        if user.first_name:
            return user.first_name
        if user.username:
            return user.username
        return user.email or f"User {user.id}"
