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
            "user_display",
            "content",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["user", "created_at", "updated_at"]

    def get_user_display(self, obj):
        user = obj.user
        full = getattr(user, "get_full_name", lambda: "")()
        if full:
            return full
        if user.first_name:
            return user.first_name
        if user.username:
            return user.username
        return user.email or f"User {user.id}"
