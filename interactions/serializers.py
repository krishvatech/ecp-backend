# interactions/serializers.py
from rest_framework import serializers
from .models import (
    Question,
    QnAReply,
    QnAQuestionGroup,
    QnAQuestionGroupMembership,
    QnAQuestionGroupSuggestion,
)


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
            "is_answered",
            "answered_at",
            "requires_followup",
            "is_anonymous",
            "anonymized_by",
            "is_seed",
            "attribution_label",
        ]
        read_only_fields = ["user", "guest_asker", "created_at", "updated_at", "is_hidden", "hidden_by", "hidden_at", "moderation_status", "rejection_reason", "is_answered", "answered_at", "requires_followup", "is_anonymous", "anonymized_by", "is_seed", "attribution_label"]

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


class QnAReplySerializer(serializers.ModelSerializer):
    class Meta:
        model = QnAReply
        fields = [
            "id",
            "question",
            "event",
            "lounge_table",
            "user",
            "guest_asker",
            "content",
            "created_at",
            "updated_at",
            "moderation_status",
            "rejection_reason",
            "is_anonymous",
            "is_hidden",
            "hidden_by",
            "hidden_at",
            "anonymized_by",
        ]
        read_only_fields = [
            "user", "guest_asker", "event", "lounge_table", "created_at",
            "updated_at", "moderation_status", "rejection_reason",
        ]


class QnAQuestionGroupSuggestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = QnAQuestionGroupSuggestion
        fields = "__all__"
        read_only_fields = [
            "event",
            "generated_by",
            "created_at",
            "reviewed_at",
            "reviewed_by",
            "status",
            "raw_ai_response",
            "confidence_score",
            "suggested_question_ids"
        ]


class QnAQuestionGroupMembershipSerializer(serializers.ModelSerializer):
    class Meta:
        model = QnAQuestionGroupMembership
        fields = "__all__"
        read_only_fields = ["created_at", "added_by"]


class QnAQuestionGroupSerializer(serializers.ModelSerializer):
    memberships = QnAQuestionGroupMembershipSerializer(many=True, read_only=True)
    
    class Meta:
        model = QnAQuestionGroup
        fields = "__all__"
        read_only_fields = ["event", "created_by", "source", "ai_suggestion", "created_at", "updated_at"]

