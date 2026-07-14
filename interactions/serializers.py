# interactions/serializers.py
from rest_framework import serializers
from .models import (
    Question,
    QnAReply,
    QnAQuestionGroup,
    QnAQuestionGroupMembership,
    QnAQuestionGroupSuggestion,
    QnAAIPublicSuggestion,
    QnAAIPublicSuggestionAdoption,
)


class QuestionSerializer(serializers.ModelSerializer):
    user_display = serializers.SerializerMethodField(read_only=True)
    upvote_count = serializers.SerializerMethodField(read_only=True)
    user_upvoted = serializers.SerializerMethodField(read_only=True)
    upvoters = serializers.SerializerMethodField(read_only=True)
    reply_count = serializers.SerializerMethodField(read_only=True)

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
            "answered_by",
            "answer_text",
            "answered_phase",
            "requires_followup",
            "is_pinned",
            "pinned_at",
            "pinned_by",
            "is_anonymous",
            "anonymized_by",
            "is_seed",
            "attribution_label",
            "submission_phase",
            "covered_by_group",
            "grouped_answer_parent",
            "is_deleted",
            "deleted_at",
            "deleted_by",
            "deletion_reason",
            "feedback_message",
            "feedback_by",
            "feedback_at",
            "upvote_count",
            "user_upvoted",
            "upvoters",
            "reply_count",
        ]
        read_only_fields = ["user", "guest_asker", "created_at", "updated_at", "is_hidden", "hidden_by", "hidden_at", "moderation_status", "rejection_reason", "is_answered", "answered_at", "answered_by", "answer_text", "answered_phase", "requires_followup", "is_pinned", "pinned_at", "pinned_by", "is_anonymous", "anonymized_by", "is_seed", "attribution_label", "submission_phase", "covered_by_group", "grouped_answer_parent", "is_deleted", "deleted_at", "deleted_by", "deletion_reason", "feedback_message", "feedback_by", "feedback_at", "upvote_count", "user_upvoted", "upvoters", "reply_count"]

    def get_upvote_count(self, obj):
        annotated = getattr(obj, "upvotes_count", None)
        if annotated is not None:
            return int(annotated)
        return obj.upvoters.count() + obj.guest_upvotes.count()

    def get_user_upvoted(self, obj):
        annotated = getattr(obj, "user_upvoted", None)
        if annotated is not None:
            return bool(annotated)

        request = self.context.get("request")
        user = getattr(request, "user", None) if request else None
        if not user or not getattr(user, "is_authenticated", False):
            return False

        if getattr(user, "is_guest", False):
            guest = getattr(user, "guest", None)
            if not guest:
                return False
            return obj.guest_upvotes.filter(guest=guest).exists()

        return obj.upvoters.filter(id=user.id).exists()

    def get_upvoters(self, obj):
        """
        Host/admin tooltip data. Attendees still receive an empty list, while
        upvote_count remains available for all users.
        """
        request = self.context.get("request")
        user = getattr(request, "user", None) if request else None
        if not user or not getattr(user, "is_authenticated", False):
            return []

        is_manager = bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))
        event = getattr(obj, "event", None)
        if event is not None:
            is_manager = is_manager or getattr(event, "created_by_id", None) == getattr(user, "id", None)

        if not is_manager:
            return []

        rows = []
        for u in obj.upvoters.all()[:20]:
            name = (f"{getattr(u, 'first_name', '')} {getattr(u, 'last_name', '')}".strip()
                    or getattr(u, "username", "")
                    or getattr(u, "email", "")
                    or f"User {u.id}")
            rows.append({"id": u.id, "name": name})

        for gu in obj.guest_upvotes.all()[:20]:
            guest = getattr(gu, "guest", None)
            name = guest.get_display_name() if guest and hasattr(guest, "get_display_name") else f"Guest {getattr(gu, 'guest_id', '')}"
            rows.append({"id": f"guest_{getattr(gu, 'guest_id', '')}", "name": name})

        return rows

    def get_reply_count(self, obj):
        annotated = getattr(obj, "replies_count", None)
        if annotated is not None:
            return int(annotated)
        return obj.replies.count()

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


class PostEventAnswerSerializer(serializers.Serializer):
    """Serializer for the POST request body when publishing a post-event answer."""
    answer_text = serializers.CharField(
        max_length=5000,
        allow_blank=False,
        trim_whitespace=True,
        help_text="The written answer to the question.",
    )
    notify_author = serializers.BooleanField(
        default=True,
        help_text="Whether to notify the question author.",
    )
    notify_interested_participants = serializers.BooleanField(
        default=True,
        help_text="Whether to notify users who upvoted the question.",
    )
    notify_all_participants = serializers.BooleanField(
        default=False,
        help_text="Whether to notify all event participants.",
    )


class MarkAnsweredSerializer(serializers.Serializer):
    """Serializer for marking a question as answered (live or post-event)."""
    answer_text = serializers.CharField(
        max_length=5000,
        allow_blank=True,
        trim_whitespace=True,
        required=False,
        help_text="Optional written answer provided during live session.",
    )
    requires_followup = serializers.BooleanField(
        required=False,
        help_text="Whether this question requires follow-up.",
    )


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
            "is_deleted",
            "deleted_at",
            "deleted_by",
            "deletion_reason",
        ]
        read_only_fields = [
            "user", "guest_asker", "event", "lounge_table", "created_at",
            "updated_at", "moderation_status", "rejection_reason",
            "is_deleted", "deleted_at", "deleted_by", "deletion_reason",
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
    aggregated_vote_count = serializers.SerializerMethodField()

    class Meta:
        model = QnAQuestionGroup
        fields = "__all__"
        read_only_fields = [
            "event",
            "created_by",
            "source",
            "ai_suggestion",
            "is_deleted",
            "deleted_at",
            "deleted_by",
            "deletion_reason",
            "question_ids_snapshot",
            "created_at",
            "updated_at",
            "aggregated_vote_count",
        ]

    def get_aggregated_vote_count(self, obj):
        return obj.aggregated_vote_count


class QnAAIPublicSuggestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = QnAAIPublicSuggestion
        fields = "__all__"
        read_only_fields = ["created_by", "created_at", "updated_at", "reviewed_by", "published_at"]


class QnAAIPublicSuggestionAdoptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = QnAAIPublicSuggestionAdoption
        fields = "__all__"
        read_only_fields = ["adopted_at", "user", "guest"]
