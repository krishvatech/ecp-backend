from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import Report, ModerationAction, ProfileReportMetadata

User = get_user_model()


def parse_target_type(value: str) -> ContentType:
    """
    Accepts: "comment", numeric CT id, or "app_label.ModelName".
    """
    if not value:
        raise serializers.ValidationError("target_type is required")
    v = str(value).strip()
    if v.lower() == "comment":
        return ContentType.objects.get(app_label="engagements", model="comment")
    if v.isdigit():
        return ContentType.objects.get(id=int(v))
    if "." not in v:
        raise serializers.ValidationError("Invalid target_type format")
    app_label, model = v.split(".", 1)
    return ContentType.objects.get(app_label=app_label.lower(), model=model.lower())


class ReportCreateSerializer(serializers.Serializer):
    target_type = serializers.CharField(required=True)
    target_id = serializers.IntegerField(required=True)
    reason = serializers.ChoiceField(choices=[c[0] for c in Report.REASON_CHOICES])
    notes = serializers.CharField(required=False, allow_blank=True, max_length=2000)


class ReportReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ["id", "content_type", "object_id", "reason", "notes", "created_at"]


class ModerationActionSerializer(serializers.Serializer):
    target_type = serializers.CharField(required=True)
    target_id = serializers.IntegerField(required=True)
    action = serializers.ChoiceField(choices=[c[0] for c in ModerationAction.ACTION_CHOICES])
    note = serializers.CharField(required=False, allow_blank=True, max_length=2000)
    patch = serializers.JSONField(required=False)
    set_status = serializers.ChoiceField(
        required=False,
        choices=["clear", "under_review", "removed"],
    )


# Profile Reporting Serializers
class ProfileReportMetadataSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProfileReportMetadata
        fields = [
            'relationship_to_deceased',
            'death_date',
            'obituary_url',
            'impersonated_person_name',
            'proof_urls',
            'correction_fields',
            'correction_reason',
            'illegal_content_description',
            'illegal_content_location',
        ]


class ProfileReportCreateSerializer(serializers.Serializer):
    """Serializer for creating profile reports with extended metadata."""

    target_user_id = serializers.IntegerField(required=True)
    reason = serializers.ChoiceField(
        choices=[
            choice for choice in Report.REASON_CHOICES
            if choice[0].startswith('profile_')
        ],
        required=True
    )
    notes = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=2000,
        help_text="Additional details about the report"
    )

    # Extended metadata (conditional on reason)
    metadata = ProfileReportMetadataSerializer(required=False)

    def validate_target_user_id(self, value):
        if not User.objects.filter(id=value).exists():
            raise serializers.ValidationError("User not found.")
        return value

    def validate(self, data):
        reason = data.get('reason')
        metadata = data.get('metadata', {})

        # Validate required metadata based on reason
        if reason == 'profile_deceased':
            if not metadata.get('relationship_to_deceased'):
                raise serializers.ValidationError({
                    'metadata': 'relationship_to_deceased is required for deceased reports'
                })

        elif reason == 'profile_impersonation':
            if not metadata.get('impersonated_person_name'):
                raise serializers.ValidationError({
                    'metadata': 'impersonated_person_name is required for impersonation reports'
                })

        elif reason == 'profile_correction':
            if not metadata.get('correction_fields'):
                raise serializers.ValidationError({
                    'metadata': 'correction_fields is required for correction requests'
                })

        return data


class ProfileReportReadSerializer(serializers.ModelSerializer):
    """Serializer for reading profile reports in admin queue."""

    reporter = serializers.SerializerMethodField()
    reported_user = serializers.SerializerMethodField()
    metadata = ProfileReportMetadataSerializer(source='profile_metadata', read_only=True)

    class Meta:
        model = Report
        fields = [
            'id',
            'reporter',
            'reported_user',
            'reason',
            'notes',
            'metadata',
            'created_at',
        ]

    def get_reporter(self, obj):
        from users.serializers import UserMiniSerializer
        return UserMiniSerializer(obj.reporter).data if obj.reporter else None

    def get_reported_user(self, obj):
        from users.serializers import UserProfileSerializer

        if obj.content_type.model == 'user':
            user = User.objects.filter(id=obj.object_id).first()
            if user and hasattr(user, 'profile'):
                return UserProfileSerializer(user.profile).data
        return None
