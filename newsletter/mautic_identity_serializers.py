"""Serializers for Mautic identity mapping management and audit reads.

These never accept or expose credentials: a mapping stores an existing Mautic
user id plus display metadata only.
"""

from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import MauticIdentityAuditLog

User = get_user_model()

# Matches the model column and Mautic's signed integer user id column.
MAX_MAUTIC_USER_ID = 2147483647


class MauticUserConnectionCreateSerializer(serializers.Serializer):
    ecp_user_id = serializers.IntegerField(min_value=1)
    mautic_user_id = serializers.IntegerField(min_value=1, max_value=MAX_MAUTIC_USER_ID)

    UNSUPPORTED_METADATA_FIELDS = {
        "mautic_username",
        "mautic_email",
        "mautic_display_name",
        "mautic_role_name",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_user = None

    def validate_ecp_user_id(self, value):
        user = User.objects.filter(pk=value).first()
        if user is None:
            raise serializers.ValidationError("ECP user does not exist.")
        self.target_user = user
        return value

    def validate(self, attrs):
        supplied = set(getattr(self, "initial_data", {}) or {})
        unsupported = sorted(supplied & self.UNSUPPORTED_METADATA_FIELDS)
        if unsupported:
            raise serializers.ValidationError(
                {
                    field: "Mautic user metadata is canonical and cannot be supplied."
                    for field in unsupported
                }
            )
        return attrs


class MauticUserConnectionDeactivateSerializer(serializers.Serializer):
    reason = serializers.CharField(max_length=255, required=False, allow_blank=True)


class MauticIdentityAuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = MauticIdentityAuditLog
        fields = [
            "id",
            "ecp_user_id",
            "ecp_user_label",
            "mautic_user_id",
            "action",
            "resource",
            "resource_id",
            "status",
            "auth_mode",
            "correlation_id",
            "assertion_jti",
            "error_code",
            "detail",
            "created_at",
        ]
        read_only_fields = fields
