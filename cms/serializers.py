from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from rest_framework import serializers

from cms.models import EmailTemplate


class EmailTemplateSerializer(serializers.Serializer):
    template_key = serializers.CharField(read_only=True)
    label = serializers.CharField(read_only=True)
    category = serializers.CharField(read_only=True)
    subject = serializers.CharField()
    html_body = serializers.CharField(allow_blank=True, required=False)
    text_body = serializers.CharField(allow_blank=True, required=False)
    editor_json = serializers.JSONField(required=False, allow_null=True)
    mjml_body = serializers.CharField(allow_blank=True, required=False)
    editor_type = serializers.CharField(required=False, allow_blank=True)
    is_active = serializers.BooleanField(required=False)
    notes = serializers.CharField(allow_blank=True, required=False)
    last_updated = serializers.DateTimeField(read_only=True, allow_null=True)
    created_at = serializers.DateTimeField(read_only=True, allow_null=True)
    updated_by_name = serializers.CharField(read_only=True, allow_blank=True, allow_null=True)
    source = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)
    merge_tags = serializers.ListField(read_only=True)
    required_placeholders = serializers.ListField(read_only=True)

    def validate_subject(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Subject cannot be empty.")
        return value


class EmailTemplatePreviewSerializer(serializers.Serializer):
    subject = serializers.CharField(required=False, allow_blank=True)
    html_body = serializers.CharField(required=False, allow_blank=True)
    text_body = serializers.CharField(required=False, allow_blank=True)
    mjml_body = serializers.CharField(required=False, allow_blank=True)


class EmailTemplateSendTestSerializer(serializers.Serializer):
    test_email = serializers.EmailField()

    def validate_test_email(self, value):
        try:
            validate_email(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError("Enter a valid email address.") from exc
        return value
