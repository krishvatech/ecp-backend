"""
Serializers for the events app.

Provides a serializer for creating and updating events. The
`organization_id` is required in the request body for creation.
"""
from django.utils import timezone
from rest_framework import serializers

from .models import Event


class EventSerializer(serializers.ModelSerializer):
    """Serializer for Event objects."""
    organization_id = serializers.IntegerField()
    created_by_id = serializers.IntegerField(read_only=True)

    class Meta:
        model = Event
        fields = [
            "id",
            "organization_id",
            "title",
            "slug",
            "description",
            "start_time",
            "end_time",
            "status",
            "is_live",
            "active_speaker",
            "recording_url",
            "created_by_id",
            "created_at",
            "updated_at",
            "live_started_at",
            "live_ended_at",
        ]

        # Mark auto‑managed fields and new live metadata fields as read only.
        read_only_fields = [
            "id",
            "slug",
            "created_by_id",
            "created_at",
            "updated_at",
            "active_speaker",
            "live_started_at",
            "live_ended_at",
        ]

    # Browsable API uses these formats for rendering/parsing
    start_time = serializers.DateTimeField(
        required=False,
        allow_null=True,
        format="%Y-%m-%dT%H:%M",
        input_formats=[
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",      
            "%Y-%m-%dT%H:%M:%S.%f%z",   
            "%Y-%m-%dT%H:%M:%S.%fZ",
        ],
        style={"input_type": "datetime-local"},  # 'min' is injected dynamically in __init__
    )
    end_time = serializers.DateTimeField(
        required=False,
        allow_null=True,
        format="%Y-%m-%dT%H:%M",
        input_formats=[
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",   
        ],
        style={"input_type": "datetime-local"},
    )

    def __init__(self, *args, **kwargs):
        """
        Inject a dynamic HTML `min` attribute for the browsable API datetime inputs,
        so past times are disabled *visually* in DRF’s debug UI.
        (Back-end validation still enforces the rule regardless.)
        """
        super().__init__(*args, **kwargs)
        # Use local time to match the datetime-local control expectation
        now_local = timezone.localtime().strftime("%Y-%m-%dT%H:%M")
        for fname in ("start_time", "end_time"):
            if fname in self.fields:
                style = self.fields[fname].style or {}
                style.update({
                    "input_type": "datetime-local",
                    "min": now_local,
                })
                self.fields[fname].style = style

    def create(self, validated_data):
        # Assign the creator automatically
        validated_data["created_by_id"] = self.context["request"].user.id
        return super().create(validated_data)

    # ---------- Field-level validations ----------

    def validate_title(self, value: str) -> str:
        if value and value.isdigit():
            raise serializers.ValidationError("Title cannot be only numbers.")
        if value and len(value.strip()) < 3:
            raise serializers.ValidationError("Title must be at least 3 characters long.")
        return value

    def validate_description(self, value: str) -> str:
        # Allow blank/None, but if provided it cannot be purely numeric
        if value and value.isdigit():
            raise serializers.ValidationError("Description cannot be only numbers.")
        return value

    # ---------- Object-level validation ----------

    def validate(self, data):
        """
        Rules:
        - start_time and end_time are compared as timezone-aware datetimes
        - end_time must be strictly later than start_time
        - end_time cannot be provided without start_time
        - both start_time and end_time cannot be in the past
        """
        start_time = data.get("start_time")
        end_time = data.get("end_time")

        # Normalize to aware datetimes for safe comparisons
        def _aware(dt):
            if dt is None:
                return None
            return timezone.make_aware(dt, timezone.get_current_timezone()) if timezone.is_naive(dt) else dt

        start_time = _aware(start_time)
        end_time = _aware(end_time)

        now = timezone.now()

        # If end_time is provided but start_time is missing → not allowed
        if end_time and not start_time:
            raise serializers.ValidationError({"start_time": "Provide start_time when setting end_time."})

        if start_time and start_time < now:
            raise serializers.ValidationError({"start_time": "Start time cannot be in the past."})

        if end_time and end_time < now:
            raise serializers.ValidationError({"end_time": "End time cannot be in the past."})

        # Strict ordering: end_time must be > start_time (not equal)
        if start_time and end_time and not (end_time > start_time):
            raise serializers.ValidationError({"end_time": "End time must be later than start time."})

        return data

