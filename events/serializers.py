"""
Serializers for the events app.

Provides a serializer for creating and updating events. The
`community_id` is required in the request body for creation.
"""
from django.utils import timezone
from datetime import timezone as dt_timezone, timedelta
import os
from rest_framework import serializers
from urllib.parse import urlparse
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.conf import settings
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from django.db import transaction

from django.utils.dateparse import parse_datetime
from django.db.models import Q
from content.tasks import publish_resource_task
from users.serializers import UserMiniSerializer
from .models import (
    Event, EventRegistration, EventParticipant, SpeedNetworkingSession, SpeedNetworkingMatch, SpeedNetworkingQueue,
    EventSession, SessionParticipant, SessionAttendance
)
from community.models import Community
from content.models import Resource
import json


class ParticipantsField(serializers.ListField):
    """Custom field to handle participants sent as JSON string from FormData."""

    def to_internal_value(self, data):
        # DRF multipart parsing may provide participants as a single-item list
        # containing a JSON string, so normalize both string and list-wrapped string.
        if isinstance(data, (list, tuple)) and len(data) == 1 and isinstance(data[0], str):
            data = data[0]

        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                raise serializers.ValidationError("Invalid JSON format for participants")

        # Then use parent validation for list of dicts
        return super().to_internal_value(data)


class SessionsInputField(serializers.ListField):
    """Custom field to handle sessions_input sent as JSON string from FormData."""

    def to_internal_value(self, data):
        # DRF multipart parsing may provide sessions as a single-item list
        # containing a JSON string, so normalize both string and list-wrapped string.
        print(f"\n🔍 SessionsInputField.to_internal_value called:")
        print(f"   Input type: {type(data)}")
        print(f"   Input value: {data}")

        if isinstance(data, (list, tuple)) and len(data) == 1 and isinstance(data[0], str):
            print(f"   Converting list-wrapped string to string")
            data = data[0]

        if isinstance(data, str):
            print(f"   Parsing JSON string")
            try:
                data = json.loads(data)
                print(f"   ✅ Parsed successfully: {data}")
            except (json.JSONDecodeError, TypeError) as e:
                print(f"   ❌ Failed to parse: {e}")
                raise serializers.ValidationError(f"Invalid JSON format for sessions_input: {e}")

        # Then use parent validation for list of dicts
        print(f"   Calling parent to_internal_value")
        result = super().to_internal_value(data)
        print(f"   Parent returned: {result}")
        return result


class EventParticipantSerializer(serializers.ModelSerializer):
    """Read-only serializer for EventParticipant with computed fields supporting both staff and guest types."""

    user_id = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    profile_image_url = serializers.SerializerMethodField()
    bio_text = serializers.SerializerMethodField()
    participant_type = serializers.CharField(read_only=True)

    class Meta:
        model = EventParticipant
        fields = [
            'id',
            'participant_type',
            'user_id',
            'name',
            'email',
            'role',
            'bio_text',
            'profile_image_url',
            'display_order',
            'created_at',
        ]
        read_only_fields = fields

    def get_user_id(self, obj):
        """Get user ID for staff type, None for guest."""
        if obj.participant_type == EventParticipant.PARTICIPANT_TYPE_STAFF and obj.user:
            return obj.user.id
        return None

    def get_name(self, obj):
        """Get display name based on participant type."""
        return obj.get_name()

    def get_email(self, obj):
        """Get email based on participant type."""
        return obj.get_email()

    def get_profile_image_url(self, obj):
        """Get profile image URL with fallback logic."""
        url = obj.get_image_url()
        if url:
            request = self.context.get('request')
            return request.build_absolute_uri(url) if request else url
        return None

    def get_bio_text(self, obj):
        """Get bio with fallback logic."""
        return obj.get_bio()


class SessionParticipantSerializer(serializers.ModelSerializer):
    """Read-only serializer for session participants (mirrors EventParticipantSerializer)."""

    user_id = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    bio_text = serializers.SerializerMethodField()
    profile_image_url = serializers.SerializerMethodField()

    class Meta:
        model = SessionParticipant
        fields = [
            'id', 'participant_type', 'user_id', 'name', 'email', 'role',
            'bio_text', 'profile_image_url', 'display_order', 'created_at'
        ]
        read_only_fields = fields

    def get_user_id(self, obj):
        return obj.user.id if obj.user else None

    def get_name(self, obj):
        return obj.get_name()

    def get_email(self, obj):
        return obj.get_email()

    def get_bio_text(self, obj):
        return obj.get_bio()

    def get_profile_image_url(self, obj):
        url = obj.get_image_url()
        if url:
            request = self.context.get('request')
            return request.build_absolute_uri(url) if request else url
        return None


class SessionAttendanceSerializer(serializers.ModelSerializer):
    """Serializer for session attendance tracking."""

    user_name = serializers.SerializerMethodField()

    class Meta:
        model = SessionAttendance
        fields = ['id', 'session', 'user', 'user_name', 'joined_at', 'left_at', 'duration_seconds', 'is_online']
        read_only_fields = ['joined_at', 'left_at', 'duration_seconds']

    def get_user_name(self, obj):
        return obj.user.get_full_name() or obj.user.username


class EventSessionSerializer(serializers.ModelSerializer):
    """Serializer for event sessions with nested participant support."""

    # Event field - not required in POST (set by view), but included in response
    event = serializers.PrimaryKeyRelatedField(
        queryset=Event.objects.all(),
        required=False,  # Not required in POST since it's set by perform_create()
    )

    # Write-only: accept participants during creation
    participants = serializers.ListField(
        child=serializers.DictField(),
        write_only=True,
        required=False,
        help_text="List of participants: [{'type': 'staff'|'guest', 'user_id': int, 'role': 'speaker'|'moderator'|'host', ...}]"
    )

    # Read-only: return grouped participants
    session_participants = serializers.SerializerMethodField()
    attendance_count = serializers.SerializerMethodField()

    class Meta:
        model = EventSession
        fields = [
            'id', 'event', 'session_date', 'title', 'description', 'start_time', 'end_time',
            'session_type', 'display_order', 'is_live', 'live_started_at', 'live_ended_at',
            'use_parent_meeting', 'dyte_meeting_id', 'recording_url',
            'participants', 'session_participants', 'attendance_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['is_live', 'live_started_at', 'live_ended_at', 'dyte_meeting_id']

    def validate(self, data):
        """Validate session times against event times."""
        from django.utils import timezone

        start = data.get('start_time')
        end = data.get('end_time')
        event = data.get('event')

        # Validate session end is after session start
        if start and end and end <= start:
            raise serializers.ValidationError(
                {"end_time": "end_time must be after start_time"}
            )

        # Get event from context if not in data (for POST requests)
        if not event:
            view = self.context.get('view')
            if view:
                event_id = view.kwargs.get('event_id')
                if event_id:
                    try:
                        event = Event.objects.get(id=event_id)
                    except Event.DoesNotExist:
                        event = None

        # Validate session times are within event times
        if event and start and end:
            event_start = event.start_time
            event_end = event.end_time

            # Check if event has valid start/end times
            if event_start and event_end:
                # Session cannot start before event starts
                if start < event_start:
                    raise serializers.ValidationError(
                        {"start_time": f"Session cannot start before event starts ({event_start.isoformat()})"}
                    )

                # Session cannot end after event ends
                # Allow sessions on the end date if the event ends at midnight (00:00:00)
                # This handles cases where user selects "Feb 20" as end date (saved as Feb 20 00:00)
                # but expects the whole day of Feb 20 to be available.
                cutoff_time = event_end
                if event_end.hour == 0 and event_end.minute == 0 and event_end.second == 0:
                     cutoff_time = event_end + timedelta(days=1)

                if end > cutoff_time:
                    raise serializers.ValidationError(
                        {"end_time": f"Session cannot end after event ends ({event_end.isoformat()})"}
                    )

        return data

    def get_session_participants(self, obj):
        """Return participants grouped by role."""
        from itertools import groupby
        from operator import attrgetter

        participants = obj.participants.all().order_by('role', 'display_order')
        grouped = {}
        for role, group in groupby(participants, key=attrgetter('role')):
            grouped[role] = SessionParticipantSerializer(list(group), many=True, context=self.context).data
        return grouped

    def get_attendance_count(self, obj):
        """Return count of users who attended/are attending."""
        return obj.attendances.count()

    def create(self, validated_data):
        """Create session and associated participants."""
        participants_data = validated_data.pop('participants', [])
        session = EventSession.objects.create(**validated_data)

        if participants_data:
            self._create_participants(session, participants_data)

        return session

    def update(self, instance, validated_data):
        """Update session and optionally replace participants."""
        participants_data = validated_data.pop('participants', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if participants_data is not None:
            # Replace all participants
            instance.participants.all().delete()
            self._create_participants(instance, participants_data)

        return instance

    def _create_participants(self, session, participants_data):
        """Create SessionParticipant records (mirrors EventSerializer._create_participants)."""
        from django.contrib.auth.models import User

        participants_to_create = []
        seen = set()

        for item in participants_data:
            ptype = item.get('type', 'staff')
            role = item.get('role', 'speaker')

            if ptype == 'staff':
                user_id = item.get('user_id')
                if not user_id:
                    continue

                # De-duplicate
                key = ('staff', user_id, role)
                if key in seen:
                    continue
                seen.add(key)

                try:
                    user = User.objects.get(id=user_id)
                except User.DoesNotExist:
                    continue

                participants_to_create.append(SessionParticipant(
                    session=session,
                    participant_type='staff',
                    user=user,
                    role=role,
                    session_bio=item.get('bio', ''),
                    display_order=item.get('display_order', 0)
                ))

            elif ptype == 'guest':
                name = item.get('name', '').strip()
                if not name:
                    continue

                # De-duplicate
                key = ('guest', name.lower(), role)
                if key in seen:
                    continue
                seen.add(key)

                participants_to_create.append(SessionParticipant(
                    session=session,
                    participant_type='guest',
                    guest_name=name,
                    guest_email=item.get('email', ''),
                    guest_bio=item.get('bio', ''),
                    role=role,
                    display_order=item.get('display_order', 0)
                ))

        if participants_to_create:
            SessionParticipant.objects.bulk_create(participants_to_create)


class EventSerializer(serializers.ModelSerializer):
    """Serializer for Event objects."""
    community_id = serializers.PrimaryKeyRelatedField(
        source="community",
        queryset=Community.objects.all(),
        write_only=True,
    )
    community = serializers.IntegerField(source='community.id', read_only=True)
    # Accept resources in the same event-create request (all OPTIONAL)
    resource_files = serializers.ListField(
        child=serializers.FileField(allow_empty_file=False, use_url=False),
        write_only=True, required=False, default=list
    )
    resource_links = serializers.ListField(
        child=serializers.CharField(allow_blank=True, trim_whitespace=True),
        write_only=True, required=False, default=list
    )
    resource_videos = serializers.ListField(
        child=serializers.CharField(allow_blank=True, trim_whitespace=True),
        write_only=True, required=False, default=list
    )

    # (Optional) read-only convenience to see what got attached later
    resources = serializers.SerializerMethodField(read_only=True)
    created_by_id = serializers.IntegerField(read_only=True)
    attending_count = serializers.IntegerField(read_only=True)
    registrations_count = serializers.IntegerField(read_only=True)

    # Let recording_url be blank or omitted; we will normalize/validate in validate()
    recording_url = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    # Write-only field for participants input (handles JSON string or list)
    participants = ParticipantsField(
        child=serializers.DictField(),
        write_only=True,
        required=False,
        default=list,
        help_text="List of participants (staff or guest). Staff: {'type': 'staff', 'user_id': 1, 'role': 'speaker'}. Guest: {'type': 'guest', 'name': 'Name', 'email': 'email@example.com', 'role': 'speaker'}"
    )

    # Read-only field for participants output
    event_participants = serializers.SerializerMethodField(read_only=True)

    # Session-related fields
    sessions = EventSessionSerializer(many=True, read_only=True)
    has_sessions = serializers.SerializerMethodField(read_only=True)

    # Cancellation fields
    recommended_event_id = serializers.PrimaryKeyRelatedField(
        queryset=Event.objects.all(),
        source="recommended_event",
        write_only=True,
        required=False,
        allow_null=True
    )
    recommended_event = serializers.SerializerMethodField(read_only=True)

    def get_recommended_event(self, obj):
        if obj.recommended_event_id:
            return {
                "id": obj.recommended_event.id,
                "slug": obj.recommended_event.slug,
                "title": obj.recommended_event.title,
                "start_time": obj.recommended_event.start_time,
            }
        return None

    # Write-only field for sessions input during event creation (atomic with event)
    # Using custom field to handle JSON strings from FormData
    sessions_input = SessionsInputField(
        child=serializers.DictField(),
        write_only=True,
        required=False,
        allow_empty=True,
        help_text="List of sessions: [{'title': 'Session 1', 'session_date': '2026-02-16', 'start_time': '2026-02-16T08:30:00Z', 'end_time': '2026-02-16T08:40:00Z', ...}]"
    )

    class Meta:
        model = Event
        fields = [
            "id",
            "community_id",
            "community",
            "title",
            "slug",
            "description",
            "start_time",
            "end_time",
            "timezone",
            "status",
            "is_live",
            "is_on_break",
            "is_multi_day",
            "cancelled_at",
            "cancelled_by_id",
            "cancellation_message",
            "recommended_event",
            "recommended_event_id",
            "replay_available",
            "replay_availability_duration",
            "category",
            "format",
            "location",
            "price",
            "is_free",
            "max_participants",
            "saleor_product_id",
            "saleor_variant_id",
            "attending_count",
            "registrations_count",
            "preview_image",
            "lounge_table_capacity",
            "breakout_rooms_active",
            "waiting_room_enabled",
            "auto_admit_seconds",
            "waiting_room_grace_period_minutes",
            "lounge_enabled_waiting_room",
            "networking_tables_enabled_waiting_room",
            "active_speaker",
            "recording_url",
            "rtk_recording_id",
            "is_recording",
            "recording_paused_at",
            "dyte_meeting_id",    
            "dyte_meeting_title",  
            "created_by_id",
            "created_at",
            "updated_at",
            "live_started_at",
            "live_ended_at",
            "resource_files",
            "resource_links",
            "resource_videos",
            "resources",
            "lounge_enabled_before",
            "lounge_before_buffer",
            "lounge_enabled_during",
            "lounge_enabled_breaks",
            "lounge_enabled_after",
            "lounge_after_buffer",
            "show_participants_before_event",
            "show_participants_after_event",
            "participants",
            "event_participants",
            "sessions",
            "has_sessions",
            "sessions_input",
        ]
        
        read_only_fields = [
            "id",
            "created_by_id",
            "created_at",
            "updated_at",
            "active_speaker",
            "attending_count",
            "registrations_count",
            "live_started_at",
            "live_ended_at",
            "dyte_meeting_id",
            "dyte_meeting_title",
        ]
        extra_kwargs = {
            # Let custom validate_slug() handle uniqueness so create can auto-suffix collisions.
            "slug": {"validators": []},
        }


    # Browsable API uses these formats for rendering/parsing
    start_time = serializers.DateTimeField(
        required=False,
        allow_null=True,
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
    end_time = serializers.DateTimeField(
        required=False,
        allow_null=True,
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
                
                
    def _normalize_url(self, u: str) -> str:
        """If user types 'www.foo.com', make it 'https://www.foo.com' (leave empty as-is)."""
        u = (u or "").strip()
        if not u:
            return u
        parsed = urlparse(u)
        if not parsed.scheme:
            return f"https://{u}"
        return u

    def _filter_urls(self, values):
        """
        Coerce single string → list, drop placeholders ('string', 'null', 'None'),
        normalize, validate (http/https/s3), and return only valid URLs.
        We *silently ignore* invalid/placeholder entries so links/videos remain optional.
        """
        placeholder_set = {"string", "null", "none", "[]"}
        if values is None:
            values = []
        if isinstance(values, str):
            values = [values]

        validator = URLValidator(schemes=["http", "https", "s3"])
        kept = []
        for raw in values:
            s = (raw or "").strip()
            if not s or s.lower() in placeholder_set:
                continue
            s = self._normalize_url(s)

            # Validate and also require a dot in hostname for http/https (avoid 'https://string')
            try:
                validator(s)
                parsed = urlparse(s)
                if parsed.scheme in ("http", "https"):
                    if not parsed.netloc or "." not in parsed.netloc:
                        continue
            except DjangoValidationError:
                continue

            kept.append(s)
        return kept

    def _create_participants(self, event, participants_data):
        """
        Create EventParticipant records from input data.

        Supports both staff users and guest speakers:

        Staff format:
        {
            "type": "staff",
            "user_id": 1,
            "role": "speaker",
            "bio": "Optional event-specific bio override",
            "display_order": 0
        }

        Guest format:
        {
            "type": "guest",
            "name": "Guest Speaker Name",
            "email": "guest@example.com",
            "bio": "Guest speaker bio",
            "role": "speaker",
            "display_order": 0
        }

        For backwards compatibility, if no "type" is provided, assumes staff.
        """
        if not participants_data:
            return

        from django.contrib.auth.models import User
        from django.core.files.base import ContentFile

        validated_participants = []
        staff_user_ids = []
        request = self.context.get("request")
        request_files = getattr(request, "FILES", None)

        for idx, p_data in enumerate(participants_data):
            # Determine participant type (default to 'staff' for backwards compatibility)
            p_type = p_data.get('type', 'staff').lower()
            role = p_data.get('role', '').lower()

            # Validate role
            if role not in ['speaker', 'moderator', 'host']:
                raise serializers.ValidationError({
                    'participants': f'Invalid role "{role}" at index {idx}. Must be: speaker, moderator, or host'
                })

            if p_type == 'staff':
                # Staff participant requires user_id
                user_id = p_data.get('user_id')
                if not user_id:
                    raise serializers.ValidationError({
                        'participants': f'Missing user_id for staff participant at index {idx}'
                    })
                staff_user_ids.append(user_id)

                validated_participants.append({
                    'type': 'staff',
                    'user_id': user_id,
                    'role': role,
                    'event_bio': (p_data.get('bio') or '').strip(),
                    'display_order': p_data.get('display_order', idx),
                    'client_index': p_data.get('client_index', idx),
                })

            elif p_type == 'guest':
                # Guest participant requires name
                guest_name = (p_data.get('name') or '').strip()
                if not guest_name:
                    raise serializers.ValidationError({
                        'participants': f'Missing name for guest participant at index {idx}'
                    })

                validated_participants.append({
                    'type': 'guest',
                    'guest_name': guest_name,
                    'guest_email': (p_data.get('email') or '').strip(),
                    'guest_bio': (p_data.get('bio') or '').strip(),
                    'role': role,
                    'display_order': p_data.get('display_order', idx),
                    'client_index': p_data.get('client_index', idx),
                })
            else:
                raise serializers.ValidationError({
                    'participants': f'Invalid type "{p_type}" at index {idx}. Must be: staff or guest'
                })

        # Verify all staff user IDs exist (batch query)
        if staff_user_ids:
            existing_users = User.objects.filter(id__in=staff_user_ids).values_list('id', flat=True)
            existing_user_ids = set(existing_users)

            missing_ids = [uid for uid in staff_user_ids if uid not in existing_user_ids]
            if missing_ids:
                raise serializers.ValidationError({
                    'participants': f'User IDs not found: {missing_ids}'
                })

        # De-duplicate: for staff by (user_id, role), for guest by (name, email, role)
        dedup_key_map = {}
        for p in validated_participants:
            if p['type'] == 'staff':
                key = ('staff', p['user_id'], p['role'])
            else:
                key = ('guest', p['guest_name'], p['guest_email'], p['role'])

            if key not in dedup_key_map:
                dedup_key_map[key] = p

        # Create EventParticipant records and handle guest account creation
        registration_user_ids = set()
        guests_to_create_accounts = []  # Track guests needing account creation

        def _get_participant_image_from_request(client_index):
            if request_files is None:
                return None
            return request_files.get(f"participant_image_{client_index}")

        for p_data in dedup_key_map.values():
            participant_image_file = _get_participant_image_from_request(
                p_data.get("client_index", 0)
            )
            if p_data['type'] == 'staff':
                registration_user_ids.add(p_data['user_id'])
                participant = EventParticipant(
                    event=event,
                    participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
                    user_id=p_data['user_id'],
                    role=p_data['role'],
                    event_bio=p_data['event_bio'],
                    display_order=p_data['display_order'],
                )
                if participant_image_file:
                    participant.event_image = participant_image_file
                participant.save()
            else:  # guest
                guest_email = p_data['guest_email']
                guest_name = p_data['guest_name']

                # Check if user already exists for this guest
                user = User.objects.filter(email=guest_email).first()
                if not user and guest_email:
                    # Create new user account for guest
                    # Generate unique username from email
                    base_username = guest_email.split('@')[0]
                    username = base_username
                    counter = 1
                    while User.objects.filter(username=username).exists():
                        username = f"{base_username}{counter}"
                        counter += 1

                    # Parse guest name into first and last name
                    name_parts = guest_name.split(' ', 1)
                    first_name = name_parts[0] if name_parts else ''
                    last_name = name_parts[1] if len(name_parts) > 1 else ''

                    # Create user record now; credentials are generated/sent later
                    # by send_speaker_credentials_task -> send_speaker_credentials_email.
                    user = User(
                        username=username,
                        email=guest_email,
                        first_name=first_name,
                        last_name=last_name,
                        is_staff=False,
                        is_active=True
                    )
                    user.set_unusable_password()
                    user.save()

                    # Queue for sending credentials email
                    guests_to_create_accounts.append(user.id)
                if user:
                    registration_user_ids.add(user.id)
                    if participant_image_file:
                        from users.models import UserProfile

                        profile, _ = UserProfile.objects.get_or_create(user=user)
                        participant_image_file.seek(0)
                        image_copy = ContentFile(
                            participant_image_file.read(),
                            name=participant_image_file.name,
                        )
                        profile.user_image = image_copy
                        profile.save(update_fields=["user_image"])
                        participant_image_file.seek(0)

                participant = EventParticipant(
                    event=event,
                    participant_type=EventParticipant.PARTICIPANT_TYPE_GUEST,
                    role=p_data['role'],
                    guest_name=p_data['guest_name'],
                    guest_email=p_data['guest_email'],
                    guest_bio=p_data['guest_bio'],
                    display_order=p_data['display_order'],
                )
                if participant_image_file:
                    participant.guest_image = participant_image_file
                participant.save()

        # Auto-register all participant users so events appear in "My Events".
        # This includes staff participants and guests with user accounts.
        for user_id in registration_user_ids:
            EventRegistration.objects.get_or_create(
                event=event,
                user_id=user_id,
                defaults={
                    "status": "registered",
                    "admission_status": "admitted",
                    "was_ever_admitted": True,
                },
            )

        # Send credentials emails to newly created guest accounts
        if guests_to_create_accounts:
            from users.task import send_speaker_credentials_task
            for user_id in guests_to_create_accounts:
                send_speaker_credentials_task.delay(user_id)

    def create(self, validated_data):
        # Extract sessions_input before processing other data (must be done first for atomicity)
        sessions_input = validated_data.pop('sessions_input', [])

        print(f"\n🔍 DEBUG sessions_input type: {type(sessions_input)}")
        print(f"   sessions_input value: {sessions_input}")
        print(f"   isinstance(sessions_input, list): {isinstance(sessions_input, list)}")
        print(f"   isinstance(sessions_input, str): {isinstance(sessions_input, str)}")

        # Handle JSON string sessions_input (from FormData) - CRITICAL FIX
        if isinstance(sessions_input, str):
            import json
            try:
                sessions_input = json.loads(sessions_input)
                print(f"✅ Parsed sessions_input from JSON string: {len(sessions_input)} sessions")
                print(f"   Parsed data: {sessions_input}")
            except (json.JSONDecodeError, TypeError) as e:
                print(f"❌ Failed to parse sessions_input JSON: {e}")
                sessions_input = []
        elif isinstance(sessions_input, list):
            print(f"✅ sessions_input is already a list with {len(sessions_input)} items")
        else:
            print(f"⚠️ sessions_input is neither string nor list: {type(sessions_input)}")

        # Extract participants data before creating Event
        participants_data = validated_data.pop('participants', [])

        # Handle JSON string participants (from FormData)
        if isinstance(participants_data, str):
            import json
            try:
                participants_data = json.loads(participants_data)
            except (json.JSONDecodeError, TypeError):
                participants_data = []

        files  = validated_data.pop("resource_files", [])
        links  = validated_data.pop("resource_links", [])
        videos = validated_data.pop("resource_videos", [])

        # attach creator
        validated_data["created_by_id"] = self.context["request"].user.id

        print(f"\n🔴 BACKEND CREATE METHOD:")
        print(f"  validated_data['start_time']: {validated_data.get('start_time')}")
        print(f"  validated_data['end_time']: {validated_data.get('end_time')}")
        print(f"  validated_data['timezone']: {validated_data.get('timezone')}")
        print(f"  sessions_input count: {len(sessions_input)}")

        # Wrap entire creation in atomic transaction
        with transaction.atomic():
            event = super().create(validated_data)

            print(f"  Event created with ID {event.id}:")
            print(f"    Stored start_time: {event.start_time}")
            print(f"    Stored end_time: {event.end_time}")
            print(f"🔴 BACKEND CREATE METHOD END\n")

            # Automatically add event creator as attendee
            creator = self.context["request"].user
            EventRegistration.objects.get_or_create(
                event=event,
                user=creator,
                defaults={"status": "registered", "admission_status": "admitted"}
            )

            # ----- read "Attach Resources" metadata coming from the form -----
            req = self.context.get("request")
            meta_title = (req.data.get("resource_title") or "").strip() if req else ""
            meta_desc  = (req.data.get("resource_description") or "").strip() if req else ""

            # tags can be repeated keys in multipart; prefer getlist when available
            if req and hasattr(req.data, "getlist"):
                meta_tags = [t.strip() for t in req.data.getlist("resource_tags") if t.strip()]
            else:
                raw = (req.data.get("resource_tags") if req else []) or []
                meta_tags = [t.strip() for t in raw.split(",")] if isinstance(raw, str) else list(raw)

            # publish controls
            # UI: toggle "Publish resources immediately" + an optional datetime
            publish_toggle = (req.data.get("publish_resources_immediately")  # boolean "true"/"false"
                            if req else None)
            publish_at_raw = (req.data.get("resource_publish_at") or req.data.get("publish_at")) if req else None

            def _to_bool(val):
                if isinstance(val, bool):
                    return val
                if val is None:
                    return None
                return str(val).strip().lower() in {"1","true","yes","y","on"}

            publish_now_flag = _to_bool(publish_toggle)
            publish_at = parse_datetime(publish_at_raw) if publish_at_raw else None
            if publish_at and timezone.is_naive(publish_at):
                publish_at = timezone.make_aware(publish_at, timezone.get_current_timezone())

            # decide final publishing state
            if publish_now_flag is False and publish_at and publish_at > timezone.now():
                is_published = False
            else:
                # publish immediately if toggle true OR no schedule OR schedule in the past
                is_published = True
                publish_at = None

            # helper: apply title/desc/tags overrides only if provided
            def apply_meta(title, description, tags):
                t = (meta_title or title or event.title)
                d = (meta_desc if meta_desc != "" else description)
                tg = (meta_tags if meta_tags else (tags or []))
                return t, d, tg

            user = self.context["request"].user if self.context.get("request") else None
            org = event.community

            scheduled_ids = []

            # ---------------- Files ----------------
            import os as _os
            for file_data in files or []:
                if hasattr(file_data, "name"):
                    base_title = _os.path.splitext(file_data.name)[0] or event.title
                    title, description, tags = apply_meta(base_title, "", [])
                    r = Resource.objects.create(
                        community=org, event=event, type=Resource.TYPE_FILE,
                        title=title, description=description, tags=tags,
                        file=file_data, uploaded_by=user,
                        is_published=is_published, publish_at=publish_at,
                    )
                else:
                    title = file_data.get("title") or _os.path.splitext(getattr(file_data.get("file"), "name", "file"))[0] or event.title
                    description = file_data.get("description", "")
                    tags = file_data.get("tags", [])
                    title, description, tags = apply_meta(title, description, tags)
                    r = Resource.objects.create(
                        community=org, event=event, type=Resource.TYPE_FILE,
                        title=title, description=description, tags=tags,
                        file=file_data.get("file"), uploaded_by=user,
                        is_published=is_published, publish_at=publish_at,
                    )
                if not r.is_published and r.publish_at:
                    publish_resource_task.apply_async(args=[r.id], eta=r.publish_at)
                    scheduled_ids.append(r.id)

            # ---------------- Links ----------------
            for link_data in links or []:
                if isinstance(link_data, str):
                    title, description, tags = apply_meta(link_data, "", [])
                    url = link_data
                else:
                    base_title = link_data.get("title", link_data.get("url"))
                    url = link_data.get("url")
                    base_desc = link_data.get("description", "")
                    base_tags = link_data.get("tags", [])
                    title, description, tags = apply_meta(base_title, base_desc, base_tags)

                r = Resource.objects.create(
                    community=org, event=event, type=Resource.TYPE_LINK,
                    title=title, description=description, tags=tags,
                    link_url=url, uploaded_by=user,
                    is_published=is_published, publish_at=publish_at,
                )
                if not r.is_published and r.publish_at:
                    publish_resource_task.apply_async(args=[r.id], eta=r.publish_at)
                    scheduled_ids.append(r.id)

            # ---------------- Videos ----------------
            for video_data in videos or []:
                if isinstance(video_data, str):
                    title, description, tags = apply_meta(video_data, "", [])
                    url = video_data
                else:
                    base_title = video_data.get("title", video_data.get("url"))
                    url = video_data.get("url")
                    base_desc = video_data.get("description", "")
                    base_tags = video_data.get("tags", [])
                    title, description, tags = apply_meta(base_title, base_desc, base_tags)

                r = Resource.objects.create(
                    community=org, event=event, type=Resource.TYPE_VIDEO,
                    title=title, description=description, tags=tags,
                    video_url=url, uploaded_by=user,
                    is_published=is_published, publish_at=publish_at,
                )
                if not r.is_published and r.publish_at:
                    publish_resource_task.apply_async(args=[r.id], eta=r.publish_at)
                    scheduled_ids.append(r.id)

            # Create participants (add after resource creation)
            self._create_participants(event, participants_data)

            # Create sessions atomically with the event
            for session_data in sessions_input:
                from dateutil.parser import parse as parse_datetime
                session_data.pop('event', None)  # prevent stale key conflicts

                # Convert ISO string timestamps to datetime objects if needed
                if isinstance(session_data.get('start_time'), str):
                    try:
                        session_data['start_time'] = parse_datetime(session_data['start_time'])
                    except (ValueError, TypeError):
                        print(f"⚠️ Failed to parse start_time: {session_data.get('start_time')}")

                if isinstance(session_data.get('end_time'), str):
                    try:
                        session_data['end_time'] = parse_datetime(session_data['end_time'])
                    except (ValueError, TypeError):
                        print(f"⚠️ Failed to parse end_time: {session_data.get('end_time')}")

                print(f"✅ Creating session: {session_data.get('title')}")
                print(f"   start_time type: {type(session_data.get('start_time'))}")
                print(f"   end_time type: {type(session_data.get('end_time'))}")

                EventSession.objects.create(event=event, **session_data)

        return event

    def update(self, instance, validated_data):
        # Extract and handle participants separately
        participants_data = validated_data.pop('participants', None)

        # Handle JSON string participants (from FormData)
        if isinstance(participants_data, str):
            import json
            try:
                participants_data = json.loads(participants_data)
            except (json.JSONDecodeError, TypeError):
                participants_data = None

        # Update event fields
        instance = super().update(instance, validated_data)

        # If participants data provided, replace existing participants
        if participants_data is not None:
            # Delete existing participants
            instance.participants.all().delete()
            # Create new participants
            self._create_participants(instance, participants_data)

        return instance

    def get_resources(self, obj):
        # small, safe read to show what's attached (no extra queries if prefetched)
        qs = getattr(obj, "resources", None)
        if not qs:
            return []
        # Minimal shape to avoid circular import of content.serializers
        return [
            {
                "id": r.id,
                "type": r.type,
                "title": r.title,
                "file": getattr(r.file, "url", None) if getattr(r, "file", None) else None,
                "link_url": r.link_url or None,
                "video_url": r.video_url or None,
                "is_published": r.is_published,
                "created_at": getattr(r, "created_at", None),
            }
            for r in qs.all().order_by("-created_at")
        ]

    def get_event_participants(self, obj):
        """Return all participants grouped by role."""
        qs = getattr(obj, 'participants', None)
        if not qs:
            return {
                'speakers': [],
                'moderators': [],
                'hosts': [],
            }

        # Prefetch related user profiles for efficiency
        participants = qs.select_related('user', 'user__profile').all()

        serializer = EventParticipantSerializer(
            participants,
            many=True,
            context=self.context
        )

        # Group by role for easier frontend consumption
        grouped = {
            'speakers': [],
            'moderators': [],
            'hosts': [],
        }

        for p_data in serializer.data:
            role = str(p_data.get('role', '') if isinstance(p_data, dict) else '').lower()
            if role == 'host':
                grouped['hosts'].append(p_data)
            elif role == 'speaker':
                grouped['speakers'].append(p_data)
            elif role == 'moderator':
                grouped['moderators'].append(p_data)

        return grouped

    def get_has_sessions(self, obj):
        """Check if event has sessions."""
        return obj.has_sessions

    # ---------- Field-level validations ----------
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get("request")
        if instance.preview_image:
            url = instance.preview_image.url
            data["preview_image"] = request.build_absolute_uri(url) if request else url
        if instance.cover_image:
            url = instance.cover_image.url
            data["cover_image"] = request.build_absolute_uri(url) if request else url
        if instance.waiting_room_image:
            url = instance.waiting_room_image.url
            data["waiting_room_image"] = request.build_absolute_uri(url) if request else url
        return data

    def validate_price(self, value):
        if value is not None and value < 0:
            raise serializers.ValidationError("Price cannot be negative.")
        return value

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
    
    def validate_timezone(self, value):
        tz_value = value or settings.TIME_ZONE
        if isinstance(tz_value, str):
            tz_value = tz_value.strip()
        if not tz_value:
            tz_value = settings.TIME_ZONE
        try:
            ZoneInfo(tz_value)
        except ZoneInfoNotFoundError:
            raise serializers.ValidationError(
                "Invalid timezone. Use IANA timezone like Asia/Kolkata"
            )
        return tz_value

    def validate_slug(self, value):
        """Validate slug format and uniqueness."""
        if not value:
            return value  # Allow blank (auto-generated in save())
        import re
        if not re.match(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', value):
            raise serializers.ValidationError(
                "Slug must contain only lowercase letters, numbers, and hyphens."
            )
        # Check uniqueness (exclude self if updating)
        qs = Event.objects.filter(slug=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if not qs.exists():
            return value

        # For create flow, hidden slug input can collide (same title multiple times).
        # Auto-resolve to a unique slug instead of failing.
        if not self.instance:
            max_len = Event._meta.get_field("slug").max_length or 255
            base_slug = value[:max_len]
            candidate = base_slug
            suffix = 2
            while Event.objects.filter(slug=candidate).exists():
                suffix_str = f"-{suffix}"
                candidate = f"{base_slug[: max_len - len(suffix_str)]}{suffix_str}"
                suffix += 1
            return candidate

        raise serializers.ValidationError("This slug is already in use.")

    # ---------- Object-level validation ----------

    def validate(self, data):
        """
        URL normalization + validation (non-fatal for links/videos), then existing time rules.
        """

        # ---- recording_url: allow blank/placeholder; normalize if valid; else set "" ----
        ru = data.get("recording_url")
        if ru is None or str(ru).strip() == "" or str(ru).strip().lower() in {"string","null","none"}:
            data["recording_url"] = ""
        else:
            candidate = self._normalize_url(str(ru))
            validator = URLValidator(schemes=["http","https","s3"])
            try:
                validator(candidate)
                parsed = urlparse(candidate)
                if parsed.scheme in ("http","https"):
                    if not parsed.netloc or "." not in parsed.netloc:
                        candidate = ""
            except DjangoValidationError:
                candidate = ""
            data["recording_url"] = candidate

        # ---- optional arrays: coerce and filter; never raise on links/videos ----
        data["resource_links"]  = self._filter_urls(data.get("resource_links", []))
        data["resource_videos"] = self._filter_urls(data.get("resource_videos", []))

        tz_value = data.get("timezone") or settings.TIME_ZONE
        if isinstance(tz_value, str):
            tz_value = tz_value.strip()
        if not tz_value:
            tz_value = settings.TIME_ZONE
        try:
            event_tz = ZoneInfo(tz_value)
        except ZoneInfoNotFoundError:
            raise serializers.ValidationError(
                {"timezone": "Invalid timezone. Use IANA timezone like Asia/Kolkata"}
            )
        data["timezone"] = tz_value

        # ---- your existing time rules below (unchanged) ----
        start_time = data.get("start_time")
        end_time = data.get("end_time")

        print(f"\n🔴 BACKEND TIME VALIDATION START:")
        print(f"  Received start_time: {start_time} (type: {type(start_time).__name__})")
        print(f"  Received end_time: {end_time} (type: {type(end_time).__name__})")
        print(f"  Event timezone: {tz_value} -> {event_tz}")

        def _to_utc(dt):
            if dt is None:
                return None
            if timezone.is_naive(dt):
                print(f"    Converting naive datetime to {event_tz}")
                dt = timezone.make_aware(dt, event_tz)
            is_naive = timezone.is_naive(dt)
            print(f"    Input: {dt} (naive: {is_naive}, tzinfo: {dt.tzinfo if not is_naive else 'N/A'})")
            result = dt.astimezone(dt_timezone.utc)
            print(f"    Output (UTC): {result}")
            return result

        start_time = _to_utc(start_time)
        end_time = _to_utc(end_time)

        print(f"  After conversion - start_time: {start_time}")
        print(f"  After conversion - end_time: {end_time}")

        if start_time is not None:
            data["start_time"] = start_time
        if end_time is not None:
            data["end_time"] = end_time

        print(f"  Data before return: start_time={data.get('start_time')}, end_time={data.get('end_time')}")
        print(f"🔴 BACKEND TIME VALIDATION END\n")

        now = timezone.now()

        # On edit (PATCH/PUT), allow already-past times if they are unchanged from the stored event.
        # This lets users update metadata/sessions for events that already started.
        existing_start = getattr(self.instance, "start_time", None)
        existing_end = getattr(self.instance, "end_time", None)
        if existing_start and timezone.is_naive(existing_start):
            existing_start = timezone.make_aware(existing_start, dt_timezone.utc)
        if existing_end and timezone.is_naive(existing_end):
            existing_end = timezone.make_aware(existing_end, dt_timezone.utc)

        def _unchanged_dt(new_value, old_value, tolerance_seconds=60):
            if not new_value or not old_value:
                return False
            return abs((new_value - old_value).total_seconds()) <= tolerance_seconds

        if end_time and not start_time:
            raise serializers.ValidationError({"start_time": "Provide start_time when setting end_time."})
        if start_time and start_time < now:
            if not (self.instance and _unchanged_dt(start_time, existing_start)):
                raise serializers.ValidationError({"start_time": "Start time cannot be in the past."})
        if end_time and end_time < now:
            if not (self.instance and _unchanged_dt(end_time, existing_end)):
                raise serializers.ValidationError({"end_time": "End time cannot be in the past."})
        if start_time and end_time and not (end_time > start_time):
            raise serializers.ValidationError({"end_time": "End time must be later than start time."})

        # Validate sessions_input: all session dates must fall within event dates
        sessions_input = data.get('sessions_input', [])

        print(f"\n🔍 VALIDATE METHOD - sessions_input check:")
        print(f"   Type: {type(sessions_input)}")
        print(f"   Value: {sessions_input}")
        print(f"   Is empty: {not sessions_input}")

        event_start = data.get('start_time')
        event_end = data.get('end_time')

        if sessions_input and event_start and event_end:
            from dateutil.parser import parse as parse_datetime
            errors = []
            for i, session in enumerate(sessions_input):
                sess_start = session.get('start_time')
                sess_end = session.get('end_time')
                label = session.get('title', f'Session {i+1}')

                # Parse session times if they're strings (ISO format)
                if isinstance(sess_start, str):
                    try:
                        sess_start = parse_datetime(sess_start)
                    except (ValueError, TypeError):
                        errors.append(f"'{label}' has invalid start_time format: {sess_start}")
                        continue

                if isinstance(sess_end, str):
                    try:
                        sess_end = parse_datetime(sess_end)
                    except (ValueError, TypeError):
                        errors.append(f"'{label}' has invalid end_time format: {sess_end}")
                        continue

                # Now compare with event times (both are datetime objects)
                if sess_start and sess_start < event_start:
                    errors.append(
                        f"'{label}' starts before the event "
                        f"({sess_start.isoformat()} < {event_start.isoformat()})"
                    )
                if sess_end and sess_end > event_end:
                    errors.append(
                        f"'{label}' ends after the event "
                        f"({sess_end.isoformat()} > {event_end.isoformat()})"
                    )
            if errors:
                raise serializers.ValidationError({"sessions_input": errors})

        # Validate participants structure
        participants = data.get('participants', [])
        if participants:
            if not isinstance(participants, list):
                raise serializers.ValidationError({
                    'participants': 'Must be a list of participant objects'
                })

            for idx, p in enumerate(participants):
                if not isinstance(p, dict):
                    raise serializers.ValidationError({
                        'participants': f'Item at index {idx} must be a dictionary'
                    })

        return data


class PublicEventSerializer(serializers.ModelSerializer):
    """
    Public-facing serializer for event landing pages.
    Only exposes non-sensitive fields safe for anonymous users.
    """
    speakers = serializers.SerializerMethodField()
    preview_image = serializers.SerializerMethodField()
    sessions = EventSessionSerializer(many=True, read_only=True)

    class Meta:
        model = Event
        fields = [
            "id", "slug", "title", "description",
            "start_time", "end_time", "timezone",
            "status", "is_live", "category", "format",
            "location", "price", "is_free",
            "preview_image", "attending_count",
            "created_at", "sessions", "speakers",
            "is_multi_day",
        ]
        read_only_fields = fields

    def get_speakers(self, obj):
        """Fetch speaker cards from EventParticipant entries."""
        participants = (
            obj.participants
            .filter(role=EventParticipant.ROLE_SPEAKER)
            .select_related("user", "user__profile")
            [:10]
        )

        result = []
        for participant in participants:
            result.append(
                {
                    "name": participant.get_name() or "",
                    "bio": participant.get_bio() or "",
                    "image": participant.get_image_url() or "",
                }
            )
        return result

    def get_preview_image(self, obj):
        """Return absolute URL for preview image."""
        if not obj.preview_image:
            return None
        req = self.context.get('request')
        try:
            if req:
                return req.build_absolute_uri(obj.preview_image.url)
            return str(obj.preview_image.url)
        except Exception:
            return str(obj.preview_image)


class EventLiteSerializer(serializers.ModelSerializer):
    # Session-related fields for multi-day events
    sessions = EventSessionSerializer(many=True, read_only=True)
    recommended_event = serializers.SerializerMethodField(read_only=True)

    def get_recommended_event(self, obj):
        if obj.recommended_event_id:
            return {
                "id": obj.recommended_event.id,
                "slug": obj.recommended_event.slug,
                "title": obj.recommended_event.title,
                "start_time": obj.recommended_event.start_time,
            }
        return None

    class Meta:
        model = Event
        fields = (
            "id", "slug", "title", "start_time", "end_time", "timezone", "status", "live_ended_at",
            "preview_image", "cover_image", "waiting_room_image", "location", "category", "is_live", "recording_url", "replay_available", "replay_availability_duration", "price", "is_free",
            "waiting_room_enabled", "waiting_room_grace_period_minutes", "lounge_enabled_waiting_room", "networking_tables_enabled_waiting_room", "auto_admit_seconds",
            "lounge_enabled_before", "lounge_before_buffer",
            "lounge_enabled_after", "lounge_after_buffer",
            "is_multi_day", "sessions",  # ✅ Added for multi-day event support
            "cancellation_message", "recommended_event",
        )

class EventRegistrationSerializer(serializers.ModelSerializer):
    event = EventLiteSerializer(read_only=True)
    event_id = serializers.PrimaryKeyRelatedField(
        queryset=Event.objects.all(),
        source="event",
        write_only=True,
        required=True,
    )
    # used when creating – still hidden
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())

    # extra read-only fields so owner can see who bought
    user_id = serializers.IntegerField(source="user.id", read_only=True)
    user_name = serializers.SerializerMethodField()
    user_email = serializers.EmailField(source="user.email", read_only=True)
    user_avatar_url = serializers.SerializerMethodField()
    user_kyc_status = serializers.SerializerMethodField()
    is_host = serializers.SerializerMethodField()

    class Meta:
        model = EventRegistration
        fields = (
            "id",
            "event",
            "event_id",
            "user",
            "user_id",
            "user_name",
            "user_email",
            "user_avatar_url",
            "user_kyc_status",
            "registered_at",
            "joined_live",
            "watched_replay",
            "admission_status",
            "admitted_at",
            "admitted_by",
            "rejected_at",
            "rejected_by",
            "rejection_reason",
            "waiting_started_at",
            "waiting_started_at",
            "joined_live_at",
            "status",
            "is_host",
        )
        read_only_fields = (
            "id",
            "registered_at",
            "joined_live",
            "watched_replay",
            "user_id",
            "user_name",
            "user_email",
            "user_avatar_url",
            "user_kyc_status",
            "admission_status",
            "admitted_at",
            "admitted_by",
            "rejected_at",
            "rejected_by",
            "rejection_reason",
            "waiting_started_at",
            "joined_live_at",
            "status",
            "is_host",
        )

    def get_is_host(self, obj):
        event = obj.event
        user_id = obj.user_id
        if not event or not user_id:
            return False

        if (
            user_id == getattr(event, "created_by_id", None)
            or user_id == getattr(getattr(event, "community", None), "owner_id", None)
        ):
            return True

        # Account for explicit Host role assignment in EventParticipant list.
        host_match = Q(participant_type="staff", user_id=user_id)
        user_email = (getattr(obj.user, "email", "") or "").strip()
        if user_email:
            host_match = host_match | Q(participant_type="guest", guest_email__iexact=user_email)
        return event.participants.filter(role="host").filter(host_match).exists()

    def get_user_name(self, obj):
        first = (getattr(obj.user, "first_name", "") or "").strip()
        last = (getattr(obj.user, "last_name", "") or "").strip()
        full = (first + " " + last).strip()
        if full:
            return full
        return getattr(obj.user, "username", "") or ""

    def get_user_avatar_url(self, obj):
        ser = UserMiniSerializer(obj.user, context=self.context)
        return ser.data.get("avatar_url", "") or ""

    def get_user_kyc_status(self, obj):
        u = getattr(obj, "user", None)
        if not u:
            return None
        prof = getattr(u, "profile", None)
        if prof and hasattr(prof, "kyc_status"):
            return prof.kyc_status
        return getattr(u, "kyc_status", None)


class SpeedNetworkingMatchSerializer(serializers.ModelSerializer):
    participant_1 = UserMiniSerializer(read_only=True)
    participant_2 = UserMiniSerializer(read_only=True)

    class Meta:
        model = SpeedNetworkingMatch
        fields = [
            'id', 'session', 'participant_1', 'participant_2',
            'status', 'dyte_room_name', 'match_score', 'match_breakdown', 'rule_compliance',
            'match_probability', 'config_version', 'last_recalculated_at',
            'created_at', 'ended_at',
            'extension_requested_p1', 'extension_requested_p2', 'extension_applied', 'extended_by_seconds'
        ]
        read_only_fields = ['id', 'created_at', 'ended_at', 'status', 'dyte_room_name',
                           'match_score', 'match_breakdown', 'rule_compliance',
                           'match_probability', 'config_version', 'last_recalculated_at',
                           'extension_requested_p1', 'extension_requested_p2', 'extension_applied', 'extended_by_seconds']


class SpeedNetworkingSessionSerializer(serializers.ModelSerializer):
    matches = SpeedNetworkingMatchSerializer(many=True, read_only=True)
    queue_count = serializers.SerializerMethodField()
    active_matches_count = serializers.SerializerMethodField()

    def get_queue_count(self, obj):
        # Count ALL active queue entries (both waiting and in active matches)
        return obj.queue.filter(is_active=True).count()

    def get_active_matches_count(self, obj):
        return obj.matches.filter(status='ACTIVE').count()

    class Meta:
        model = SpeedNetworkingSession
        fields = [
            'id', 'event', 'name', 'status', 'duration_minutes', 'buffer_seconds',
            'matching_strategy', 'criteria_config', 'config_version',
            'started_at', 'ended_at', 'matches', 'created_at',
            'queue_count', 'active_matches_count'
        ]
        read_only_fields = ['id', 'started_at', 'ended_at', 'created_at', 'event', 'config_version']


class SpeedNetworkingQueueSerializer(serializers.ModelSerializer):
    user = UserMiniSerializer(read_only=True)
    current_match = SpeedNetworkingMatchSerializer(read_only=True)
    
    class Meta:
        model = SpeedNetworkingQueue
        fields = [
            'id', 'session', 'user', 'is_active',
            'current_match', 'joined_at'
        ]
        read_only_fields = ['id', 'joined_at', 'session']
