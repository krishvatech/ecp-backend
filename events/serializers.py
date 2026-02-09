"""
Serializers for the events app.

Provides a serializer for creating and updating events. The
`community_id` is required in the request body for creation.
"""
from django.utils import timezone
from datetime import timezone as dt_timezone
import os
from rest_framework import serializers
from urllib.parse import urlparse
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.conf import settings
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.utils.dateparse import parse_datetime
from content.tasks import publish_resource_task
from users.serializers import UserMiniSerializer
from .models import Event, EventRegistration, EventParticipant, SpeedNetworkingSession, SpeedNetworkingMatch, SpeedNetworkingQueue
from community.models import Community
from content.models import Resource

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

    # Write-only field for participants input
    participants = serializers.ListField(
        child=serializers.DictField(),
        write_only=True,
        required=False,
        default=list,
        help_text="List of participants (staff or guest). Staff: {'type': 'staff', 'user_id': 1, 'role': 'speaker'}. Guest: {'type': 'guest', 'name': 'Name', 'email': 'email@example.com', 'role': 'speaker'}"
    )

    # Read-only field for participants output
    event_participants = serializers.SerializerMethodField(read_only=True)

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
            "replay_available",
            "replay_availability_duration",
            "category",
            "format",
            "location",
            "price",
            "is_free",
            "attending_count",
            "registrations_count",
            "preview_image",
            "cover_image",
            "waiting_room_image",
            "waiting_room_enabled",
            "auto_admit_seconds",
            "waiting_room_grace_period_minutes",
            "lounge_enabled_waiting_room",
            "networking_tables_enabled_waiting_room",
            "active_speaker",
            "recording_url",
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
        ]
        
        read_only_fields = [
            "id",
            "slug",
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

        validated_participants = []
        staff_user_ids = []

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

        # Create EventParticipant records using bulk_create
        rows = []
        for p_data in dedup_key_map.values():
            if p_data['type'] == 'staff':
                rows.append(
                    EventParticipant(
                        event=event,
                        participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
                        user_id=p_data['user_id'],
                        role=p_data['role'],
                        event_bio=p_data['event_bio'],
                        display_order=p_data['display_order'],
                    )
                )
            else:  # guest
                rows.append(
                    EventParticipant(
                        event=event,
                        participant_type=EventParticipant.PARTICIPANT_TYPE_GUEST,
                        role=p_data['role'],
                        guest_name=p_data['guest_name'],
                        guest_email=p_data['guest_email'],
                        guest_bio=p_data['guest_bio'],
                        display_order=p_data['display_order'],
                    )
                )

        # Use bulk_create with ignore_conflicts for safety
        EventParticipant.objects.bulk_create(rows, ignore_conflicts=True)

    def create(self, validated_data):
        # Extract participants data before creating Event
        participants_data = validated_data.pop('participants', [])

        files  = validated_data.pop("resource_files", [])
        links  = validated_data.pop("resource_links", [])
        videos = validated_data.pop("resource_videos", [])

        # attach creator
        validated_data["created_by_id"] = self.context["request"].user.id
        event = super().create(validated_data)

        # ----- read “Attach Resources” metadata coming from the form -----
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
        # UI: toggle “Publish resources immediately” + an optional datetime
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

        return event

    def update(self, instance, validated_data):
        # Extract and handle participants separately
        participants_data = validated_data.pop('participants', None)

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
            role = p_data['role']
            if role in grouped:
                grouped[role].append(p_data)

        return grouped


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

        def _to_utc(dt):
            if dt is None:
                return None
            if timezone.is_naive(dt):
                dt = timezone.make_aware(dt, event_tz)
            return dt.astimezone(dt_timezone.utc)

        start_time = _to_utc(start_time)
        end_time = _to_utc(end_time)
        if start_time is not None:
            data["start_time"] = start_time
        if end_time is not None:
            data["end_time"] = end_time

        now = timezone.now()

        if end_time and not start_time:
            raise serializers.ValidationError({"start_time": "Provide start_time when setting end_time."})
        if start_time and start_time < now:
            raise serializers.ValidationError({"start_time": "Start time cannot be in the past."})
        if end_time and end_time < now:
            raise serializers.ValidationError({"end_time": "End time cannot be in the past."})
        if start_time and end_time and not (end_time > start_time):
            raise serializers.ValidationError({"end_time": "End time must be later than start time."})

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

class EventLiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = (
            "id", "slug", "title", "start_time", "end_time", "timezone", "status", "live_ended_at",
            "preview_image", "cover_image", "waiting_room_image", "location", "category", "is_live", "recording_url", "replay_available", "replay_availability_duration", "price", "is_free",
            "waiting_room_enabled", "waiting_room_grace_period_minutes", "lounge_enabled_waiting_room", "networking_tables_enabled_waiting_room", "auto_admit_seconds",
            "lounge_enabled_before", "lounge_before_buffer",
            "lounge_enabled_after", "lounge_after_buffer",
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
        # Event might be select_related or just an ID locally; safe access
        # If obj.event is a full object, created_by_id exists.
        return obj.user_id == getattr(obj.event, "created_by_id", None)

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
            'status', 'dyte_room_name', 'created_at', 'ended_at'
        ]
        read_only_fields = ['id', 'created_at', 'ended_at', 'status', 'dyte_room_name']


class SpeedNetworkingSessionSerializer(serializers.ModelSerializer):
    matches = SpeedNetworkingMatchSerializer(many=True, read_only=True)
    
    class Meta:
        model = SpeedNetworkingSession
        fields = [
            'id', 'event', 'name', 'status', 'duration_minutes',
            'started_at', 'ended_at', 'matches', 'created_at'
        ]
        read_only_fields = ['id', 'started_at', 'ended_at', 'created_at', 'event']


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
