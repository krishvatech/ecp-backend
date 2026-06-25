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
from django.db.models import Q, Max, F
from content.tasks import publish_resource_task
from users.serializers import UserMiniSerializer
from .models import (
    Event, EventRegistration, EventBadgeLabel, EventParticipant, SpeedNetworkingSession, SpeedNetworkingMatch, SpeedNetworkingQueue,
    EventSession, SessionParticipant, SessionAttendance, SessionBreak, EventApplication, VirtualSpeaker, GuestAttendee,
    SaleorChannel, SaleorWarehouse, SaleorShippingZone, SaleorProductType, SaleorStaffUser, SaleorPermissionGroup,
    EventPreApprovalCode, EventPreApprovalAllowlist, EventSeries, SeriesRegistration, EventSaleorDiscount, EventEmailTemplate,
    EventNetworkingSettings, NetworkingTable, NetworkingMeeting, EventSessionBookmark,
    PostAcceptanceFormTemplate, PostAcceptanceFormAssignment, PostAcceptanceFormSubmission, PostAcceptanceFormAnswer,
    AdminAuditLog, PostAcceptanceFormDraft, EventFormCustomization, EventRole, EventApplicationTrack, EventApplicationTrackApplication, TrackPricingTier,
    SharedQuestionCategory, SharedQuestion, FormField, EventAttendeeOrigin
)
from django.db.models import Prefetch as DjangoPrefetch
from community.models import Community
from content.models import Resource
import json
from .validators import validate_non_multiday_event, validate_multiday_event, validate_session_datetimes


ROLE_PRIORITY = {
    EventParticipant.ROLE_HOST: 0,
    EventParticipant.ROLE_SPEAKER: 1,
    EventParticipant.ROLE_MODERATOR: 2,
}

ROLE_LABELS = {
    EventParticipant.ROLE_HOST: "Host",
    EventParticipant.ROLE_SPEAKER: "Speaker",
    EventParticipant.ROLE_MODERATOR: "Moderator",
}


def role_priority(role):
    return ROLE_PRIORITY.get((role or "").lower(), 99)


def role_label(role):
    return ROLE_LABELS.get((role or "").lower(), "Participant")


def is_public_role_visible(event, role):
    role = (role or "").lower()
    if role == EventParticipant.ROLE_HOST:
        return bool(getattr(event, "show_public_hosts", True))
    if role == EventParticipant.ROLE_SPEAKER:
        return bool(getattr(event, "show_public_speakers", True))
    if role == EventParticipant.ROLE_MODERATOR:
        return bool(getattr(event, "show_public_moderators", False))
    return True


def normalize_participant_email(value):
    return (value or "").strip().lower()


def _get_prefetched_related_list(instance, relation_name):
    cache = getattr(instance, "_prefetched_objects_cache", None) or {}
    if relation_name in cache:
        return list(cache[relation_name])
    manager = getattr(instance, relation_name, None)
    if manager is None:
        return []
    return list(manager.all())


def _get_event_sessions_cached(event):
    cached = getattr(event, "_event_sessions_cache", None)
    if cached is not None:
        return cached
    cached = _get_prefetched_related_list(event, "sessions")
    setattr(event, "_event_sessions_cache", cached)
    return cached


def _get_event_participants_cached(event):
    cached = getattr(event, "_event_participants_cache", None)
    if cached is not None:
        return cached
    cached = _get_prefetched_related_list(event, "participants")
    setattr(event, "_event_participants_cache", cached)
    return cached


def build_event_participant_lookup(event):
    participant_qs = _get_event_participants_cached(event)
    if not participant_qs:
        participant_qs = list(
            event.participants.select_related("user", "user__profile").all()
        )
    by_user_id = {}
    by_email = {}

    for participant in participant_qs:
        if participant.user_id:
            by_user_id.setdefault(participant.user_id, []).append(participant)

        email = normalize_participant_email(participant.get_email())
        if email:
            by_email.setdefault(email, []).append(participant)

    return {
        "participants": list(participant_qs),
        "by_user_id": by_user_id,
        "by_email": by_email,
    }


def resolve_registration_roles(registration, participant_lookup, event=None):
    matches = []
    user_id = getattr(registration, "user_id", None)
    if user_id:
        matches.extend(participant_lookup["by_user_id"].get(user_id, []))

    if not matches:
        email = normalize_participant_email(getattr(getattr(registration, "user", None), "email", ""))
        if email:
            matches.extend(participant_lookup["by_email"].get(email, []))

    deduped = []
    seen_ids = set()
    for participant in matches:
        if participant.id in seen_ids:
            continue
        seen_ids.add(participant.id)
        deduped.append(participant)

    deduped.sort(key=lambda p: (role_priority(p.role), p.display_order, (p.get_name() or "").lower(), p.id))
    roles = [p.role for p in deduped if p.role]
    if not roles and user_id and user_id == getattr(event, "created_by_id", None):
        roles = [EventParticipant.ROLE_HOST]
    primary_role = roles[0] if roles else None
    return deduped, roles, primary_role


def build_profile_url(user_id):
    return f"/community/rich-profile/{user_id}" if user_id else None


def serialize_featured_participants(event, context=None, skip_visibility_filter=False):
    context = context or {}
    request = context.get("request")
    featured = []
    participants = _get_event_participants_cached(event)
    if not participants:
        participants = list(
            event.participants.select_related("user", "user__profile", "virtual_speaker")
            .prefetch_related("user__experiences")
            .all()
        )
    # Skip visibility filter if requested (e.g., for public marketing pages)
    if skip_visibility_filter:
        visible_participants = list(participants)
    else:
        visible_participants = [
            participant
            for participant in participants
            if is_public_role_visible(event, participant.role)
        ]
    visible_participants.sort(
        key=lambda participant: (
            role_priority(participant.role),
            participant.display_order,
            (participant.get_name() or "").lower(),
            participant.id,
        )
    )

    for participant in visible_participants:
        image_url = participant.get_image_url() or ""
        if image_url and request and not str(image_url).startswith(("http://", "https://")):
            image_url = request.build_absolute_uri(image_url)

        # Determine participant type label
        if participant.participant_type == "virtual":
            participant_type_label = "Virtual Speaker"
        elif participant.participant_type == "guest":
            participant_type_label = "Guest"
        elif participant.participant_type == "user":
            participant_type_label = "User"
        else:  # staff
            participant_type_label = "Staff"

        # Get professional info/experience based on participant type
        professional_info = ""
        bio_text = ""
        if participant.participant_type == "staff" and participant.user and hasattr(participant.user, 'profile'):
            profile = participant.user.profile
            # Priority: headline > latest_experience > (job_title + company) > event_bio
            if profile.headline:
                professional_info = profile.headline
            else:
                # Try to get latest experience (most recent work)
                prefetched_experiences = (
                    getattr(participant.user, "_prefetched_objects_cache", {}).get("experiences")
                )
                if prefetched_experiences is not None:
                    latest_experience = next(
                        iter(
                            sorted(
                                prefetched_experiences,
                                key=lambda exp: (
                                    exp.start_date.toordinal() if exp.start_date else -1,
                                    exp.end_date.toordinal() if exp.end_date else -1,
                                    exp.id,
                                ),
                                reverse=True,
                            )
                        ),
                        None,
                    )
                else:
                    latest_experience = (
                        participant.user.experiences.all()
                        .order_by('-start_date', '-end_date', '-id')
                        .first()
                    )
                if latest_experience:
                    # Use position (job title) and community_name (company) from experience
                    parts = [latest_experience.position, latest_experience.community_name]
                    professional_info = " – ".join([p for p in parts if p]).strip()
                else:
                    # Fallback to profile job_title and company
                    parts = [profile.job_title, profile.company]
                    professional_info = " – ".join([p for p in parts if p]).strip()

                # Final fallback to event bio if nothing else
                professional_info = professional_info or participant.event_bio
        elif participant.participant_type == "guest":
            professional_info = participant.guest_bio
        elif participant.participant_type == "virtual" and participant.virtual_speaker:
            # For virtual speakers: use job_title and company as professional_info
            virtual_speaker = participant.virtual_speaker
            parts = [virtual_speaker.job_title, virtual_speaker.company]
            professional_info = ", ".join([p for p in parts if p]).strip()
            # Preserve bio separately for expanded view
            bio_text = virtual_speaker.bio

        featured.append(
            {
                "user_id": participant.user_id,
                "display_name": participant.get_name() or "",
                "avatar_url": image_url or None,
                "role": participant.role,
                "role_label": role_label(participant.role),
                "participant_type": participant.participant_type,
                "participant_type_label": participant_type_label,
                "professional_info": professional_info or "",
                "profile_url": build_profile_url(participant.user_id),
                "is_profile_clickable": bool(participant.user_id),
                "bio": bio_text or professional_info or "",
            }
        )
    return featured


def compute_public_registered_count(event, registrations_qs=None):
    """
    Count registered users visible in public participant listings.
    Excludes:
    - superusers
    - registrations mapped to organizer roles hidden by event visibility settings
    """
    qs = registrations_qs
    if qs is None:
        prefetched = getattr(event, "_prefetched_objects_cache", {}).get("registrations")
        if prefetched is not None:
            qs = [
                reg
                for reg in prefetched
                if reg.status == "registered"
                and not getattr(getattr(reg, "user", None), "is_superuser", False)
            ]
        else:
            qs = (
                EventRegistration.objects
                .filter(event=event, status='registered')
                .exclude(user__is_superuser=True)
                .select_related("user", "user__profile")
            )

    participant_lookup = build_event_participant_lookup(event)
    visible_count = 0

    for registration in qs:
        _matched_participants, roles, _primary_role = resolve_registration_roles(
            registration,
            participant_lookup,
            event=event,
        )
        public_role_visible = all(
            is_public_role_visible(event, role)
            for role in roles
        )
        hidden_from_public = bool(roles) and not public_role_visible
        if hidden_from_public:
            continue
        visible_count += 1

    return visible_count


def compute_public_guest_count(event, guest_qs=None):
    """
    Count active guest registrations shown publicly on event cards.
    Excludes:
    - banned guests
    - converted guests (already moved to registered users)
    - unverified guest records
    """
    qs = guest_qs
    if qs is None:
        prefetched = getattr(event, "_prefetched_objects_cache", {}).get("guest_attendees")
        if prefetched is not None:
            return sum(
                1
                for guest in prefetched
                if not guest.is_banned
                and guest.converted_user_id is None
                and guest.email_verified
            )
        qs = GuestAttendee.objects.filter(event=event)

    return qs.filter(
        is_banned=False,
        converted_user__isnull=True,
        email_verified=True,
    ).count()


def serialize_tier_for_status(tier):
    if not tier:
        return None
    return {
        "id": tier.id,
        "key": tier.key,
        "label": tier.label,
        "price": str(tier.price),
        "currency": tier.currency,
    }


def get_confirmed_registered_count_for_event(event):
    """Count confirmed attendees without treating payment_pending as registered."""
    from events.models import EventAttendeeOrigin, EventRegistration

    confirmed_origin_registration_ids = set(
        EventAttendeeOrigin.objects.filter(
            registration__event=event,
            status="active",
            origin_status="confirmed",
        ).values_list("registration_id", flat=True)
    )
    confirmed_without_origins = set(
        EventRegistration.objects.filter(
            event=event,
            status="registered",
            attendee_status="confirmed",
        )
        .exclude(origins__status="active")
        .values_list("id", flat=True)
    )
    return len(confirmed_origin_registration_ids | confirmed_without_origins)


def build_current_user_event_status(event, request):
    if not request or not request.user.is_authenticated:
        return None

    from events.models import EventApplication, EventRegistration

    # Get applications ordered by applied_at DESC (newest first)
    # Prioritize active applications (pending, pre_approved, accepted) over declined/cancelled
    all_apps = list(
        EventApplication.objects
        .filter(event=event, user=request.user)
        .prefetch_related("track_applications__track", "track_applications__accepted_tier")
        .order_by('-applied_at')
    )

    # Find the best application to use: prefer active statuses over declined/cancelled
    app = None
    for candidate_app in all_apps:
        # Get child statuses if any
        track_statuses = [ta.status for ta in candidate_app.track_applications.all()]

        # Determine if this application is "active"
        is_active = False
        if not track_statuses:
            # Legacy app without children - check parent status
            is_active = candidate_app.status in ['pending', 'approved']
        else:
            # Check child statuses
            blocking_statuses = ['pending', 'pre_approved', 'accepted', 'waitlisted']
            is_active = any(status in blocking_statuses for status in track_statuses)

        if is_active:
            # Found an active application - use it
            app = candidate_app
            break
        elif not app:
            # No active app found yet, keep first (most recent) as fallback
            app = candidate_app

    reg = (
        EventRegistration.objects
        .filter(event=event, user=request.user, status__in=["registered", "cancellation_requested"])
        .prefetch_related("origins__track", "origins__role", "origins__accepted_tier")
        .first()
    )

    track_apps_data = []
    assigned_tier = None
    application_status = None
    if app:
        track_statuses = []
        for ta in app.track_applications.all():
            tier_data = serialize_tier_for_status(ta.accepted_tier)
            if tier_data and not assigned_tier:
                assigned_tier = tier_data
            track_statuses.append(ta.status)
            track_apps_data.append({
                "track_id": ta.track.id,
                "track_label": ta.track.label,
                "status": ta.status,
                "accepted_tier": tier_data,
            })

        if "accepted" in track_statuses:
            application_status = "accepted"
        elif "pending" in track_statuses or "pre_approved" in track_statuses:
            # Prioritize pending/pre_approved over declined/cancelled
            application_status = "pending"
        elif track_statuses and any(status == "waitlisted" for status in track_statuses):
            application_status = "waitlisted"
        elif track_statuses and all(status == "declined" for status in track_statuses):
            application_status = "declined"
        else:
            application_status = app.status

    if reg:
        origins_data = []
        payment_pending = reg.attendee_status == "payment_pending"
        for origin in reg.origins.filter(status="active").select_related("track", "role", "accepted_tier"):
            tier_data = serialize_tier_for_status(origin.accepted_tier)
            if origin.origin_status == "payment_pending":
                payment_pending = True
                if tier_data:
                    assigned_tier = tier_data
            elif tier_data and not assigned_tier:
                assigned_tier = tier_data

            origins_data.append({
                "id": origin.id,
                "track_label": origin.track.label if origin.track else None,
                "role_label": origin.role.label,
                "tier_label": origin.accepted_tier.label if origin.accepted_tier else None,
                "price": str(origin.accepted_tier.price) if origin.accepted_tier else "0",
                "currency": origin.accepted_tier.currency if origin.accepted_tier else None,
                "origin_status": origin.origin_status,
                "payment_reference": origin.payment_reference,
                "marked_paid_at": origin.marked_paid_at.isoformat() if origin.marked_paid_at else None,
            })

        confirmed_count = reg.origins.filter(status="active", origin_status="confirmed").count()
        pending_count = reg.origins.filter(status="active", origin_status="payment_pending").count()
        is_confirmed_registered = reg.attendee_status == "confirmed" and pending_count == 0
        origin_status = "payment_pending" if payment_pending else ("confirmed" if is_confirmed_registered or confirmed_count > 0 else None)

        return {
            "application_status": application_status,
            "track_applications": track_apps_data,
            "registration_status": reg.status,
            "attendee_status": reg.attendee_status,
            "origin_status": origin_status,
            "payment_pending": payment_pending,
            "is_confirmed_registered": is_confirmed_registered,
            "assigned_tier": assigned_tier,
            "origins": origins_data,
            "confirmed_origins_count": confirmed_count,
            "pending_origins_count": pending_count,
        }

    if app:
        return {
            "application_status": application_status,
            "track_applications": track_apps_data,
            "registration_status": None,
            "attendee_status": None,
            "origin_status": None,
            "payment_pending": False,
            "is_confirmed_registered": False,
            "assigned_tier": assigned_tier,
            "origins": [],
        }

    return None


def safe_int(value, default=0):
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


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
    """Read-only serializer for EventParticipant with computed fields supporting staff, guest, and virtual types."""

    user_id = serializers.SerializerMethodField()
    virtual_speaker_id = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    job_title = serializers.SerializerMethodField()
    company = serializers.SerializerMethodField()
    profile_image_url = serializers.SerializerMethodField()
    bio_text = serializers.SerializerMethodField()
    participant_type = serializers.CharField(read_only=True)

    class Meta:
        model = EventParticipant
        fields = [
            'id',
            'participant_type',
            'user_id',
            'virtual_speaker_id',
            'name',
            'email',
            'job_title',
            'company',
            'role',
            'bio_text',
            'profile_image_url',
            'display_order',
            'created_at',
        ]
        read_only_fields = fields

    def get_user_id(self, obj):
        """Get user ID for staff type, None for guest/virtual."""
        if obj.participant_type == EventParticipant.PARTICIPANT_TYPE_STAFF and obj.user:
            return obj.user.id
        return None

    def get_virtual_speaker_id(self, obj):
        """Get virtual speaker ID for virtual type."""
        return obj.virtual_speaker_id if obj.participant_type == EventParticipant.PARTICIPANT_TYPE_VIRTUAL else None

    def get_name(self, obj):
        """Get display name based on participant type."""
        return obj.get_name()

    def get_email(self, obj):
        """Get email based on participant type."""
        return obj.get_email()

    def get_job_title(self, obj):
        """Get job title from virtual speaker or user profile."""
        if obj.virtual_speaker:
            return obj.virtual_speaker.job_title
        if obj.user and hasattr(obj.user, 'profile'):
            return obj.user.profile.job_title or ""
        return ""

    def get_company(self, obj):
        """Get company from virtual speaker or user profile."""
        if obj.virtual_speaker:
            return obj.virtual_speaker.company
        if obj.user and hasattr(obj.user, 'profile'):
            return obj.user.profile.company or ""
        return ""

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


class FeaturedParticipantSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(allow_null=True)
    display_name = serializers.CharField()
    avatar_url = serializers.CharField(allow_null=True, allow_blank=True)
    role = serializers.CharField()
    role_label = serializers.CharField()
    professional_info = serializers.CharField(allow_blank=True, default='')
    profile_url = serializers.CharField(allow_null=True, allow_blank=True)
    is_profile_clickable = serializers.BooleanField()
    bio = serializers.CharField(allow_blank=True, default='', required=False)


class EventParticipantListItemSerializer(serializers.Serializer):
    registration_id = serializers.IntegerField()
    user_id = serializers.IntegerField(allow_null=True)
    display_name = serializers.CharField()
    email = serializers.CharField(allow_null=True, allow_blank=True)
    avatar_url = serializers.CharField(allow_null=True, allow_blank=True)
    kyc_status = serializers.CharField(allow_null=True, allow_blank=True)
    profile_url = serializers.CharField(allow_null=True, allow_blank=True)
    is_profile_clickable = serializers.BooleanField()
    roles = serializers.ListField(child=serializers.CharField(), default=list)
    primary_role = serializers.CharField(allow_null=True, allow_blank=True)
    role_labels = serializers.ListField(child=serializers.CharField(), default=list)
    is_public_role_visible = serializers.BooleanField()
    is_hidden_from_public_role_display = serializers.BooleanField()
    registered_at = serializers.DateTimeField(allow_null=True)
    participant_id = serializers.IntegerField(allow_null=True)
    display_order = serializers.IntegerField(allow_null=True)


#  Lightweight participant serializer for live meeting (batched endpoint)
class ParticipantsLiteSerializer(serializers.Serializer):
    """Minimal participant data for live meeting participant list/cards."""
    id = serializers.IntegerField()
    name = serializers.CharField()
    avatar = serializers.URLField(allow_null=True, allow_blank=True)
    kyc_status = serializers.CharField(allow_null=True, allow_blank=True)
    current_location = serializers.CharField(default="main_room")


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


# ============================================================================
# ================= Virtual Speaker Serializers ==========================
# ============================================================================

class VirtualSpeakerSerializer(serializers.ModelSerializer):
    """Serializer for virtual speaker profiles (CRUD operations)."""

    profile_image_url = serializers.SerializerMethodField()
    is_converted = serializers.SerializerMethodField()
    converted_user_id = serializers.SerializerMethodField()
    community_id = serializers.IntegerField(write_only=True, required=True)

    class Meta:
        model = VirtualSpeaker
        fields = [
            'id', 'community_id', 'name', 'job_title', 'company', 'bio',
            'profile_image', 'profile_image_url',
            'status', 'is_converted', 'converted_user_id',
            'invited_email', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'status', 'is_converted', 'converted_user_id',
            'profile_image_url', 'created_at', 'updated_at'
        ]

    def get_profile_image_url(self, obj):
        if obj.profile_image:
            request = self.context.get('request')
            url = obj.profile_image.url
            return request.build_absolute_uri(url) if request else url
        return None

    def get_is_converted(self, obj):
        return obj.status == VirtualSpeaker.STATUS_CONVERTED

    def get_converted_user_id(self, obj):
        return obj.converted_user_id

    def create(self, validated_data):
        community_id = validated_data.pop('community_id', None)
        if community_id:
            validated_data['community_id'] = community_id
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data['created_by'] = request.user
        return super().create(validated_data)


class VirtualSpeakerConvertSerializer(serializers.Serializer):
    """Serializer for converting a virtual speaker to a real user account."""

    email = serializers.EmailField()
    send_invite = serializers.BooleanField(default=True, required=False)


class SessionBreakSerializer(serializers.ModelSerializer):
    """Serializer for session breaks."""

    class Meta:
        model = SessionBreak
        fields = ['id', 'label', 'break_type', 'duration_minutes', 'break_order', 'created_at']


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

    # Hours calculation fields
    session_breaks = SessionBreakSerializer(many=True, read_only=True)
    duration_minutes_override = serializers.IntegerField(required=False, allow_null=True)
    has_duration_override = serializers.BooleanField(required=False)
    computed_duration_minutes = serializers.SerializerMethodField()
    effective_duration_minutes = serializers.SerializerMethodField()
    day_label = serializers.SerializerMethodField()

    class Meta:
        model = EventSession
        fields = [
            'id', 'event', 'session_date', 'title', 'description', 'start_time', 'end_time',
            'session_type', 'display_order', 'is_live', 'live_started_at', 'live_ended_at',
            'use_parent_meeting', 'rtk_meeting_id', 'recording_url', 'session_image',
            'duration_minutes_override', 'has_duration_override', 'computed_duration_minutes',
            'effective_duration_minutes', 'session_breaks', 'day_label',
            'participants', 'session_participants', 'attendance_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['is_live', 'live_started_at', 'live_ended_at', 'rtk_meeting_id',
                            'computed_duration_minutes', 'effective_duration_minutes', 'day_label',
                            'session_breaks']

    def validate(self, data):
        """Validate session times against event times."""
        start = data.get('start_time')
        end = data.get('end_time')
        event = data.get('event')

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

        # Validate session times (includes end > start, event boundary checks, and 30-min rule for today)
        if start and end and event:
            validate_session_datetimes(start, end, event, instance=self.instance)
        elif start and end and end <= start:
            raise serializers.ValidationError(
                {"end_time": "Session end time must be after start time."}
            )

        return data

    def get_session_participants(self, obj):
        """Return participants grouped by role."""
        from itertools import groupby
        from operator import attrgetter

        prefetched = getattr(obj, "_prefetched_objects_cache", {}).get("participants")
        if prefetched is not None:
            participants = sorted(prefetched, key=lambda p: (p.role, p.display_order, p.id))
        else:
            participants = obj.participants.all().order_by('role', 'display_order')
        grouped = {}
        for role, group in groupby(participants, key=attrgetter('role')):
            grouped[role] = SessionParticipantSerializer(list(group), many=True, context=self.context).data
        return grouped

    def get_attendance_count(self, obj):
        """Return count of users who attended/are attending."""
        return obj.attendances.count()

    def get_computed_duration_minutes(self, obj):
        """Return computed session duration from start/end times."""
        return obj.computed_duration_minutes()

    def get_effective_duration_minutes(self, obj):
        """Return effective duration (computed or override) minus breaks."""
        return obj.effective_duration_minutes()

    def get_day_label(self, obj):
        """Return day label (Day 1, Day 2, etc.) based on session position."""
        if not obj.session_date or not obj.event:
            return None
        event = obj.event
        day_map = getattr(event, "_session_day_label_map", None)
        if day_map is None:
            sessions = _get_event_sessions_cached(event)
            unique_dates = sorted({s.session_date for s in sessions if s.session_date})
            if not unique_dates:
                db_dates = (
                    event.sessions.filter(session_date__isnull=False)
                    .order_by('session_date', 'display_order', 'start_time')
                    .values_list('session_date', flat=True)
                )
                unique_dates = sorted(set(db_dates))
            day_map = {session_date: idx + 1 for idx, session_date in enumerate(unique_dates)}
            setattr(event, "_session_day_label_map", day_map)
        try:
            return f"Day {day_map[obj.session_date]}"
        except (KeyError, ValueError, IndexError):
            return None

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
    public_registered_count = serializers.SerializerMethodField(read_only=True)
    public_guest_count = serializers.SerializerMethodField(read_only=True)
    total_registered = serializers.SerializerMethodField(read_only=True)
    application_tracks = serializers.SerializerMethodField(read_only=True)
    confirmed_registered_count = serializers.SerializerMethodField(read_only=True)
    user_status = serializers.SerializerMethodField(read_only=True)
    application_status = serializers.SerializerMethodField(read_only=True)
    registration_status = serializers.SerializerMethodField(read_only=True)
    attendee_status = serializers.SerializerMethodField(read_only=True)
    origin_status = serializers.SerializerMethodField(read_only=True)
    payment_pending = serializers.SerializerMethodField(read_only=True)
    is_confirmed_registered = serializers.SerializerMethodField(read_only=True)
    assigned_tier = serializers.SerializerMethodField(read_only=True)
    origins = serializers.SerializerMethodField(read_only=True)

    # Access-controlled recording_url (host can always see, participants only if visible)
    recording_url = serializers.SerializerMethodField(read_only=True)
    replay_visible_to_participants = serializers.BooleanField(read_only=True)

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
    featured_participants = serializers.SerializerMethodField(read_only=True)
    featured_participants_total = serializers.SerializerMethodField(read_only=True)

    # Q&A Questions (lazy import to avoid circular dependency)
    questions = serializers.SerializerMethodField(read_only=True)

    # Session-related fields
    sessions = EventSessionSerializer(many=True, read_only=True)
    has_sessions = serializers.SerializerMethodField(read_only=True)
    main_sessions_count = serializers.SerializerMethodField(read_only=True)
    breakout_sessions_count = serializers.SerializerMethodField(read_only=True)
    workshops_count = serializers.SerializerMethodField(read_only=True)
    networking_count = serializers.SerializerMethodField(read_only=True)
    calculated_hours_minutes = serializers.SerializerMethodField(read_only=True)
    calculated_hours_display = serializers.SerializerMethodField(read_only=True)
    cpd_cpe_credits = serializers.SerializerMethodField(read_only=True)
    cpd_cpe_minutes = serializers.IntegerField(required=False, allow_null=True, min_value=1)
    cpd_cpe_minutes_per_credit = serializers.IntegerField(required=False, allow_null=True, min_value=1, default=60)
    show_cpd_cpe = serializers.BooleanField(required=False, default=True)

    # Total hours override fields
    total_hours_override_minutes = serializers.IntegerField(required=False, allow_null=True, min_value=0)
    has_total_hours_override = serializers.BooleanField(required=False, default=False)

    # Cancellation fields
    recommended_event_id = serializers.PrimaryKeyRelatedField(
        queryset=Event.objects.all(),
        source="recommended_event",
        write_only=True,
        required=False,
        allow_null=True
    )
    recommended_event = serializers.SerializerMethodField(read_only=True)
    series = serializers.PrimaryKeyRelatedField(read_only=True, allow_null=True)

    def get_recommended_event(self, obj):
        if obj.recommended_event_id:
            return {
                "id": obj.recommended_event.id,
                "slug": obj.recommended_event.slug,
                "title": obj.recommended_event.title,
                "start_time": obj.recommended_event.start_time,
            }
        return None

    def get_recording_url(self, obj):
        """
        Access control for recording_url:
        - Host can always see the URL
        - Participants can only see if replay_visible_to_participants = True
        """
        from events.views import _is_event_host
        from events.models import EventRegistration

        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return None

        # Host can always see
        if _is_event_host(request.user, obj):
            return obj.recording_url

        # Participants can only see if visible
        is_participant = EventRegistration.objects.filter(
            event=obj,
            user=request.user,
            status__in=["registered", "cancellation_requested"]
        ).exists()

        if is_participant and obj.replay_visible_to_participants:
            return obj.recording_url

        # Otherwise, hide the URL
        return None

    def get_questions(self, obj):
        """Return Q&A only when explicitly requested via include=questions."""
        request = self.context.get("request")
        include = request.query_params.get("include", "") if request else ""
        include_parts = {part.strip() for part in include.split(",") if part.strip()}
        if "questions" not in include_parts:
            return []

        from interactions.serializers import QuestionSerializer
        questions = _get_prefetched_related_list(obj, "questions")
        return QuestionSerializer(questions, many=True).data

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
            "is_hidden",
            "replay_available",
            "replay_availability_duration",
            "replay_visible_to_participants",
            "replay_publishing_mode",
            "category",
            "format",
            "location",
            "location_city",
            "location_country",
            "venue_name",
            "venue_address",
            "price",
            "price_label",
            "currency",
            "is_free",
            "registration_type",
            "preapproval_code_enabled",
            "preapproval_allowlist_enabled",
            "attendee_marker_enabled",
            "attendee_marker_label",
            "max_participants",
            "cpd_cpe_minutes",
            "cpd_cpe_minutes_per_credit",
            "show_cpd_cpe",
            "cpd_cpe_credits",
            "saleor_product_id",
            "saleor_variant_id",
            "attending_count",
            "registrations_count",
            "public_registered_count",
            "public_guest_count",
            "total_registered",
            "application_tracks",
            "confirmed_registered_count",
            "user_status",
            "application_status",
            "registration_status",
            "attendee_status",
            "origin_status",
            "payment_pending",
            "is_confirmed_registered",
            "assigned_tier",
            "origins",
            "preview_image",
            "cover_image",
            "waiting_room_image",
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
            "rtk_meeting_id",
            "rtk_meeting_title",
            "use_external_streaming",
            "external_streaming_platform",
            "external_streaming_url",
            "external_streaming_meeting_id",
            "external_streaming_password",
            "external_streaming_other_details",
            "external_streaming_host_link",
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
            "lounge_enabled_speed_networking",
            "show_participants_before_event",
            "show_participants_after_event",
            "show_registered_participant_count",
            "show_guest_participant_count",
            "show_public_hosts",
            "show_public_speakers",
            "show_public_moderators",
            "show_speed_networking_match_history",
            "qna_moderation_enabled",
            "qna_anonymous_mode",
            "qna_ai_public_suggestions_enabled",
            "pre_event_qna_enabled",
            "participants",
            "event_participants",
            "featured_participants",
            "featured_participants_total",
            "questions",
            "sessions",
            "has_sessions",
            "main_sessions_count",
            "breakout_sessions_count",
            "workshops_count",
            "networking_count",
            "calculated_hours_minutes",
            "calculated_hours_display",
            "hours_calculation_session_types",
            "total_hours_override_minutes",
            "has_total_hours_override",
            "sessions_input",
            "series",
            "series_order",
            "series_session_label",
            "is_pinned",
            "pin_priority",
            "pinned_at",
            "pinned_by_id",
            "is_featured",
            "replay_enabled",
            "replay_video_url",
            "youtube_summary_url",
            "linkedin_summary_url",
            "replay_cta_text",
        ]

        read_only_fields = [
            "id",
            "created_by_id",
            "created_at",
            "updated_at",
            "active_speaker",
            "attending_count",
            "registrations_count",
            "public_registered_count",
            "public_guest_count",
            "total_registered",
            "live_started_at",
            "live_ended_at",
            "rtk_meeting_id",
            "rtk_meeting_title",
            "currency",  # Always SGD, read-only
            "series",
            "series_order",
            "series_session_label",
            "is_pinned",
            "pin_priority",
            "pinned_at",
            "pinned_by_id",
            "is_featured",
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

    def _update_participants(self, event, participants_data):
        """
        Intelligently update event participants.

        - Keeps existing participants (no duplicate emails) but updates their role if changed
        - Only sends confirmation emails to NEWLY ADDED participants
        - Deletes removed participants
        - Handles role changes gracefully
        """
        if not participants_data:
            # If participants list is empty, delete all
            event.participants.all().delete()
            return

        from django.contrib.auth.models import User

        # Build keys from existing participants (WITHOUT role for identity matching)
        existing_participants = event.participants.all()
        existing_by_identity = {}  # Map of identity_key → (ep_object, role)

        for ep in existing_participants:
            if ep.participant_type == EventParticipant.PARTICIPANT_TYPE_STAFF:
                identity_key = ('staff', ep.user_id)
            elif ep.participant_type == EventParticipant.PARTICIPANT_TYPE_GUEST:
                identity_key = ('guest', ep.guest_name, ep.guest_email)
            else:  # virtual
                identity_key = ('virtual', ep.virtual_speaker_id)

            existing_by_identity[identity_key] = (ep, ep.role)

        # Build identity keys from new participants data
        new_by_identity = {}  # Map of identity_key → (role, p_data)
        for p_data in participants_data:
            p_type = (p_data.get('type', 'staff') or 'staff').lower()
            role = (p_data.get('role') or '').lower()

            if p_type == 'staff':
                user_id = p_data.get('user_id')
                if user_id:
                    identity_key = ('staff', user_id)
                    new_by_identity[identity_key] = (role, p_data)
            elif p_type == 'guest':
                guest_name = (p_data.get('name') or '').strip()
                guest_email = (p_data.get('email') or '').strip()
                if guest_name:
                    identity_key = ('guest', guest_name, guest_email)
                    new_by_identity[identity_key] = (role, p_data)
            elif p_type == 'virtual':
                vs_id = p_data.get('virtual_speaker_id')
                if vs_id:
                    identity_key = ('virtual', vs_id)
                    new_by_identity[identity_key] = (role, p_data)

        # Process deletions and updates
        for identity_key, (ep, old_role) in existing_by_identity.items():
            if identity_key not in new_by_identity:
                # Participant was removed
                ep.delete()
            else:
                # Participant still exists; check if role or display_order changed
                new_role, p_data = new_by_identity[identity_key]
                new_display_order = p_data.get('display_order', 0)

                # Track what needs updating
                update_fields = []
                if new_role != old_role:
                    ep.role = new_role
                    update_fields.append('role')

                # Always update display_order based on the new order
                if ep.display_order != new_display_order:
                    ep.display_order = new_display_order
                    update_fields.append('display_order')

                # Save only if there are changes
                if update_fields:
                    ep.save(update_fields=update_fields)

        # Create only new participants (those not in existing_by_identity)
        new_participants_data = []
        for identity_key, (new_role, p_data) in new_by_identity.items():
            if identity_key not in existing_by_identity:
                new_participants_data.append(p_data)

        # Create new participants (this will trigger confirmation emails only for truly new ones)
        if new_participants_data:
            self._create_participants(event, new_participants_data)

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

            elif p_type == 'virtual':
                # Virtual participant requires virtual_speaker_id
                vs_id = p_data.get('virtual_speaker_id')
                if not vs_id:
                    raise serializers.ValidationError({
                        'participants': f'Missing virtual_speaker_id for virtual participant at index {idx}'
                    })

                validated_participants.append({
                    'type': 'virtual',
                    'virtual_speaker_id': vs_id,
                    'role': role,
                    'display_order': p_data.get('display_order', idx),
                    'client_index': p_data.get('client_index', idx),
                })
            else:
                raise serializers.ValidationError({
                    'participants': f'Invalid type "{p_type}" at index {idx}. Must be: staff, guest, or virtual'
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

        # De-duplicate: for staff by (user_id, role), for guest by (name, email, role), for virtual by (virtual_speaker_id, role)
        dedup_key_map = {}
        for p in validated_participants:
            if p['type'] == 'staff':
                key = ('staff', p['user_id'], p['role'])
            elif p['type'] == 'guest':
                key = ('guest', p['guest_name'], p['guest_email'], p['role'])
            else:  # virtual
                key = ('virtual', p['virtual_speaker_id'], p['role'])

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

            elif p_data['type'] == 'guest':
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

            elif p_data['type'] == 'virtual':
                # Virtual participant - try to get converted user first
                vs = VirtualSpeaker.objects.get(pk=p_data['virtual_speaker_id'])

                if vs.status == VirtualSpeaker.STATUS_CONVERTED and vs.converted_user:
                    # Virtual speaker already converted - use as staff
                    registration_user_ids.add(vs.converted_user.id)
                    participant = EventParticipant(
                        event=event,
                        participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
                        user=vs.converted_user,
                        role=p_data['role'],
                        display_order=p_data['display_order'],
                    )
                else:
                    # Virtual speaker still virtual - create virtual participant
                    participant = EventParticipant(
                        event=event,
                        participant_type=EventParticipant.PARTICIPANT_TYPE_VIRTUAL,
                        virtual_speaker=vs,
                        role=p_data['role'],
                        display_order=p_data['display_order'],
                    )
                participant.save()

        # Auto-register all participant users so events appear in "My Events".
        # This includes staff participants and guests with user accounts.
        for user_id in registration_user_ids:
            obj, was_created = EventRegistration.objects.get_or_create(
                event=event,
                user_id=user_id,
                defaults={
                    "status": "registered",
                    "attendee_status": "confirmed",
                    "admission_status": "admitted",
                    "was_ever_admitted": True,
                },
            )
            # Auto-assign Participant badge if registration has no badges
            if was_created and not obj.badge_labels.exists():
                participant_badge = event.get_or_create_participant_badge()
                obj.badge_labels.add(participant_badge)

        # Send credentials emails to newly created guest accounts
        if guests_to_create_accounts:
            from users.task import send_speaker_credentials_task
            for user_id in guests_to_create_accounts:
                send_speaker_credentials_task.delay(user_id)

    def create(self, validated_data):
        # ✅ CRITICAL FIX: Apply visibility defaults if missing from request
        # This ensures DB always has correct values even if frontend doesn't send them
        visibility_defaults = {
            "show_participants_before_event": True,
            "show_participants_after_event": False,
            "show_registered_participant_count": True,
            "show_guest_participant_count": False,
            "show_public_hosts": False,
            "show_public_speakers": False,
            "show_public_moderators": False,
            "show_speed_networking_match_history": True,
        }
        for field, default_value in visibility_defaults.items():
            if field not in validated_data:
                validated_data[field] = default_value

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

        # Force Application Required events to Draft status until valid tracks are configured
        if validated_data.get('registration_type') == 'apply':
            validated_data['status'] = 'draft'

        print(f"\n🔴 BACKEND CREATE METHOD:")
        print(f"  validated_data['start_time']: {validated_data.get('start_time')}")
        print(f"  validated_data['end_time']: {validated_data.get('end_time')}")
        print(f"  validated_data['timezone']: {validated_data.get('timezone')}")
        print(f"  sessions_input count: {len(sessions_input)}")
        print(f"  registration_type: {validated_data.get('registration_type')}")
        print(f"  status: {validated_data.get('status')}")

        # Wrap entire creation in atomic transaction
        with transaction.atomic():
            event = super().create(validated_data)

            print(f"  Event created with ID {event.id}:")
            print(f"    Stored start_time: {event.start_time}")
            print(f"    Stored end_time: {event.end_time}")
            print(f"🔴 BACKEND CREATE METHOD END\n")

            # Handle one-featured-at-a-time constraint: unfeature all other events
            if event.is_featured:
                Event.objects.filter(is_featured=True).exclude(pk=event.pk).update(is_featured=False)

            # Automatically add event creator as attendee
            creator = self.context["request"].user
            obj, was_created = EventRegistration.objects.get_or_create(
                event=event,
                user=creator,
                defaults={
                    "status": "registered",
                    "attendee_status": "confirmed",
                    "admission_status": "admitted",
                }
            )
            # Auto-assign Participant badge if registration has no badges
            if was_created and not obj.badge_labels.exists():
                participant_badge = event.get_or_create_participant_badge()
                obj.badge_labels.add(participant_badge)

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

        # Permission check: only superusers (platform_admin) can update hours_calculation_session_types
        request = self.context.get('request')
        if 'hours_calculation_session_types' in validated_data:
            if not (request and request.user and request.user.is_superuser):
                raise serializers.ValidationError(
                    {"hours_calculation_session_types": "Only platform administrators can modify session types for hours calculation."}
                )

        # Force Application Required events to Draft status if trying to publish without valid tracks
        if 'registration_type' in validated_data or instance.registration_type == 'apply':
            reg_type = validated_data.get('registration_type', instance.registration_type)
            if reg_type == 'apply' and 'status' in validated_data and validated_data['status'] == 'published':
                # Check if event has valid application tracks
                temp_instance = instance
                if 'registration_type' in validated_data:
                    temp_instance.registration_type = validated_data['registration_type']
                if not temp_instance.has_valid_application_tracks():
                    validated_data['status'] = 'draft'

        featured_changed = 'is_featured' in validated_data

        # Handle one-featured-at-a-time constraint: unfeature all other events.
        # QuerySet.update() bypasses model signals, so invalidate event list/landing
        # caches explicitly after the transaction commits.
        if validated_data.get('is_featured') is True:
            with transaction.atomic():
                Event.objects.filter(is_featured=True).exclude(pk=instance.pk).update(is_featured=False)
                instance = super().update(instance, validated_data)
        else:
            # Update event fields
            instance = super().update(instance, validated_data)

        if featured_changed:
            try:
                from .cache_utils import invalidate_event_list_caches
                transaction.on_commit(lambda: invalidate_event_list_caches(instance.id))
            except Exception:
                pass

        # If participants data provided, intelligently update participants
        # Only send confirmation emails to newly added participants
        if participants_data is not None:
            self._update_participants(instance, participants_data)

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
        """Return all participants grouped by role, sorted by display_order within each role."""
        participants = _get_event_participants_cached(obj)
        if not participants:
            return {
                'speakers': [],
                'moderators': [],
                'hosts': [],
            }

        participants = sorted(participants, key=lambda participant: (participant.display_order, participant.id))

        serializer = EventParticipantSerializer(
            participants,
            many=True,
            context=self.context
        )

        # Group by role for easier frontend consumption (order preserved by display_order from query)
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

    def get_featured_participants(self, obj):
        request = self.context.get("request")
        skip_visibility = request and request.query_params.get("featured_all") == "true" if request else False
        participants = serialize_featured_participants(obj, self.context, skip_visibility_filter=skip_visibility)
        return FeaturedParticipantSerializer(participants, many=True).data

    def get_featured_participants_total(self, obj):
        request = self.context.get("request")
        skip_visibility = request and request.query_params.get("featured_all") == "true" if request else False
        return len(serialize_featured_participants(obj, self.context, skip_visibility_filter=skip_visibility))

    def get_public_registered_count(self, obj):
        cached = getattr(obj, "_cached_public_registered_count", None)
        if cached is not None:
            return cached
        value = compute_public_registered_count(obj)
        setattr(obj, "_cached_public_registered_count", value)
        return value

    def get_public_guest_count(self, obj):
        cached = getattr(obj, "_cached_public_guest_count", None)
        if cached is not None:
            return cached
        value = compute_public_guest_count(obj)
        setattr(obj, "_cached_public_guest_count", value)
        return value

    def get_total_registered(self, obj):
        registered_users = self.get_public_registered_count(obj)
        guest_users = self.get_public_guest_count(obj)
        return max(0, safe_int(registered_users) + safe_int(guest_users))

    def get_application_tracks(self, obj):
        if obj.registration_type != "apply":
            return []
        tracks = obj.application_tracks.all().order_by("sort_order", "label")
        return EventApplicationTrackSerializer(tracks, many=True).data

    def get_user_status(self, obj):
        return build_current_user_event_status(obj, self.context.get("request"))

    def get_confirmed_registered_count(self, obj):
        return get_confirmed_registered_count_for_event(obj)

    def _current_user_status_value(self, obj, key, default=None):
        status = self.get_user_status(obj) or {}
        return status.get(key, default)

    def get_application_status(self, obj):
        return self._current_user_status_value(obj, "application_status")

    def get_registration_status(self, obj):
        return self._current_user_status_value(obj, "registration_status")

    def get_attendee_status(self, obj):
        return self._current_user_status_value(obj, "attendee_status")

    def get_origin_status(self, obj):
        return self._current_user_status_value(obj, "origin_status")

    def get_payment_pending(self, obj):
        return self._current_user_status_value(obj, "payment_pending", False)

    def get_is_confirmed_registered(self, obj):
        return self._current_user_status_value(obj, "is_confirmed_registered", False)

    def get_assigned_tier(self, obj):
        return self._current_user_status_value(obj, "assigned_tier")

    def get_origins(self, obj):
        return self._current_user_status_value(obj, "origins", [])

    def get_has_sessions(self, obj):
        """Check if event has sessions."""
        return obj.has_sessions

    def get_main_sessions_count(self, obj):
        """Count sessions of type 'main'."""
        return sum(1 for session in _get_event_sessions_cached(obj) if session.session_type == "main")

    def get_breakout_sessions_count(self, obj):
        """Count sessions of type 'breakout'."""
        return sum(1 for session in _get_event_sessions_cached(obj) if session.session_type == "breakout")

    def get_workshops_count(self, obj):
        """Count sessions of type 'workshop'."""
        return sum(1 for session in _get_event_sessions_cached(obj) if session.session_type == "workshop")

    def get_networking_count(self, obj):
        """Count sessions of type 'networking'."""
        return sum(1 for session in _get_event_sessions_cached(obj) if session.session_type == "networking")

    def get_calculated_hours_minutes(self, obj):
        """Calculate total hours in minutes based on selected session types, respecting breaks and overrides."""
        return obj.calculate_total_hours()

    def get_calculated_hours_display(self, obj):
        """Return formatted hours:minutes display."""
        total_minutes = self.get_calculated_hours_minutes(obj)
        hours = total_minutes // 60
        minutes = total_minutes % 60
        return f"{hours}h {minutes}m" if hours > 0 or minutes > 0 else "0h"

    def get_cpd_cpe_credits(self, obj):
        minutes = obj.cpd_cpe_minutes
        if not minutes:
            return None
        per_credit = obj.cpd_cpe_minutes_per_credit or 60
        if per_credit <= 0:
            return None
        return round(minutes / per_credit, 4)

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

        # Privacy gate: only show venue_name and venue_address to registered/admitted members or host
        if request and request.user.is_authenticated:
            from events.views import _is_event_manager

            is_manager = _is_event_manager(request.user, instance)
            is_registered = EventRegistration.objects.filter(
                event=instance,
                user=request.user,
                status__in=["registered", "admitted", "cancellation_requested"]
            ).exists()

            # If not manager and not registered, remove venue details
            if not is_manager and not is_registered:
                data.pop("venue_name", None)
                data.pop("venue_address", None)
        else:
            # Unauthenticated users: don't show venue details
            data.pop("venue_name", None)
            data.pop("venue_address", None)

        return data

    def validate_price(self, value):
        # Allow None/null for paid events (price managed in Product Management tab)
        if value is None:
            return None
        if value < 0:
            raise serializers.ValidationError("Price cannot be negative.")
        return value

    def to_internal_value(self, data):
        """
        Override to coerce empty string price → None, so paid events can be saved with null price.
        FormData always sends strings; empty string must become None for DecimalField(null=True).
        """
        mutable_data = data.copy() if hasattr(data, 'copy') else dict(data)
        if 'price' in mutable_data and mutable_data['price'] in ('', None, 'null', 'undefined'):
            mutable_data['price'] = None
        if 'max_participants' in mutable_data and mutable_data['max_participants'] in ('', None, 'null', 'undefined'):
            mutable_data['max_participants'] = None
        return super().to_internal_value(mutable_data)

    def validate_cpd_cpe_minutes(self, value):
        if value is None:
            return value
        if value <= 0:
            raise serializers.ValidationError("CPD/CPE minutes must be greater than 0.")
        return value

    def validate_cpd_cpe_minutes_per_credit(self, value):
        if value in (None, ""):
            return 60
        if value <= 0:
            raise serializers.ValidationError("Minutes per credit must be greater than 0.")
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
        """Validate slug format and uniqueness. Special chars like @, #, $, & are allowed."""
        if not value:
            return value  # Allow blank (auto-generated in save())

        value = value.strip()
        if not value:
            raise serializers.ValidationError("Slug cannot be blank.")
        if '/' in value:
            raise serializers.ValidationError(
                "Slug cannot contain forward slashes (/)."
            )
        if '\x00' in value:
            raise serializers.ValidationError(
                "Slug cannot contain null characters."
            )
        if len(value) > 255:
            raise serializers.ValidationError(
                "Slug is too long (max 255 characters)."
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

        # ---- recording_url: only process if explicitly provided in request ----
        # For PATCH requests, preserve instance.recording_url if not in incoming data
        if "recording_url" in data:
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
        elif self.instance:
            # Preserve existing recording_url for PATCH/update requests
            data["recording_url"] = self.instance.recording_url

        # ---- optional arrays: coerce and filter; never raise on links/videos ----
        data["resource_links"]  = self._filter_urls(data.get("resource_links", []))
        data["resource_videos"] = self._filter_urls(data.get("resource_videos", []))

        # Preserve existing event timezone on updates when timezone is omitted.
        # Falling back to settings.TIME_ZONE here can silently rewrite timezone
        # during unrelated PATCH requests (e.g. settings toggles).
        incoming_timezone = data.get("timezone", None)
        if incoming_timezone is None:
            tz_value = getattr(self.instance, "timezone", None) or settings.TIME_ZONE
        else:
            tz_value = incoming_timezone
            if isinstance(tz_value, str):
                tz_value = tz_value.strip()
            if not tz_value:
                tz_value = getattr(self.instance, "timezone", None) or settings.TIME_ZONE
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

        # Timezone-aware validation with support for today's +30min rule and multiday events
        is_multi_day = data.get("is_multi_day", getattr(self.instance, "is_multi_day", False))
        if is_multi_day:
            validate_multiday_event(start_time, end_time, tz_value, self.instance)
        else:
            validate_non_multiday_event(start_time, end_time, tz_value, self.instance)

        # Validate sessions_input: all session dates must fall within event dates
        # and respect the 30-minute rule if event is scheduled for today
        sessions_input = data.get('sessions_input', [])

        event_start = data.get('start_time')
        event_end = data.get('end_time')

        if sessions_input and event_start and event_end:
            from dateutil.parser import parse as parse_datetime
            from types import SimpleNamespace

            # Create a mock event object with the necessary fields for session validation
            mock_event = SimpleNamespace(
                start_time=event_start,
                end_time=event_end,
                timezone=tz_value,
                is_multi_day=is_multi_day,
            )

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

                # Validate session times using the timezone-aware validator
                # This enforces: end > start, within event bounds, and 30-min rule if event is today
                try:
                    validate_session_datetimes(sess_start, sess_end, mock_event)
                except serializers.ValidationError as e:
                    if isinstance(e.detail, dict):
                        # Extract field-specific errors
                        for field, msg in e.detail.items():
                            errors.append(f"'{label}' {msg.lower()}")
                    else:
                        errors.append(f"'{label}': {e.detail}")

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

        # Auto-populate location from location_city + location_country
        location_city = (data.get('location_city') or '').strip()
        location_country = (data.get('location_country') or '').strip()

        if location_city and location_country:
            data['location'] = f"{location_city}, {location_country}"
        elif location_city:
            data['location'] = location_city
        elif location_country:
            data['location'] = location_country
        # Otherwise, keep the location value as provided or blank

        cpd_minutes = data.get("cpd_cpe_minutes", getattr(self.instance, "cpd_cpe_minutes", None))
        per_credit = data.get("cpd_cpe_minutes_per_credit", getattr(self.instance, "cpd_cpe_minutes_per_credit", 60))
        if per_credit in (None, ""):
            data["cpd_cpe_minutes_per_credit"] = 60
            per_credit = 60
        if cpd_minutes is not None and cpd_minutes <= 0:
            raise serializers.ValidationError({"cpd_cpe_minutes": "CPD/CPE minutes must be greater than 0."})
        if per_credit <= 0:
            raise serializers.ValidationError({"cpd_cpe_minutes_per_credit": "Minutes per credit must be greater than 0."})

        return data


class PublicEventSerializer(serializers.ModelSerializer):
    """
    Public-facing serializer for event landing pages.
    Only exposes non-sensitive fields safe for anonymous users.
    """
    speakers = serializers.SerializerMethodField()
    preview_image = serializers.SerializerMethodField()
    cover_image = serializers.SerializerMethodField()
    sessions = EventSessionSerializer(many=True, read_only=True)
    featured_participants = serializers.SerializerMethodField()
    featured_participants_total = serializers.SerializerMethodField()
    cpd_cpe_credits = serializers.SerializerMethodField(read_only=True)
    replay_video_url = serializers.SerializerMethodField()
    is_registered_for_event = serializers.SerializerMethodField()
    user_status = serializers.SerializerMethodField()
    confirmed_registered_count = serializers.SerializerMethodField()
    replay_signup_enabled = serializers.SerializerMethodField()
    can_signup_for_replay = serializers.SerializerMethodField()
    has_replay_access = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = [
            "id", "slug", "title", "description",
            "start_time", "end_time", "timezone",
            "status", "is_live", "category", "format",
            "location", "location_city", "location_country",
            "price", "price_label", "price_display_label", "allow_manual_price_display", "currency", "is_free",
            "preview_image", "cover_image", "attending_count", "confirmed_registered_count",
            "created_at", "sessions", "speakers",
            "featured_participants", "featured_participants_total",
            "cpd_cpe_minutes", "cpd_cpe_minutes_per_credit", "show_cpd_cpe", "cpd_cpe_credits",
            "is_multi_day", "series",
            "use_external_streaming", "external_streaming_platform", "external_streaming_url",
            "external_streaming_meeting_id", "external_streaming_password", "external_streaming_other_details",
            "external_streaming_host_link",
            "replay_enabled", "replay_video_url", "youtube_summary_url", "linkedin_summary_url", "replay_cta_text",
            "is_registered_for_event", "user_status", "replay_signup_enabled", "can_signup_for_replay", "has_replay_access",
        ]
        read_only_fields = fields

    def get_cpd_cpe_credits(self, obj):
        minutes = obj.cpd_cpe_minutes
        if not minutes:
            return None
        per_credit = obj.cpd_cpe_minutes_per_credit or 60
        if per_credit <= 0:
            return None
        return round(minutes / per_credit, 4)

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

    def get_cover_image(self, obj):
        """Return absolute URL for cover image."""
        if not obj.cover_image:
            return None
        req = self.context.get('request')
        try:
            if req:
                return req.build_absolute_uri(obj.cover_image.url)
            return str(obj.cover_image.url)
        except Exception:
            return str(obj.cover_image)

    def get_featured_participants(self, obj):
        request = self.context.get("request")
        skip_visibility = request and request.query_params.get("featured_all") == "true" if request else False
        participants = serialize_featured_participants(obj, self.context, skip_visibility_filter=skip_visibility)
        return FeaturedParticipantSerializer(participants, many=True).data

    def get_featured_participants_total(self, obj):
        request = self.context.get("request")
        skip_visibility = request and request.query_params.get("featured_all") == "true" if request else False
        return len(serialize_featured_participants(obj, self.context, skip_visibility_filter=skip_visibility))

    def get_replay_video_url(self, obj):
        from events.views import _is_event_host
        from events.models import EventRegistration
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return None
        if _is_event_host(request.user, obj):
            # Host can view replay if replay_visible_to_participants is True or if they have direct access
            if not obj.replay_visible_to_participants:
                return None
            return obj.replay_video_url or obj.recording_url
        is_registered = EventRegistration.objects.filter(
            event=obj, user=request.user,
            status__in=["registered", "cancellation_requested"]
        ).exists()
        if is_registered and obj.replay_visible_to_participants:
            return obj.replay_video_url or obj.recording_url
        return None

    def get_is_registered_for_event(self, obj):
        """Check if the current user is registered for this event."""
        from events.models import EventRegistration
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return EventRegistration.objects.filter(
            event=obj, user=request.user,
            status__in=["registered", "cancellation_requested"],
            attendee_status="confirmed",
        ).exists()

    def get_user_status(self, obj):
        """Get current user's application/registration status for this event with tier info."""
        return build_current_user_event_status(obj, self.context.get('request'))

    def get_confirmed_registered_count(self, obj):
        """Count only confirmed registrations/origins, not payment_pending."""
        return get_confirmed_registered_count_for_event(obj)

    def get_replay_signup_enabled(self, obj):
        """Return whether replay signup is enabled for this event."""
        return bool(obj.replay_enabled)

    def get_can_signup_for_replay(self, obj):
        """
        Check if user can signup for replay.
        True only when:
        - replay is enabled
        - event is ended/past
        - replay recording is published/ready (has replay_visible_to_participants and recording)
        - user is not registered
        """
        from django.utils import timezone
        request = self.context.get('request')

        # Check if event is ended
        now = timezone.now()
        is_ended = obj.status == "ended" or (obj.end_time and obj.end_time < now)

        # Check if replay is enabled
        replay_enabled = bool(obj.replay_enabled)

        # Check if replay is published/ready to participants
        # Must have replay_visible_to_participants=True AND either replay_video_url or recording_url
        replay_ready = bool(obj.replay_visible_to_participants) and bool(obj.replay_video_url or obj.recording_url)

        # Check registration status
        if not request or not request.user.is_authenticated:
            # Anonymous users: can signup if ended, replay enabled, and recording is ready
            return is_ended and replay_enabled and replay_ready

        # Authenticated users: can signup only if not already registered
        is_registered = self.get_is_registered_for_event(obj)
        return is_ended and replay_enabled and replay_ready and not is_registered

    def get_has_replay_access(self, obj):
        """
        Check if user has replay access (is registered for the event).
        """
        return self.get_is_registered_for_event(obj)


class SessionSummarySerializer(serializers.ModelSerializer):
    """Lightweight session serializer for card view (minimal fields only)."""
    class Meta:
        model = EventSession
        fields = ("id", "title", "start_time", "end_time", "session_date")


class MyEventCardSerializer(serializers.ModelSerializer):
    """Lightweight serializer for My Events card view - includes only frontend-required fields."""
    sessions_summary = SessionSummarySerializer(source="sessions", many=True, read_only=True)
    my_registration = serializers.SerializerMethodField(read_only=True)

    def get_my_registration(self, obj):
        request = self.context.get("request")
        if not request or not request.user or not request.user.is_authenticated:
            return None
        registration = getattr(obj, "_prefetched_my_registration", None)
        if registration:
            return {
                "id": registration.id,
                "status": registration.status,
                "registered_at": registration.registered_at,
                "joined_live": registration.joined_live,
                "watched_replay": registration.watched_replay,
                "admitted_at": registration.admitted_at,
                "admission_status": registration.admission_status,
                "is_host": self._compute_is_host(obj, registration),
            }
        return None

    def _compute_is_host(self, event, registration):
        if registration.user_id == getattr(event, "created_by_id", None):
            return True
        host_match = Q(participant_type="staff", user_id=registration.user_id)
        user_email = (getattr(registration.user, "email", "") or "").strip()
        if user_email:
            host_match = host_match | Q(participant_type="guest", guest_email__iexact=user_email)
        return event.participants.filter(role="host").filter(host_match).exists()

    class Meta:
        model = Event
        fields = (
            "id", "slug", "title", "start_time", "end_time", "timezone", "status", "live_ended_at",
            "preview_image", "cover_image", "waiting_room_image", "location", "location_city",
            "location_country", "category", "is_live", "recording_url", "replay_available",
            "replay_visible_to_participants", "price", "price_label", "currency", "is_free",
            "registration_type", "waiting_room_enabled", "waiting_room_grace_period_minutes",
            "lounge_enabled_waiting_room", "networking_tables_enabled_waiting_room", "auto_admit_seconds",
            "lounge_enabled_before", "lounge_before_buffer", "lounge_enabled_after", "lounge_after_buffer",
            "is_multi_day", "sessions_summary", "cancellation_message", "recommended_event", "created_by_id",
            "use_external_streaming", "external_streaming_platform", "external_streaming_url",
            "external_streaming_meeting_id", "external_streaming_password", "external_streaming_other_details",
            "external_streaming_host_link", "replay_enabled", "replay_video_url", "youtube_summary_url",
            "linkedin_summary_url", "replay_cta_text", "is_pinned", "pin_priority", "pinned_at",
            "is_featured", "my_registration",
        )


class EventLiteSerializer(serializers.ModelSerializer):
    # Session-related fields for multi-day events
    sessions = EventSessionSerializer(many=True, read_only=True)
    recommended_event = serializers.SerializerMethodField(read_only=True)
    cpd_cpe_credits = serializers.SerializerMethodField(read_only=True)

    def get_recommended_event(self, obj):
        if obj.recommended_event_id:
            return {
                "id": obj.recommended_event.id,
                "slug": obj.recommended_event.slug,
                "title": obj.recommended_event.title,
                "start_time": obj.recommended_event.start_time,
            }
        return None

    def get_cpd_cpe_credits(self, obj):
        minutes = obj.cpd_cpe_minutes
        if not minutes:
            return None
        per_credit = obj.cpd_cpe_minutes_per_credit or 60
        if per_credit <= 0:
            return None
        return round(minutes / per_credit, 4)

    class Meta:
        model = Event
        fields = (
            "id", "slug", "title", "start_time", "end_time", "timezone", "status", "live_ended_at",
            "preview_image", "cover_image", "waiting_room_image", "location", "location_city", "location_country", "category", "is_live", "recording_url", "replay_available", "replay_availability_duration", "replay_visible_to_participants", "price", "price_label", "currency", "is_free", "registration_type",
            "preapproval_code_enabled", "preapproval_allowlist_enabled", "attendee_marker_enabled", "attendee_marker_label",
            "waiting_room_enabled", "waiting_room_grace_period_minutes", "lounge_enabled_waiting_room", "networking_tables_enabled_waiting_room", "auto_admit_seconds",
            "lounge_enabled_before", "lounge_before_buffer",
            "lounge_enabled_after", "lounge_after_buffer",
            "is_multi_day", "sessions", "series",
            "cpd_cpe_minutes", "cpd_cpe_minutes_per_credit", "show_cpd_cpe", "cpd_cpe_credits",
            "cancellation_message", "recommended_event", "created_by_id",
            # ✅ External streaming fields
            "use_external_streaming", "external_streaming_platform", "external_streaming_url",
            "external_streaming_meeting_id", "external_streaming_password", "external_streaming_other_details",
            "external_streaming_host_link",
            "replay_enabled", "replay_video_url", "youtube_summary_url", "linkedin_summary_url", "replay_cta_text",
        )


class EventListSerializer(serializers.ModelSerializer):
    """
    Optimized serializer for event list endpoints.
    Includes registration counts (via efficient DB annotations) and user status (per-user computed fields).
    Frontend gets full details from /events/{id}/ detail view if needed.
    """
    sessions = EventSessionSerializer(many=True, read_only=True)
    recommended_event = serializers.SerializerMethodField(read_only=True)
    cpd_cpe_credits = serializers.SerializerMethodField(read_only=True)
    attending_count = serializers.IntegerField(read_only=True)
    registrations_count = serializers.IntegerField(read_only=True)
    public_registered_count = serializers.SerializerMethodField(read_only=True)
    public_guest_count = serializers.SerializerMethodField(read_only=True)
    total_registered = serializers.SerializerMethodField(read_only=True)
    confirmed_registered_count = serializers.SerializerMethodField(read_only=True)
    user_status = serializers.SerializerMethodField(read_only=True)
    payment_pending = serializers.SerializerMethodField(read_only=True)
    is_confirmed_registered = serializers.SerializerMethodField(read_only=True)
    assigned_tier = serializers.SerializerMethodField(read_only=True)
    origins = serializers.SerializerMethodField(read_only=True)
    show_participants_before_event = serializers.BooleanField(read_only=True)
    show_participants_after_event = serializers.BooleanField(read_only=True)
    show_registered_participant_count = serializers.BooleanField(read_only=True)

    def get_recommended_event(self, obj):
        if obj.recommended_event_id:
            return {
                "id": obj.recommended_event.id,
                "slug": obj.recommended_event.slug,
                "title": obj.recommended_event.title,
                "start_time": obj.recommended_event.start_time,
            }
        return None

    def get_cpd_cpe_credits(self, obj):
        minutes = obj.cpd_cpe_minutes
        if not minutes:
            return None
        per_credit = obj.cpd_cpe_minutes_per_credit or 60
        if per_credit <= 0:
            return None
        return round(minutes / per_credit, 4)

    def get_public_registered_count(self, obj):
        """Use annotated count or fallback to computation."""
        cached = getattr(obj, "_cached_public_registered_count", None)
        if cached is not None:
            return cached
        # Fallback to annotation if available
        annotated = getattr(obj, "public_registered_count_annotated", None)
        if annotated is not None:
            return annotated
        value = compute_public_registered_count(obj)
        setattr(obj, "_cached_public_registered_count", value)
        return value

    def get_public_guest_count(self, obj):
        """Use annotated count or fallback to computation."""
        cached = getattr(obj, "_cached_public_guest_count", None)
        if cached is not None:
            return cached
        # Fallback to annotation if available
        annotated = getattr(obj, "public_guest_count_annotated", None)
        if annotated is not None:
            return annotated
        value = compute_public_guest_count(obj)
        setattr(obj, "_cached_public_guest_count", value)
        return value

    def get_total_registered(self, obj):
        registered_users = self.get_public_registered_count(obj)
        guest_users = self.get_public_guest_count(obj)
        return max(0, safe_int(registered_users) + safe_int(guest_users))

    def get_confirmed_registered_count(self, obj):
        """Get confirmed registration count."""
        cached = getattr(obj, "_cached_confirmed_registered_count", None)
        if cached is not None:
            return cached
        value = get_confirmed_registered_count_for_event(obj)
        setattr(obj, "_cached_confirmed_registered_count", value)
        return value

    def get_user_status(self, obj):
        """Get current user's registration/application status for this event."""
        return build_current_user_event_status(obj, self.context.get("request"))

    def _current_user_status_value(self, obj, key, default=None):
        status = self.get_user_status(obj) or {}
        return status.get(key, default)

    def get_payment_pending(self, obj):
        return self._current_user_status_value(obj, "payment_pending", False)

    def get_is_confirmed_registered(self, obj):
        return self._current_user_status_value(obj, "is_confirmed_registered", False)

    def get_assigned_tier(self, obj):
        return self._current_user_status_value(obj, "assigned_tier")

    def get_origins(self, obj):
        return self._current_user_status_value(obj, "origins", [])

    class Meta:
        model = Event
        fields = (
            "id", "slug", "title", "start_time", "end_time", "timezone", "status", "live_ended_at",
            "preview_image", "cover_image", "waiting_room_image", "location", "location_city", "location_country",
            "category", "is_live", "recording_url", "replay_available", "replay_availability_duration",
            "replay_visible_to_participants", "price", "price_label", "currency", "is_free", "registration_type",
            "preapproval_code_enabled", "preapproval_allowlist_enabled", "attendee_marker_enabled", "attendee_marker_label",
            "waiting_room_enabled", "waiting_room_grace_period_minutes", "lounge_enabled_waiting_room",
            "networking_tables_enabled_waiting_room", "auto_admit_seconds",
            "lounge_enabled_before", "lounge_before_buffer",
            "lounge_enabled_after", "lounge_after_buffer",
            "is_multi_day", "sessions", "series",
            "cpd_cpe_minutes", "cpd_cpe_minutes_per_credit", "show_cpd_cpe", "cpd_cpe_credits",
            "cancellation_message", "recommended_event", "created_by_id",
            "use_external_streaming", "external_streaming_platform", "external_streaming_url",
            "external_streaming_meeting_id", "external_streaming_password", "external_streaming_other_details",
            "external_streaming_host_link",
            "replay_enabled", "replay_video_url", "youtube_summary_url", "linkedin_summary_url", "replay_cta_text",
            "attending_count", "registrations_count", "is_pinned", "pin_priority", "is_featured",
            "public_registered_count", "public_guest_count", "total_registered", "confirmed_registered_count",
            "user_status", "payment_pending", "is_confirmed_registered", "assigned_tier", "origins",
            "show_participants_before_event", "show_participants_after_event", "show_registered_participant_count",
        )


class EventLandingSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for /api/events/landing/.
    Do not add user-specific or count-heavy fields here; dashboard/home uses this during event-end redirects.
    """
    event_type = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = (
            "id", "slug", "title", "description", "start_time", "end_time", "timezone", "status",
            "preview_image", "cover_image", "location", "location_city", "location_country",
            "category", "format", "event_type", "price", "price_label", "currency", "is_free",
            "registration_type", "is_pinned", "pin_priority", "pinned_at", "is_featured",
        )

    def get_event_type(self, obj):
        return obj.category or obj.format or "Event"


class EventRoleSerializer(serializers.ModelSerializer):
    """Serializer for EventRole model - attendee role catalog for events."""

    class Meta:
        model = EventRole
        fields = [
            'id', 'event_id', 'key', 'label', 'description',
            'visibility', 'sort_priority', 'badge_color', 'badge_style',
            'triggers_promotional_profile', 'is_system_default',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class EventApplicationTrackSerializer(serializers.ModelSerializer):
    """Serializer for EventApplicationTrack - application track configuration."""

    class Meta:
        model = EventApplicationTrack
        fields = [
            'id', 'event_id', 'key', 'label', 'short_description',
            'status', 'sort_order', 'is_active',
            'enabled_submission_modes', 'form_schema',
            'preapproval_configuration', 'role_mappings_on_acceptance',
            'content_surfaces', 'landing_page_content', 'form_header_notice',
            'confirmation_page_content', 'is_system_default',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'is_system_default', 'created_at', 'updated_at']


class TrackPricingTierSerializer(serializers.ModelSerializer):
    """Serializer for TrackPricingTier - track-specific pricing tiers."""

    is_paid = serializers.SerializerMethodField()
    is_free = serializers.SerializerMethodField()

    def get_is_paid(self, obj):
        return obj.is_paid()

    def get_is_free(self, obj):
        return obj.is_free()

    class Meta:
        model = TrackPricingTier
        fields = [
            'id', 'track_id', 'key', 'label', 'description',
            'price', 'currency', 'visibility', 'is_default', 'is_active',
            'sort_order', 'is_paid', 'is_free',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class EventAttendeeOriginSerializer(serializers.ModelSerializer):
    """Phase 11: Serializer for EventAttendeeOrigin - tracks origin metadata for each attendee role."""
    track_label = serializers.CharField(source='track.label', read_only=True)
    role_label = serializers.CharField(source='role.label', read_only=True)
    tier_label = serializers.CharField(source='accepted_tier.label', read_only=True)
    accepted_tier_label = serializers.CharField(source='accepted_tier.label', read_only=True)
    tier_price = serializers.DecimalField(
        source='accepted_tier.price',
        read_only=True,
        max_digits=10,
        decimal_places=2
    )
    price = serializers.DecimalField(source='accepted_tier.price', read_only=True, max_digits=10, decimal_places=2)
    currency = serializers.CharField(source='accepted_tier.currency', read_only=True)
    accepted_by_id = serializers.IntegerField(source='accepted_by.id', read_only=True)
    accepted_by_name = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = EventAttendeeOrigin
        fields = [
            'id', 'registration_id', 'role_id', 'role_label',
            'track_id', 'track_label', 'submission_mode',
            'accepted_tier_id', 'tier_label', 'accepted_tier_label', 'tier_price', 'price', 'currency',
            'accepted_by_id', 'accepted_by_name', 'accepted_at',
            'nominator_name', 'nominator_email',
            'status', 'origin_status', 'payment_reference', 'marked_paid_at',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at',
            'role_label', 'track_label', 'tier_label', 'accepted_tier_label', 'tier_price', 'price', 'currency',
            'accepted_by_id', 'accepted_by_name'
        ]

    def get_accepted_by_name(self, obj):
        if obj.accepted_by:
            return f"{obj.accepted_by.first_name} {obj.accepted_by.last_name}".strip()
        return None


class EventRegistrationLiteSerializer(serializers.ModelSerializer):
    """Lightweight serializer for /event-registrations/mine/ endpoint.
    Includes registration fields + nested event with recording/replay info.
    Optimized for My Recordings page while keeping payload reasonable.
    """
    event = EventLiteSerializer(read_only=True)
    event_id = serializers.IntegerField(source='event.id', read_only=True)
    is_host = serializers.SerializerMethodField()

    def get_is_host(self, obj):
        # User is host if they created the event (most common case for card footer)
        # For full host check including participants, use EventRegistrationSerializer
        return obj.user_id == getattr(obj.event, 'created_by_id', None)

    class Meta:
        model = EventRegistration
        fields = (
            'id', 'event', 'event_id', 'status', 'attendee_status', 'registered_at',
            'joined_live', 'watched_replay', 'admission_status', 'admitted_at',
            'current_location', 'is_host'
        )
        read_only_fields = tuple(fields)


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
    attendance_duration_seconds = serializers.SerializerMethodField()
    attendance_category = serializers.SerializerMethodField()
    badge_labels = serializers.SerializerMethodField()
    roles = EventRoleSerializer(many=True, read_only=True)
    origins = EventAttendeeOriginSerializer(many=True, read_only=True)
    # Phase 11: Payment tracking fields
    marked_paid_by = UserMiniSerializer(read_only=True)
    marked_paid_at = serializers.DateTimeField(read_only=True)
    payment_reference = serializers.CharField(read_only=True)
    attendee_status = serializers.CharField(read_only=True)

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
            "current_location",
            "attendance_duration_seconds",
            "attendance_category",
            "badge_labels",
            "roles",
            "origins",
            "attendee_status",
            "marked_paid_by",
            "marked_paid_at",
            "payment_reference",
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
            "current_location",
            "badge_labels",
            "roles",
            "origins",
            "marked_paid_by",
            "marked_paid_at",
            "payment_reference",
            "attendee_status",
        )

    def get_badge_labels(self, obj):
        return [{'id': bl.id, 'name': bl.name, 'color': bl.color} for bl in obj.badge_labels.all()]

    def get_is_host(self, obj):
        event = obj.event
        user_id = obj.user_id
        if not event or not user_id:
            return False

        if user_id == getattr(event, "created_by_id", None):
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

    def get_attendance_duration_seconds(self, obj):
        """
        Calculate total attendance duration for this user at this event.
        Uses SessionAttendance records aggregated by duration_seconds.
        """
        from django.db.models import Sum
        from .models import SessionAttendance

        if not obj.event_id or not obj.user_id:
            return 0

        total = SessionAttendance.objects.filter(
            session__event_id=obj.event_id,
            user_id=obj.user_id
        ).aggregate(total=Sum('duration_seconds'))['total']

        return total or 0

    def get_attendance_category(self, obj):
        """
        Determine attendance category based on joined_live status and duration.

        ✅ EXCLUDES HOSTS/ADMINS - they should not appear in attendee categories

        Categories:
        - None: User is host/creator/owner (EXCLUDED from attendee lists)
        - 'noshow': Did not join live
        - 'partial': Joined but attended < 80% of event duration
        - 'full': Joined and attended >= 80% of event duration
        """
        # ✅ Exclude hosts, creators, and community owners
        # These should not appear in attendee categorization
        event = obj.event
        user_id = obj.user_id
        if event and user_id:
            if (user_id == getattr(event, "created_by_id", None) or
                user_id == getattr(getattr(event, "community", None), "owner_id", None)):
                return None  # ← Exclude from attendee lists

        # Regular attendee categorization
        if not obj.joined_live:
            return 'noshow'

        if not event or not event.start_time or not event.end_time:
            # If no event duration, mark as partial
            return 'partial'

        event_duration_seconds = (event.end_time - event.start_time).total_seconds()
        if event_duration_seconds <= 0:
            return 'partial'

        threshold = 0.8 * event_duration_seconds
        attendance_duration = self.get_attendance_duration_seconds(obj)

        if attendance_duration >= threshold:
            return 'full'
        else:
            return 'partial'


class SpeedNetworkingMatchSerializer(serializers.ModelSerializer):
    participant_1 = UserMiniSerializer(read_only=True)
    participant_2 = UserMiniSerializer(read_only=True)

    class Meta:
        model = SpeedNetworkingMatch
        fields = [
            'id', 'session', 'participant_1', 'participant_2',
            'status', 'rtk_room_name', 'match_score', 'match_breakdown', 'rule_compliance',
            'match_probability', 'config_version', 'last_recalculated_at',
            'created_at', 'ended_at',
            'extension_requested_p1', 'extension_requested_p2', 'extension_applied', 'extended_by_seconds'
        ]
        read_only_fields = ['id', 'created_at', 'ended_at', 'status', 'rtk_room_name',
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


class EventApplicationSerializer(serializers.ModelSerializer):
    """Serializer for EventApplication model - read-only for fetching applications."""
    applicant_name = serializers.SerializerMethodField()
    track_applications = serializers.SerializerMethodField()
    application_status = serializers.SerializerMethodField()

    def get_applicant_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"

    def get_track_applications(self, obj):
        # Return nested track applications if they exist (Phase 7)
        ta = obj.track_applications.all()
        if ta.exists():
            return EventApplicationTrackApplicationSerializer(ta, many=True).data
        return []

    def get_application_status(self, obj):
        """Compute application status from track applications.
        Prioritizes active statuses (pending/pre_approved/accepted) over declined/cancelled."""
        track_apps = obj.track_applications.all()
        if not track_apps.exists():
            return obj.status

        track_statuses = [ta.status for ta in track_apps]

        # Prioritize active statuses - return immediately if found
        if "accepted" in track_statuses:
            return "accepted"
        elif "pending" in track_statuses or "pre_approved" in track_statuses:
            return "pending"
        elif track_statuses and any(status == "waitlisted" for status in track_statuses):
            return "waitlisted"
        elif track_statuses and all(status == "declined" for status in track_statuses):
            return "declined"
        else:
            # Fallback to parent status
            return obj.status

    class Meta:
        model = EventApplication
        fields = [
            'id', 'event_id', 'user_id', 'applicant_name',
            'first_name', 'last_name', 'email',
            'job_title', 'company_name', 'linkedin_url',
            'attendee_marker_value', 'comments',
            'status', 'application_status', 'applied_at', 'reviewed_at',
            'reviewed_by_id', 'rejection_message',
            'is_preapproved', 'preapproval_source', 'preapproved_at',
            # Phase 3: Submission modes
            'application_track_id', 'submission_mode',
            'nominator_name', 'nominator_email',
            'nominee_name', 'nominee_email', 'nominee_details',
            'sponsor_organization',
            # Phase 7: Multi-track support
            'selected_tracks', 'track_applications',
        ]
        read_only_fields = [
            'id', 'applied_at', 'reviewed_at', 'reviewed_by_id', 'status', 'application_status'
        ]


class EventApplicationSubmitSerializer(serializers.Serializer):
    """Serializer for submitting an application - write-only, used for POST requests."""
    first_name = serializers.CharField(max_length=150, required=True, help_text="First name is required")
    last_name = serializers.CharField(max_length=150, required=True, help_text="Last name is required")
    email = serializers.CharField(max_length=254, required=True, help_text="Email is required")
    job_title = serializers.CharField(max_length=200, required=True, help_text="Job title is required")
    company_name = serializers.CharField(max_length=200, required=True, help_text="Company name is required")
    linkedin_url = serializers.URLField(required=False, allow_blank=True, default='')
    attendee_marker_value = serializers.BooleanField(required=False, default=False)
    comments = serializers.CharField(required=False, allow_blank=True, default='')
    preapproved_code = serializers.CharField(required=False, allow_blank=True, default='')
    pre_approval_code = serializers.CharField(required=False, allow_blank=True, default='')  # Alias for preapproved_code

    # Phase 3: Submission modes
    track_id = serializers.IntegerField(required=False, allow_null=True)
    track_key = serializers.CharField(required=False, allow_blank=True)
    submission_mode = serializers.ChoiceField(
        choices=['self_submission', 'confirmed', 'self_nomination', 'third_party_nomination'],
        default='self_submission'
    )

    # Mode-specific fields
    nominator_name = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    nominator_email = serializers.EmailField(required=False, allow_blank=True, default='')
    nominee_name = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    nominee_email = serializers.EmailField(required=False, allow_blank=True, default='')
    nominee_details = serializers.JSONField(required=False, default=dict)
    sponsor_organization = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')

    # CRITICAL FIX: Support multiple tracks
    track_applications = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        allow_empty=True,
        help_text='Array of track applications with track_id/track_key, submission_mode, tier_preference'
    )

    # Form data for track applications
    form_answers = serializers.JSONField(required=False, default=dict)
    file_uploads = serializers.JSONField(required=False, default=dict)
    tier_preference = serializers.IntegerField(required=False, allow_null=True)
    requested_tier = serializers.IntegerField(required=False, allow_null=True)

    def validate(self, attrs):
        """Merge pre_approval_code into preapproved_code for compatibility."""
        if attrs.get('pre_approval_code') and not attrs.get('preapproved_code'):
            attrs['preapproved_code'] = attrs['pre_approval_code']
        return attrs


class EventPreApprovalCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventPreApprovalCode
        fields = [
            "id",
            "event_id",
            "track_id",
            "submission_mode",
            "code",
            "status",
            "used_by_email",
            "used_at",
            "created_by_id",
            "created_at",
            "revoked_by_id",
            "revoked_at",
            "notes",
        ]
        read_only_fields = ["id", "event_id", "status", "used_by_email", "used_at", "created_by_id", "created_at", "revoked_by_id", "revoked_at"]

    def validate_track(self, value):
        """Ensure track belongs to the event."""
        if value is None:
            return value  # NULL track (applies to all tracks) is allowed
        event = self.initial_data.get('event_id')
        if event and value.event_id != int(event):
            raise serializers.ValidationError("Track does not belong to this event.")
        return value

    def validate_submission_mode(self, value):
        """Ensure submission_mode is valid (either empty or in valid choices)."""
        if not value:
            return value  # Empty string (applies to all modes) is allowed
        valid_modes = ['self_submission', 'confirmed', 'self_nomination', 'third_party_nomination']
        if value not in valid_modes:
            raise serializers.ValidationError(f"Invalid submission mode. Must be one of: {', '.join(valid_modes)}")
        return value

    def validate(self, data):
        """Validate track and mode compatibility if track is specified."""
        track = data.get('track')
        submission_mode = data.get('submission_mode')
        if track and submission_mode:
            enabled_modes = track.enabled_submission_modes or []
            if submission_mode not in enabled_modes:
                raise serializers.ValidationError(f"Submission mode '{submission_mode}' is not enabled for track '{track.label}'.")
        return data


class EventPreApprovalAllowlistSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventPreApprovalAllowlist
        fields = [
            "id",
            "event_id",
            "track_id",
            "submission_mode",
            "first_name",
            "last_name",
            "email",
            "is_active",
            "created_by_id",
            "created_at",
            "removed_by_id",
            "removed_at",
            "notes",
        ]
        read_only_fields = ["id", "event_id", "is_active", "created_by_id", "created_at", "removed_by_id", "removed_at"]

    def validate_track(self, value):
        """Ensure track belongs to the event."""
        if value is None:
            return value  # NULL track (applies to all tracks) is allowed
        event = self.initial_data.get('event_id')
        if event and value.event_id != int(event):
            raise serializers.ValidationError("Track does not belong to this event.")
        return value

    def validate_submission_mode(self, value):
        """Ensure submission_mode is valid (either empty or in valid choices)."""
        if not value:
            return value  # Empty string (applies to all modes) is allowed
        valid_modes = ['self_submission', 'confirmed', 'self_nomination', 'third_party_nomination']
        if value not in valid_modes:
            raise serializers.ValidationError(f"Invalid submission mode. Must be one of: {', '.join(valid_modes)}")
        return value

    def validate(self, data):
        """Validate track and mode compatibility if track is specified."""
        track = data.get('track')
        submission_mode = data.get('submission_mode')
        if track and submission_mode:
            enabled_modes = track.enabled_submission_modes or []
            if submission_mode not in enabled_modes:
                raise serializers.ValidationError(f"Submission mode '{submission_mode}' is not enabled for track '{track.label}'.")
        return data


# Phase 7: Multi-track applications
class TrackApplicationDataSerializer(serializers.Serializer):
    """Nested serializer for track-specific application data."""
    track_id = serializers.IntegerField()
    submission_mode = serializers.CharField(max_length=50)
    tier_preference_id = serializers.IntegerField(required=False, allow_null=True)
    form_answers = serializers.JSONField(required=False, default=dict)
    file_uploads = serializers.JSONField(required=False, default=dict)

    # Mode-specific fields
    nominator_name = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    nominator_email = serializers.EmailField(required=False, allow_blank=True, default='')
    nominee_name = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    nominee_email = serializers.EmailField(required=False, allow_blank=True, default='')
    nominee_details = serializers.JSONField(required=False, default=dict)
    sponsor_organization = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')


class MultiTrackApplicationSubmitSerializer(serializers.Serializer):
    """Serializer for submitting multi-track applications."""
    # Applicant identity
    first_name = serializers.CharField(max_length=150)
    last_name = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    job_title = serializers.CharField(max_length=200, required=False, allow_blank=True, default='')
    company_name = serializers.CharField(max_length=200, required=False, allow_blank=True, default='')
    linkedin_url = serializers.URLField(required=False, allow_blank=True, default='')
    comments = serializers.CharField(required=False, allow_blank=True, default='')

    # Pre-approval (optional)
    preapproved_code = serializers.CharField(required=False, allow_blank=True, default='')

    # Track applications (array)
    track_applications = TrackApplicationDataSerializer(many=True)


class EventApplicationTrackApplicationSerializer(serializers.ModelSerializer):
    """Serializer for per-track application data."""
    track_label = serializers.SerializerMethodField()
    track_short_description = serializers.SerializerMethodField()
    status_display = serializers.SerializerMethodField()
    accepted_tier_label = serializers.SerializerMethodField()

    class Meta:
        model = EventApplicationTrackApplication
        fields = [
            'id', 'application_id', 'track_id', 'track_label', 'track_short_description',
            'submission_mode', 'status', 'status_display', 'tier_preference_id', 'accepted_tier_label',
            'form_answers', 'file_uploads', 'created_at', 'updated_at', 'reviewed_at', 'reviewed_by_id'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'reviewed_at', 'reviewed_by_id']

    def get_track_label(self, obj):
        return obj.track.label

    def get_track_short_description(self, obj):
        return obj.track.short_description

    def get_status_display(self, obj):
        return obj.get_status_display()

    def get_accepted_tier_label(self, obj):
        if obj.accepted_tier:
            return obj.accepted_tier.label
        return None


# Phase 9: Review queue detail view
class EventApplicationTrackApplicationDetailSerializer(serializers.ModelSerializer):
    """Detailed view of track application with all related applicant and submission data."""
    # Track info
    track_label = serializers.CharField(source='track.label', read_only=True)
    track_short_description = serializers.CharField(source='track.short_description', read_only=True)
    submission_mode_display = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    # Applicant info
    applicant_email = serializers.CharField(source='application.email', read_only=True)
    applicant_first_name = serializers.CharField(source='application.first_name', read_only=True)
    applicant_last_name = serializers.CharField(source='application.last_name', read_only=True)
    applicant_job_title = serializers.CharField(source='application.job_title', read_only=True)
    applicant_company = serializers.CharField(source='application.company_name', read_only=True)
    applicant_linkedin = serializers.CharField(source='application.linkedin_url', read_only=True, required=False)

    # Pre-approval info
    is_preapproved = serializers.CharField(source='application.is_preapproved', read_only=True)
    preapproval_source = serializers.CharField(source='application.preapproval_source', read_only=True)

    # Third-party nomination fields
    nominator_name = serializers.CharField(source='application.nominator_name', read_only=True, required=False)
    nominator_email = serializers.CharField(source='application.nominator_email', read_only=True, required=False)
    nominee_name = serializers.CharField(source='application.nominee_name', read_only=True, required=False)
    nominee_email = serializers.CharField(source='application.nominee_email', read_only=True, required=False)

    # Sponsor fields
    sponsor_organization = serializers.CharField(source='application.sponsor_organization', read_only=True, required=False)

    # Event-level optional marker answer (from the parent application)
    attendee_marker_value = serializers.BooleanField(source='application.attendee_marker_value', read_only=True)

    # Reviewer info
    reviewed_by_user = serializers.SerializerMethodField()
    registration_id = serializers.SerializerMethodField()

    # Tier info
    tier_label = serializers.SerializerMethodField()
    accepted_tier_label = serializers.SerializerMethodField()
    accepted_tier_price = serializers.SerializerMethodField()
    accepted_tier_currency = serializers.SerializerMethodField()

    # Payment status - from EventAttendeeOrigin
    origin_status = serializers.SerializerMethodField()

    class Meta:
        model = EventApplicationTrackApplication
        fields = [
            'id', 'application_id', 'track_id', 'track_label', 'track_short_description',
            'submission_mode', 'submission_mode_display', 'status', 'status_display',
            'tier_preference_id', 'tier_label', 'accepted_tier_label', 'form_answers', 'file_uploads',
            'applicant_email', 'applicant_first_name', 'applicant_last_name',
            'applicant_job_title', 'applicant_company', 'applicant_linkedin',
            'is_preapproved', 'preapproval_source',
            'nominator_name', 'nominator_email', 'nominee_name', 'nominee_email',
            'sponsor_organization', 'attendee_marker_value',
            'reviewed_by_user', 'registration_id', 'reviewed_at', 'created_at', 'updated_at',
            'accepted_at', 'declined_at', 'waitlisted_at', 'cancelled_at',
            'accepted_tier_price', 'accepted_tier_currency', 'origin_status'
        ]
        read_only_fields = fields

    def get_submission_mode_display(self, obj):
        mode_labels = {
            'self_submission': 'Self Submission',
            'confirmed': 'Confirmed Submission',
            'self_nomination': 'Self Nomination',
            'third_party_nomination': 'Third-Party Nomination',
        }
        return mode_labels.get(obj.submission_mode, obj.submission_mode)

    def get_reviewed_by_user(self, obj):
        if obj.reviewed_by:
            return {
                'id': obj.reviewed_by.id,
                'username': obj.reviewed_by.username,
                'first_name': obj.reviewed_by.first_name,
                'last_name': obj.reviewed_by.last_name,
                'email': obj.reviewed_by.email,
            }
        return None

    def get_tier_label(self, obj):
        if obj.tier_preference:
            return obj.tier_preference.label
        return None

    def get_accepted_tier_label(self, obj):
        if obj.accepted_tier:
            return obj.accepted_tier.label
        return None

    def get_accepted_tier_price(self, obj):
        if obj.accepted_tier:
            return str(obj.accepted_tier.price)
        return None

    def get_accepted_tier_currency(self, obj):
        if obj.accepted_tier:
            return obj.accepted_tier.currency
        return None

    def get_registration_id(self, obj):
        user = obj.application.user
        if not user:
            return None
        registration = EventRegistration.objects.filter(
            event=obj.track.event,
            user=user,
            status__in=['registered', 'cancellation_requested']
        ).first()
        return registration.id if registration else None

    def get_origin_status(self, obj):
        """Get the actual origin_status from EventAttendeeOrigin for accepted applications."""
        if obj.status != 'accepted':
            return None

        user = obj.application.user
        if not user:
            return None

        origin = EventAttendeeOrigin.objects.filter(
            registration__event=obj.track.event,
            registration__user=user,
            track=obj.track,
            status='active'
        ).first()

        return origin.origin_status if origin else None


class SaleorChannelSerializer(serializers.ModelSerializer):
    class Meta:
        model = SaleorChannel
        fields = [
            'id', 'saleor_id', 'name', 'slug', 'currency', 'is_active',
            'default_country', 'countries', 'warehouse_ids', 'allocation_strategy', 'synced_at'
        ]
        read_only_fields = ['id', 'synced_at']


class SaleorWarehouseSerializer(serializers.ModelSerializer):
    class Meta:
        model = SaleorWarehouse
        fields = [
            'id', 'saleor_id', 'name', 'slug', 'email',
            'company_name', 'street_address_1', 'street_address_2',
            'city', 'country', 'country_code', 'postal_code', 'country_area', 'phone',
            'click_and_collect', 'is_private', 'is_active', 'shipping_zone_ids', 'synced_at'
        ]
        read_only_fields = ['id', 'synced_at']


class SaleorShippingZoneSerializer(serializers.ModelSerializer):
    class Meta:
        model = SaleorShippingZone
        fields = [
            'id', 'saleor_id', 'name', 'description', 'is_default',
            'countries', 'channel_ids', 'warehouse_ids', 'shipping_methods',
            'is_active', 'synced_at'
        ]
        read_only_fields = ['id', 'synced_at']


class SaleorProductTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = SaleorProductType
        fields = [
            'id', 'saleor_id', 'name', 'slug', 'kind',
            'is_shipping_required', 'tax_class_id', 'tax_class_name',
            'product_attribute_ids', 'variant_attribute_ids',
            'metadata', 'private_metadata', 'synced_at',
        ]
        read_only_fields = ['id', 'synced_at']


class SaleorStaffUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = SaleorStaffUser
        fields = [
            'id', 'saleor_id', 'first_name', 'last_name', 'email',
            'is_staff', 'is_active', 'permissions', 'metadata', 'synced_at',
        ]
        read_only_fields = ['id', 'synced_at']


class SaleorPermissionGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = SaleorPermissionGroup
        fields = [
            'id', 'saleor_id', 'name', 'permissions', 'user_count', 'metadata', 'synced_at',
        ]
        read_only_fields = ['id', 'synced_at']


# WebinarSeries Serializers

def _is_current_user_registered_for_series(obj, request):
    user = getattr(request, 'user', None)
    if not user or not user.is_authenticated:
        return False
    return obj.series_registrations.filter(user_id=user.id, status='registered').exists()


# Image field names (in priority order) checked on a series' child events when
# deriving the series card image. Supports both file fields (ImageField/FileField,
# which expose `.url`) and plain URL/char fields (returned as-is).
SERIES_EVENT_IMAGE_FIELD_NAMES = (
    "cover_image", "image", "banner_image", "thumbnail",
    "featured_image", "preview_image", "image_url",
)


def _resolve_event_image_url(event, request):
    """Return the first non-empty image URL found on an event, or None.

    Looks through SERIES_EVENT_IMAGE_FIELD_NAMES defensively via getattr so that
    events without a given field are simply skipped (never raising).
    """
    for field_name in SERIES_EVENT_IMAGE_FIELD_NAMES:
        value = getattr(event, field_name, None)
        if not value:
            continue
        # FileField/ImageField expose `.url`; plain URL/char fields are strings.
        url = getattr(value, "url", None)
        if url is None:
            url = str(value).strip()
        if not url:
            continue
        if request is not None and url.startswith("/"):
            return request.build_absolute_uri(url)
        return url
    return None


def _get_series_card_image_url(series, request):
    """First available image from the series' events, in series-added order.

    Ordering follows the explicit ``series_order`` (1-indexed add position); any
    unset values and ties fall back to creation order. Event start time is never
    used for ordering. Returns None when no event in the series has an image, so
    the frontend can render a blank media area instead of a placeholder/default.
    """
    child_events = series.child_events.all().order_by(
        F("series_order").asc(nulls_last=True), "created_at", "id"
    )
    for event in child_events:
        url = _resolve_event_image_url(event, request)
        if url:
            return url
    return None


class SeriesEventNestedSerializer(serializers.ModelSerializer):
    """Nested event representation for series detail view"""
    registrations_count = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = [
            'id', 'title', 'description', 'start_time', 'end_time',
            'series_order', 'series_session_label', 'status',
            'registrations_count'
        ]
        read_only_fields = fields

    def get_registrations_count(self, obj):
        return obj.registrations.filter(status='registered').count()


class EventSeriesListSerializer(serializers.ModelSerializer):
    """Series list view - minimal fields"""
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    events_count = serializers.SerializerMethodField()
    registrations_count = serializers.SerializerMethodField()
    cover_image_url = serializers.SerializerMethodField()
    card_image_url = serializers.SerializerMethodField()
    is_registered = serializers.SerializerMethodField()

    class Meta:
        model = EventSeries
        fields = [
            'id', 'title', 'slug', 'description', 'status', 'is_free',
            'price', 'visibility', 'events_count', 'registrations_count',
            'created_by_name', 'cover_image_url', 'card_image_url',
            'is_registered', 'created_at'
        ]
        read_only_fields = [
            'id', 'slug', 'created_at', 'events_count', 'registrations_count',
            'is_registered'
        ]

    def get_events_count(self, obj):
        return obj.child_events.count()

    def get_registrations_count(self, obj):
        return obj.series_registrations.filter(status='registered').count()

    def get_cover_image_url(self, obj):
        if obj.cover_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.cover_image.url)
            return obj.cover_image.url
        return None

    def get_card_image_url(self, obj):
        return _get_series_card_image_url(obj, self.context.get('request'))

    def get_is_registered(self, obj):
        return _is_current_user_registered_for_series(obj, self.context.get('request'))


class EventSeriesDetailSerializer(serializers.ModelSerializer):
    """Series detail view - full information with nested events"""
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    created_by_id = serializers.IntegerField(source='created_by.id', read_only=True)
    community_id = serializers.IntegerField(source='community.id', read_only=True)
    community_name = serializers.CharField(source='community.name', read_only=True)
    events = SeriesEventNestedSerializer(source='child_events', many=True, read_only=True)
    events_count = serializers.SerializerMethodField()
    registrations_count = serializers.SerializerMethodField()
    cover_image_url = serializers.SerializerMethodField()
    card_image_url = serializers.SerializerMethodField()
    is_owner = serializers.SerializerMethodField()
    is_registered = serializers.SerializerMethodField()

    class Meta:
        model = EventSeries
        fields = [
            'id', 'title', 'slug', 'description', 'status', 'is_free',
            'price', 'currency', 'visibility', 'registration_mode',
            'metadata', 'events', 'events_count', 'registrations_count',
            'created_by_id', 'created_by_name', 'community_id', 'community_name',
            'cover_image_url', 'card_image_url', 'is_owner', 'is_registered',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'slug', 'currency', 'created_at', 'updated_at',
            'events_count', 'registrations_count', 'is_owner', 'is_registered'
        ]

    def get_events_count(self, obj):
        return obj.child_events.count()

    def get_registrations_count(self, obj):
        return obj.series_registrations.filter(status='registered').count()

    def get_cover_image_url(self, obj):
        if obj.cover_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.cover_image.url)
            return obj.cover_image.url
        return None

    def get_card_image_url(self, obj):
        return _get_series_card_image_url(obj, self.context.get('request'))

    def get_is_owner(self, obj):
        request = self.context.get('request')
        if not request:
            return False
        return bool(
            request.user
            and (
                obj.created_by_id == request.user.id
                or getattr(request.user, 'is_superuser', False)
            )
        )

    def get_is_registered(self, obj):
        return _is_current_user_registered_for_series(obj, self.context.get('request'))


class EventSeriesCreateUpdateSerializer(serializers.ModelSerializer):
    """Serializer for creating/updating series"""
    community_id = serializers.PrimaryKeyRelatedField(
        source='community',
        queryset=Community.objects.all(),
        write_only=True,
        required=True,
    )
    # Reflect the requesting user's registration state in the create/update
    # response so the frontend knows the creator is already registered without
    # needing a second fetch.
    is_registered = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = EventSeries
        fields = [
            'id', 'title', 'description', 'status', 'registration_mode',
            'is_free', 'price', 'visibility', 'metadata', 'community_id',
            'cover_image', 'slug', 'is_registered'
        ]
        read_only_fields = ['id', 'slug', 'is_registered']

    def get_is_registered(self, obj):
        return _is_current_user_registered_for_series(obj, self.context.get('request'))

    def validate_title(self, value):
        if not value or len(value.strip()) < 3:
            raise serializers.ValidationError("Title must be at least 3 characters long")
        return value

    def validate_community_id(self, value):
        request = self.context.get('request')
        if not request or not request.user:
            raise serializers.ValidationError("Authentication required")
        if not request.user.community.filter(id=value.id).exists():
            raise serializers.ValidationError("You must be a member of this community")
        return value

    def create(self, validated_data):
        request = self.context.get('request')
        if not request:
            raise serializers.ValidationError("Request context required")
        validated_data['created_by'] = request.user
        return super().create(validated_data)


class SeriesRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for series registrations"""
    user_id = serializers.IntegerField(source='user.id', read_only=True)
    user_name = serializers.SerializerMethodField()
    user_email = serializers.EmailField(source='user.email', read_only=True)
    series_id = serializers.IntegerField(source='series.id', read_only=True)
    events_attended_count = serializers.SerializerMethodField()
    total_events = serializers.SerializerMethodField()

    class Meta:
        model = SeriesRegistration
        fields = [
            'id', 'user_id', 'user_name', 'user_email', 'series_id',
            'status', 'registered_at', 'events_attended_count', 'total_events'
        ]
        read_only_fields = [
            'id', 'user_id', 'user_name', 'user_email', 'series_id',
            'registered_at', 'events_attended_count', 'total_events'
        ]

    def get_user_name(self, obj):
        user = obj.user
        if user.first_name and user.last_name:
            return f"{user.first_name} {user.last_name}"
        return user.username

    def get_events_attended_count(self, obj):
        from .models import EventRegistration
        event_ids = obj.series.child_events.values_list('id', flat=True)
        return EventRegistration.objects.filter(
            user=obj.user,
            event_id__in=event_ids,
            joined_live=True
        ).count()

    def get_total_events(self, obj):
        return obj.series.child_events.count()


class PublicEventSeriesSerializer(serializers.ModelSerializer):
    """Public series landing page - minimal, public info only"""
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    events = SeriesEventNestedSerializer(source='child_events', many=True, read_only=True)
    events_count = serializers.SerializerMethodField()
    registrations_count = serializers.SerializerMethodField()
    cover_image_url = serializers.SerializerMethodField()
    card_image_url = serializers.SerializerMethodField()
    is_registered = serializers.SerializerMethodField()
    is_owner = serializers.SerializerMethodField()

    class Meta:
        model = EventSeries
        fields = [
            'id', 'title', 'slug', 'description', 'status', 'visibility',
            'registration_mode', 'is_free', 'price', 'events', 'events_count',
            'registrations_count', 'created_by_name', 'cover_image_url',
            'card_image_url', 'is_registered', 'is_owner'
        ]
        read_only_fields = fields

    def get_is_owner(self, obj):
        request = self.context.get('request')
        if not request:
            return False
        user = getattr(request, 'user', None)
        return bool(
            user
            and user.is_authenticated
            and (
                obj.created_by_id == user.id
                or getattr(user, 'is_superuser', False)
            )
        )

    def get_events_count(self, obj):
        return obj.child_events.filter(status='published').count()

    def get_registrations_count(self, obj):
        return obj.series_registrations.filter(status='registered').count()

    def get_cover_image_url(self, obj):
        if obj.cover_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.cover_image.url)
            return obj.cover_image.url
        return None

    def get_card_image_url(self, obj):
        return _get_series_card_image_url(obj, self.context.get('request'))

    def get_is_registered(self, obj):
        return _is_current_user_registered_for_series(obj, self.context.get('request'))


class EventSaleorDiscountSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)

    class Meta:
        model = EventSaleorDiscount
        fields = [
            'id', 'event', 'saleor_promotion_id', 'saleor_rule_id',
            'name', 'description', 'discount_type',
            'channel_id', 'channel_name', 'channel_slug', 'currency',
            'reward_value_type', 'reward_value',
            'start_date', 'end_date', 'badge_label', 'is_active',
            'created_by', 'created_by_name', 'created_at', 'updated_at', 'last_sync_error'
        ]
        read_only_fields = [
            'id', 'event', 'saleor_promotion_id', 'saleor_rule_id',
            'discount_type', 'channel_name', 'channel_slug', 'currency',
            'created_by', 'created_by_name', 'created_at', 'updated_at', 'last_sync_error'
        ]

    def validate_name(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Name is required.")
        return value

    def validate_channel_id(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Channel is required.")
        return value

    def validate_reward_value_type(self, value):
        if value not in ['PERCENTAGE', 'FIXED']:
            raise serializers.ValidationError("Reward type must be PERCENTAGE or FIXED.")
        return value

    def validate_reward_value(self, value):
        try:
            val = float(value) if isinstance(value, str) else value
            if val <= 0:
                raise serializers.ValidationError("Reward value must be greater than 0.")
        except (ValueError, TypeError):
            raise serializers.ValidationError("Reward value must be a valid number.")
        return value

    def validate_badge_label(self, value):
        if not value or value not in ['early_bird', 'bundle_price']:
            raise serializers.ValidationError("Badge label must be early_bird or bundle_price.")
        return value

    def validate(self, data):
        reward_value = data.get('reward_value')
        reward_value_type = data.get('reward_value_type')
        start_date = data.get('start_date')
        end_date = data.get('end_date')

        if reward_value and reward_value_type:
            try:
                val = float(reward_value) if isinstance(reward_value, str) else reward_value
                if reward_value_type == 'PERCENTAGE' and val > 100:
                    raise serializers.ValidationError("Percentage reward value must be <= 100.")
            except (ValueError, TypeError):
                raise serializers.ValidationError("Reward value must be a valid number.")

        if start_date and end_date and end_date < start_date:
            raise serializers.ValidationError("End date must be same as or after start date.")

        return data


class EventEmailTemplateSerializer(serializers.ModelSerializer):
    """Serializer for per-event email template overrides."""
    updated_by_name = serializers.CharField(source='updated_by.get_full_name', read_only=True)
    label = serializers.SerializerMethodField()
    category = serializers.SerializerMethodField()
    source = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    merge_tags = serializers.SerializerMethodField()
    required_placeholders = serializers.SerializerMethodField()

    def _metadata(self, obj):
        from cms.email_template_registry import get_template_metadata
        return get_template_metadata(obj.template_key) or {}

    class Meta:
        model = EventEmailTemplate
        fields = [
            'id', 'event', 'template_key', 'subject', 'html_body', 'text_body',
            'editor_json', 'mjml_body', 'editor_type', 'is_active', 'notes',
            'updated_by', 'updated_by_name', 'created_at', 'updated_at',
            'label', 'category', 'source', 'status', 'merge_tags', 'required_placeholders',
        ]
        read_only_fields = [
            'id', 'event', 'created_at', 'updated_at', 'updated_by_name',
            'label', 'category', 'source', 'status', 'merge_tags', 'required_placeholders',
        ]

    def get_label(self, obj):
        return self._metadata(obj).get('label', obj.get_template_key_display())

    def get_category(self, obj):
        return self._metadata(obj).get('category', 'Events')

    def get_source(self, obj):
        return 'event_specific'

    def get_status(self, obj):
        return 'active' if obj.is_active else 'inactive'

    def get_merge_tags(self, obj):
        return self._metadata(obj).get('merge_tags', [])

    def get_required_placeholders(self, obj):
        return self._metadata(obj).get('required_placeholders', [])


class EventBadgeLabelSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventBadgeLabel
        fields = ['id', 'event', 'name', 'color', 'created_at', 'updated_at']
        read_only_fields = ['id', 'event', 'created_at', 'updated_at']

    def validate_name(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Label name is required.")
        return value.strip()

    def validate_color(self, value):
        import re
        if not re.match(r'^#[0-9A-Fa-f]{6}$', value):
            raise serializers.ValidationError("Color must be a valid 6-digit hex, e.g. #6366f1.")
        return value.lower()


class EventNetworkingSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventNetworkingSettings
        fields = [
            'id', 'event', 'enabled', 'duration_options_minutes', 'allowed_windows',
            'reminder_minutes_before', 'sms_enabled', 'max_meetings_per_attendee_per_day',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'event', 'created_at', 'updated_at']

    def validate_duration_options_minutes(self, value):
        if not isinstance(value, list) or not value:
            raise serializers.ValidationError("Duration options must be a non-empty list.")
        if not all(isinstance(v, int) and v > 0 for v in value):
            raise serializers.ValidationError("All durations must be positive integers.")
        return value

    def validate_allowed_windows(self, value):
        from datetime import datetime

        if not isinstance(value, list):
            raise serializers.ValidationError("Allowed windows must be a list.")

        for i, window in enumerate(value):
            if not isinstance(window, dict):
                raise serializers.ValidationError(f"Window {i}: must be a dict.")

            required = ['date', 'start', 'end']
            if not all(k in window for k in required):
                raise serializers.ValidationError(f"Window {i}: must have keys {required}.")

            # Validate date format
            try:
                datetime.strptime(window.get('date'), "%Y-%m-%d")
            except (ValueError, TypeError):
                raise serializers.ValidationError(
                    f"Window {i}: invalid date format. Use YYYY-MM-DD (e.g., 2026-05-15)."
                )

            # Validate time formats (support both HH:MM and HH:MM AM/PM)
            for time_field in ['start', 'end']:
                time_str = window.get(time_field, '').strip()
                valid_format = False

                # Try HH:MM format
                try:
                    datetime.strptime(time_str, "%H:%M")
                    valid_format = True
                except ValueError:
                    pass

                # Try HH:MM AM/PM format
                if not valid_format:
                    for fmt in ["%I:%M %p", "%I:%M%p"]:
                        try:
                            datetime.strptime(time_str, fmt)
                            valid_format = True
                            break
                        except ValueError:
                            pass

                if not valid_format:
                    raise serializers.ValidationError(
                        f"Window {i}: {time_field} has invalid time format. Use HH:MM (24h) or HH:MM AM/PM (12h)."
                    )

        return value

    def validate(self, data):
        from datetime import datetime
        from pytz import timezone as pytz_timezone

        # Get event from context or instance
        event = self.context.get('event')
        if not event and self.instance:
            event = self.instance.event

        if not event:
            return data

        # Only validate if allowed_windows is being updated
        allowed_windows = data.get('allowed_windows', self.instance.allowed_windows if self.instance else None)
        if not allowed_windows:
            return data

        # Get event timezone
        try:
            event_tz = pytz_timezone(event.timezone)
        except Exception:
            event_tz = pytz_timezone('UTC')

        if not event.start_time or not event.end_time:
            raise serializers.ValidationError({
                'allowed_windows': 'Event must have start_time and end_time set.'
            })

        # Helper to parse time in HH:MM or HH:MM AM/PM format
        def parse_time_str(time_str):
            time_str = time_str.strip()
            try:
                return datetime.strptime(time_str, "%H:%M").time()
            except ValueError:
                pass
            for fmt in ["%I:%M %p", "%I:%M%p"]:
                try:
                    return datetime.strptime(time_str, fmt).time()
                except ValueError:
                    pass
            raise ValueError(f"Invalid time format: {time_str}")

        # Format event time for error messages
        event_start_str = event.start_time.strftime('%b %d, %Y, %I:%M %p')
        event_end_str = event.end_time.strftime('%I:%M %p')
        event_time_display = f"{event_start_str} – {event_end_str}"

        # Validate each window
        errors = {}
        for i, window in enumerate(allowed_windows):
            try:
                date_str = window.get('date')
                start_str = window.get('start')
                end_str = window.get('end')

                if not all([date_str, start_str, end_str]):
                    continue

                # Parse window date and times
                window_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                window_start_time = parse_time_str(start_str)
                window_end_time = parse_time_str(end_str)

                # Combine into timezone-aware datetimes
                window_start_dt = event_tz.localize(datetime.combine(window_date, window_start_time))
                window_end_dt = event_tz.localize(datetime.combine(window_date, window_end_time))

                # Check window is within event date bounds
                if window_date < event.start_time.date() or window_date > event.end_time.date():
                    errors[f'window_{i}'] = f"Window {i + 1} must be within event time: {event_time_display}."
                    continue

                # Check window times are within event bounds
                if window_start_dt < event.start_time or window_end_dt > event.end_time:
                    errors[f'window_{i}'] = f"Window {i + 1} must be within event time: {event_time_display}."
                    continue

                # Check end > start
                if window_end_dt <= window_start_dt:
                    errors[f'window_{i}'] = f"Window {i + 1} end time must be after start time."

            except (ValueError, TypeError) as e:
                errors[f'window_{i}'] = f"Window {i + 1}: Invalid date or time format."

        if errors:
            raise serializers.ValidationError({'allowed_windows': list(errors.values())})

        return data

    def validate_reminder_minutes_before(self, value):
        if value < 0:
            raise serializers.ValidationError("Reminder minutes must be non-negative.")
        return value

    def validate_max_meetings_per_attendee_per_day(self, value):
        if value is not None and value <= 0:
            raise serializers.ValidationError("Max meetings per day must be positive or null.")
        return value


class NetworkingTableSerializer(serializers.ModelSerializer):
    table_number = serializers.IntegerField(read_only=True)

    class Meta:
        model = NetworkingTable
        fields = [
            'id', 'event', 'table_number', 'name', 'location_note', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'event', 'table_number', 'created_at', 'updated_at']

    def validate_name(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Table name cannot be empty.")
        if len(value) > 255:
            raise serializers.ValidationError("Table name must be 255 characters or less.")
        return value

    def create(self, validated_data):
        event = self.context.get("event")
        if event is None:
            raise serializers.ValidationError({"event": "Event context is required."})

        # Remove read-only fields from validated_data to avoid conflicts
        validated_data.pop("table_number", None)
        validated_data.pop("event", None)

        with transaction.atomic():
            Event.objects.select_for_update().get(pk=event.pk)
            max_number = (
                NetworkingTable.objects
                .filter(event=event)
                .aggregate(max_number=Max("table_number"))
                .get("max_number")
            ) or 0

            return NetworkingTable.objects.create(
                event=event,
                table_number=max_number + 1,
                **validated_data,
            )


class NetworkingMeetingSerializer(serializers.ModelSerializer):
    requester_user_name = serializers.CharField(source='requester.user.username', read_only=True)
    recipient_user_name = serializers.CharField(source='recipient.user.username', read_only=True)
    suggested_by_user_name = serializers.CharField(source='suggested_by.user.username', read_only=True, allow_null=True)
    table_name = serializers.CharField(source='table.name', read_only=True, allow_null=True)
    table = NetworkingTableSerializer(read_only=True)
    requester_detail = serializers.SerializerMethodField()
    recipient_detail = serializers.SerializerMethodField()

    class Meta:
        model = NetworkingMeeting
        fields = [
            'id', 'event', 'requester', 'requester_user_name', 'requester_detail', 'recipient', 'recipient_user_name', 'recipient_detail',
            'duration_minutes', 'start_time', 'end_time', 'table', 'table_name', 'status',
            'message', 'suggested_start_time', 'suggested_end_time', 'suggested_by', 'suggested_by_user_name',
            'accepted_at', 'declined_at', 'cancelled_at', 'created_at', 'updated_at', 'requester_seen_at', 'recipient_seen_at'
        ]
        read_only_fields = [
            'id', 'event', 'requester', 'recipient', 'status', 'suggested_start_time',
            'suggested_end_time', 'suggested_by', 'accepted_at', 'declined_at', 'cancelled_at',
            'created_at', 'updated_at', 'requester_seen_at', 'recipient_seen_at', 'requester_user_name', 'recipient_user_name',
            'suggested_by_user_name', 'table_name', 'requester_detail', 'recipient_detail'
        ]

    def _get_avatar_url(self, profile):
        """Safely get avatar URL from profile."""
        if not profile:
            return None

        # Try user_image field (ImageField)
        user_image = getattr(profile, 'user_image', None)
        if user_image and hasattr(user_image, 'url'):
            # Build absolute URL if request available in context
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(user_image.url)
            return user_image.url

        # Fallback to wordpress_avatar_url if no image
        wordpress_avatar = getattr(profile, 'wordpress_avatar_url', None)
        if wordpress_avatar:
            return wordpress_avatar

        return None

    def get_requester_detail(self, obj):
        if not obj.requester or not obj.requester.user:
            return None
        user = obj.requester.user
        profile = getattr(user, 'profile', None)
        return {
            'id': obj.requester.id,
            'user_id': user.id,
            'display_name': user.get_full_name() or user.username,
            'company': profile.company if profile else None,
            'job_title': profile.job_title if profile else None,
            'avatar_url': self._get_avatar_url(profile),
        }

    def get_recipient_detail(self, obj):
        if not obj.recipient or not obj.recipient.user:
            return None
        user = obj.recipient.user
        profile = getattr(user, 'profile', None)
        return {
            'id': obj.recipient.id,
            'user_id': user.id,
            'display_name': user.get_full_name() or user.username,
            'company': profile.company if profile else None,
            'job_title': profile.job_title if profile else None,
            'avatar_url': self._get_avatar_url(profile),
        }

    def validate_duration_minutes(self, value):
        if value <= 0:
            raise serializers.ValidationError("Duration must be positive.")
        return value


class NetworkingMeetingCreateSerializer(serializers.Serializer):
    recipient_registration_id = serializers.IntegerField()
    duration_minutes = serializers.IntegerField()
    start_time = serializers.DateTimeField()
    message = serializers.CharField(required=False, allow_blank=True)

    def validate_duration_minutes(self, value):
        if value <= 0:
            raise serializers.ValidationError("Duration must be positive.")
        return value


class NetworkingMeetingSuggestSerializer(serializers.Serializer):
    suggested_start_time = serializers.DateTimeField()
    suggested_end_time = serializers.DateTimeField()

    def validate(self, data):
        if data['suggested_end_time'] <= data['suggested_start_time']:
            raise serializers.ValidationError("End time must be after start time.")
        return data


class EventParticipantDirectorySerializer(serializers.ModelSerializer):
    """Serializer for public participant directory (in-person events only)."""

    display_name = serializers.SerializerMethodField()
    avatar_url = serializers.SerializerMethodField()
    company = serializers.SerializerMethodField()
    job_title = serializers.SerializerMethodField()
    badges = serializers.SerializerMethodField()

    class Meta:
        model = EventRegistration
        fields = [
            'id',
            'display_name',
            'avatar_url',
            'company',
            'job_title',
            'badges',
        ]

    def get_display_name(self, obj):
        """Get full name or username."""
        return obj.user.get_full_name() or obj.user.username

    def get_avatar_url(self, obj):
        """Get avatar URL from user profile."""
        profile = getattr(obj.user, 'profile', None)
        if not profile:
            return None

        # Try user_image field (ImageField)
        user_image = getattr(profile, 'user_image', None)
        if user_image and hasattr(user_image, 'url'):
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(user_image.url)
            return user_image.url

        # Fallback to wordpress_avatar_url
        wordpress_avatar = getattr(profile, 'wordpress_avatar_url', None)
        if wordpress_avatar:
            return wordpress_avatar

        return None

    def get_company(self, obj):
        """Get company from user profile."""
        profile = getattr(obj.user, 'profile', None)
        return profile.company if profile else None

    def get_job_title(self, obj):
        """Get job title from user profile."""
        profile = getattr(obj.user, 'profile', None)
        return profile.job_title if profile else None

    def get_badges(self, obj):
        """Get badge labels with colors."""
        return [
            {
                'id': label.id,
                'name': label.name,
                'color': label.color,
            }
            for label in obj.badge_labels.all()
        ]


class SessionSpeakerSerializer(serializers.Serializer):
    """Minimal speaker info from SessionParticipant."""
    id = serializers.IntegerField(source='user.id')
    name = serializers.CharField(source='user.get_full_name', allow_null=True)
    username = serializers.CharField(source='user.username')
    avatar_url = serializers.SerializerMethodField()
    role = serializers.CharField(source='get_participant_type_display', allow_null=True)

    def get_avatar_url(self, obj):
        """Get avatar URL from user profile."""
        profile = getattr(obj.user, 'profile', None)
        if profile and hasattr(profile, 'user_image') and profile.user_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(profile.user_image.url)
            return profile.user_image.url
        return None


class ScheduleSessionSerializer(serializers.ModelSerializer):
    """Full session details for schedule view including speakers and bookmark status."""
    speakers = serializers.SerializerMethodField()
    is_bookmarked = serializers.SerializerMethodField()
    duration_minutes = serializers.IntegerField(source='computed_duration_minutes', read_only=True)

    class Meta:
        model = EventSession
        fields = [
            'id', 'title', 'description', 'start_time', 'end_time',
            'room', 'location_note', 'session_type', 'display_order',
            'speakers', 'is_bookmarked', 'session_image', 'duration_minutes'
        ]
        read_only_fields = ['id', 'session_type', 'display_order']

    def get_speakers(self, obj):
        """Get speaker list from SessionParticipant."""
        participants = obj.participants.all()
        serializer = SessionSpeakerSerializer(participants, many=True, context=self.context)
        return serializer.data

    def get_is_bookmarked(self, obj):
        """Check if current user has bookmarked this session."""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return obj.bookmarks.filter(user=request.user).exists()


class EventSessionBookmarkSerializer(serializers.ModelSerializer):
    """Bookmark toggle for sessions."""

    class Meta:
        model = EventSessionBookmark
        fields = ['id', 'event', 'session', 'created_at']
        read_only_fields = ['id', 'event', 'created_at']


class PostAcceptanceFormTemplateSerializer(serializers.ModelSerializer):
    """Serializer for post-acceptance form templates."""
    form_type_display = serializers.CharField(source='get_form_type_display', read_only=True)

    class Meta:
        model = PostAcceptanceFormTemplate
        fields = [
            'id', 'event', 'form_type', 'form_type_display',
            'title', 'description', 'question_schema',
            'is_enabled', 'deadline_days', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class PostAcceptanceFormAssignmentSerializer(serializers.ModelSerializer):
    """Serializer for form assignments."""
    form_type_display = serializers.CharField(source='get_form_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    attendee_name = serializers.SerializerMethodField()
    attendee_email = serializers.SerializerMethodField()
    user_id = serializers.IntegerField(source='event_registration.user.id', read_only=True)
    form_template = PostAcceptanceFormTemplateSerializer(read_only=True)
    event_title = serializers.CharField(source='event.title', read_only=True)
    event_format = serializers.CharField(source='event.format', read_only=True)
    draft_data = serializers.SerializerMethodField()

    class Meta:
        model = PostAcceptanceFormAssignment
        fields = [
            'id', 'event', 'event_title', 'event_format', 'form_template', 'event_registration',
            'form_type', 'form_type_display', 'status', 'status_display',
            'deadline', 'started_at', 'completed_at',
            'reminders_sent', 'last_reminder_sent_at',
            'attendee_name', 'attendee_email', 'user_id',
            'active_modules', 'module_completion_status',
            'draft_data',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'event', 'form_template', 'form_type',
            'reminders_sent', 'last_reminder_sent_at',
            'active_modules', 'module_completion_status',
            'created_at', 'updated_at'
        ]

    def get_attendee_name(self, obj):
        """Get attendee full name."""
        user = obj.event_registration.user
        return user.get_full_name() or user.username

    def get_attendee_email(self, obj):
        """Get attendee email."""
        return obj.event_registration.user.email

    def get_draft_data(self, obj):
        """Return draft data if it exists."""
        try:
            draft = PostAcceptanceFormDraft.objects.get(assignment=obj)
            return draft.draft_data or {}
        except PostAcceptanceFormDraft.DoesNotExist:
            return {}


class PostAcceptanceFormAnswerSerializer(serializers.ModelSerializer):
    """Serializer for form answers with optional restricted field masking."""
    # Restricted fields that require explicit permission to view
    RESTRICTED_FIELDS = {
        'emergency_contact_name',
        'emergency_contact_phone',
        'emergency_contact_relationship',
        'emergency_contact_relationship_other',
        'accessibility_needs_detail',
        'mobility_seating_requirements',
        'medical_info_emergency',
        'food_allergies',
        'food_allergies_other',
        'dietary_restrictions',
        'dietary_restrictions_other',
        'food_notes'
    }

    class Meta:
        model = PostAcceptanceFormAnswer
        fields = ['id', 'question_key', 'answer_text', 'answer_data', 'created_at']
        read_only_fields = ['id', 'created_at']

    def to_representation(self, instance):
        """Mask restricted field values if user lacks permission."""
        data = super().to_representation(instance)

        # Check if user has permission to view restricted data
        context = self.context or {}
        has_restricted_access = context.get('has_restricted_access', False)

        # Mask restricted fields if user doesn't have permission
        if not has_restricted_access and instance.question_key in self.RESTRICTED_FIELDS:
            data['answer_text'] = '[RESTRICTED]'
            data['answer_data'] = {}

        return data


class PostAcceptanceFormSubmissionSerializer(serializers.ModelSerializer):
    """Serializer for form submissions with answers."""
    answers = serializers.SerializerMethodField()

    class Meta:
        model = PostAcceptanceFormSubmission
        fields = ['id', 'assignment', 'answers', 'submitted_at']
        read_only_fields = ['id', 'submitted_at']

    def get_answers(self, obj):
        """Serialize answers with context passed for restricted field masking."""
        return PostAcceptanceFormAnswerSerializer(
            obj.answers.all(),
            many=True,
            context=self.context
        ).data


class AdminAuditLogSerializer(serializers.ModelSerializer):
    """Serializer for admin audit logs."""
    performed_by_name = serializers.CharField(source='performed_by.get_full_name', read_only=True)
    performed_by_email = serializers.CharField(source='performed_by.email', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    event_title = serializers.CharField(source='event.title', read_only=True)

    class Meta:
        model = AdminAuditLog
        fields = ['id', 'event', 'event_title', 'performed_by', 'performed_by_name', 'performed_by_email',
                  'assignment', 'action', 'action_display', 'details', 'created_at']
        read_only_fields = ['id', 'created_at']


class PostAcceptanceFormAssignmentAdminDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for admin viewing assignment with submission."""
    form_type_display = serializers.CharField(source='get_form_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    attendee_name = serializers.SerializerMethodField()
    attendee_email = serializers.SerializerMethodField()
    attendee_role = serializers.SerializerMethodField()
    submission = serializers.SerializerMethodField()
    form_template = PostAcceptanceFormTemplateSerializer(read_only=True)
    event_title = serializers.CharField(source='event.title', read_only=True)
    manual_completed_by_name = serializers.CharField(source='manual_completed_by.get_full_name', read_only=True, allow_null=True)

    # Computed flags from registration
    visa_support_requested = serializers.BooleanField(source='event_registration.visa_support_requested', read_only=True)
    photo_video_consent = serializers.CharField(source='event_registration.photo_video_consent', read_only=True)
    directory_visibility = serializers.BooleanField(source='event_registration.directory_visibility', read_only=True)

    # Computed from submission data
    attendance_mode = serializers.SerializerMethodField()
    accessibility_need_declared = serializers.SerializerMethodField()
    photo_consent_denied = serializers.SerializerMethodField()

    class Meta:
        model = PostAcceptanceFormAssignment
        fields = [
            'id', 'event', 'event_title', 'form_template', 'form_type', 'form_type_display',
            'status', 'status_display', 'deadline', 'started_at', 'completed_at',
            'reminders_sent', 'last_reminder_sent_at',
            'manual_completed_by', 'manual_completed_by_name', 'manual_completed_at',
            'attendee_name', 'attendee_email', 'attendee_role',
            'attendance_mode', 'accessibility_need_declared', 'photo_consent_denied',
            'submission', 'visa_support_requested', 'photo_video_consent', 'directory_visibility',
            'created_at', 'updated_at'
        ]
        read_only_fields = fields

    def get_attendee_name(self, obj):
        """Get attendee full name."""
        user = obj.event_registration.user
        return user.get_full_name() or user.username

    def get_attendee_email(self, obj):
        """Get attendee email."""
        return obj.event_registration.user.email

    def get_attendee_role(self, obj):
        """Get attendee role from EventParticipant."""
        from events.models import EventParticipant
        user = obj.event_registration.user
        participant = EventParticipant.objects.filter(
            event=obj.event,
            user=user
        ).first()
        return participant.get_participant_type_display() if participant else 'Attendee'

    def get_attendance_mode(self, obj):
        """Extract attendance_mode from submission if completed."""
        try:
            submission = obj.submission
        except:
            return None
        try:
            answer = submission.answers.get(question_key='attendance_mode')
            return answer.answer_text
        except:
            return None

    def get_accessibility_need_declared(self, obj):
        """Check if accessibility support needs were declared (yes value)."""
        try:
            submission = obj.submission
        except:
            return False
        try:
            answer = submission.answers.get(question_key='accessibility_support_needs')
            return answer.answer_text == 'yes'
        except:
            return False

    def get_photo_consent_denied(self, obj):
        """Check if photo/video consent is denied."""
        try:
            submission = obj.submission
        except:
            return False
        try:
            answer = submission.answers.get(question_key='photo_video_consent')
            return answer.answer_text == 'no'
        except:
            return False

    def get_submission(self, obj):
        """Serialize submission with context for restricted field masking."""
        try:
            submission = obj.submission
        except:
            return None
        if not submission:
            return None
        return PostAcceptanceFormSubmissionSerializer(
            submission,
            context=self.context
        ).data


class EventFormCustomizationSerializer(serializers.ModelSerializer):
    """Serializer for per-event form customization."""
    section_config = serializers.SerializerMethodField()
    custom_questions_count = serializers.SerializerMethodField()

    class Meta:
        model = EventFormCustomization
        fields = [
            'id', 'event', 'form_type',
            'enable_accessibility_section',
            'enable_emergency_contact_section',
            'enable_food_requirements_section',
            'enable_privacy_permissions_section',
            'enable_travel_information_section',
            'section_config',
            'field_overrides',
            'custom_questions',
            'custom_questions_count',
            'form_deadline',
            'module_deadlines',
            'file_specs',
            'reminder_schedule',
            'created_at',
            'updated_at',
            'updated_by'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_section_config(self, obj):
        """Return all section settings."""
        return obj.get_section_config()

    def get_custom_questions_count(self, obj):
        """Return count of custom questions."""
        return len(obj.custom_questions or [])

    def create(self, validated_data):
        """Create form customization."""
        from events.models import EventFormCustomization
        return EventFormCustomization.objects.create(**validated_data)

    def update(self, instance, validated_data):
        """Update form customization."""
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.updated_by = self.context['request'].user
        instance.save()
        return instance


class CustomQuestionSerializer(serializers.Serializer):
    """Serializer for custom question within form customization."""
    id = serializers.CharField(required=False)
    type = serializers.ChoiceField(choices=['text', 'textarea', 'select', 'multi_select', 'checkbox', 'radio'])
    label = serializers.CharField(max_length=500)
    help_text = serializers.CharField(required=False, allow_blank=True)
    required = serializers.BooleanField(default=False)
    options = serializers.ListField(child=serializers.CharField(), required=False, allow_empty=True)
    show_if = serializers.JSONField(required=False, allow_null=True)
    placeholder = serializers.CharField(required=False, allow_blank=True)
    rows = serializers.IntegerField(required=False, min_value=1, max_value=20)

    def validate(self, data):
        """Validate custom question."""
        # Multi-select and select fields require options
        if data['type'] in ['select', 'multi_select', 'radio'] and not data.get('options'):
            raise serializers.ValidationError("Options required for select/multi_select/radio fields")
        return data


class FormFieldOverrideSerializer(serializers.Serializer):
    """Serializer for field-level overrides."""
    required = serializers.BooleanField(required=False)
    help_text = serializers.CharField(required=False, allow_blank=True)
    label = serializers.CharField(required=False, max_length=500)
    options = serializers.ListField(child=serializers.CharField(), required=False)
    hidden = serializers.BooleanField(required=False, default=False)


# Phase 5: Form Schema Primitives and Shared Question Library

class SharedQuestionCategorySerializer(serializers.ModelSerializer):
    """Serializer for shared question categories."""
    questions = serializers.SerializerMethodField()

    class Meta:
        model = SharedQuestionCategory
        fields = ['id', 'name', 'description', 'sort_order', 'questions', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_questions(self, obj):
        """Get questions in this category."""
        questions = obj.questions.all()
        return SharedQuestionSerializer(questions, many=True).data


class SharedQuestionSerializer(serializers.ModelSerializer):
    """Serializer for shared reusable form questions."""
    category_name = serializers.CharField(source='category.name', read_only=True)

    class Meta:
        model = SharedQuestion
        fields = [
            'id', 'category', 'category_name', 'label', 'field_type',
            'help_text', 'placeholder', 'options', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class FormFieldSerializer(serializers.ModelSerializer):
    """Serializer for form fields in application tracks."""
    field_type_display = serializers.CharField(source='get_field_type_display', read_only=True)
    shared_question_label = serializers.CharField(source='shared_question.label', read_only=True, allow_null=True)

    class Meta:
        model = FormField
        fields = [
            'id', 'track', 'shared_question', 'shared_question_label',
            'field_type', 'field_type_display', 'label', 'help_text', 'placeholder',
            'required', 'options', 'min_length', 'max_length', 'min_value', 'max_value',
            'profile_binding', 'profile_binding_mode', 'conditional_visibility',
            'visibility_per_mode', 'visible_in_review_list', 'visible_in_review_detail',
            'sort_order', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'track', 'created_at', 'updated_at']
