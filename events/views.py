"""
ViewSets for the events app.

Users can list, create, retrieve, update, and delete events belonging to
community they are members of. Creation is restricted to users
belonging to the target community.
"""

# ============================================================
# ================ Standard Library / Third-Party ============
# ============================================================
from collections import defaultdict
from datetime import timedelta
from contextlib import contextmanager
import logging
import csv
from functools import wraps
from django.http import Http404, HttpResponse
import os                          # NOTE: intentionally kept even if duplicated later
import base64                      # NOTE: currently unused; kept as requested
import requests
import time
import random
import threading
import unicodedata
import secrets
from ecp_backend.celery import app as celery_app

# ============================================================
# ======================= Django Imports =====================
# ============================================================
from django.db import transaction
from django.db.models import Q, F, Max, Count, Prefetch
from django.db.models.functions import Lower
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from django.template import Template as DjangoTemplate, Context
from django.core.cache import cache

# ============================================================
# ================= DRF (Django REST Framework) ==============
# ============================================================
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework import permissions, viewsets, status, views, generics   # NOTE: permissions, views may be unused; kept
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.pagination import LimitOffsetPagination
from django_filters.rest_framework import DjangoFilterBackend

from rest_framework.permissions import (
    AllowAny,
    BasePermission,
    SAFE_METHODS,
    IsAuthenticatedOrReadOnly,      # NOTE: currently unused; kept as requested
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.renderers import BaseRenderer, JSONRenderer

# ============================================================
# ===================== Local App Imports ====================
# ============================================================

from .models import Event, EventRegistration, EventBadgeLabel, LoungeTable, LoungeParticipant, EventSession, SessionAttendance, WaitingRoomAuditLog, WaitingRoomAnnouncement, GuestAttendee, EventApplication, VirtualSpeaker, EventParticipant, GuestProfileAuditLog, SaleorChannel, SaleorWarehouse, SaleorShippingZone, SaleorProductType, SaleorStaffUser, SaleorPermissionGroup, EventPreApprovalCode, EventPreApprovalAllowlist, EventSeries, SeriesRegistration, EventSaleorDiscount, EventEmailTemplate, EventSessionBookmark, PostAcceptanceFormTemplate, PostAcceptanceFormAssignment, PostAcceptanceFormSubmission, PostAcceptanceFormAnswer, EventApplicationTrack, EventApplicationTrackApplication, SharedQuestionCategory, SharedQuestion, FormField, TrackPricingTier, EventRole, EventAttendeeOrigin
from .permissions import IsSuperuserOnly, IsEventAdminOrSuperuser, HasRestrictedDataPermission
from .cache_utils import event_list_cache_key, get_cached_event_list, set_cached_event_list
from friends.models import Notification
from groups.models import Group, GroupMembership
from messaging.models import Conversation, Message
from .serializers import (
    EventSerializer,
    PublicEventSerializer,
    EventLiteSerializer,
    EventListSerializer,
    MyEventCardSerializer,
    EventRegistrationSerializer,
    EventRegistrationLiteSerializer,
    EventSessionSerializer,
    SessionAttendanceSerializer,
    EventParticipantListItemSerializer,
    SessionBreakSerializer,
    build_event_participant_lookup,
    build_profile_url,
    is_public_role_visible,
    role_label,
    role_priority,
    resolve_registration_roles,
    EventApplicationSerializer,
    EventApplicationSubmitSerializer,
    EventApplicationTrackSerializer,
    EventPreApprovalCodeSerializer,
    EventPreApprovalAllowlistSerializer,
    EventApplicationTrackApplicationDetailSerializer,
    VirtualSpeakerSerializer,
    VirtualSpeakerConvertSerializer,
    SaleorChannelSerializer,
    SaleorProductTypeSerializer,
    SaleorWarehouseSerializer,
    SaleorShippingZoneSerializer,
    SaleorStaffUserSerializer,
    SaleorPermissionGroupSerializer,
    EventSeriesListSerializer,
    EventSeriesDetailSerializer,
    EventSeriesCreateUpdateSerializer,
    SeriesRegistrationSerializer,
    PublicEventSeriesSerializer,
    EventSaleorDiscountSerializer,
    EventEmailTemplateSerializer,
    EventBadgeLabelSerializer,
    ScheduleSessionSerializer,
    EventSessionBookmarkSerializer,
    PostAcceptanceFormTemplateSerializer,
    PostAcceptanceFormAssignmentSerializer,
    PostAcceptanceFormSubmissionSerializer,
    PostAcceptanceFormAnswerSerializer,
    SharedQuestionCategorySerializer,
    SharedQuestionSerializer,
    FormFieldSerializer,
    TrackPricingTierSerializer,
    EventRoleSerializer,
    EventAttendeeOriginSerializer,
)
from users.serializers import UserMiniSerializer
from .utils import (
    RTK_API_BASE,
    RTK_PRESET_HOST,
    RTK_PRESET_PARTICIPANT,
    _rtk_headers,
    create_rtk_meeting,
    add_rtk_participant,
    send_admission_status_changed,  # ✅ NEW: For real-time admission status updates
)
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from .saleor_sync import (
    sync_channels_from_saleor,
    sync_warehouses_from_saleor,
    sync_shipping_zones_from_saleor,
    sync_product_types_from_saleor,
    sync_staff_users_from_saleor,
    sync_permission_groups_from_saleor,
    create_channel_in_saleor,
    update_channel_in_saleor,
    delete_channel_in_saleor,
    create_warehouse_in_saleor,
    update_warehouse_in_saleor,
    delete_warehouse_in_saleor,
    create_shipping_zone_in_saleor,
    update_shipping_zone_in_saleor,
    delete_shipping_zone_in_saleor,
    create_product_type_in_saleor,
    update_product_type_in_saleor,
    delete_product_type_in_saleor,
    get_shipping_zone_options,
    get_product_type_options,
    fetch_event_saleor_product_details,
    update_event_saleor_product_details,
    create_event_saleor_discount,
    update_event_saleor_discount,
    delete_event_saleor_discount,
    sync_event_saleor_discounts,
    sync_event_saleor_discount,
)
from .email_template_api import (
    EVENT_EMAIL_TEMPLATE_KEYS,
    get_event_email_template_payload,
    render_event_email_payload,
    save_event_email_template,
    send_event_email_test,
    user_can_manage_event_email_templates,
)

# ============================================================
# ================== Env / Settings Bootstrap ================
# ============================================================
import os  # NOTE: duplicate import retained intentionally

from pathlib import Path
from dotenv import load_dotenv
from django.conf import settings

# Resolve project root and load .env so AGORA_* variables work locally as well
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(os.path.join(BASE_DIR, ".env"))

User = get_user_model()

# AWS S3 configuration
AWS_S3_BUCKET = getattr(settings, "AWS_S3_BUCKET", os.getenv("AWS_BUCKET_NAME", ""))
AWS_S3_REGION = getattr(settings, "AWS_S3_REGION", os.getenv("AWS_REGION_NAME", "eu-central-1"))

logger = logging.getLogger("events")

MOOD_ALLOWED_EMOJIS = [
    "😀", "😄", "😁", "😎", "😊", "🙂", "🤩", "😍",
    "🤔", "😌", "😴", "😇", "🙌", "👏", "👍", "🔥",
    "🚀", "💯", "🎉", "❤️", "💙", "💚", "🤝", "🙏",
    "😅", "😬", "😐", "😕", "😮", "😢", "😭", "😡",
]


def _get_converted_guest_for_event(user, event):
    if not user or not getattr(user, "id", None) or not event:
        return None

    return (
        GuestAttendee.objects.filter(event=event, converted_user=user)
        .order_by("-joined_live_at", "-converted_at", "-created_at")
        .first()
    )
MOOD_ALLOWED_SET = set(MOOD_ALLOWED_EMOJIS)


class MoodRateThrottle(UserRateThrottle):
    scope = "mood"


class ReviewQueueCSVRenderer(BaseRenderer):
    media_type = "text/csv"
    format = "csv"
    charset = "utf-8"

    def render(self, data, accepted_media_type=None, renderer_context=None):
        if data is None:
            return b""
        if isinstance(data, (bytes, bytearray)):
            return data
        return str(data).encode(self.charset)


def _sanitize_mood(raw_value):
    """
    Validate and sanitize mood emoji.
    Returns: (mood_value, error_message)
      - If valid: (mood_str, None)
      - If invalid: (None, error_reason)

    Accepts any single emoji or emoji sequence from the emoji picker.
    Validates length, whitespace, and control characters.
    """
    mood = (raw_value or "").strip()

    if not mood:
        return None, "Mood value is empty or missing"

    if len(mood) > 32:
        return None, f"Mood value exceeds max length of 32 characters (got {len(mood)})"

    if any(ch.isspace() for ch in mood):
        return None, "Mood value contains whitespace characters"

    if any(unicodedata.category(ch).startswith("C") for ch in mood):
        return None, "Mood value contains control characters"

    # Accept any emoji
    return mood, None

# --- Cloudflare RealtimeKit recording config ---
RTK_API_BASE = os.getenv("RTK_API_BASE", "https://api.realtime.cloudflare.com/v2")
RTK_ORG_ID = os.getenv("RTK_ORG_ID", "")
RTK_API_KEY = os.getenv("RTK_API_KEY", "")

# RTK helpers remain here as they are only used in views
def _rtk_headers():
    """
    HTTP headers for Cloudflare RealtimeKit REST API.
    Uses Basic auth with base64("<ORG_ID>:<API_KEY>").
    """
    if not (RTK_ORG_ID and RTK_API_KEY):
        return {} # Fallback
    import base64
    token_bytes = f"{RTK_ORG_ID}:{RTK_API_KEY}".encode("utf-8")
    basic_token = base64.b64encode(token_bytes).decode("ascii")
    return {
        "Authorization": f"Basic {basic_token}",
        "Content-Type": "application/json",
    }


RTK_JOIN_TOKEN_CACHE_TTL_SECONDS = int(
    getattr(settings, "LIVE_RTK_JOIN_TOKEN_CACHE_TTL_SECONDS", 180) or 180
)


def _rtk_join_cache_key(event_id, actor_key, role, room_type="main_room"):
    """Small idempotency cache for RTK/Dyte join bursts.

    During browser refresh/reconnect, the frontend can call rtk/join multiple
    times before roomJoined is fired. This cache avoids repeatedly calling the
    external RTK Add Participant API for the same event/user/role.
    """
    safe_actor = str(actor_key).replace(":", "_")
    safe_role = str(role or "audience").replace(":", "_")
    safe_room = str(room_type or "main_room").replace(":", "_")
    return f"event:{event_id}:rtk_join_token:{safe_actor}:{safe_role}:{safe_room}:v1"


def _get_cached_rtk_join_payload(event_id, actor_key, role, room_type="main_room"):
    payload = cache.get(_rtk_join_cache_key(event_id, actor_key, role, room_type))
    if not isinstance(payload, dict):
        return None
    if not payload.get("authToken") or not payload.get("meetingId"):
        return None
    return dict(payload)


def _set_cached_rtk_join_payload(event_id, actor_key, role, payload, room_type="main_room"):
    if not isinstance(payload, dict):
        return
    if not payload.get("authToken") or not payload.get("meetingId"):
        return
    cache.set(
        _rtk_join_cache_key(event_id, actor_key, role, room_type),
        dict(payload),
        timeout=max(30, RTK_JOIN_TOKEN_CACHE_TTL_SECONDS),
    )


def _ensure_rtk_meeting_for_event(event: Event) -> str:
    """
    Ensure this Event has a RTK meeting.
    If not, create one via RTK API and persist rtk_meeting_id.
    """
    if event.rtk_meeting_id:
        return event.rtk_meeting_id

    payload = {
        "title": event.title or f"Event {event.id}",
        "record_on_start": bool(event.replay_available),
    }
    try:
        resp = requests.post(
            f"{RTK_API_BASE}/meetings",
            headers=_rtk_headers(),
            json=payload,
            timeout=10,
        )
    except requests.RequestException as e:
        logger.exception("❌ RTK meeting create exception: %s", e)
        raise RuntimeError(str(e))

    if resp.status_code not in (200, 201):
        logger.error("❌ RTK meeting create failed: %s", resp.text[:500])
        raise RuntimeError(f"RTK meeting create failed ({resp.status_code})")

    data = (resp.json() or {}).get("data") or {}
    meeting_id = data.get("id")
    if not meeting_id:
        raise RuntimeError("RTK response missing meeting id")

    event.rtk_meeting_id = meeting_id
    event.rtk_meeting_title = data.get("title", event.title)
    event.save(update_fields=["rtk_meeting_id", "rtk_meeting_title", "updated_at"])
    return meeting_id

def _cache_event_join_snapshot(event: Event) -> None:
    """
     Cache event fields needed for join to reduce DB queries.

    Caches only safe, read-only event fields. Does not cache sensitive data.
    TTL: 2-5 seconds (covers brief bursts of joins).
    """
    cache_key = f"event:{event.id}:join_snapshot"
    snapshot = {
        "event_id": event.id,
        "status": event.status,
        "is_live": event.is_live,
        "rtk_meeting_id": event.rtk_meeting_id,
        "waiting_room_enabled": event.waiting_room_enabled,
        "waiting_room_grace_period_minutes": event.waiting_room_grace_period_minutes,
        "lounge_enabled_waiting_room": event.lounge_enabled_waiting_room,
        "networking_tables_enabled_waiting_room": event.networking_tables_enabled_waiting_room,
        "start_time": event.start_time.isoformat() if event.start_time else None,
        "is_on_break": event.is_on_break,
    }
    try:
        cache.set(cache_key, snapshot, timeout=3)  # 3 second TTL for join bursts
    except Exception as e:
        logger.warning(f"[PHASE2] Failed to cache event snapshot: {e}")

def _start_rtk_recording_for_event(event: Event) -> None:
    """
    Ask Cloudflare RealtimeKit to start a recording for this event's meeting.

    We do NOT raise errors to the caller; we just log, because
    live-status should still succeed even if recording fails.
    """
    # Meeting id is the RTK meeting id stored on the Event
    meeting_id = event.rtk_meeting_id
    if not meeting_id:
        try:
            meeting_id = _ensure_rtk_meeting_for_event(event)
        except Exception as exc:
            logger.exception(
                "❌ Cannot start recording; failed to ensure meeting for event=%s: %s",
                event.id,
                exc,
            )
            return

    try:
        headers = _rtk_headers()
    except RuntimeError as exc:
        logger.error("❌ RealtimeKit credentials missing: %s", exc)
        return

    payload = {"meeting_id": meeting_id}

    try:
        resp = requests.post(
            f"{RTK_API_BASE}/recordings",
            headers=headers,
            json=payload,
            timeout=15,
        )
    except requests.RequestException as exc:
        logger.exception(
            "❌ RealtimeKit start recording exception for event=%s: %s",
            event.id,
            exc,
        )
        return

    if resp.status_code not in (200, 201):
        logger.error(
            "❌ RealtimeKit start recording failed for event=%s meeting=%s: %s",
            event.id,
            meeting_id,
            resp.text[:500],
        )
        return

    data = (resp.json() or {}).get("data") or {}
    rec_id = data.get("id")
    logger.info(
        "🎥 RealtimeKit recording started for event=%s meeting=%s recording_id=%s",
        event.id,
        meeting_id,
        rec_id,
    )


def _stop_rtk_recording_for_event(event: Event) -> None:
    """
    Ask Cloudflare RealtimeKit to stop recording for this event's meeting.

    We do NOT raise errors to the caller; we just log, because
    end-meeting should still succeed even if stop-recording fails.
    """
    meeting_id = event.rtk_meeting_id
    if not meeting_id:
        logger.warning(
            "⚠️ Cannot stop recording; no meeting_id for event=%s",
            event.id,
        )
        return

    try:
        headers = _rtk_headers()
    except RuntimeError as exc:
        logger.error("❌ RealtimeKit credentials missing: %s", exc)
        return

    try:
        # GET /recordings to find active recording for this meeting
        resp = requests.get(
            f"{RTK_API_BASE}/recordings",
            headers=headers,
            params={"meeting_id": meeting_id},
            timeout=15,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.exception(
            "❌ RealtimeKit get recordings exception for event=%s: %s",
            event.id,
            exc,
        )
        return

    recordings = (resp.json() or {}).get("data") or []

    # Find the active recording (not STOPPED, not UPLOADED)
    active_rec = next(
        (r for r in recordings if r.get("status") not in ["STOPPED", "UPLOADED"]),
        None,
    )

    if not active_rec:
        logger.info(
            "ℹ️ No active recording found for event=%s meeting=%s",
            event.id,
            meeting_id,
        )
        return

    rec_id = active_rec.get("id")
    if not rec_id:
        logger.error(
            "❌ Recording found but missing id for event=%s meeting=%s",
            event.id,
            meeting_id,
        )
        return

    try:
        # PUT /recordings/{rec_id} to stop it
        stop_resp = requests.put(
            f"{RTK_API_BASE}/recordings/{rec_id}",
            headers=headers,
            json={"action": "stop"},
            timeout=15,
        )
    except requests.RequestException as exc:
        logger.exception(
            "❌ RealtimeKit stop recording exception for event=%s: %s",
            event.id,
            exc,
        )
        return

    if stop_resp.status_code not in (200, 201, 204):
        logger.error(
            "❌ RealtimeKit stop recording failed for event=%s meeting=%s recording=%s: %s",
            event.id,
            meeting_id,
            rec_id,
            stop_resp.text[:500],
        )
        return

    logger.info(
        "🛑 RealtimeKit recording stopped for event=%s meeting=%s recording_id=%s",
        event.id,
        meeting_id,
        rec_id,
    )


def _start_rtk_recording_for_event_manual(event: Event):
    """Start recording and return status tuple for API response."""
    meeting_id = event.rtk_meeting_id
    if not meeting_id:
        try:
            meeting_id = _ensure_rtk_meeting_for_event(event)
        except Exception as exc:
            logger.exception("❌ Cannot ensure meeting before start recording for event=%s: %s", event.id, exc)
            return False, "", "Failed to ensure meeting before starting recording."

    headers = _rtk_headers()
    if not headers:
        return False, "", "RealtimeKit credentials are not configured."
    logger.info(
        "🔴 RealtimeKit manual start requested for event=%s meeting=%s",
        event.id,
        meeting_id,
    )

    def _find_active_recording_id():
        try:
            list_resp = requests.get(
                f"{RTK_API_BASE}/recordings",
                headers=headers,
                params={"meeting_id": meeting_id},
                timeout=15,
            )
            if list_resp.status_code not in (200, 201):
                logger.warning(
                    "⚠️ RealtimeKit list recordings failed while reconciling start for event=%s: %s",
                    event.id,
                    list_resp.text[:500],
                )
                return ""
            recordings = (list_resp.json() or {}).get("data") or []
            active = next(
                (r for r in recordings if r.get("status") not in ["STOPPED", "UPLOADED"]),
                None,
            )
            return (active or {}).get("id") or ""
        except requests.RequestException as exc:
            logger.exception(
                "❌ RealtimeKit list recordings exception while reconciling start for event=%s: %s",
                event.id,
                exc,
            )
            return ""

    try:
        resp = requests.post(
            f"{RTK_API_BASE}/recordings",
            headers=headers,
            json={"meeting_id": meeting_id},
            timeout=15,
        )
    except requests.RequestException as exc:
        logger.exception("❌ RealtimeKit manual start exception for event=%s: %s", event.id, exc)
        return False, "", "Failed to start recording."

    if resp.status_code == 409:
        # RTK already has an active recorder for this meeting. Reconcile and adopt it.
        existing_id = _find_active_recording_id()
        if existing_id:
            logger.info(
                "ℹ️ RealtimeKit recording already running; adopting existing recording for event=%s recording_id=%s",
                event.id,
                existing_id,
            )
            return True, existing_id, "Recording already active."
        logger.error(
            "❌ RealtimeKit returned 409 but no active recording found for event=%s",
            event.id,
        )
        return False, "", "Recording is already running but could not be reconciled."

    if resp.status_code not in (200, 201):
        logger.error("❌ RealtimeKit manual start failed for event=%s: %s", event.id, resp.text[:500])
        return False, "", "RealtimeKit rejected recording start."

    data = (resp.json() or {}).get("data") or {}
    rec_id = data.get("id") or ""
    logger.info(
        "✅ RealtimeKit manual start accepted for event=%s meeting=%s recording=%s",
        event.id,
        meeting_id,
        rec_id,
    )
    return True, rec_id, "Recording started."


def _pause_rtk_recording_for_event(event: Event):
    """Pause active recording by explicit recording id."""
    if not event.rtk_recording_id:
        return False, "No active recording found for this event."

    headers = _rtk_headers()
    if not headers:
        return False, "RealtimeKit credentials are not configured."
    logger.info(
        "⏸️ RealtimeKit pause requested for event=%s recording=%s",
        event.id,
        event.rtk_recording_id,
    )

    try:
        resp = requests.put(
            f"{RTK_API_BASE}/recordings/{event.rtk_recording_id}",
            headers=headers,
            json={"action": "pause"},
            timeout=15,
        )
    except requests.RequestException as exc:
        logger.exception("❌ RealtimeKit pause exception for event=%s: %s", event.id, exc)
        return False, "Failed to pause recording."

    if resp.status_code not in (200, 201, 204):
        body_text = (resp.text or "")[:500]
        body_lower = (resp.text or "").lower()
        if resp.status_code == 400:
            try:
                status_resp = requests.get(
                    f"{RTK_API_BASE}/recordings/{event.rtk_recording_id}",
                    headers=headers,
                    timeout=15,
                )
                status_data = (status_resp.json() or {}).get("data") or {}
                current_status = str(status_data.get("status") or "").upper()
                if current_status in {"PAUSED", "PAUSING"}:
                    logger.info(
                        "ℹ️ RealtimeKit pause reconciled as paused for event=%s recording=%s (status=%s, body=%s)",
                        event.id,
                        event.rtk_recording_id,
                        current_status,
                        body_text,
                    )
                    return True, "Recording already paused."
                logger.warning(
                    "⚠️ RealtimeKit pause rejected for event=%s recording=%s (status=%s, body=%s)",
                    event.id,
                    event.rtk_recording_id,
                    current_status,
                    body_text,
                )
                return False, f"Recording cannot be paused right now (status={current_status or 'unknown'})."
            except requests.RequestException as exc:
                logger.exception(
                    "❌ RealtimeKit pause status reconciliation failed for event=%s recording=%s: %s",
                    event.id,
                    event.rtk_recording_id,
                    exc,
                )
                return False, "Pause failed and current recording status could not be verified."
        logger.error("❌ RealtimeKit pause failed for event=%s recording=%s: %s", event.id, event.rtk_recording_id, body_text)
        return False, "RealtimeKit rejected recording pause."

    logger.info(
        "✅ RealtimeKit pause accepted for event=%s recording=%s",
        event.id,
        event.rtk_recording_id,
    )
    return True, "Recording paused."


def _resume_rtk_recording_for_event(event: Event):
    """Resume paused recording by explicit recording id."""
    if not event.rtk_recording_id:
        return False, "No active recording found for this event."

    headers = _rtk_headers()
    if not headers:
        return False, "RealtimeKit credentials are not configured."
    logger.info(
        "▶️ RealtimeKit resume requested for event=%s recording=%s",
        event.id,
        event.rtk_recording_id,
    )

    try:
        resp = requests.put(
            f"{RTK_API_BASE}/recordings/{event.rtk_recording_id}",
            headers=headers,
            json={"action": "resume"},
            timeout=15,
        )
    except requests.RequestException as exc:
        logger.exception("❌ RealtimeKit resume exception for event=%s: %s", event.id, exc)
        return False, "Failed to resume recording."

    if resp.status_code not in (200, 201, 204):
        body_text = (resp.text or "")[:500]
        body_lower = (resp.text or "").lower()
        if resp.status_code == 400:
            try:
                status_resp = requests.get(
                    f"{RTK_API_BASE}/recordings/{event.rtk_recording_id}",
                    headers=headers,
                    timeout=15,
                )
                status_data = (status_resp.json() or {}).get("data") or {}
                current_status = str(status_data.get("status") or "").upper()
                if current_status in {"RECORDING", "STARTED", "RUNNING"}:
                    logger.info(
                        "ℹ️ RealtimeKit resume reconciled as running for event=%s recording=%s (status=%s, body=%s)",
                        event.id,
                        event.rtk_recording_id,
                        current_status,
                        body_text,
                    )
                    return True, "Recording already running."
                logger.warning(
                    "⚠️ RealtimeKit resume rejected for event=%s recording=%s (status=%s, body=%s)",
                    event.id,
                    event.rtk_recording_id,
                    current_status,
                    body_text,
                )
                return False, f"Recording cannot be resumed right now (status={current_status or 'unknown'})."
            except requests.RequestException as exc:
                logger.exception(
                    "❌ RealtimeKit resume status reconciliation failed for event=%s recording=%s: %s",
                    event.id,
                    event.rtk_recording_id,
                    exc,
                )
                return False, "Resume failed and current recording status could not be verified."
        logger.error("❌ RealtimeKit resume failed for event=%s recording=%s: %s", event.id, event.rtk_recording_id, body_text)
        return False, "RealtimeKit rejected recording resume."

    logger.info(
        "✅ RealtimeKit resume accepted for event=%s recording=%s",
        event.id,
        event.rtk_recording_id,
    )
    return True, "Recording resumed."


def _stop_rtk_recording_for_event_manual(event: Event):
    """Stop active recording by explicit recording id."""
    if not event.rtk_recording_id:
        return False, "No active recording found for this event."
    logger.info(
        "🛑 RealtimeKit manual stop requested for event=%s recording=%s",
        event.id,
        event.rtk_recording_id,
    )

    headers = _rtk_headers()
    if not headers:
        return False, "RealtimeKit credentials are not configured."

    try:
        resp = requests.put(
            f"{RTK_API_BASE}/recordings/{event.rtk_recording_id}",
            headers=headers,
            json={"action": "stop"},
            timeout=15,
        )
    except requests.RequestException as exc:
        logger.exception("❌ RealtimeKit manual stop exception for event=%s: %s", event.id, exc)
        return False, "Failed to stop recording."

    if resp.status_code not in (200, 201, 204):
        body_text = (resp.text or "")[:500]
        body_lower = (resp.text or "").lower()
        # RealtimeKit may return 400 during transitional/non-active states (e.g. INVOKED).
        # Treat these as idempotent success for UX consistency.
        if resp.status_code == 400 and (
            "not in progress" in body_lower
            or "current status is invoked" in body_lower
            or "current status is stopped" in body_lower
            or "current status is uploaded" in body_lower
        ):
            logger.info(
                "ℹ️ RealtimeKit stop treated as idempotent success for event=%s recording=%s: %s",
                event.id,
                event.rtk_recording_id,
                body_text,
            )
            return True, "Recording already stopping/stopped."
        logger.error(
            "❌ RealtimeKit manual stop failed for event=%s recording=%s: %s",
            event.id,
            event.rtk_recording_id,
            body_text,
        )
        return False, "RealtimeKit rejected recording stop."

    logger.info(
        "✅ RealtimeKit manual stop accepted for event=%s recording=%s",
        event.id,
        event.rtk_recording_id,
    )
    return True, "Recording stopped."


def _delete_rtk_recording_for_event(event: Event):
    """
    Permanently delete a recording from RealtimeKit and best-effort S3 cleanup.
    """
    if not event.rtk_recording_id:
        return False, "No recording to delete."

    recording_id = event.rtk_recording_id
    headers = _rtk_headers()
    if not headers:
        return False, "RealtimeKit credentials are not configured."

    logger.warning("🗑️ RealtimeKit delete requested for event=%s recording=%s", event.id, recording_id)
    try:
        resp = requests.delete(
            f"{RTK_API_BASE}/recordings/{recording_id}",
            headers=headers,
            timeout=8,
        )
    except requests.RequestException as exc:
        logger.exception("❌ RealtimeKit delete exception for event=%s recording=%s: %s", event.id, recording_id, exc)
        return False, "Failed to delete recording from RealtimeKit."

    if resp.status_code not in (200, 202, 204, 404):
        logger.error(
            "❌ RealtimeKit delete failed for event=%s recording=%s: %s",
            event.id,
            recording_id,
            (resp.text or "")[:500],
        )
        return False, "RealtimeKit rejected recording deletion."

    logger.warning("✅ RealtimeKit delete accepted for event=%s recording=%s", event.id, recording_id)

    # Best-effort cleanup if uploaded artifact already exists in S3.
    # Run asynchronously so API response is not delayed.
    if event.recording_url and AWS_S3_BUCKET:
        event_id = event.id
        s3_key = event.recording_url

        def _delete_s3_recording_bg():
            try:
                import boto3
                from botocore.config import Config
                s3_client = boto3.client(
                    "s3",
                    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                    region_name=AWS_S3_REGION,
                    config=Config(
                        signature_version="s3v4",
                        connect_timeout=2,
                        read_timeout=3,
                        retries={"max_attempts": 1},
                    ),
                )
                s3_client.delete_object(Bucket=AWS_S3_BUCKET, Key=s3_key)
                logger.warning("✅ S3 recording deleted for event=%s key=%s", event_id, s3_key)
            except Exception as exc:
                logger.warning("⚠️ Failed S3 cleanup for cancelled recording event=%s key=%s err=%s", event_id, s3_key, exc)

        threading.Thread(target=_delete_s3_recording_bg, daemon=True).start()

    return True, "Recording permanently deleted."


def _broadcast_recording_status(event: Event, action_name: str):
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"event_{event.id}",
        {
            "type": "recording_status_changed",
            "event_id": event.id,
            "is_recording": event.is_recording,
            "recording_id": event.rtk_recording_id or "",
            "is_paused": bool(event.recording_paused_at),
            "action": action_name,
            "timestamp": timezone.now().isoformat(),
        }
    )

# ============================================================
# ================= Pagination / Permissions =================
# ============================================================
class EventLimitOffsetPagination(LimitOffsetPagination):
    """
    Limit/Offset pagination tuned for the events grid on the UI.
    """
    default_limit = 9  # 9 per page
    limit_query_param = "limit"
    offset_query_param = "offset"
    max_limit = 1000


class IsCreatorOrReadOnly(BasePermission):
    """
    - SAFE_METHODS (GET/HEAD/OPTIONS) are open.
    - Mutations allowed for:
      1) the actual event creator (created_by), or
      2) platform superusers.
    - Non-superuser lower roles retain creator-bound restrictions.
    """
    def has_permission(self, request, view):
        # Anyone can read; must be authenticated to write
        if request.method in SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        # Read is open; writes allowed only to creator
        if request.method in SAFE_METHODS:
            return True
        return bool(
            request.user
            and (
                obj.created_by_id == request.user.id
                or getattr(request.user, "is_superuser", False)
            )
        )


def _is_event_owner(user, event) -> bool:
    """
    Check if user can be treated as event owner for owner-level management paths.
    Platform superusers are considered owners for all events.
    """
    if not (user and user.is_authenticated and event):
        return False
    return bool(event.created_by_id == user.id or getattr(user, "is_superuser", False))


def _is_event_manager(user, event) -> bool:
    """
    Administrative check: can this user manage the event?
    Includes: creator, platform staff, superusers, and community owners.
    """
    if not (user and user.is_authenticated and event):
        return False

    if (
        user.is_staff
        or getattr(user, "is_superuser", False)
        or event.created_by_id == user.id
        or getattr(event.community, "owner_id", None) == user.id
    ):
        return True

    return False


def _is_event_host(user, event) -> bool:
    """
    Strict role check: is this user a Host for the live room?
    Includes:
      1) platform superusers,
      2) actual creator,
      3) explicitly assigned EventParticipant with role="host".
    """
    if not (user and user.is_authenticated and event):
        return False

    # Platform superusers are always hosts across events.
    if getattr(user, "is_superuser", False):
        return True

    # 1. Event Creator is always a host
    if event.created_by_id == user.id:
        return True

    # 2. Check for explicit Host role assignment in EventParticipant list.
    host_match = Q(participant_type="staff", user_id=user.id)
    user_email = (getattr(user, "email", "") or "").strip()
    if user_email:
        host_match = host_match | Q(participant_type="guest", guest_email__iexact=user_email)

    return event.participants.filter(role="host").filter(host_match).exists()


def _absolute_media_url(request, value) -> str:
    if not value:
        return ""
    try:
        url = getattr(value, "url", "") or str(value)
    except Exception:
        url = str(value) if value else ""
    if not url:
        return ""
    if request and url.startswith("/"):
        try:
            return request.build_absolute_uri(url)
        except Exception:
            return url
    return url


def _serialize_event_summary(event, request=None) -> dict:
    return {
        "id": event.id,
        "slug": event.slug,
        "title": event.title,
        "status": event.status,
        "is_live": event.is_live,
        "created_by_id": event.created_by_id,
        "start_time": event.start_time,
        "end_time": event.end_time,
        "timezone": event.timezone,
        "live_started_at": event.live_started_at,
        "live_ended_at": event.live_ended_at,
        "waiting_room_enabled": event.waiting_room_enabled,
        "pre_event_qna_enabled": getattr(event, "pre_event_qna_enabled", False),
        "qna_moderation_enabled": getattr(event, "qna_moderation_enabled", False),
        "qna_anonymous_mode": getattr(event, "qna_anonymous_mode", False),
        "qna_ai_public_suggestions_enabled": getattr(event, "qna_ai_public_suggestions_enabled", False),
        "lounge_enabled_waiting_room": getattr(event, "lounge_enabled_waiting_room", False),
        "lounge_enabled_speed_networking": getattr(event, "lounge_enabled_speed_networking", False),
        "replay_available": getattr(event, "replay_available", False),
        "cover_image": _absolute_media_url(request, getattr(event, "cover_image", None)),
        "preview_image": _absolute_media_url(request, getattr(event, "preview_image", None)),
        "waiting_room_image": _absolute_media_url(request, getattr(event, "waiting_room_image", None)),
    }


def _current_user_event_participant_role(event, user) -> str:
    """
    Return current user's explicit live role for this event:
    Host / Moderator / Speaker / ""
    Does not return full event_participants list.
    """
    if not (user and getattr(user, "is_authenticated", False)):
        return ""

    role_filter = Q()

    if getattr(user, "is_guest", False):
        guest = getattr(user, "guest", None)
        guest_email = (getattr(guest, "email", "") or getattr(user, "email", "") or "").strip()
        if guest_email:
            role_filter |= Q(
                participant_type=EventParticipant.PARTICIPANT_TYPE_GUEST,
                guest_email__iexact=guest_email,
            )
    else:
        if getattr(user, "id", None):
            role_filter |= Q(
                participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
                user_id=user.id,
            )

        user_email = (getattr(user, "email", "") or "").strip()
        if user_email:
            role_filter |= Q(
                participant_type=EventParticipant.PARTICIPANT_TYPE_GUEST,
                guest_email__iexact=user_email,
            )

    if not role_filter:
        return ""

    roles = set(
        EventParticipant.objects.filter(event_id=event.id)
        .filter(role_filter)
        .filter(
            role__in=[
                EventParticipant.ROLE_HOST,
                EventParticipant.ROLE_MODERATOR,
                EventParticipant.ROLE_SPEAKER,
            ]
        )
        .values_list("role", flat=True)
    )

    if EventParticipant.ROLE_HOST in roles:
        return "Host"
    if EventParticipant.ROLE_MODERATOR in roles:
        return "Moderator"
    if EventParticipant.ROLE_SPEAKER in roles:
        return "Speaker"

    return ""


def _serialize_event_participant_roles(event) -> list[dict]:
    """
    Compact role list for LiveMeetingPage.

    This intentionally avoids returning full event_participants payload.
    It only returns identity keys needed by frontend assignedRoleByIdentity.
    """
    rows = (
        EventParticipant.objects.filter(
            event_id=event.id,
            role__in=[
                EventParticipant.ROLE_HOST,
                EventParticipant.ROLE_MODERATOR,
                EventParticipant.ROLE_SPEAKER,
            ],
        )
        .select_related("user")
        .only(
            "id",
            "event_id",
            "role",
            "participant_type",
            "user_id",
            "guest_email",
            "guest_name",
            "user__id",
            "user__email",
            "user__first_name",
            "user__last_name",
        )
    )

    data = []

    for participant in rows:
        user = getattr(participant, "user", None)
        user_id = getattr(user, "id", None) or participant.user_id
        user_email = (getattr(user, "email", "") or "").strip()
        guest_email = (getattr(participant, "guest_email", "") or "").strip()
        role_value = participant.role

        if role_value == EventParticipant.ROLE_HOST:
            role_value = "Host"
        elif role_value == EventParticipant.ROLE_MODERATOR:
            role_value = "Moderator"
        elif role_value == EventParticipant.ROLE_SPEAKER:
            role_value = "Speaker"

        user_name = " ".join(
            part for part in [
                getattr(user, "first_name", "") or "",
                getattr(user, "last_name", "") or "",
            ]
            if part
        ).strip()

        guest_name = (getattr(participant, "guest_name", "") or "").strip()
        name = user_name or guest_name or user_email or guest_email or ""

        data.append({
            "user_id": user_id,
            "email": user_email,
            "guest_email": guest_email,
            "name": name,
            "role": role_value,
        })

    return data


def _serialize_event_live_context(event, request=None) -> dict:
    """
    Lightweight payload for LiveMeetingPage.

    Important:
    - Does not return full event_participants.
    - Computes current user's permissions server-side.
    - Does not cache globally because permissions are user-specific.
    """
    user = getattr(request, "user", None) if request else None

    is_authenticated = bool(user and getattr(user, "is_authenticated", False))
    is_guest = bool(getattr(user, "is_guest", False)) if is_authenticated else False

    is_owner = _is_event_owner(user, event) if is_authenticated and not is_guest else False
    is_manager = _is_event_manager(user, event) if is_authenticated and not is_guest else False

    explicit_role = _current_user_event_participant_role(event, user) if is_authenticated else ""

    current_user_live_role = "Host" if is_manager else explicit_role

    is_host = current_user_live_role == "Host"
    is_moderator = current_user_live_role == "Moderator"
    is_speaker = current_user_live_role == "Speaker"

    can_receive_support_requests = bool(is_host or is_moderator)
    can_manage_participant_mic = bool(is_host or is_moderator or is_speaker)
    can_manage_recording = bool(is_host or is_manager)
    can_moderate_qna = bool(is_host or is_moderator)
    can_publish_qna = bool(is_host or is_moderator)

    data = _serialize_event_summary(event, request=request)

    data.update({
        "current_user_live_role": current_user_live_role,
        "current_user_role": current_user_live_role,
        "event_participant_roles": _serialize_event_participant_roles(event) if is_manager else [],
        "is_owner": is_owner,
        "is_host": is_host,
        "is_moderator": is_moderator,
        "is_speaker": is_speaker,
        "is_guest": is_guest,
        "current_user_permissions": {
            "can_receive_support_requests": can_receive_support_requests,
            "can_manage_participant_mic": can_manage_participant_mic,
            "can_manage_recording": can_manage_recording,
            "can_moderate_qna": can_moderate_qna,
            "can_publish_qna": can_publish_qna,
        },
        "is_recording": bool(getattr(event, "is_recording", False)) if can_manage_recording else False,
        "rtk_recording_id": (getattr(event, "rtk_recording_id", "") or "") if can_manage_recording else "",
        "recording_paused_at": getattr(event, "recording_paused_at", None) if can_manage_recording else None,
    })

    return data


EVENT_SUMMARY_CACHE_TTL_SECONDS = 2


def _event_summary_cache_key(event_id) -> str:
    return f"event:{event_id}:summary:v1"


def _public_event_summary_cache_key(event_id) -> str:
    return f"event:{event_id}:summary:public:v1"


def _is_publicly_cacheable_event(event) -> bool:
    return not getattr(event, "is_hidden", False) and event.status in {"published", "live"}


def _cache_event_summary(event, data: dict) -> None:
    cache.set(_event_summary_cache_key(event.id), data, EVENT_SUMMARY_CACHE_TTL_SECONDS)
    public_key = _public_event_summary_cache_key(event.id)
    if _is_publicly_cacheable_event(event):
        cache.set(public_key, data, EVENT_SUMMARY_CACHE_TTL_SECONDS)
    else:
        cache.delete(public_key)


def _delete_event_summary_cache(event_id) -> None:
    cache.delete(_event_summary_cache_key(event_id))
    cache.delete(_public_event_summary_cache_key(event_id))


@contextmanager
def live_join_slot(event_id, limit=None, ttl=None):
    """
    Redis-backed soft limiter for /rtk/join/.

    This limits how many users per event can run heavy join logic at the same time.
    If Redis/cache has any issue, it fails open and allows join instead of blocking live meeting.

    NOTE: This context manager uses try/finally (not try/except around yield) to ensure
    exceptions from the with-body propagate normally. Cache errors are caught separately.
    """
    limit = int(limit or getattr(settings, "LIVE_JOIN_CONCURRENT_LIMIT", 60))
    ttl = int(ttl or getattr(settings, "LIVE_JOIN_SLOT_TTL_SECONDS", 30))

    if not event_id or limit <= 0:
        yield True
        return

    key = f"event:{event_id}:rtk_join_slots"
    acquired = False
    allowed = True  # fail open by default

    # Determine allowed status by attempting cache operations.
    # Only catches cache/Redis errors, not exceptions from with-body.
    try:
        cache.add(key, 0, timeout=ttl)
        count = cache.incr(key)

        try:
            cache.touch(key, timeout=ttl)
        except Exception:
            pass

        allowed = count <= limit
        logger.info(
            "[LIVE_JOIN_QUEUE] event=%s allowed=%s limit=%s",
            event_id,
            str(allowed).lower(),
            limit,
        )

        if allowed:
            acquired = True
        else:
            try:
                cache.decr(key)
            except Exception:
                pass

    except Exception:
        # Cache/Redis error: fail open and allow join
        logger.info(
            "[LIVE_JOIN_QUEUE] event=%s allowed=true limit=%s (cache failed)",
            event_id,
            limit,
        )
        allowed = True
        acquired = False

    # Yield outside the cache try/except so exceptions from with-body propagate.
    # Use try/finally to guarantee cleanup.
    try:
        yield allowed
    finally:
        if acquired:
            try:
                remaining = cache.decr(key)
                if remaining <= 0:
                    cache.delete(key)
            except Exception:
                pass


def live_join_queue(view_func):
    """
    Decorator for rtk_join.

    Returns 202 queued when too many users are joining same event at once.
    Frontend should wait and retry automatically.
    """

    @wraps(view_func)
    def _wrapped(self, request, *args, **kwargs):
        event_id = kwargs.get("pk") or (args[0] if args else None)

        limit = int(getattr(settings, "LIVE_JOIN_CONCURRENT_LIMIT", 60))
        retry_after = int(getattr(settings, "LIVE_JOIN_RETRY_AFTER_SECONDS", 2))

        with live_join_slot(event_id, limit=limit) as allowed:
            if not allowed:
                return Response(
                    {
                        "queued": True,
                        "reason": "join_capacity_busy",
                        "message": "Joining meeting, please wait...",
                        "retry_after": retry_after,
                    },
                    status=202,
                )

            return view_func(self, request, *args, **kwargs)

    return _wrapped


@contextmanager
def live_rejoin_slot(event_id, limit=None, ttl=None):
    """
    Redis-backed soft limiter for /live/rejoin/.

    This limits how many users per event can run heavy live rejoin logic at the same time.
    If Redis/cache has any issue, it fails open and allows rejoin instead of blocking users.

    NOTE: This context manager uses try/finally (not try/except around yield) to ensure
    exceptions from the with-body propagate normally. Cache errors are caught separately.
    """
    limit = int(limit or getattr(settings, "LIVE_REJOIN_CONCURRENT_LIMIT", 80))
    ttl = int(ttl or getattr(settings, "LIVE_REJOIN_SLOT_TTL_SECONDS", 30))

    if not event_id or limit <= 0:
        yield True
        return

    key = f"event:{event_id}:live_rejoin_slots"
    acquired = False
    allowed = True  # fail open by default

    # Determine allowed status by attempting cache operations.
    # Only catches cache/Redis errors, not exceptions from with-body.
    try:
        cache.add(key, 0, timeout=ttl)
        count = cache.incr(key)

        try:
            cache.touch(key, timeout=ttl)
        except Exception:
            pass

        allowed = count <= limit
        logger.info(
            "[LIVE_REJOIN_QUEUE] event=%s allowed=%s limit=%s",
            event_id,
            str(allowed).lower(),
            limit,
        )

        if allowed:
            acquired = True
        else:
            try:
                cache.decr(key)
            except Exception:
                pass

    except Exception:
        # Cache/Redis error: fail open and allow rejoin
        logger.info(
            "[LIVE_REJOIN_QUEUE] event=%s allowed=true limit=%s (cache failed)",
            event_id,
            limit,
        )
        allowed = True
        acquired = False

    # Yield outside the cache try/except so exceptions from with-body propagate.
    # Use try/finally to guarantee cleanup.
    try:
        yield allowed
    finally:
        if acquired:
            try:
                remaining = cache.decr(key)
                if remaining <= 0:
                    cache.delete(key)
            except Exception:
                pass


def live_rejoin_queue(view_func):
    """
    Decorator for live_rejoin.

    Returns 202 queued when too many users are restoring a live session at once.
    Frontend should wait and retry automatically.
    """

    @wraps(view_func)
    def _wrapped(self, request, *args, **kwargs):
        event_id = kwargs.get("pk") or (args[0] if args else None)

        limit = int(getattr(settings, "LIVE_REJOIN_CONCURRENT_LIMIT", 80))
        retry_after = int(getattr(settings, "LIVE_REJOIN_RETRY_AFTER_SECONDS", 2))

        with live_rejoin_slot(event_id, limit=limit) as allowed:
            if not allowed:
                return Response(
                    {
                        "queued": True,
                        "reason": "live_rejoin_busy",
                        "message": "Restoring live session, please wait...",
                        "retry_after": retry_after,
                    },
                    status=202,
                )

            return view_func(self, request, *args, **kwargs)

    return _wrapped


def _grant_invited_event_access(event, user, invited_by=None):
    """
    Grant Companion access to an invited user by creating/reactivating EventRegistration.
    Bypasses application requirement even for apply-type events.
    Auto-approves any pending applications.

    Args:
        event: Event instance
        user: User instance to grant access
        invited_by: Optional User instance who sent the invite

    Returns:
        dict with keys:
        - registration_created: bool (True if new registration or reactivated)
        - registration: EventRegistration instance
        - application_approved: bool (True if pending app was approved)
    """
    now = timezone.now()
    registration_created = False
    application_approved = False

    # Create or reactivate EventRegistration
    existing_reg = EventRegistration.objects.filter(
        event=event,
        user=user
    ).first()

    if existing_reg and existing_reg.status == 'registered':
        # Already registered, no action needed
        registration = existing_reg
    elif existing_reg and existing_reg.status in ['cancelled', 'deregistered']:
        # Reactivate registration
        existing_reg.status = 'registered'
        existing_reg.save(update_fields=['status'])
        registration = existing_reg
        registration_created = True
    else:
        # Create new registration
        initial_admission_status = 'waiting' if event.waiting_room_enabled else 'admitted'
        registration = EventRegistration.objects.create(
            event=event,
            user=user,
            status='registered',
            admission_status=initial_admission_status
        )
        registration_created = True

    # Auto-assign Participant badge if newly created
    if registration_created and not registration.badge_labels.exists():
        participant_badge = event.get_or_create_participant_badge()
        registration.badge_labels.add(participant_badge)

    # Update attending_count only when new/reactivated
    if registration_created:
        Event.objects.filter(pk=event.pk).update(
            attending_count=F('attending_count') + 1
        )

    # Auto-approve any pending applications for this user
    pending_app = EventApplication.objects.filter(
        event=event,
        user=user,
        status__in=['pending', 'submitted']
    ).first()

    if pending_app:
        pending_app.status = 'approved'
        pending_app.reviewed_at = now
        pending_app.reviewed_by = invited_by
        pending_app.is_preapproved = True
        pending_app.preapproved_at = now
        pending_app.save(update_fields=[
            'status', 'reviewed_at', 'reviewed_by', 'is_preapproved', 'preapproved_at'
        ])
        application_approved = True

    return {
        'registration_created': registration_created,
        'registration': registration,
        'application_approved': application_approved
    }


def _execute_lounge_transition(event_id, transition, user_ids):
    """
    Shared helper for lounge participant transitions.
    Handles both synchronous and Celery-delayed execution.

    Args:
        event_id: Event.id to transition participants for
        transition: "to_main_room" or "to_waiting_room"
        user_ids: List of user IDs to transition

    Performs:
    1. Update EventRegistration.admission_status and current_location
    2. Delete LoungeParticipant records
    3. Broadcast lounge_stopped WebSocket event
    """
    if not user_ids:
        return

    try:
        with transaction.atomic():
            if transition == "to_main_room":
                # Admit directly to main room
                EventRegistration.objects.filter(
                    event_id=event_id, user_id__in=user_ids
                ).update(
                    admission_status="admitted",
                    admitted_at=timezone.now(),
                    was_ever_admitted=True,
                    current_location="main_room",
                )
            else:  # to_waiting_room (default)
                # Move to waiting room
                EventRegistration.objects.filter(
                    event_id=event_id, user_id__in=user_ids
                ).update(
                    admission_status="waiting",
                    waiting_started_at=timezone.now(),
                    current_location="waiting_room",
                )

            # Remove from lounge seating
            LoungeParticipant.objects.filter(
                table__event_id=event_id, user_id__in=user_ids
            ).delete()

        # Broadcast lounge_stopped event to all participants
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"event_{event_id}",
            {"type": "lounge_stopped", "transition": transition}
        )
        logger.info(f"✅ Lounge transition complete: event={event_id}, transition={transition}, users={len(user_ids)}")
    except Exception as e:
        logger.exception(f"❌ Lounge transition failed: event={event_id}, transition={transition}: {e}")


# ============================================================
# ======================== Event ViewSet =====================
# ============================================================

def _apply_bucket_filter(qs, bucket):
    """
    Applies simplified bucket filtering to a QuerySet.
    Choices: upcoming, live, past.
    """
    now = timezone.now()
    
    if bucket == "live":
        # Live = status is 'live' (explicit) OR (status!='ended' AND now within start..end)
        return qs.filter(Q(status="live") | (Q(start_time__lte=now, end_time__gte=now) & ~Q(status="ended"))).exclude(status="cancelled")
    
    elif bucket == "upcoming":
        # Upcoming = status!='ended' AND start_time > now
        return qs.exclude(status="ended").filter(start_time__gt=now).exclude(status="cancelled")
        
    elif bucket == "past":
        # Past = status='ended' OR end_time < now OR (end_time is null AND start_time < now), EXCLUDING cancelled
        qs = qs.filter(
            Q(status="ended") |
            Q(end_time__lt=now) |
            Q(end_time__isnull=True, start_time__lt=now)
        )
        # Exclude cancelled from past
        return qs.exclude(status="cancelled")
        
    elif bucket == "cancelled":
        # Cancelled = status="cancelled"
        return qs.filter(status="cancelled")
    
    return qs

# ============================================================================
# ================== Virtual Speaker ViewSet ==============================
# ============================================================================

class VirtualSpeakerViewSet(viewsets.ModelViewSet):
    """
    CRUD operations for virtual speaker profiles (reusable across events).
    Supports conversion to real user accounts.
    Restricted to superusers (platform admins) only.
    """

    serializer_class = VirtualSpeakerSerializer
    permission_classes = [IsSuperuserOnly]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ['name', 'job_title', 'company']
    ordering_fields = ['name', 'created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        """Filter by community from query param (optional for list, required filtering applied)."""
        community_id = self.request.query_params.get('community_id')

        # For list endpoint, filter by community_id if provided
        if self.action == 'list' and community_id:
            return VirtualSpeaker.objects.filter(community_id=community_id)

        # For detail endpoints (retrieve, update, delete, convert, etc.), return all
        if self.action in ['retrieve', 'update', 'partial_update', 'destroy', 'convert', 'resend_invite']:
            return VirtualSpeaker.objects.all()

        # For list without community_id, return all (allows browsing all speakers)
        return VirtualSpeaker.objects.all()

    def perform_create(self, serializer):
        """Set the creator and community when creating."""
        # Get community_id from request data
        community_id = self.request.data.get('community_id')
        # Ensure community_id is always set
        serializer.save(community_id=community_id, created_by=self.request.user)

    @action(detail=True, methods=['post'], permission_classes=[IsSuperuserOnly], url_path='convert')
    def convert(self, request, pk=None):
        """Convert a virtual speaker to a real user account."""
        from django.contrib.auth.models import User
        from django.core.files.base import ContentFile
        from users.models import UserProfile
        from users.task import send_speaker_credentials_task

        vs = self.get_object()

        if vs.status == VirtualSpeaker.STATUS_CONVERTED:
            return Response({'detail': 'Already converted.'}, status=status.HTTP_400_BAD_REQUEST)

        print(f"DEBUG: request.data = {request.data}")
        print(f"DEBUG: request.content_type = {request.content_type}")

        serializer = VirtualSpeakerConvertSerializer(data=request.data)
        if not serializer.is_valid():
            print(f"DEBUG: serializer.errors = {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        email = serializer.validated_data['email']
        send_invite = serializer.validated_data.get('send_invite', True)

        # Check if email already in use
        if User.objects.filter(email=email).exists():
            return Response({'detail': 'A user with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            # 1. Create Django User
            name_parts = vs.name.split(' ', 1)
            base_username = email.split('@')[0]
            username = base_username
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1

            user = User.objects.create(
                username=username,
                email=email,
                first_name=name_parts[0],
                last_name=name_parts[1] if len(name_parts) > 1 else '',
                is_active=True,
            )
            user.set_unusable_password()
            user.save()

            # 2. Create UserProfile with VirtualSpeaker data
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.bio = vs.bio
            profile.job_title = vs.job_title
            profile.company = vs.company
            if vs.profile_image:
                vs.profile_image.seek(0)
                profile.user_image.save(vs.profile_image.name, ContentFile(vs.profile_image.read()))
            profile.save()

            # 3. Update EventParticipant records for this virtual speaker
            from .models import EventParticipant, SessionParticipant
            EventParticipant.objects.filter(
                virtual_speaker=vs,
                participant_type=EventParticipant.PARTICIPANT_TYPE_VIRTUAL,
            ).update(
                participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
                user=user,
                virtual_speaker=None,
            )

            # 4. Update SessionParticipant records
            SessionParticipant.objects.filter(
                virtual_speaker=vs,
                participant_type=SessionParticipant.PARTICIPANT_TYPE_VIRTUAL,
            ).update(
                participant_type=SessionParticipant.PARTICIPANT_TYPE_STAFF,
                user=user,
                virtual_speaker=None,
            )

            # 5. Mark VirtualSpeaker as converted
            vs.status = VirtualSpeaker.STATUS_CONVERTED
            vs.converted_user = user
            vs.converted_at = timezone.now()
            vs.invited_email = email
            vs.save()

        # 6. Send invite email asynchronously (Cognito + credentials)
        if send_invite:
            send_speaker_credentials_task.delay(user.id)

        return Response({
            'ok': True,
            'user_id': user.id,
            'email': email,
            'invite_sent': send_invite,
        })

    @action(detail=True, methods=['post'], permission_classes=[IsSuperuserOnly], url_path='resend-invite')
    def resend_invite(self, request, pk=None):
        """Resend invitation to a converted virtual speaker."""
        from users.task import send_speaker_credentials_task

        vs = self.get_object()
        if vs.status != VirtualSpeaker.STATUS_CONVERTED or not vs.converted_user:
            return Response({'detail': 'Not yet converted.'}, status=status.HTTP_400_BAD_REQUEST)

        send_speaker_credentials_task.delay(vs.converted_user_id)
        return Response({'ok': True})


class EventViewSet(viewsets.ModelViewSet):
    """
    Full CRUD over events with:
    - Search & ordering
    - Filter helpers (format, category, date range, price)
    - Utility endpoints (categories, formats, locations, max-price, mine)
    - Registration helpers (register, register-bulk)
    - RTK meeting join (/rtk/join) and live status (/live-status)
    """
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    serializer_class = EventSerializer
    permission_classes = [IsCreatorOrReadOnly]
    pagination_class = EventLimitOffsetPagination
    throttle_classes = []  # NOTE: no throttling by default

    # 🔎 Search & ordering
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ["title", "location", "category", "description", "community__name"]
    ordering_fields = ["start_time", "created_at", "title", "is_pinned", "pin_priority", "pinned_at"]
    ordering = ["-start_time"]

    # ------------------------ Queryset -----------------------
    def get_queryset(self):
        """
        Visibility:
          - Anonymous users see only 'published' events
          - Authenticated users also see events from orgs they belong to
        Filters (optional):
          - format (?event_format=A&event_format=B or ?event_format=A,B)
          - category (?category=A&category=B or ?category=A,B)
          - date_range (This Week | This Month | Next 90 days)
          - location (?location=ExactCity)
          - start_date/end_date (?start_date=YYYY-MM-DD&end_date=YYYY-MM-DD)
          - price bounds (?min_price=..&max_price=..)
          - bucket (?bucket=upcoming|live|past)
        """
        user = self.request.user
        is_platform_admin = bool(getattr(user, "is_superuser", False)) or bool(getattr(user, "is_staff", False))

        is_guest_user = bool(getattr(user, "is_guest", False))
        guest_event_id = getattr(getattr(user, "guest", None), "event_id", None) if is_guest_user else None
        # ⚡ OPTIMIZED: Only select_related(community) for list queries. Prefetches moved to retrieve().
        qs = Event.objects.select_related("community")

        # Handle hidden events: visible ONLY to creator OR registered users
        if user.is_authenticated:
            if is_platform_admin:
                # Platform superusers can access all events, including hidden.
                pass
            else:
                # ⚡ OPTIMIZED: Use subquery for registrations to avoid expensive JOIN+distinct
                hidden_accessible_ids = EventRegistration.objects.filter(
                    user_id=user.id,
                    status__in=['registered', 'cancellation_requested']
                ).values_list('event_id', flat=True)

                qs = qs.filter(
                    Q(is_hidden=False) |
                    Q(is_hidden=True, created_by_id=user.id) |
                    Q(is_hidden=True, id__in=hidden_accessible_ids)
                )
        else:
            # Non-authenticated users: only non-hidden events
            qs = qs.filter(is_hidden=False)

        # ✅ Hide unpublished recordings from regular participants
        # Exclude events with unpublished recordings, BUT only from users who are
        # ONLY registered participants (not hosts, owners, or community members)
        # This allows hosts/owners to see unpublished recordings, but hides them from other participants

        if user.is_authenticated and not is_platform_admin and not is_guest_user:
            # ⚡ OPTIMIZED: Use subquery instead of expensive multi-JOIN+distinct
            user_registered_ids = EventRegistration.objects.filter(
                user_id=user.id,
                status="registered"
            ).values_list('event_id', flat=True)

            user_is_host_or_admin = Q(created_by_id=user.id) | Q(community__owner_id=user.id) | Q(community__members=user)

            # Hide unpublished recordings from non-host registered users (no distinct needed here)
            qs = qs.exclude(
                Q(recording_url__isnull=False, recording_url__gt='') &
                Q(replay_visible_to_participants=False) &
                Q(id__in=user_registered_ids) &
                ~user_is_host_or_admin
            )

        # ---- Filters (applied only when provided) ----
        params = self.request.query_params

        # Include ended events flag (?include_ended=true)
        include_ended = (params.get("include_ended") or "").strip().lower() in {"1", "true", "yes", "on"}

        # ✅ FOR DETAIL VIEWS: default to including ended/past events so hosts/participants don't 404
        # Also include "register" and "apply" so users can register/apply for replay events (which are "ended")
        if self.action in ["retrieve", "update", "partial_update", "destroy", "register", "apply", "live_context"]:
            include_ended = True

        # ✅ DRAFT EVENTS: Always visible to creator, regardless of include_ended
        if user.is_authenticated and not is_guest_user:
            # Creator can always see their draft events
            draft_creator_filter = Q(status="draft", created_by_id=user.id)
        else:
            draft_creator_filter = Q()  # Empty Q object

        # Base visibility filters (only apply if include_ended is NOT requested)
        if not include_ended:
            if not user.is_authenticated:
                qs = qs.filter(status__in=["published", "live"])
            elif is_guest_user:
                # Guest tokens are scoped to a single event. Avoid ORM joins that expect a Django User.
                if guest_event_id is None:
                    return Event.objects.none()
                qs = qs.filter(id=guest_event_id, status__in=["published", "live"])
            else:
                if is_platform_admin:
                    # Full visibility for superusers regardless of creator/community membership.
                    pass
                else:
                    # ⚡ OPTIMIZED: Use subquery for registrations to avoid expensive JOIN+distinct
                    # Registered users can see published/live events they're registered to
                    registered_event_ids = EventRegistration.objects.filter(
                        user_id=user.id,
                        status="registered"
                    ).values_list('event_id', flat=True)

                    qs = qs.filter(
                        Q(status__in=["published", "live"]) |
                        draft_creator_filter |
                        Q(status__in=["published", "live"], community__members=user) |
                        Q(status__in=["published", "live"], community__owner_id=user.id) |
                        Q(status__in=["published", "live"], id__in=registered_event_ids)  # Registered: published/live only
                    )
        else:
            # When include_ended=true, apply proper visibility rules with ended events included
            if not user.is_authenticated:
                # Non-authenticated users: only published & live (NO ended events)
                qs = qs.filter(status__in=["published", "live"])
            elif is_guest_user:
                # Guest tokens scoped to single event: only published & live
                if guest_event_id is None:
                    return Event.objects.none()
                qs = qs.filter(id=guest_event_id, status__in=["published", "live"])
            elif is_platform_admin:
                # Platform admin: full visibility (no filter)
                pass
            else:
                # Authenticated users: can see published/live, but PAST events only if registered/creator/owner/replay-enabled
                now = timezone.now()
                registered_event_ids = EventRegistration.objects.filter(
                    user_id=user.id,
                    status="registered"
                ).values_list('event_id', flat=True)

                qs = qs.filter(
                    # ✅ Published/Live events (not yet past)
                    Q(status__in=["published", "live"], end_time__isnull=True) |  # No end time
                    Q(status__in=["published", "live"], end_time__gte=now) |  # Still ongoing
                    draft_creator_filter |  # ✅ Creator sees own draft
                    # ✅ PAST events (status ended OR end_time passed): visible to registered/creator/owner/replay-enabled
                    Q(Q(status="ended") | Q(end_time__lt=now), created_by_id=user.id) |  # Event creator
                    Q(Q(status="ended") | Q(end_time__lt=now), community__owner_id=user.id) |  # Community owner
                    Q(Q(status="ended") | Q(end_time__lt=now), id__in=registered_event_ids) |  # Registered users
                    Q(status="ended", replay_enabled=True, replay_visible_to_participants=True)  # Replay-enabled events
                )

        # Hidden filter (platform_admin only) - filter to show only hidden events
        is_hidden_param = (params.get("is_hidden") or "").strip().lower()
        if is_hidden_param in {"1", "true", "yes", "on"}:
            if is_platform_admin:
                qs = qs.filter(is_hidden=True)
            else:
                # Non-platform-admin users cannot see hidden events
                return Event.objects.none()

        # Bucket filter (upcoming / live / past) - applies to both list & mine
        bucket = (params.get("bucket") or "").strip().lower()
        if bucket:
            qs = _apply_bucket_filter(qs, bucket)

        exclude_pinned = (params.get("exclude_pinned") or "").strip().lower() in {"1", "true", "yes", "on"}
        if exclude_pinned:
            qs = qs.filter(is_pinned=False)

        created_by_param = params.get("created_by")
        if created_by_param:
            if created_by_param == "me":
                if not self.request.user.is_authenticated or is_guest_user:
                    return Event.objects.none()
                qs = qs.filter(created_by_id=self.request.user.id)
            else:
                # allow numeric id as well: ?created_by=123
                try:
                    qs = qs.filter(created_by_id=int(created_by_param))
                except (TypeError, ValueError):
                    pass

        exclude_ended = (params.get("exclude_ended") or "").strip().lower()
        if exclude_ended in {"1", "true", "yes", "on"}:
            now = timezone.now()
            qs = qs.exclude(status__in=["ended", "cancelled"])
            qs = qs.exclude(Q(end_time__isnull=False, end_time__lt=now) & ~Q(status="live"))
            qs = qs.exclude(
                Q(end_time__isnull=True, start_time__isnull=False, start_time__lt=now) & ~Q(status="live")
            )

        # Event format (use 'event_format' if that's your field name)
        fmts = params.getlist("event_format")
        if not fmts:
            raw_fmts = params.get("event_format", "")
            if raw_fmts:
                fmts = [v.strip() for v in raw_fmts.split(",") if v.strip()]

        if fmts:
            qs = qs.filter(format__in=fmts)

        # Category / Topic (supports ?category=A&category=B and ?category=A,B)
        cats = params.getlist("category")
        if not cats:
            raw = params.get("category", "")
            if raw:
                cats = [c.strip() for c in raw.split(",") if c.strip()]
        if cats:
            qs = qs.filter(category__in=cats)

        # Date ranges
        dr = params.get("date_range")
        if dr in {"This Week", "This Month", "Next 90 days"}:
            now = timezone.now()

            if dr == "This Week":
                # Monday 00:00 to next Monday 00:00 (half-open interval)
                start_win = (now - timedelta(days=now.weekday())).replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
                end_win = start_win + timedelta(days=7)

            elif dr == "This Month":
                # 1st day 00:00 to 1st of next month 00:00
                start_win = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                # next month first day 00:00
                if start_win.month == 12:
                    end_win = start_win.replace(year=start_win.year + 1, month=1)
                else:
                    end_win = start_win.replace(month=start_win.month + 1)

            else:  # "Next 90 days"
                start_win = now
                end_win = now + timedelta(days=90)

            # Simple rule: show events whose *start* falls inside the window
            qs = qs.filter(start_time__gte=start_win, start_time__lt=end_win)

        # Location (case-insensitive exact match)
        loc = params.get("location", "").strip()
        if loc:
            qs = qs.filter(location__iexact=loc)

        # Slug filter (exact match)
        slug = params.get("slug", "").strip()
        if slug:
            qs = qs.filter(slug=slug)

        # Start / end dates (inclusive)
        start_date = params.get("start_date")
        end_date = params.get("end_date")

        if start_date or end_date:
            s = parse_date(start_date) if start_date else None
            e = parse_date(end_date) if end_date else None
            if s and e and s > e:
                s, e = e, s  # swap if user inverted

            if s and e:
                qs = qs.filter(start_time__date__gte=s, start_time__date__lte=e)
            elif s:
                qs = qs.filter(start_time__date__gte=s)
            elif e:
                qs = qs.filter(start_time__date__lte=e)

        # Price bounds
        min_price = params.get("min_price")
        max_price = params.get("max_price")
        if min_price or max_price:
            # Build price Q object
            price_filter = Q()
            if min_price:
                price_filter &= Q(price__gte=min_price)
            if max_price:
                price_filter &= Q(price__lte=max_price)
            
            # Include NULL price events (Paid events waiting for setup) 
            # if the filter includes 0 (the starting price)
            if not min_price or str(min_price) == "0":
                qs = qs.filter(price_filter | Q(price__isnull=True))
            else:
                qs = qs.filter(price_filter)



        # ⚡ OPTIMIZED: Annotate registration counts for list views (efficient DB queries)
        qs = qs.annotate(
            registrations_count=Count(
                'registrations',
                filter=Q(registrations__status__in=['registered', 'cancellation_requested'])
            )
        )
        return qs

    def get_serializer_class(self):
        """Use optimized EventListSerializer for list action to avoid expensive user_status computation."""
        if self.action == 'list':
            return EventListSerializer
        return EventSerializer

    def list(self, request, *args, **kwargs):
        """
        List events with Redis caching for 45 seconds.
        Cache is user-specific and query-param-aware.
        """
        cache_key = event_list_cache_key(request.user, request.query_params)
        cached_data = get_cached_event_list(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        response = super().list(request, *args, **kwargs)
        if response.status_code == 200:
            set_cached_event_list(cache_key, response.data)
        return response

    def _get_join_event_or_404(self, event_id):
        """
        Lightweight event fetch for the hot /rtk/join/ path.

        Safety:
        - First preserves existing visibility checks via the ViewSet queryset.
        - Then fetches only the fields needed by rtk_join.
        - Keeps object permission checks intact.
        """
        if not event_id:
            raise Http404("Event not found")

        visible_qs = self.filter_queryset(self.get_queryset()).filter(pk=event_id)
        if not visible_qs.only("id").exists():
            raise Http404("Event not found")

        event = get_object_or_404(
            Event.objects.select_related("community").only(
                "id",
                "title",
                "slug",
                "created_by_id",
                "community_id",
                "community__id",
                "community__owner_id",
                "status",
                "is_live",
                "format",
                "is_on_break",
                "waiting_room_enabled",
                "waiting_room_grace_period_minutes",
                "start_time",
                "end_time",
                "timezone",
                "rtk_meeting_id",
                "rtk_meeting_title",
                "replay_available",
                "lounge_enabled_waiting_room",
                "networking_tables_enabled_waiting_room",
            ),
            pk=event_id,
        )
        self.check_object_permissions(self.request, event)
        return event

    def retrieve(self, request, *args, **kwargs):
        """
        ⚡ OPTIMIZED: Add prefetches only for detail views (not list).
        This keeps list queries fast while detail views get full data.
        """
        from interactions.models import Question
        from .models import SessionParticipant

        participant_qs = (
            EventParticipant.objects.select_related("user", "user__profile", "virtual_speaker")
            .prefetch_related("user__experiences")
            .order_by("display_order", "id")
        )
        session_participant_qs = (
            SessionParticipant.objects.select_related("user", "user__profile", "virtual_speaker")
            .order_by("role", "display_order", "id")
        )
        session_qs = EventSession.objects.prefetch_related(
            Prefetch("participants", queryset=session_participant_qs)
        )
        registration_qs = EventRegistration.objects.select_related("user", "user__profile")
        question_qs = Question.objects.select_related("user", "guest_asker")
        include = request.query_params.get("include", "")
        include_parts = {part.strip() for part in include.split(",") if part.strip()}

        prefetches = [
            Prefetch("sessions", queryset=session_qs),
            Prefetch("participants", queryset=participant_qs),
            Prefetch("registrations", queryset=registration_qs),
            "guest_attendees",
            "resources",
        ]
        if "questions" in include_parts:
            prefetches.append(Prefetch("questions", queryset=question_qs))

        queryset = self.get_queryset().prefetch_related(*prefetches)
        self.queryset = queryset
        return super().retrieve(request, *args, **kwargs)

    @action(detail=True, methods=["get"], permission_classes=[AllowAny], url_path="summary")
    def summary(self, request, pk=None):
        """
        Lightweight event detail endpoint for live polling and chat metadata.
        Avoids the full retrieve() prefetch tree.
        """
        lookup = self.kwargs.get(self.lookup_field)
        if lookup is not None and str(lookup).isdigit():
            cached_public = cache.get(_public_event_summary_cache_key(lookup))
            if cached_public is not None:
                return Response(cached_public)

        event = self._get_join_event_or_404(pk)
        cache_key = _event_summary_cache_key(event.id)
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached)

        data = _serialize_event_summary(event, request=request)
        _cache_event_summary(event, data)
        return Response(data)

    @action(detail=True, methods=["get"], permission_classes=[AllowAny], url_path="live-context")
    def live_context(self, request, pk=None):
        """
        Lightweight authenticated/user-aware payload for LiveMeetingPage.

        This avoids using the heavy full event detail endpoint during live join.
        It also avoids returning full event_participants just to calculate current user's permissions.
        """
        event = self.get_object()
        data = _serialize_event_live_context(event, request=request)
        return Response(data)

    #  Batched participant endpoint to replace individual user/<id> calls
    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="participants-lite")
    def participants_lite(self, request, pk=None):
        """
        Batched lightweight participant data for live meeting UI.

        Returns: id, name, avatar, kyc_status (permission-aware), current_location

        Replaces many individual /api/users/<id>/?ecp_lite=kyc calls.
        Cached per event + user (user-aware for permission visibility).
        Cache TTL: 45 seconds.
        """
        from events.serializers import ParticipantsLiteSerializer

        event = self.get_object()

        #  Cache key includes user_id because kyc_status visibility differs per user
        cache_key = f"event:{event.id}:participants_lite:user:{request.user.id}"
        cached_data = cache.get(cache_key)

        if cached_data is not None:
            logger.debug(f"[ParticipantsLite] Cache hit for event={event.id}, user={request.user.id}")
            return Response(cached_data)

        # Fetch participants using efficient queries
        participants_data = []

        # Check if requester is staff/manager to determine kyc_status visibility
        is_manager = _is_event_manager(request.user, event)

        wants_cursor = str(request.query_params.get("cursor", "")).lower() in {"1", "true", "yes"}
        if wants_cursor:
            try:
                limit = int(request.query_params.get("limit") or 100)
            except (TypeError, ValueError):
                limit = 100
            limit = max(1, min(limit, 200))
            try:
                after_id = int(request.query_params.get("after_id") or 0)
            except (TypeError, ValueError):
                after_id = 0

            registered_qs = EventRegistration.objects.filter(
                event=event,
                status__in=['registered', 'accepted'],
                user_id__gt=after_id,
            ).order_by('user_id').values_list(
                'user_id', 'user__first_name', 'user__last_name',
                'user__image', 'current_location'
            )[: limit + 1]

            registered_rows = list(registered_qs)
            has_more = len(registered_rows) > limit
            registered_rows = registered_rows[:limit]

            for user_id, first_name, last_name, avatar_url, current_location in registered_rows:
                name = f"{first_name} {last_name}".strip() if first_name or last_name else f"User {user_id}"
                participants_data.append({
                    'id': user_id,
                    'name': name,
                    'avatar': avatar_url,
                    'kyc_status': None,
                    'current_location': current_location or 'main_room'
                })

            return Response({
                'results': participants_data,
                'count': len(participants_data),
                'limit': limit,
                'has_more': has_more,
                'next_after_id': registered_rows[-1][0] if has_more and registered_rows else None,
            })

        # ✅ Legacy compatibility path: existing array response shape.
        registered = EventRegistration.objects.filter(
            event=event,
            status__in=['registered', 'accepted']  # Include both statuses
        ).select_related('user').values_list(
            'user_id', 'user__first_name', 'user__last_name',
            'user__image', 'current_location'
        )

        for user_id, first_name, last_name, avatar_url, current_location in registered:
            name = f"{first_name} {last_name}".strip() if first_name or last_name else f"User {user_id}"
            participants_data.append({
                'id': user_id,
                'name': name,
                'avatar': avatar_url,
                'kyc_status': None,  # kyc_status not directly available via values_list
                'current_location': current_location or 'main_room'
            })

        #  Also fetch staff participants (EventParticipant with type='staff')
        staff = EventParticipant.objects.filter(
            event=event,
            participant_type='staff',
            user__isnull=False
        ).select_related('user').values_list(
            'user_id', 'user__first_name', 'user__last_name',
            'event_image'
        )

        # Get default user profile images for staff
        staff_ids = [s[0] for s in staff]
        staff_user_map = {}
        if staff_ids:
            staff_user_map = dict(
                User.objects.filter(id__in=staff_ids).values_list(
                    'id', 'image'
                )
            )

        for user_id, first_name, last_name, event_image in staff:
            name = f"{first_name} {last_name}".strip() if first_name or last_name else f"User {user_id}"
            # Prefer event_image override, fall back to user profile image
            avatar = event_image or staff_user_map.get(user_id, '')
            participants_data.append({
                'id': user_id,
                'name': name,
                'avatar': avatar,
                'kyc_status': None,  # kyc_status not directly available via values_list
                'current_location': 'main_room'  # Staff location not tracked same way
            })

        #  Cache with 45-second TTL (balance between freshness and performance)
        cache.set(cache_key, participants_data, timeout=45)
        logger.info(
            f"[ParticipantsLite] Cached {len(participants_data)} participants for event={event.id}, user={request.user.id} (45s TTL)"
        )

        return Response(participants_data)

    # ---------------------- Permissions ----------------------
    def get_permissions(self):
        """
        Allow anonymous access to list/retrieve. All other actions require auth.
        """
        if self.action in ["list", "retrieve"]:
            return [AllowAny()]
        if self.action in ["invite_emails", "accept_invite_emails"]:
            from rest_framework.permissions import IsAuthenticated
            return [IsAuthenticated()]
        return super().get_permissions()
    # ---------------------- Object Lookup ----------------------
    def get_object(self):
        """
        Accept both numeric ID and slug as the lookup value.
        Try numeric ID first (backward compatibility), then slug.
        """
        lookup = self.kwargs.get(self.lookup_field)
        queryset = self.get_queryset()
        try:
            # Try numeric ID first (backward compatibility)
            obj = get_object_or_404(queryset, pk=int(lookup))
        except (ValueError, TypeError):
            # Fall back to slug lookup
            obj = get_object_or_404(queryset, slug=lookup)
        self.check_object_permissions(self.request, obj)
        return obj

    # ---------------------- Create/Update Hooks ----------------------
    def perform_create(self, serializer):
        """
        Enforce that:
          - request includes an 'community' (via serializer validated_data)
          - the authenticated user is a member of that community
        Then set created_by to the current user.
        Wrap in transaction.atomic() to ensure event + sessions are created atomically.
        """
        # With the serializer fix below, validated_data has 'community' (a model instance)
        org = serializer.validated_data.get("community")
        if not org:
            raise PermissionDenied("community_id is required.")
        # Ensure the user is a member of that org
        if not self.request.user.community.filter(id=org.id).exists():
            raise PermissionDenied("You must be a member of the community to create events.")
        # Attach creator automatically, wrapped in transaction for atomicity
        with transaction.atomic():
            # Paid events start as DRAFT — admin must set price in Product Management tab then publish.
            # Free events are published immediately.
            is_free = serializer.validated_data.get("is_free", True)
            initial_status = "published" if is_free else "draft"
            event = serializer.save(created_by=self.request.user, status=initial_status)



    def perform_update(self, serializer):
        """
        Custom update to broadcast lounge settings changes and validate external streaming.
        """
        instance = serializer.instance

        # Validate external streaming configuration
        validated_data = serializer.validated_data
        use_external = validated_data.get('use_external_streaming', instance.use_external_streaming)
        platform = validated_data.get('external_streaming_platform', instance.external_streaming_platform)
        url = validated_data.get('external_streaming_url', instance.external_streaming_url)

        if use_external and not url:
            from rest_framework.exceptions import ValidationError
            raise ValidationError({
                'external_streaming_url': 'Direct join URL is required when using external streaming.'
            })

        if use_external and platform == 'native':
            from rest_framework.exceptions import ValidationError
            raise ValidationError({
                'external_streaming_platform': 'Must select an external platform when use_external_streaming is True.'
            })

        # Capture old values
        old_settings = {
            "lounge_enabled_before": instance.lounge_enabled_before,
            "lounge_enabled_during": instance.lounge_enabled_during,
            "lounge_enabled_breaks": instance.lounge_enabled_breaks,
            "lounge_enabled_after": instance.lounge_enabled_after,
            "lounge_before_buffer": instance.lounge_before_buffer,
            "lounge_after_buffer": instance.lounge_after_buffer,
        }

        super().perform_update(serializer)
        _delete_event_summary_cache(instance.id)
        
        # Check for changes
        new_instance = serializer.instance # Refreshed instance
        changes = {}
        for key, old_val in old_settings.items():
            new_val = getattr(new_instance, key)
            if old_val != new_val:
                changes[key] = new_val
        
        if changes:
            # Broadcast update
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"event_{instance.id}",
                {
                    "type": "lounge_settings_update",
                    "event_id": instance.id,
                    "settings": {
                        "lounge_enabled_before": new_instance.lounge_enabled_before,
                        "lounge_enabled_during": new_instance.lounge_enabled_during,
                        "lounge_enabled_breaks": new_instance.lounge_enabled_breaks,
                        "lounge_enabled_after": new_instance.lounge_enabled_after,
                        "lounge_before_buffer": new_instance.lounge_before_buffer,
                        "lounge_after_buffer": new_instance.lounge_after_buffer,
                    },
                    "timestamp": timezone.now().isoformat(),
                }
            )

    def destroy(self, request, *args, **kwargs):
        """
        Allow hard deletion only if the event is a draft.
        Platform admins (superuser only) may also permanently delete
        any event status.  All related OrderItems are removed first to avoid
        the ProtectedError raised by OrderItem.event (on_delete=PROTECT).
        """
        instance = self.get_object()

        is_platform_admin = getattr(request.user, "is_superuser", False)

        if instance.status != "draft" and not is_platform_admin:
            return Response(
                {"detail": "Only draft events can be hard deleted. For published events, please use the cancel functionality."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Pre-delete OrderItems linked to this event so the CASCADE on the
        # Event row is not blocked by the PROTECT FK on OrderItem.event.
        if is_platform_admin:
            try:
                from orders.models import OrderItem, Order
                affected_order_ids = list(
                    OrderItem.objects.filter(event=instance).values_list("order_id", flat=True)
                )
                OrderItem.objects.filter(event=instance).delete()
                for order in Order.objects.filter(id__in=affected_order_ids):
                    order.recalc()
            except Exception:
                pass  # orders app may not be installed in all environments

        return super().destroy(request, *args, **kwargs)

    # ------------------ Dictionary Endpoints -----------------
    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="by-slug/(?P<slug>[^/]+)")
    def by_slug(self, request, slug=None):
        """
        Fetch a single event by slug for public landing page display.
        Returns comprehensive event data including cover image, venue info, and registration type.
        """
        try:
            event = self.get_queryset().get(slug=slug)
            serializer = self.get_serializer(event)
            return Response(serializer.data)
        except Event.DoesNotExist:
            return Response(
                {"detail": "Event not found"},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="categories")
    def categories(self, request):
        """
        Return distinct category values (published for anon; published+org for authed via get_queryset()).
        """
        qs = self.get_queryset()  # ← uses the same auth logic you already have
        cats = (
            qs.exclude(category__isnull=True)
            .exclude(category__exact="")
            .values_list("category", flat=True)
            .distinct()
            .order_by(Lower("category"))
        )
        return Response({"results": list(cats)})

    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="slug-availability")
    def slug_availability(self, request):
        """Check whether an event slug is available."""
        slug = (request.query_params.get("slug") or "").strip().lower()
        if not slug:
            return Response({"detail": "slug query parameter is required"}, status=400)

        qs = Event.objects.filter(slug=slug)
        exclude_id = request.query_params.get("exclude_id")
        if exclude_id:
            try:
                qs = qs.exclude(pk=int(exclude_id))
            except (TypeError, ValueError):
                pass

        return Response({"slug": slug, "available": not qs.exists()})

    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="formats")
    def formats(self, request, *args, **kwargs):
        """
        Return distinct non-empty event formats.
        """
        qs = Event.objects.all()
        qs = qs.exclude(format__exact="")   # ✅ avoids empty-string entries
        formats = qs.values_list("format", flat=True).distinct()
        return Response(formats)

    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="locations")
    def locations(self, request, *args, **kwargs):
        """
        Return distinct non-empty event locations.
        """
        qs = Event.objects.all()
        qs = qs.exclude(location__exact="")  # ✅ avoids empty-string entries
        locations = qs.values_list("location", flat=True).distinct()
        return Response(locations)

    # ------------------- Registration Helpers ----------------
    # POST /api/events/register-bulk/   body: {"event_ids": [1,2,3]}
    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="register-bulk")
    def register_bulk(self, request):
        """
        Register the current user to many events at once. Ignores duplicates gracefully.
        """
        event_ids = request.data.get("event_ids") or []
        if not isinstance(event_ids, list) or not event_ids:
            return Response({"detail": "event_ids must be a non-empty list"}, status=400)

        # Only existing events; (optionally) filter to published if your UX demands so
        qs = Event.objects.filter(id__in=event_ids)
        created = []

        # Use atomic to ensure all-or-nothing behavior
        with transaction.atomic():
            for ev in qs:
                # Check capacity
                if ev.max_participants is not None:
                    count = ev.registrations.filter(status="registered").count()
                    is_registered = ev.registrations.filter(user=request.user, status="registered").exists()
                    if not is_registered and count >= ev.max_participants:
                        # Skip this event if full
                        continue

                # ✅ NEW: Set admission_status based on event's waiting_room_enabled setting
                initial_admission_status = "waiting" if ev.waiting_room_enabled else "admitted"

                obj, was_created = EventRegistration.objects.get_or_create(
                    user=request.user,
                    event=ev,
                    defaults={"admission_status": initial_admission_status}
                )
                if was_created:
                    # Auto-assign Participant badge if registration has no badges
                    if not obj.badge_labels.exists():
                        participant_badge = ev.get_or_create_participant_badge()
                        obj.badge_labels.add(participant_badge)
                    # keep a running count on Event
                    Event.objects.filter(pk=ev.pk).update(attending_count=F("attending_count") + 1)
                    created.append(ev.id)

        return Response({"ok": True, "created": created, "count": len(created)})



    # GET /api/events/{id}/check_registration/
    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="check_registration")
    def check_registration(self, request, pk=None):
        """
        Check if the current user is registered for the event.
        Returns: { "is_registered": bool, "slug": event.slug }
        """
        event = self.get_object()
        is_registered = EventRegistration.objects.filter(
            event=event, 
            user=request.user, 
            status__in=["registered", "cancellation_requested"]
        ).exists()
        
        return Response({
            "is_registered": is_registered,
            "slug": event.slug,
            "id": event.id
        })


    # POST /api/events/{id}/invite_users/
    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="invite_users")
    def invite_users(self, request, pk=None):
        """
        Invite users and group members to an event.
        Creates EventRegistration and bypasses application requirement for invited users.
        Auto-approves any pending applications for the invited user/email.
        Only staff users can perform this action.
        """
        if not request.user.is_staff:
            return Response({"detail": "Only staff users can invite users."}, status=403)

        event = self.get_object()
        user_ids = request.data.get("user_ids", [])
        group_ids = request.data.get("group_ids", [])
        invite_message = str(request.data.get("invite_message") or "").strip()
        raw_send_message = request.data.get("send_message", False)
        send_message = (
            raw_send_message is True
            or str(raw_send_message).strip().lower() in {"1", "true", "yes", "on"}
        ) and bool(invite_message)

        invited_users = {}
        invite_sources = {}

        def _display_name(user):
            if not user:
                return "System"
            full_name = f"{getattr(user, 'first_name', '')} {getattr(user, 'last_name', '')}".strip()
            return full_name or getattr(user, "username", "") or getattr(user, "email", "") or "User"

        sender_name = _display_name(request.user)

        def _set_user_source(target_user, source_type, source_name, source_id=None):
            if not target_user:
                return
            invited_users[target_user.id] = target_user
            entry = invite_sources.get(target_user.id)
            if source_type == "group":
                if entry and entry.get("type") == "group":
                    names = entry.setdefault("names", [])
                    if source_name and source_name not in names:
                        names.append(source_name)
                else:
                    invite_sources[target_user.id] = {
                        "type": "group",
                        "id": source_id,
                        "names": [source_name] if source_name else [],
                    }
                return

            if not entry:
                invite_sources[target_user.id] = {
                    "type": source_type,
                    "id": source_id,
                    "name": source_name,
                }

        # 1. Process individual users
        if user_ids:
            users = User.objects.filter(id__in=user_ids)
            for u in users:
                _set_user_source(u, "user", sender_name, request.user.id)

        # 2. Process groups
        if group_ids:
            # Fetch members of these groups
            memberships = GroupMembership.objects.filter(
                group_id__in=group_ids,
                status="active"
            ).select_related("user", "group")
            for m in memberships:
                _set_user_source(m.user, "group", getattr(m.group, "name", "Group"), m.group_id)

        # 3. Filter out the actor themselves if they selected themselves (optional but good UX)
        invited_users.pop(request.user.id, None)
        invite_sources.pop(request.user.id, None)

        # 4. Use helper to grant access and approve applications
        registrations_created_count = 0
        applications_approved_count = 0

        for user_id, user in invited_users.items():
            result = _grant_invited_event_access(event, user, invited_by=request.user)
            if result['registration_created']:
                registrations_created_count += 1
            if result['application_approved']:
                applications_approved_count += 1

        # 5. Send Notifications
        notifications_to_create = []
        direct_messages_to_create = []

        for recipient in invited_users.values():
            source = invite_sources.get(recipient.id) or {
                "type": "user",
                "id": request.user.id,
                "name": sender_name,
            }
            source_names = [x for x in (source.get("names") or []) if x]
            if source.get("type") == "group":
                invite_source_name = (
                    source_names[0]
                    if len(source_names) <= 1
                    else f"{source_names[0]} +{len(source_names) - 1} more groups"
                )
            else:
                invite_source_name = source.get("name") or sender_name

            notifications_to_create.append(
                Notification(
                    recipient=recipient,
                    actor=request.user,
                    kind="event",
                    title=f"Invitation: {event.title}",
                    description=invite_message or f"You have been invited to {event.title}. You can now access the Event Companion.",
                    data={
                        "event_id": event.id,
                        "event_title": event.title,
                        "invite_source_type": source.get("type") or "user",
                        "invite_source_id": source.get("id"),
                        "invite_source_name": invite_source_name,
                    },
                    is_read=False
                )
            )

            if send_message:
                user_pair = sorted([request.user.id, recipient.id])
                conversation, _ = Conversation.objects.get_or_create(
                    user1_id=user_pair[0],
                    user2_id=user_pair[1],
                    defaults={"created_by": request.user},
                )
                direct_messages_to_create.append(
                    Message(
                        conversation=conversation,
                        sender=request.user,
                        body=invite_message,
                        event=event,
                    )
                )

        if notifications_to_create:
            Notification.objects.bulk_create(notifications_to_create)
        if direct_messages_to_create:
            Message.objects.bulk_create(direct_messages_to_create)

        return Response({
            "ok": True,
            "invited_count": len(invited_users),
            "registrations_created": registrations_created_count,
            "applications_approved": applications_approved_count,
            "messaged_count": len(direct_messages_to_create),
            "message": (
                f"Sent invitations to {len(invited_users)} users."
                + (f" Created {registrations_created_count} registrations." if registrations_created_count > 0 else "")
                + (f" Approved {applications_approved_count} pending applications." if applications_approved_count > 0 else "")
                + (f" Also sent {len(direct_messages_to_create)} event messages." if direct_messages_to_create else "")
            )
        })


    # GET/PATCH /api/events/{id}/saleor-product/
    @action(detail=True, methods=["get", "patch"], permission_classes=[IsCreatorOrReadOnly], url_path="saleor-product")
    def saleor_product(self, request, pk=None):
        """
        Fetch or update Saleor product details (price, stock, channels) for a paid event.
        GET: Fetch current product data from Saleor.
        PATCH: Update product pricing or inventory in Saleor.
        Only available if SALEOR_ENABLED is True.
        """
        if not getattr(settings, "SALEOR_ENABLED", False):
            return Response(
                {"detail": "Saleor integration is currently disabled."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        event = self.get_object()

        # Superuser check (platform_admin) or Creator
        if not (request.user.is_superuser or event.created_by_id == request.user.id):
            raise PermissionDenied("You do not have permission to manage this product.")

        if not event.saleor_product_id:
            return Response({"error": "No Saleor product linked to this event."}, status=400)

        if request.method == "GET":
            details = fetch_event_saleor_product_details(event.saleor_product_id)
            details["target_channel_slug"] = getattr(settings, "SALEOR_CHANNEL_SLUG", "default-channel")
            details["event_price_label"] = event.price_label
            return Response(details)

        elif request.method == "PATCH":
            variant_id = event.saleor_variant_id
            if not variant_id:
                # Try to get it from Saleor if missing locally
                details = fetch_event_saleor_product_details(event.saleor_product_id)
                product = details.get("data", {}).get("product")
                if product and product.get("variants"):
                    variant_id = product["variants"][0]["id"]
                    event.saleor_variant_id = variant_id
                    event.save(update_fields=["saleor_variant_id"])
                else:
                    return Response({"error": "No variant found for this product in Saleor."}, status=400)

            result = update_event_saleor_product_details(event.saleor_product_id, variant_id, request.data)

            # After successful Saleor update, sync price and stock back to ECP DB
            if "error" not in result:
                fresh = fetch_event_saleor_product_details(event.saleor_product_id)
                fresh_product = fresh.get("data", {}).get("product")
                if fresh_product and fresh_product.get("variants"):
                    variant = fresh_product["variants"][0]
                    target_slug = getattr(settings, "SALEOR_CHANNEL_SLUG", "default-channel")
                    for cl in variant.get("channelListings", []):
                        if cl.get("channel", {}).get("slug") == target_slug:
                            amt = cl.get("price", {}).get("amount")
                            if amt is not None and float(amt) > 0:
                                event.price = float(amt)
                            break
                    event.max_participants = sum(s.get("quantity", 0) for s in variant.get("stocks", []))

                # Save price_label if provided
                update_fields = ["price", "max_participants"]
                if "price_label" in request.data:
                    event.price_label = request.data.get("price_label", "").strip()
                    update_fields.append("price_label")

                event.save(update_fields=update_fields)

            return Response(result)

    # POST /api/events/{id}/sync-saleor-product/
    @action(detail=True, methods=["post"], permission_classes=[IsCreatorOrReadOnly], url_path="sync-saleor-product")
    def sync_saleor_product(self, request, pk=None):
        """
        Queue async task to sync Saleor product for a paid event.
        Returns immediately with a queued message.
        Only available if SALEOR_ENABLED is True.
        """
        if not getattr(settings, "SALEOR_ENABLED", False):
            return Response(
                {"detail": "Saleor integration is currently disabled."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        event = self.get_object()

        # Permission check
        if not (request.user.is_superuser or event.created_by_id == request.user.id):
            raise PermissionDenied("You do not have permission to sync this product.")

        if event.is_free:
            return Response({"error": "Free events do not need Saleor products."}, status=400)

        try:
            from .tasks import sync_event_to_saleor_async
            sync_event_to_saleor_async.delay(event.id)
            return Response({
                "status": "queued",
                "message": "Event sync to Saleor queued in background",
                "event_id": event.id,
            })
        except Exception as e:
            logger.error(f"Error queuing Saleor sync task for event {event.id}: {e}")
            return Response({"error": f"Failed to queue sync: {str(e)}"}, status=500)

    # POST /api/events/{id}/publish/
    @action(detail=True, methods=["post"], permission_classes=[IsCreatorOrReadOnly], url_path="publish")
    def publish_event(self, request, pk=None):
        """
        Publish a draft paid event or an Application Required event.
        For Application Required events: validates that at least one valid application track exists.
        For paid events: validates that price and stock are configured in Saleor.
        """
        event = self.get_object()

        # Permission check (same pattern as saleor_product)
        if not (request.user.is_superuser or event.created_by_id == request.user.id):
            raise PermissionDenied("You do not have permission to publish this event.")

        if event.status != "draft":
            return Response({"error": f"Event is already '{event.status}'."}, status=400)

        # Validate Application Required events
        if event.registration_type == 'apply':
            if not event.has_valid_application_tracks():
                return Response({
                    "error": "Application Required events must have at least one valid application track before publishing.",
                    "details": "Each track requires: label, key, submission mode(s), pricing tier(s), and role mapping(s)"
                }, status=400)
            event.status = "published"
            event.save(update_fields=["status"])
            serializer = self.get_serializer(event)
            return Response({"event": serializer.data}, status=200)

        if event.is_free:
            return Response({"error": "Free events are published automatically on creation."}, status=400)
        if not event.saleor_product_id:
            return Response({"error": "No Saleor product linked to this event."}, status=400)

        # Fetch Saleor product
        details = fetch_event_saleor_product_details(event.saleor_product_id)
        if "error" in details:
            return Response({"error": f"Failed to fetch Saleor product: {details['error']}"}, status=502)

        product = details.get("data", {}).get("product")
        if not product or not product.get("variants"):
            return Response({"error": "No product variant found in Saleor."}, status=400)

        variant = product["variants"][0]
        target_slug = getattr(settings, "SALEOR_CHANNEL_SLUG", "default-channel")

        # Extract default-channel price
        channel_price = None
        for cl in variant.get("channelListings", []):
            if cl.get("channel", {}).get("slug") == target_slug:
                channel_price = cl.get("price", {}).get("amount")
                break

        total_stock = sum(s.get("quantity", 0) for s in variant.get("stocks", []))

        validation = {
            "channel_slug": target_slug,
            "channel_price": channel_price,
            "has_valid_price": channel_price is not None and float(channel_price) > 0,
            "total_stock": total_stock,
            "has_valid_stock": total_stock > 0,
        }

        if not validation["has_valid_price"]:
            return Response(
                {"error": f"Channel '{target_slug}' price must be greater than 0.", "validation": validation},
                status=400,
            )
        if not validation["has_valid_stock"]:
            return Response({"error": "Total warehouse stock must be greater than 0.", "validation": validation}, status=400)

        # Publish
        event.price = float(channel_price)
        event.max_participants = total_stock
        event.is_free = False
        event.status = "published"
        event.save(update_fields=["price", "max_participants", "is_free", "status"])

        serializer = self.get_serializer(event)
        return Response({"event": serializer.data, "validation": validation}, status=200)

    # POST /api/events/{id}/unpublish/
    @action(detail=True, methods=["post"], permission_classes=[IsCreatorOrReadOnly], url_path="unpublish")
    def unpublish_event(self, request, pk=None):
        """
        Unpublish a published paid event, reverting it to draft status.
        This allows editing pricing, inventory, or other product details.
        """
        event = self.get_object()

        # Permission check
        if not (request.user.is_superuser or event.created_by_id == request.user.id):
            raise PermissionDenied("You do not have permission to unpublish this event.")

        if event.status != "published":
            return Response({"error": f"Only published events can be unpublished. Current status: '{event.status}'."}, status=400)
        if event.is_free:
            return Response({"error": "Free events cannot be unpublished."}, status=400)

        # Unpublish
        event.status = "draft"
        event.save(update_fields=["status"])

        serializer = self.get_serializer(event)
        return Response({"event": serializer.data, "message": "Event unpublished successfully."}, status=200)

    # GET/POST /api/events/{id}/saleor-discounts/
    @action(detail=True, methods=["get", "post"], permission_classes=[IsCreatorOrReadOnly], url_path="saleor-discounts")
    def saleor_discounts(self, request, pk=None):
        """
        GET: Fetch all discounts for this event.
        POST: Create a new discount for this event (paid events only).
        """
        event = self.get_object()

        # Permission check
        if not (request.user.is_superuser or event.created_by_id == request.user.id):
            raise PermissionDenied("You do not have permission to manage discounts for this event.")

        if request.method == "GET":
            if not event.is_free:
                try:
                    discounts = sync_event_saleor_discounts(event)
                except Exception as e:
                    logger.error(f"Bulk sync failed for event {event.id}: {e}")
                    discounts = event.saleor_discounts.filter(is_active=True).order_by('-created_at')
            else:
                discounts = event.saleor_discounts.filter(is_active=True).order_by('-created_at')
            serializer = EventSaleorDiscountSerializer(discounts, many=True)
            return Response({"discounts": serializer.data})

        elif request.method == "POST":
            # Only allow for paid events
            if event.is_free:
                logger.warning(f"Discount creation attempt on free event {event.id}")
                return Response(
                    {"error": "Discounts are only available for paid events."},
                    status=400
                )

            # Require saleor_product_id
            if not event.saleor_product_id:
                logger.warning(f"Discount creation attempt on event {event.id} without saleor_product_id")
                return Response(
                    {"error": "Save/sync Saleor product before creating discounts."},
                    status=400
                )

            logger.info(f"Creating discount for event {event.id} with data: {request.data}")
            serializer = EventSaleorDiscountSerializer(data=request.data)
            if not serializer.is_valid():
                logger.warning(f"Discount serializer validation failed for event {event.id}: {serializer.errors}")
                return Response({"errors": serializer.errors}, status=400)

            try:
                discount = create_event_saleor_discount(event, serializer.validated_data, user=request.user)
                response_serializer = EventSaleorDiscountSerializer(discount)
                return Response(response_serializer.data, status=201)
            except Exception as e:
                logger.exception(f"Error creating discount for event {event.id}")
                return Response({"error": str(e)}, status=400)

    # PATCH/DELETE /api/events/{id}/saleor-discounts/{discount_id}/
    @action(detail=True, methods=["patch", "delete"], permission_classes=[IsCreatorOrReadOnly], url_path=r"saleor-discounts/(?P<discount_id>[^/.]+)")
    def saleor_discount_detail(self, request, pk=None, discount_id=None):
        """
        PATCH: Update an existing discount.
        DELETE: Delete a discount.
        """
        event = self.get_object()

        # Permission check
        if not (request.user.is_superuser or event.created_by_id == request.user.id):
            raise PermissionDenied("You do not have permission to manage discounts for this event.")

        # Only allow for paid events
        if event.is_free:
            logger.warning(f"Discount operation attempt on free event {event.id}")
            return Response(
                {"error": "Discounts are only available for paid events."},
                status=400
            )

        try:
            discount = EventSaleorDiscount.objects.get(id=discount_id, event=event)
        except EventSaleorDiscount.DoesNotExist:
            return Response({"error": "Discount not found."}, status=404)

        if request.method == "PATCH":
            serializer = EventSaleorDiscountSerializer(discount, data=request.data, partial=True)
            if not serializer.is_valid():
                return Response(serializer.errors, status=400)

            try:
                discount = update_event_saleor_discount(discount, serializer.validated_data)
                response_serializer = EventSaleorDiscountSerializer(discount)
                return Response(response_serializer.data)
            except Exception as e:
                return Response({"error": str(e)}, status=400)

        elif request.method == "DELETE":
            try:
                delete_event_saleor_discount(discount)
                return Response(status=204)
            except Exception as e:
                return Response({"error": str(e)}, status=400)

    # POST /api/events/{id}/saleor-discounts/{discount_id}/sync/
    @action(detail=True, methods=["post"], permission_classes=[IsCreatorOrReadOnly], url_path=r"saleor-discounts/(?P<discount_id>[^/.]+)/sync")
    def sync_saleor_discount(self, request, pk=None, discount_id=None):
        """Sync discount data from Saleor back to ECP."""
        event = self.get_object()

        # Permission check
        if not (request.user.is_superuser or event.created_by_id == request.user.id):
            raise PermissionDenied("You do not have permission to manage discounts for this event.")

        # Only allow for paid events
        if event.is_free:
            logger.warning(f"Discount sync attempt on free event {event.id}")
            return Response(
                {"error": "Discounts are only available for paid events."},
                status=400
            )

        try:
            discount = EventSaleorDiscount.objects.get(id=discount_id, event=event)
        except EventSaleorDiscount.DoesNotExist:
            return Response({"error": "Discount not found."}, status=404)

        try:
            discount = sync_event_saleor_discount(discount)
            response_serializer = EventSaleorDiscountSerializer(discount)
            return Response(response_serializer.data)
        except Exception as e:
            return Response({"error": str(e)}, status=400)

    def _get_missing_lead_gen_fields(self, user):
        """
        Check if user has all required lead-generation fields for event registration.
        Validates from correct sources to avoid false positives:
        - Name: user.first_name/last_name (primary) or profile.full_name (fallback)
        - Email: user.email
        - Job Title: profile.job_title (primary) or latest Experience.position (fallback)
        - Company: profile.company (primary) or latest Experience.community_name (fallback)
        - Contact Number: profile.links.contact.phones
        - Country/Region: profile.location (country field, not just city)

        Returns: (is_complete, missing_fields_dict)
        - is_complete: Boolean - True if all fields present and non-empty
        - missing_fields_dict: Dict with field keys and display names
        """
        missing = {}

        # 1. Check name: user.first_name + user.last_name, or fallback to profile.full_name
        profile = getattr(user, 'profile', None)
        has_first_name = user.first_name and user.first_name.strip()
        has_last_name = user.last_name and user.last_name.strip()
        has_full_name = profile and profile.full_name and profile.full_name.strip()

        # Name is complete if either (first_name AND last_name) OR full_name
        if not ((has_first_name and has_last_name) or has_full_name):
            missing['first_name'] = 'First Name'
            missing['last_name'] = 'Last Name'

        # 2. Check email
        if not (user.email and user.email.strip()):
            missing['email'] = 'Email'

        # 3 & 4. Check job title and company from profile, and fetch latest experience once if needed
        has_job_title = profile and profile.job_title and profile.job_title.strip()
        has_company = profile and profile.company and profile.company.strip()

        # Only query latest_exp if either job_title or company is missing from profile
        latest_exp = None
        if not has_job_title or not has_company:
            latest_exp = user.experiences.order_by('-start_date').first()

        # Check job title fallback to latest experience
        if not has_job_title:
            has_job_title = latest_exp and latest_exp.position and latest_exp.position.strip()

        if not has_job_title:
            missing['job_title'] = 'Job Title'

        # Check company fallback to latest experience
        if not has_company:
            has_company = latest_exp and latest_exp.community_name and latest_exp.community_name.strip()

        if not has_company:
            missing['company'] = 'Company'

        # 5. Check country/region: profile.location (must be country/region, not just city)
        has_location = profile and profile.location and profile.location.strip()
        if not has_location:
            missing['location'] = 'Country/Region'

        # 6. Check contact number: profile.links.contact.phones (primary phone)
        has_phone = False
        if profile:
            phones = (profile.links or {}).get('contact', {}).get('phones', [])
            has_phone = any(p.get('number') and str(p.get('number')).strip() for p in phones)

        if not has_phone:
            missing['phone'] = 'Contact Number'

        return len(missing) == 0, missing

    # POST /api/events/{id}/register/
    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="register")
    def register(self, request, pk=None):
        """
        Register the current user for a single event.
        For 'apply' type events, only allows registration if user is already registered or has approved application.
        """
        event = self.get_object()

        if event.status == "cancelled":
            return Response({"detail": "Cannot register for a cancelled event."}, status=400)

        # Prevent /register/ from bypassing application requirement for 'apply' type events
        if event.registration_type == 'apply':
            is_already_registered = EventRegistration.objects.filter(
                event=event,
                user=request.user,
                status='registered'
            ).exists()
            has_approved_application = EventApplication.objects.filter(
                event=event,
                user=request.user,
                status='approved'
            ).exists()
            if not (is_already_registered or has_approved_application):
                return Response({
                    "detail": "This event requires an application. Please submit an application first.",
                    "code": "application_required"
                }, status=400)

        # Check if event is ended and replay access is not enabled
        if event.status == "ended":
            if not event.replay_enabled:
                return Response({"detail": "Replay sign-up is not enabled for this event."}, status=400)
            if not event.replay_visible_to_participants:
                return Response({"detail": "Replay is not available yet."}, status=400)

        # Check capactity limit
        if event.max_participants is not None:
            # We check if strict count >= max (note: race condition possible without lock, but acceptable for MVP)
            # Exclude this user if they are already registered to avoid false positive on re-register?
            # Actually get_or_create handles re-register.
            # But if new, we must check capacity.
            current_count = event.registrations.filter(status="registered").count()

            # If user is NOT already registered, check if full
            is_already_registered = event.registrations.filter(user=request.user, status="registered").exists()
            if not is_already_registered and current_count >= event.max_participants:
                return Response({"detail": "Event is full."}, status=409)

        if not event.is_free and event.price and event.price > 0:
            is_already_registered = event.registrations.filter(user=request.user, status__in=["registered", "waitlisted"]).exists()
            if not is_already_registered:
                return Response({"detail": "This is a paid event. Please purchase a ticket to register.", "code": "requires_payment"}, status=402)

        # ✅ Validate lead-generation fields before registration
        is_lead_gen_complete, missing_fields = self._get_missing_lead_gen_fields(request.user)
        if not is_lead_gen_complete:
            return Response({
                "status": "missing_lead_gen_fields",
                "detail": "Please complete your registration profile to register for this event.",
                "missing_fields": missing_fields
            }, status=400)

        # ✅ NEW: Set admission_status based on event's waiting_room_enabled setting
        # If waiting room is enabled, new users start as "waiting" for host admission
        # If waiting room is disabled, new users are automatically "admitted"
        #
        # ⚠️ IMPORTANT: This REGISTERS the user, but does NOT add them to the waiting room queue yet!
        # - admission_status="waiting" means they MIGHT need to wait (policy), but
        # - waiting_started_at is intentionally left NULL because they haven't JOINED yet
        #
        # Users are only added to the waiting room list when they actually JOIN the event
        # via the rtk/join endpoint, which sets waiting_started_at=now()
        initial_admission_status = "waiting" if event.waiting_room_enabled else "admitted"

        obj, was_created = EventRegistration.objects.get_or_create(
            user=request.user,
            event=event,
            defaults={"admission_status": initial_admission_status}
            # Note: waiting_started_at is NOT set here, only when user actively joins
        )

        if not was_created and obj.status in ['cancelled', 'deregistered']:
            # Reactivate the registration
            obj.status = 'registered'
            obj.admission_status = initial_admission_status # Reset admission status
            obj.save(update_fields=['status', 'admission_status'])
            was_created = True # Treat as created so we increment count below

        # Auto-assign Participant badge if registration has no badges
        if was_created and not obj.badge_labels.exists():
            participant_badge = event.get_or_create_participant_badge()
            obj.badge_labels.add(participant_badge)

        if was_created:
             Event.objects.filter(pk=event.pk).update(attending_count=F("attending_count") + 1)

        # Send acknowledgement email for first-time registration on open events
        if was_created and event.registration_type == 'open':
            from users.email_utils import send_user_registration_acknowledgement_email
            try:
                send_user_registration_acknowledgement_email(request.user, event)
                logger.info(f"Registration acknowledgement email sent to {request.user.email} for event {event.id}")
            except Exception as e:
                logger.error(f"Failed to send registration acknowledgement email: {e}")

        # Trigger post-acceptance forms for new registrations (both open and paid events)
        if was_created:
            try:
                from events.services import trigger_post_acceptance_forms

                # Set attendee_status to confirmed for open registration
                if event.registration_type == 'open':
                    obj.attendee_status = 'confirmed'
                    obj.save(update_fields=['attendee_status'])

                # Trigger form assignments (emails are sent automatically by service layer)
                created_assignments = trigger_post_acceptance_forms(obj)
                logger.info(f"Triggered {len(created_assignments) if created_assignments else 0} form assignments for registration {obj.id}")
            except Exception as e:
                logger.error(f"Failed to trigger post-acceptance forms for registration {obj.id}: {str(e)}", exc_info=True)

        # Create in-app notification for all successful registrations
        if was_created:
            from friends.models import notify_event_registration
            try:
                notify_event_registration(request.user, event)
            except Exception as e:
                logger.error(f"Failed to create registration notification: {e}")

        # Invalidate event list caches when registration changes
        try:
            from .cache_utils import invalidate_event_list_caches
            invalidate_event_list_caches(event.id)
        except Exception as e:
            logger.warning(f"Failed to invalidate event list cache for event {event.id}: {e}")

        return Response({"ok": True, "created": was_created, "event_id": event.id})

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="save-lead-gen-fields")
    def save_lead_gen_fields(self, request):
        """
        Save lead-generation fields to user profile.
        Accepts: first_name, last_name, email, job_title, company, location, phone
        """
        user = request.user
        profile = user.profile

        # Update user fields
        if 'first_name' in request.data:
            user.first_name = request.data['first_name']
        if 'last_name' in request.data:
            user.last_name = request.data['last_name']
        if 'email' in request.data:
            user.email = request.data['email']
        user.save()

        # Update profile fields
        if 'job_title' in request.data:
            profile.job_title = request.data['job_title']
        if 'company' in request.data:
            profile.company = request.data['company']
        if 'location' in request.data:
            profile.location = request.data['location']

        # Handle phone separately (it's in a nested structure)
        if 'phone' in request.data and request.data['phone']:
            if not profile.links:
                profile.links = {}
            if 'contact' not in profile.links:
                profile.links['contact'] = {}
            if 'phones' not in profile.links['contact']:
                profile.links['contact']['phones'] = []

            # Add or update phone (replace existing phones with new one)
            new_phone = {'number': request.data['phone'], 'type': 'mobile'}
            profile.links['contact']['phones'] = [new_phone]

        profile.save()

        from users.serializers import UserProfileSerializer
        serializer = UserProfileSerializer(profile)
        return Response({"status": "success", "profile": serializer.data})

    @action(detail=True, methods=["post", "get"], permission_classes=[AllowAny], url_path="apply")
    def apply(self, request, pk=None):
        """
        Apply to an event with 'apply' registration type.
        POST: Submit application (AUTHENTICATED ONLY - FIX 1)
        GET: Check own application status (authenticated only)

        FIX 1: Require authentication for applications to ensure accepted applicants
        become proper attendees with EventRegistration records.
        """
        event = self.get_object()

        if event.registration_type != 'apply':
            return Response({'detail': 'This event uses standard registration.'}, status=400)

        if request.method == 'POST':
            # FIX 1: Require authentication to apply
            if not request.user.is_authenticated:
                return Response(
                    {'detail': 'You must be registered and logged in to apply for this event.'},
                    status=401
                )

            open_tracks = list(
                event.application_tracks
                .filter(is_active=True, status='open')
                .order_by('sort_order', 'label')
            )
            if not open_tracks:
                return Response(
                    {'detail': 'Applications are not open yet. No application tracks are available for this event.'},
                    status=400
                )

        if request.method == 'GET':
            # Authenticated users: return their latest active application
            if request.user.is_authenticated:
                app = EventApplication.get_latest_active_application(event=event, user=request.user)
                if app:
                    # Fetch fresh with prefetch for latest track applications
                    app = EventApplication.objects.prefetch_related('track_applications').get(pk=app.pk)
                    return Response(EventApplicationSerializer(app).data)
                return Response({'status': 'none'})

            # Unauthenticated users: check by email (passed as query param)
            email = request.query_params.get('email', '').strip().lower()
            if email:
                app = EventApplication.get_latest_active_application(event=event, email=email)
                if app:
                    # Fetch fresh with prefetch for latest track applications
                    app = EventApplication.objects.prefetch_related('track_applications').get(pk=app.pk)
                    return Response(EventApplicationSerializer(app).data)
                return Response({'status': 'none'})

            return Response({'status': 'none'})

        # POST — submit application
        serializer = EventApplicationSubmitSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # ✅ For authenticated users, validate lead-generation fields
        if request.user.is_authenticated:
            is_lead_gen_complete, missing_fields = self._get_missing_lead_gen_fields(request.user)
            if not is_lead_gen_complete:
                return Response({
                    "status": "missing_lead_gen_fields",
                    "detail": "Please complete your registration profile to submit an application.",
                    "missing_fields": missing_fields
                }, status=400)

        email = (data.get('email') or '').strip().lower()
        submitted_code = (data.get('preapproved_code') or '').strip()
        attendee_marker_value = bool(data.get("attendee_marker_value", False))
        comments = (data.get("comments") or "").strip()

        # Phase 3: Handle submission mode and track selection
        submission_mode = data.get('submission_mode', EventApplication.SUBMISSION_MODE_SELF)
        track_id = data.get('track_id')
        track_key = data.get('track_key')
        track_applications_payload = data.get('track_applications') or []
        application_track = None

        if not track_id and not track_key and not track_applications_payload:
            if len(open_tracks) == 1:
                application_track = open_tracks[0]
                if 'submission_mode' not in request.data:
                    enabled_modes = application_track.enabled_submission_modes or []
                    if len(enabled_modes) == 1:
                        submission_mode = enabled_modes[0]
            else:
                return Response(
                    {'detail': 'Please select an application track before applying.'},
                    status=400
                )

        # Resolve track by ID or key
        if track_id or track_key:
            try:
                if track_id:
                    application_track = EventApplicationTrack.objects.get(id=track_id, event=event)
                else:
                    application_track = EventApplicationTrack.objects.get(key=track_key, event=event)

                if not application_track.is_active or application_track.status != 'open':
                    return Response({'detail': 'Application track is not open.'}, status=400)

                # Validate submission_mode is enabled for this track
                enabled_modes = application_track.enabled_submission_modes or []
                if submission_mode not in enabled_modes:
                    return Response(
                        {'detail': f'Submission mode "{submission_mode}" is not enabled for this track.'},
                        status=400
                    )
            except EventApplicationTrack.DoesNotExist:
                return Response({'detail': 'Application track not found.'}, status=404)

        # Validate mode-specific required fields
        # Note: For confirmed mode, pre_approval_code is conditionally required - only if email is not allowlisted
        mode_required_fields = {
            EventApplication.SUBMISSION_MODE_SELF: ['first_name', 'last_name', 'email'],
            EventApplication.SUBMISSION_MODE_CONFIRMED: ['first_name', 'last_name', 'email', 'sponsor_organization'],
            EventApplication.SUBMISSION_MODE_SELF_NOMINATION: ['first_name', 'last_name', 'email'],
            EventApplication.SUBMISSION_MODE_THIRD_PARTY: ['nominator_name', 'nominator_email', 'nominee_name', 'nominee_email'],
        }

        required_fields = (
            ['first_name', 'last_name', 'email']
            if track_applications_payload
            else mode_required_fields.get(submission_mode, [])
        )
        missing_fields = []
        for field in required_fields:
            # Special handling for pre_approval_code - map to preapproved_code in payload
            if field == 'pre_approval_code':
                if not (data.get('preapproved_code') or '').strip():
                    missing_fields.append('pre_approval_code')
            else:
                if not (data.get(field) or '').strip():
                    missing_fields.append(field)

        if missing_fields:
            return Response({
                'detail': 'Missing required fields for this submission mode.',
                'missing_fields': missing_fields,
                'submission_mode': submission_mode
            }, status=400)

        with transaction.atomic():
            locked_event = Event.objects.select_for_update().get(pk=event.pk)

            # Check for existing applications and registrations
            # Strategy: Check child EventApplicationTrackApplication statuses instead of parent status
            #
            # Active (blocks reapplication) - ANY child with these statuses:
            #   - pending: still under review
            #   - pre_approved: pre-approved by admin
            #   - accepted: already accepted
            #   - waitlisted: on waitlist (active state)
            #
            # Reusable (allows reapplication) - ALL children with these statuses:
            #   - declined: user rejected
            #   - cancelled: user withdrew
            #   - withdrawn: user withdrew (alias for cancelled)
            #
            # Also update parent status:
            #   - If all children are declined/cancelled/withdrawn, set parent to 'declined'

            # Get all EventApplications for this user/email/event
            existing_apps = list(EventApplication.objects.filter(
                event=locked_event,
                email=email
            ).prefetch_related('track_applications').order_by('-applied_at'))

            # Blocking statuses: if ANY child has these, block reapplication
            blocking_child_statuses = ['pending', 'pre_approved', 'accepted', 'waitlisted']
            reusable_child_statuses = ['declined', 'cancelled']

            active_app_for_blocking = None
            reusable_app = None

            for app in existing_apps:
                track_apps = list(app.track_applications.all())

                # If no track applications yet, check parent status for legacy compatibility
                if not track_apps:
                    if app.status in ['pending', 'approved']:
                        active_app_for_blocking = app
                        break
                    elif app.status in ['declined', 'cancelled']:
                        if not reusable_app:
                            reusable_app = app

                # Check child statuses
                child_statuses = [ta.status for ta in track_apps]
                has_active_child = any(status in blocking_child_statuses for status in child_statuses)
                all_children_reusable = all(status in reusable_child_statuses for status in child_statuses)

                if has_active_child:
                    # This application has active children - block reapplication
                    active_app_for_blocking = app
                    break
                elif all_children_reusable and track_apps:
                    # All children are declined/cancelled - this is reusable
                    if not reusable_app:
                        reusable_app = app

            if active_app_for_blocking:
                return Response(
                    {'detail': 'You already have an active application for this event.'},
                    status=400
                )

            # Check pre-approved applications (cannot reapply, must use pre-approval code)
            # Only block if is_preapproved=True AND has active children
            existing_preapproved = None
            for app in existing_apps:
                if app.is_preapproved:
                    track_apps = list(app.track_applications.all())
                    if not track_apps:
                        # Legacy: no track apps, check parent status
                        if app.status not in ['declined', 'cancelled']:
                            existing_preapproved = app
                            break
                    else:
                        # Check if has active children
                        child_statuses = [ta.status for ta in track_apps]
                        if any(status in blocking_child_statuses for status in child_statuses):
                            existing_preapproved = app
                            break

            if existing_preapproved:
                return Response(
                    {'detail': 'You have a pre-approved application for this event. Use your pre-approval code to apply.'},
                    status=400
                )

            # Check active registrations (user already attending, cannot reapply)
            from events.models import EventRegistration
            existing_registration = EventRegistration.objects.filter(
                event=locked_event,
                user__email=email if request.user.is_authenticated else None,
                status__in=['registered', 'cancellation_requested']
            ).first() if request.user.is_authenticated else None

            if existing_registration:
                return Response(
                    {'detail': 'You are already registered for this event.'},
                    status=400
                )

            # Use the reusable_app we found earlier (cancelled, declined, or approved-all-declined)
            # No need to query again - we already have it from the check above

            # Resolve and validate target tracks before creating the parent application.
            # This prevents legacy parent-only EventApplication rows that never appear in Review Queue.
            tracks_to_apply = []
            track_configs = {}

            if application_track:
                tracks_to_apply = [application_track]
                track_configs[application_track] = {
                    'submission_mode': submission_mode,
                    'tier_preference_id': data.get('tier_preference') or data.get('requested_tier'),
                    'form_answers': data.get('form_answers', {}),
                    'file_uploads': data.get('file_uploads', {}),
                    'nominator_name': data.get('nominator_name', ''),
                    'nominator_email': data.get('nominator_email', ''),
                    'nominee_name': data.get('nominee_name', ''),
                    'nominee_email': data.get('nominee_email', ''),
                    'nominee_details': data.get('nominee_details') or {},
                    'sponsor_organization': data.get('sponsor_organization', ''),
                    'pre_approval_code': data.get('pre_approval_code') or data.get('preapproved_code') or '',
                }
            elif track_applications_payload:
                if isinstance(track_applications_payload, list):
                    track_validation_errors = []
                    for idx, track_app_data in enumerate(track_applications_payload):
                        track_id_item = track_app_data.get('track_id')
                        track_key_item = track_app_data.get('track_key')

                        if not track_id_item and not track_key_item:
                            track_validation_errors.append({
                                'index': idx,
                                'error': 'Track data missing track_id or track_key'
                            })
                            continue

                        try:
                            if track_id_item:
                                t = EventApplicationTrack.objects.get(id=track_id_item, event=locked_event)
                            else:
                                t = EventApplicationTrack.objects.get(key=track_key_item, event=locked_event)

                            if not t.is_active or t.status != 'open':
                                track_validation_errors.append({
                                    'track_id': t.id,
                                    'track_key': t.key,
                                    'error': f'Track "{t.label}" is not open'
                                })
                                continue

                            tracks_to_apply.append(t)
                            track_configs[t] = {
                                'submission_mode': track_app_data.get('submission_mode', submission_mode),
                                'tier_preference_id': track_app_data.get('tier_preference_id'),
                                'form_answers': track_app_data.get('form_answers', {}),
                                'file_uploads': track_app_data.get('file_uploads', {}),
                                'nominator_name': track_app_data.get('nominator_name', ''),
                                'nominator_email': track_app_data.get('nominator_email', ''),
                                'nominee_name': track_app_data.get('nominee_name', ''),
                                'nominee_email': track_app_data.get('nominee_email', ''),
                                'nominee_details': track_app_data.get('nominee_details') or {},
                                'sponsor_organization': track_app_data.get('sponsor_organization', ''),
                                'pre_approval_code': track_app_data.get('pre_approval_code', '')
                            }
                        except EventApplicationTrack.DoesNotExist:
                            track_validation_errors.append({
                                'track_id': track_id_item,
                                'track_key': track_key_item,
                                'error': 'Track not found for this event'
                            })

                    if track_validation_errors:
                        return Response({
                            'detail': 'One or more requested tracks are invalid or unavailable',
                            'track_errors': track_validation_errors
                        }, status=400)

            if not tracks_to_apply:
                return Response(
                    {'detail': 'Please select an application track before applying.'},
                    status=400
                )

            per_track_required_fields = {
                EventApplication.SUBMISSION_MODE_SELF: ['first_name', 'last_name', 'email'],
                EventApplication.SUBMISSION_MODE_CONFIRMED: ['first_name', 'last_name', 'email', 'sponsor_organization'],
                EventApplication.SUBMISSION_MODE_SELF_NOMINATION: ['first_name', 'last_name', 'email'],
                EventApplication.SUBMISSION_MODE_THIRD_PARTY: ['nominator_name', 'nominator_email', 'nominee_name', 'nominee_email'],
            }

            for track in tracks_to_apply:
                track_config = track_configs.get(track, {})
                track_submission_mode = track_config.get('submission_mode', submission_mode)
                enabled_modes = track.enabled_submission_modes or []

                if track_submission_mode not in enabled_modes:
                    return Response({
                        'detail': f'Submission mode "{track_submission_mode}" is not enabled for track "{track.label}"',
                        'track_id': track.id,
                        'submission_mode': track_submission_mode,
                        'enabled_modes': enabled_modes
                    }, status=400)

                track_errors = []
                for field in per_track_required_fields.get(track_submission_mode, []):
                    field_value = track_config.get(field)
                    if field_value is None or field_value == '':
                        field_value = data.get(field)
                    if not (field_value or '').strip():
                        track_errors.append(field)

                if track_errors:
                    return Response({
                        'detail': f'Missing required fields for track "{track.label}" with {track_submission_mode} submission mode',
                        'missing_fields': track_errors,
                        'track_id': track.id,
                        'submission_mode': track_submission_mode
                    }, status=400)

            # FIX: Validate pre-approval for all tracks BEFORE creating application
            # This prevents creating a Pending application when code is wrong
            for track in tracks_to_apply:
                track_config = track_configs.get(track, {})
                track_submission_mode = track_config.get('submission_mode', submission_mode)
                track_preapproval_code = (track_config.get('pre_approval_code') or submitted_code or '').strip()

                # For confirmed mode, must validate pre-approval NOW (before creating app)
                # Use OR logic: valid code OR valid allowlist entry
                if track_submission_mode == EventApplication.SUBMISSION_MODE_CONFIRMED:
                    track_is_preapproved = False

                    # Check if feature is enabled when code is submitted
                    if track_preapproval_code and not locked_event.preapproval_code_enabled:
                        return Response({
                            'detail': f'Pre-approval codes are not enabled for this event. Contact the event organizer to enable pre-approval codes.',
                            'code_error': 'feature_disabled',
                            'track_id': track.id,
                            'submission_mode': track_submission_mode
                        }, status=400)

                    # Check pre-approval code first
                    if track_preapproval_code and locked_event.preapproval_code_enabled:
                        from django.db.models import Q
                        existing_code = EventPreApprovalCode.objects.filter(
                            event=locked_event,
                            code=track_preapproval_code
                        ).first()

                        if not existing_code:
                            return Response({
                                'detail': f'Invalid pre-approval code for track "{track.label}".',
                                'code_error': 'invalid',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)

                        if existing_code.status == EventPreApprovalCode.STATUS_REVOKED:
                            return Response({
                                'detail': f'Pre-approval code has been revoked and cannot be used for track "{track.label}".',
                                'code_error': 'revoked',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)

                        if existing_code.status == EventPreApprovalCode.STATUS_USED:
                            return Response({
                                'detail': f'Pre-approval code has already been used for track "{track.label}".',
                                'code_error': 'used',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)

                        # Check if code is valid for this track + mode combination
                        code_valid_for_track = EventPreApprovalCode.objects.filter(
                            Q(track_id=track.id) | Q(track_id__isnull=True),
                            Q(submission_mode=track_submission_mode) | Q(submission_mode=''),
                            event=locked_event,
                            code=track_preapproval_code,
                            status=EventPreApprovalCode.STATUS_ACTIVE,
                        ).exists()

                        if not code_valid_for_track:
                            return Response({
                                'detail': f'Pre-approval code is not valid for "{track.label}" with {track_submission_mode} submission mode.',
                                'code_error': 'wrong_track_mode',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)

                        track_is_preapproved = True

                    # Check email allowlist if code didn't pre-approve
                    if not track_is_preapproved and email and locked_event.preapproval_allowlist_enabled:
                        from django.db.models import Q
                        track_allowlist = EventPreApprovalAllowlist.objects.filter(
                            Q(track_id=track.id) | Q(track_id__isnull=True),
                            Q(submission_mode=track_submission_mode) | Q(submission_mode=''),
                            event=locked_event,
                            email=email,
                            is_active=True,
                        ).first()
                        if track_allowlist:
                            track_is_preapproved = True

                    # If still not pre-approved, reject confirmed mode submission (no code and no allowlist)
                    if not track_is_preapproved:
                        if not track_preapproval_code:
                            return Response({
                                'detail': f'Pre-approval code is required for confirmed submission mode on track "{track.label}" or email must be pre-approved.',
                                'code_error': 'missing',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)
                        # Code was provided but neither condition above matched
                        return Response({
                            'detail': f'Pre-approval code is not valid for "{track.label}" with {track_submission_mode} submission mode.',
                            'code_error': 'wrong_track_mode',
                            'track_id': track.id,
                            'submission_mode': track_submission_mode
                        }, status=400)

            # Phase 8: Global pre-approval validation (legacy/backward compatibility only)
            # For single-track or old clients submitting at root level
            # Real validation happens PER-TRACK inside the loop below
            preapproval_source = EventApplication.PREAPPROVAL_SOURCE_NONE
            code_obj = None
            allowlist_entry = None

            # Only use global validation for single-track (not multi-track)
            if application_track and submitted_code and locked_event.preapproval_code_enabled:
                from django.db.models import Q
                code_obj = (
                    EventPreApprovalCode.objects
                    .select_for_update()
                    .filter(
                        Q(track_id=application_track.id) | Q(track_id__isnull=True),
                        Q(submission_mode=submission_mode) | Q(submission_mode=''),
                        event=locked_event,
                        code=submitted_code,
                        status=EventPreApprovalCode.STATUS_ACTIVE,
                    )
                    .first()
                )
                if code_obj:
                    preapproval_source = EventApplication.PREAPPROVAL_SOURCE_CODE

            # Email allowlist for global (single-track)
            if (
                preapproval_source == EventApplication.PREAPPROVAL_SOURCE_NONE
                and application_track
                and locked_event.preapproval_allowlist_enabled
                and email
            ):
                from django.db.models import Q
                allowlist_entry = (
                    EventPreApprovalAllowlist.objects
                    .filter(
                        Q(track_id=application_track.id) | Q(track_id__isnull=True),
                        Q(submission_mode=submission_mode) | Q(submission_mode=''),
                        event=locked_event,
                        email=email,
                        is_active=True,
                    )
                    .first()
                )
                if allowlist_entry:
                    preapproval_source = EventApplication.PREAPPROVAL_SOURCE_EMAIL

            # Note: For multi-track submissions, per-track pre-approval is checked in the loop below
            # This global flag is only used for legacy single-track submissions

            is_preapproved = preapproval_source != EventApplication.PREAPPROVAL_SOURCE_NONE
            now = timezone.now()
            status_value = "approved" if is_preapproved else "pending"
            reviewed_at = now if is_preapproved else None
            reviewed_by = request.user if is_preapproved and request.user.is_authenticated else None

            nomination_config = next(
                (
                    config for config in track_configs.values()
                    if config.get('submission_mode') == EventApplication.SUBMISSION_MODE_THIRD_PARTY
                ),
                {}
            )
            confirmed_config = next(
                (
                    config for config in track_configs.values()
                    if config.get('submission_mode') == EventApplication.SUBMISSION_MODE_CONFIRMED
                ),
                {}
            )

            def first_non_empty(field_name, source_config):
                return data.get(field_name) or source_config.get(field_name) or ''

            # Extract sponsor_organization: prefer root level, then from track_configs (for multi-track confirmed mode)
            sponsor_organization_value = (data.get("sponsor_organization") or "").strip()
            if not sponsor_organization_value:
                for track, track_cfg in track_configs.items():
                    if track_cfg.get('submission_mode') == EventApplication.SUBMISSION_MODE_CONFIRMED:
                        sponsor_org_from_track = (track_cfg.get('sponsor_organization') or "").strip()
                        if sponsor_org_from_track:
                            sponsor_organization_value = sponsor_org_from_track
                            break

            # Reuse reusable application (cancelled/declined/approved-all-declined) if it exists, otherwise create new
            if reusable_app:
                # Update the cancelled/declined application back to pending/approved
                app = reusable_app
                app.user = request.user if request.user.is_authenticated else app.user
                app.first_name = (data.get("first_name") or "").strip()
                app.last_name = (data.get("last_name") or "").strip()
                app.email = email
                app.job_title = (data.get("job_title") or "").strip()
                app.company_name = (data.get("company_name") or "").strip()
                app.linkedin_url = (data.get("linkedin_url") or "").strip()
                app.attendee_marker_value = attendee_marker_value
                app.comments = comments
                app.status = status_value
                app.reviewed_at = reviewed_at
                app.reviewed_by = reviewed_by
                app.is_preapproved = is_preapproved
                app.preapproval_source = preapproval_source
                app.preapproval_code = code_obj
                app.preapproval_allowlist_entry = allowlist_entry
                app.preapproved_at = now if is_preapproved else None
                app.application_track = application_track
                app.submission_mode = submission_mode
                app.nominator_name = (data.get("nominator_name") or "").strip()
                app.nominator_email = (data.get("nominator_email") or "").strip()
                app.nominee_name = (data.get("nominee_name") or "").strip()
                app.nominee_email = (data.get("nominee_email") or "").strip()
                app.nominee_details = data.get("nominee_details") or {}
                app.sponsor_organization = sponsor_organization_value
                app.save()

                # Delete old cancelled/declined track applications so we can create fresh ones
                app.track_applications.filter(status__in=['cancelled', 'declined']).delete()
            else:
                # Create new application
                app = EventApplication.objects.create(
                    event=locked_event,
                    user=request.user if request.user.is_authenticated else None,
                    first_name=(data.get("first_name") or "").strip(),
                    last_name=(data.get("last_name") or "").strip(),
                    email=email,
                    job_title=(data.get("job_title") or "").strip(),
                    company_name=(data.get("company_name") or "").strip(),
                    linkedin_url=(data.get("linkedin_url") or "").strip(),
                    attendee_marker_value=attendee_marker_value,
                    comments=comments,
                    status=status_value,
                    reviewed_at=reviewed_at,
                    reviewed_by=reviewed_by,
                    is_preapproved=is_preapproved,
                    preapproval_source=preapproval_source,
                    preapproval_code=code_obj,
                    preapproval_allowlist_entry=allowlist_entry,
                    preapproved_at=now if is_preapproved else None,
                    # Phase 3: Submission modes
                    application_track=application_track,
                    submission_mode=submission_mode,
                    nominator_name=(data.get("nominator_name") or "").strip(),
                    nominator_email=(data.get("nominator_email") or "").strip(),
                    nominee_name=(data.get("nominee_name") or "").strip(),
                    nominee_email=(data.get("nominee_email") or "").strip(),
                    nominee_details=data.get("nominee_details") or {},
                    sponsor_organization=sponsor_organization_value,
                )

            if code_obj and is_preapproved:
                code_obj.status = EventPreApprovalCode.STATUS_USED
                code_obj.used_by_application = app
                code_obj.used_by_user = request.user if request.user.is_authenticated else None
                code_obj.used_by_email = email
                code_obj.used_at = now
                code_obj.save(update_fields=["status", "used_by_application", "used_by_user", "used_by_email", "used_at"])

            # Create EventApplicationTrackApplication for each track
            track_app_objects = []
            for track in tracks_to_apply:
                # FIX 1: Use per-track configuration from track_configs
                track_config = track_configs.get(track, {})
                track_submission_mode = track_config.get('submission_mode', submission_mode)
                tier_preference_id = track_config.get('tier_preference_id')
                form_answers = track_config.get('form_answers', {})
                file_uploads = track_config.get('file_uploads', {})

                # FIX 5: Validate submission mode is enabled for this track
                # Do NOT silently skip - return 400 error to prevent silent submission failures
                enabled_modes = track.enabled_submission_modes or []
                if track_submission_mode not in enabled_modes:
                    return Response({
                        'detail': f'Submission mode "{track_submission_mode}" is not enabled for track "{track.label}"',
                        'track_id': track.id,
                        'submission_mode': track_submission_mode,
                        'enabled_modes': enabled_modes
                    }, status=400)

                # Validate per-track required fields based on submission mode.
                # Multi-track payloads carry nomination/confirmed fields inside each track application,
                # while older single-track payloads may still send them at the top level.
                required_fields_for_mode = per_track_required_fields.get(track_submission_mode, [])
                track_errors = []
                for field in required_fields_for_mode:
                    # For confirmed mode with multi-track, check sponsor_organization in track_config first
                    if field == 'sponsor_organization' and track_submission_mode == EventApplication.SUBMISSION_MODE_CONFIRMED:
                        sponsor_org = (track_config.get('sponsor_organization') or data.get(field) or '').strip()
                        if not sponsor_org:
                            track_errors.append(field)
                    else:
                        if not (data.get(field) or '').strip():
                            track_errors.append(field)

                # FIX 2: Return error if any required fields missing - do NOT skip silently
                if track_errors:
                    return Response({
                        'detail': f'Missing required fields for track "{track.label}" with {track_submission_mode} submission mode',
                        'missing_fields': track_errors,
                        'track_id': track.id,
                        'submission_mode': track_submission_mode
                    }, status=400)

                # Get tier preference if provided
                tier_preference = None

                if tier_preference_id:
                    try:
                        # Check tier belongs to this track
                        tier_preference = TrackPricingTier.objects.get(
                            id=tier_preference_id,
                            track=track
                        )
                    except TrackPricingTier.DoesNotExist:
                        logger.warning(f"Tier {tier_preference_id} not found for track {track.id}")
                        tier_preference = None

                # FIX 4: Check pre-approval per track + submission_mode inside loop
                track_is_preapproved = False
                track_preapproval_source = EventApplication.PREAPPROVAL_SOURCE_NONE
                track_preapproval_code_obj = None

                # Get pre_approval_code from track_config first (multi-track), then root level
                track_preapproval_code = (track_config.get('pre_approval_code') or submitted_code or '').strip()

                # For confirmed mode, pre_approval_code is optional if email is allowlisted
                # Check both code and allowlist (OR logic)
                if track_submission_mode == EventApplication.SUBMISSION_MODE_CONFIRMED:
                    if track_preapproval_code and locked_event.preapproval_code_enabled:
                        from django.db.models import Q
                        # First check if code exists (any status)
                        existing_code = EventPreApprovalCode.objects.filter(
                            Q(track_id=track.id) | Q(track_id__isnull=True),
                            Q(submission_mode=track_submission_mode) | Q(submission_mode=''),
                            event=locked_event,
                            code=track_preapproval_code,
                        ).first()

                        if not existing_code:
                            # Code doesn't exist for this track/mode combination
                            return Response({
                                'detail': f'Pre-approval code is not valid for track "{track.label}" with {track_submission_mode} submission mode.',
                                'code_error': 'invalid',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)

                        # Code exists, check its status
                        if existing_code.status == EventPreApprovalCode.STATUS_REVOKED:
                            return Response({
                                'detail': 'Pre-approval code has been revoked and can no longer be used.',
                                'code_error': 'revoked',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)

                        if existing_code.status == EventPreApprovalCode.STATUS_USED:
                            return Response({
                                'detail': 'Pre-approval code has already been used.',
                                'code_error': 'used',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)

                        if existing_code.status == EventPreApprovalCode.STATUS_ACTIVE:
                            track_is_preapproved = True
                            track_preapproval_source = EventApplication.PREAPPROVAL_SOURCE_CODE
                            track_preapproval_code_obj = existing_code

                    # Check email allowlist for confirmed mode too (if code didn't pre-approve)
                    if not track_is_preapproved and email and locked_event.preapproval_allowlist_enabled:
                        from django.db.models import Q
                        track_allowlist = EventPreApprovalAllowlist.objects.filter(
                            Q(track_id=track.id) | Q(track_id__isnull=True),
                            Q(submission_mode=track_submission_mode) | Q(submission_mode=''),
                            event=locked_event,
                            email=email,
                            is_active=True,
                        ).first()
                        if track_allowlist:
                            track_is_preapproved = True
                            track_preapproval_source = EventApplication.PREAPPROVAL_SOURCE_EMAIL

                # For non-confirmed modes, check optional pre-approval code and email allowlist
                elif track_submission_mode != EventApplication.SUBMISSION_MODE_CONFIRMED:
                    if track_preapproval_code and locked_event.preapproval_code_enabled:
                        from django.db.models import Q
                        track_code = EventPreApprovalCode.objects.filter(
                            Q(track_id=track.id) | Q(track_id__isnull=True),
                            Q(submission_mode=track_submission_mode) | Q(submission_mode=''),
                            event=locked_event,
                            code=track_preapproval_code,
                            status=EventPreApprovalCode.STATUS_ACTIVE,
                        ).first()
                        if track_code:
                            track_is_preapproved = True
                            track_preapproval_source = EventApplication.PREAPPROVAL_SOURCE_CODE
                            track_preapproval_code_obj = track_code

                    if not track_is_preapproved and email and locked_event.preapproval_allowlist_enabled:
                        from django.db.models import Q
                        track_allowlist = EventPreApprovalAllowlist.objects.filter(
                            Q(track_id=track.id) | Q(track_id__isnull=True),
                            Q(submission_mode=track_submission_mode) | Q(submission_mode=''),
                            event=locked_event,
                            email=email,
                            is_active=True,
                        ).first()
                        if track_allowlist:
                            track_is_preapproved = True
                            track_preapproval_source = EventApplication.PREAPPROVAL_SOURCE_EMAIL

                # FIX 3: Strict validation for confirmed mode - must have valid pre-approval (code OR allowlist)
                if track_submission_mode == EventApplication.SUBMISSION_MODE_CONFIRMED:
                    if not track_is_preapproved:
                        # Confirmed mode has no valid pre-approval (neither code nor allowlist) - return clear error
                        if not track_preapproval_code:
                            # No code provided at all - email not in allowlist either
                            return Response({
                                'detail': f'Your email is not pre-approved for track "{track.label}". Please provide a pre-approval code or contact the event organizer.',
                                'code_error': 'missing',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)

                        # Code was provided but not valid - check why
                        existing_code = EventPreApprovalCode.objects.filter(
                            event=locked_event,
                            code=track_preapproval_code
                        ).first()

                        if not existing_code:
                            return Response({
                                'detail': f'Invalid pre-approval code for track "{track.label}".',
                                'code_error': 'invalid',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)

                        if existing_code.status == EventPreApprovalCode.STATUS_REVOKED:
                            return Response({
                                'detail': f'Pre-approval code has been revoked and cannot be used for track "{track.label}".',
                                'code_error': 'revoked',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)

                        if existing_code.status == EventPreApprovalCode.STATUS_USED:
                            return Response({
                                'detail': f'Pre-approval code has already been used for track "{track.label}".',
                                'code_error': 'used',
                                'track_id': track.id,
                                'submission_mode': track_submission_mode
                            }, status=400)

                        # Code exists but not for this specific track/mode combination
                        return Response({
                            'detail': f'Pre-approval code is not valid for "{track.label}" with {track_submission_mode} submission mode.',
                            'code_error': 'wrong_track_mode',
                            'track_id': track.id,
                            'submission_mode': track_submission_mode
                        }, status=400)

                # FIX 2: Use "pre_approved" instead of "approved" for pre-approved status
                track_status = 'pre_approved' if track_is_preapproved else 'pending'

                # FIX 7: Use track-specific pre-approval flags, not global is_preapproved
                track_reviewed_at = now if track_is_preapproved else None
                track_reviewed_by = request.user if track_is_preapproved and request.user.is_authenticated else None

                # Create track application
                track_app = EventApplicationTrackApplication.objects.create(
                    application=app,
                    track=track,
                    submission_mode=track_submission_mode,
                    status=track_status,
                    tier_preference=tier_preference,
                    form_answers=form_answers,
                    file_uploads=file_uploads,
                    reviewed_at=track_reviewed_at,
                    reviewed_by=track_reviewed_by,
                )
                track_app_objects.append(track_app)
                logger.info(f"Created EventApplicationTrackApplication {track_app.id} for track {track.id} with mode={track_submission_mode}")

            # Mark pre-approval codes as used for confirmed mode tracks
            for track_app in track_app_objects:
                if track_app.status == 'pre_approved' and track_app.submission_mode == EventApplication.SUBMISSION_MODE_CONFIRMED:
                    # Get the pre-approval code for this track from track_configs
                    track = track_app.track
                    track_config = track_configs.get(track, {})
                    track_preapproval_code_to_mark = (track_config.get('pre_approval_code') or submitted_code or '').strip()

                    if track_preapproval_code_to_mark and locked_event.preapproval_code_enabled:
                        from django.db.models import Q
                        code_to_mark = EventPreApprovalCode.objects.filter(
                            Q(track_id=track.id) | Q(track_id__isnull=True),
                            Q(submission_mode=EventApplication.SUBMISSION_MODE_CONFIRMED) | Q(submission_mode=''),
                            event=locked_event,
                            code=track_preapproval_code_to_mark,
                            status=EventPreApprovalCode.STATUS_ACTIVE,
                        ).first()
                        if code_to_mark:
                            code_to_mark.status = EventPreApprovalCode.STATUS_USED
                            code_to_mark.used_by_application = app
                            code_to_mark.used_by_user = request.user if request.user.is_authenticated else None
                            code_to_mark.used_by_email = email
                            code_to_mark.used_at = now
                            code_to_mark.save(update_fields=["status", "used_by_application", "used_by_user", "used_by_email", "used_at"])
                            logger.info(f"Marked pre-approval code as used for application {app.id}")

            # FIX 2: Auto-accept pre-approved track applications independently (per-track, not global)
            # Do NOT depend on global is_preapproved flag - check each track's individual status
            if request.user.is_authenticated:
                # Auto-accept pre-approved applications using the proper acceptance flow
                # This ensures roles are assigned, attendee origins created, and forms triggered
                from events.services.application_decisions import accept_track_application
                try:
                    # Only auto-accept track apps with pre_approved status
                    for track_app in track_app_objects:
                        if track_app.status == 'pre_approved':
                            # Accept with system/admin user for auto-approval
                            # Use the requesting user as the reviewer (they approved via code/email)
                            accept_track_application(
                                track_app,
                                request.user,  # Reviewer is the applicant themselves (system auto-approval)
                                accepted_tier=None,  # Will use preference or default
                                notes=f"Auto-accepted via pre-approval"
                            )
                    # Log only if any tracks were actually auto-accepted
                    pre_approved_count = sum(1 for ta in track_app_objects if ta.status == 'pre_approved')
                    if pre_approved_count > 0:
                        logger.info(f"Application {app.id} auto-accepted for {pre_approved_count} track(s) via pre-approval")
                except Exception as e:
                    logger.error(f"Failed to auto-accept pre-approved application {app.id}: {str(e)}", exc_info=True)
                    # Do not fail the application creation - track apps are created, just not accepted
                    # Admin can manually accept later if auto-acceptance fails

        # For guest applications: NO longer create GuestAttendee or JWT immediately
        # Guest will verify via OTP on event day when checking application status
        # GuestAttendee is created during guest-join (OTP) endpoint instead

        # Update parent application status to 'declined' if all child track applications are declined
        track_apps = list(app.track_applications.all())
        if track_apps:
            child_statuses = [ta.status for ta in track_apps]
            if all(status == 'declined' for status in child_statuses):
                app.status = 'declined'
                app.save(update_fields=['status'])

        if app.status == "pending":
            from users.email_utils import send_application_acknowledgement_email
            try:
                send_application_acknowledgement_email(app)
                logger.info(f"Acknowledgement email sent for application {app.id}")
            except Exception as e:
                logger.error(f"Failed to send acknowledgement email for application {app.id}: {e}")

        # Fetch fresh from database with prefetch_related to ensure serializer gets latest track applications
        # Critical after reapply: old track app cache is stale, need fresh prefetch
        app = EventApplication.objects.prefetch_related('track_applications').get(pk=app.pk)

        # Return application with computed status from latest track applications
        response_data = EventApplicationSerializer(app).data
        logger.info(f"Application {app.id} submitted with status: {response_data.get('application_status')}")

        return Response(response_data, status=201)

    @action(detail=True, methods=["post"], permission_classes=[AllowAny], url_path="preapproval/check-code")
    def check_preapproval_code(self, request, pk=None):
        event = self.get_object()
        if not event.preapproval_code_enabled:
            return Response({"preapproved": False, "reason": "disabled", "message": "Pre-approved codes are not enabled for this event."})

        code = (request.data.get("code") or "").strip()
        if not code:
            return Response({"preapproved": False, "reason": "invalid", "message": "This code is not valid."})

        # Phase 8: Accept track_id and submission_mode for fine-grained pre-approval checking
        track_id = request.data.get("track_id")
        submission_mode = (request.data.get("submission_mode") or "").strip()

        # Validate track exists if provided
        if track_id:
            if not EventApplicationTrack.objects.filter(id=track_id, event=event).exists():
                return Response({"preapproved": False, "reason": "invalid", "message": "Track not found."}, status=400)

        from django.db.models import Q
        code_obj = EventPreApprovalCode.objects.filter(
            # Phase 8: Filter by track + submission_mode (with backward compatibility)
            Q(track_id=track_id) | Q(track_id__isnull=True),
            Q(submission_mode=submission_mode) | Q(submission_mode=''),
            event=event,
            code=code,
        ).first()

        if not code_obj:
            return Response({"preapproved": False, "reason": "invalid", "message": "This code is not valid."})
        if code_obj.status == EventPreApprovalCode.STATUS_USED:
            return Response({"preapproved": False, "reason": "used", "message": "This code has already been used."})
        if code_obj.status == EventPreApprovalCode.STATUS_REVOKED:
            return Response({"preapproved": False, "reason": "revoked", "message": "This code is no longer active."})
        return Response({"preapproved": True, "source": "code", "message": "Valid pre-approved code."})

    @action(detail=True, methods=["post"], permission_classes=[AllowAny], url_path="preapproval/check-email")
    def check_preapproval_email(self, request, pk=None):
        event = self.get_object()
        if not event.preapproval_allowlist_enabled:
            return Response({"preapproved": False, "reason": "disabled"})

        email = (request.data.get("email") or "").strip().lower()
        if not email:
            return Response({"preapproved": False, "reason": "not_found"})

        # Phase 8: Accept track_id and submission_mode for fine-grained pre-approval checking
        track_id = request.data.get("track_id")
        submission_mode = (request.data.get("submission_mode") or "").strip()

        # Validate track exists if provided
        if track_id:
            if not EventApplicationTrack.objects.filter(id=track_id, event=event).exists():
                return Response({"preapproved": False, "reason": "not_found"})

        from django.db.models import Q
        entry = EventPreApprovalAllowlist.objects.filter(
            # Phase 8: Filter by track + submission_mode (with backward compatibility)
            Q(track_id=track_id) | Q(track_id__isnull=True),
            Q(submission_mode=submission_mode) | Q(submission_mode=''),
            event=event,
            email=email,
            is_active=True,
        ).first()

        if not entry:
            return Response({"preapproved": False, "reason": "not_found"})
        return Response(
            {
                "preapproved": True,
                "source": "email",
                "first_name": entry.first_name,
                "last_name": entry.last_name,
                "message": "Email is pre-approved.",
            }
        )

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="applications")
    def applications(self, request, pk=None):
        """
        List all applications for an event (host/admin only).
        Query params:
        - status: filter by 'pending', 'approved', 'declined'
        - search: search by name or email
        """
        event = self.get_object()

        # Permission: must be actual event owner
        if not _is_event_owner(request.user, event):
            return Response({'detail': 'Forbidden. Only the event owner can manage applications.'}, status=403)

        status_filter = request.query_params.get('status')
        qs = event.applications.all()
        if status_filter:
            qs = qs.filter(status=status_filter)

        search = request.query_params.get('search', '').strip()
        if search:
            qs = qs.filter(
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(email__icontains=search)
            )
        attendee_marker = request.query_params.get("attendee_marker")
        if attendee_marker in {"true", "false"}:
            qs = qs.filter(attendee_marker_value=(attendee_marker == "true"))

        preapproved = request.query_params.get("preapproved")
        if preapproved in {"true", "false"}:
            qs = qs.filter(is_preapproved=(preapproved == "true"))

        source = request.query_params.get("preapproval_source")
        if source in {"none", "code", "email"}:
            qs = qs.filter(preapproval_source=source)

        has_comments = request.query_params.get("has_comments")
        if has_comments == "true":
            qs = qs.exclude(comments__exact="")
        elif has_comments == "false":
            qs = qs.filter(comments__exact="")

        return Response(EventApplicationSerializer(qs, many=True).data)

    @action(detail=True, methods=["get", "post"], permission_classes=[IsAuthenticated], url_path="preapproval/codes")
    def preapproval_codes(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can manage pre-approval.'}, status=403)

        if request.method == "GET":
            status_filter = request.query_params.get("status", "").strip()
            include_revoked = request.query_params.get("include_revoked", "false").lower() == "true"

            qs = event.preapproval_codes.all().order_by("-created_at")

            if status_filter in {EventPreApprovalCode.STATUS_ACTIVE, EventPreApprovalCode.STATUS_USED, EventPreApprovalCode.STATUS_REVOKED}:
                qs = qs.filter(status=status_filter)
            elif not include_revoked:
                qs = qs.exclude(status=EventPreApprovalCode.STATUS_REVOKED)

            return Response(EventPreApprovalCodeSerializer(qs, many=True).data)

        code = (request.data.get("code") or "").strip()
        notes = (request.data.get("notes") or "").strip()
        # FIX 2: Accept track_id and submission_mode for scoped pre-approval
        track_id = request.data.get("track_id")
        submission_mode = (request.data.get("submission_mode") or "").strip()

        if not code:
            code = secrets.token_urlsafe(8).replace("-", "").replace("_", "").upper()[:10]

        # Validate track exists if provided (FIX 2)
        track = None
        if track_id:
            try:
                track = EventApplicationTrack.objects.get(id=track_id, event=event)
            except EventApplicationTrack.DoesNotExist:
                return Response({'detail': 'Track not found for this event.'}, status=400)

        obj = EventPreApprovalCode.objects.create(
            event=event,
            code=code,
            notes=notes,
            track=track,  # FIX 2
            submission_mode=submission_mode,  # FIX 2
            created_by=request.user if request.user.is_authenticated else None,
        )
        return Response(EventPreApprovalCodeSerializer(obj).data, status=201)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="preapproval/codes/batch")
    def preapproval_codes_batch(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can manage pre-approval.'}, status=403)
        count = int(request.data.get("count") or 0)
        prefix = (request.data.get("prefix") or "").strip()
        # FIX 3: Accept track_id and submission_mode for scoped batch codes
        track_id = request.data.get("track_id")
        submission_mode = (request.data.get("submission_mode") or "").strip()

        if count <= 0 or count > 1000:
            return Response({"detail": "count must be between 1 and 1000."}, status=400)

        # Validate track exists if provided (FIX 3)
        track = None
        if track_id:
            try:
                track = EventApplicationTrack.objects.get(id=track_id, event=event)
            except EventApplicationTrack.DoesNotExist:
                return Response({'detail': 'Track not found for this event.'}, status=400)

        created = []
        for i in range(1, count + 1):
            code = f"{prefix}-{i:03d}" if prefix else secrets.token_urlsafe(8).replace("-", "").replace("_", "").upper()[:10]
            if EventPreApprovalCode.objects.filter(event=event, code=code).exists():
                code = f"{prefix}-{secrets.token_hex(3).upper()}" if prefix else f"PA-{secrets.token_hex(4).upper()}"
            created.append(
                EventPreApprovalCode(
                    event=event,
                    code=code,
                    track=track,  # FIX 3
                    submission_mode=submission_mode,  # FIX 3
                    created_by=request.user if request.user.is_authenticated else None,
                )
            )
        EventPreApprovalCode.objects.bulk_create(created)
        qs = event.preapproval_codes.filter(id__in=[obj.id for obj in created])
        return Response(EventPreApprovalCodeSerializer(qs, many=True).data, status=201)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path=r"preapproval/codes/(?P<code_id>\d+)/revoke")
    def preapproval_code_revoke(self, request, pk=None, code_id=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can manage pre-approval.'}, status=403)
        code = get_object_or_404(EventPreApprovalCode, id=code_id, event=event)
        code.status = EventPreApprovalCode.STATUS_REVOKED
        code.revoked_by = request.user if request.user.is_authenticated else None
        code.revoked_at = timezone.now()
        code.save(update_fields=["status", "revoked_by", "revoked_at"])
        return Response(EventPreApprovalCodeSerializer(code).data)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path=r"preapproval/codes/(?P<code_id>\d+)/mark-used")
    def preapproval_code_mark_used(self, request, pk=None, code_id=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can manage pre-approval.'}, status=403)
        code = get_object_or_404(EventPreApprovalCode, id=code_id, event=event)
        code.status = EventPreApprovalCode.STATUS_USED
        code.used_by_email = (request.data.get("email") or code.used_by_email or "").strip().lower()
        code.used_at = timezone.now()
        code.save(update_fields=["status", "used_by_email", "used_at"])
        return Response(EventPreApprovalCodeSerializer(code).data)

    @action(detail=True, methods=["get", "post"], permission_classes=[IsAuthenticated], url_path="preapproval/allowlist")
    def preapproval_allowlist(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can manage pre-approval.'}, status=403)
        if request.method == "GET":
            qs = event.preapproval_allowlist.all().order_by("-created_at")
            return Response(EventPreApprovalAllowlistSerializer(qs, many=True).data)

        # FIX 2: Accept track_id and submission_mode for scoped pre-approval
        track_id = request.data.get("track_id")
        submission_mode = (request.data.get("submission_mode") or "").strip()

        # Validate track exists if provided (FIX 2)
        track = None
        if track_id:
            try:
                track = EventApplicationTrack.objects.get(id=track_id, event=event)
            except EventApplicationTrack.DoesNotExist:
                return Response({'detail': 'Track not found for this event.'}, status=400)

        payload = {
            "first_name": (request.data.get("first_name") or "").strip(),
            "last_name": (request.data.get("last_name") or "").strip(),
            "email": (request.data.get("email") or "").strip().lower(),
            "notes": (request.data.get("notes") or "").strip(),
            "created_by": request.user if request.user.is_authenticated else None,
            "event": event,
            "track": track,  # FIX 2
            "submission_mode": submission_mode,  # FIX 2
        }
        obj = EventPreApprovalAllowlist.objects.create(**payload)
        return Response(EventPreApprovalAllowlistSerializer(obj).data, status=201)

    @action(detail=True, methods=["delete"], permission_classes=[IsAuthenticated], url_path=r"preapproval/allowlist/(?P<entry_id>\d+)")
    def preapproval_allowlist_remove(self, request, pk=None, entry_id=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can manage pre-approval.'}, status=403)
        entry = get_object_or_404(EventPreApprovalAllowlist, id=entry_id, event=event)
        entry.is_active = False
        entry.removed_by = request.user if request.user.is_authenticated else None
        entry.removed_at = timezone.now()
        entry.save(update_fields=["is_active", "removed_by", "removed_at"])
        return Response({"ok": True})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="preapproval/allowlist/import-csv")
    def preapproval_allowlist_import_csv(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can manage pre-approval.'}, status=403)

        file_obj = request.FILES.get("file")
        if not file_obj:
            return Response({"detail": "CSV file is required under 'file'."}, status=400)

        # FIX 9: Extract UI-selected defaults from request.data
        default_track_id = (request.data.get("track_id") or "").strip()
        default_submission_mode = (request.data.get("submission_mode") or "").strip()

        # Validate default track exists if provided
        default_track = None
        if default_track_id:
            try:
                default_track = EventApplicationTrack.objects.get(id=default_track_id, event=event)
            except EventApplicationTrack.DoesNotExist:
                return Response({'detail': f'Default track {default_track_id} not found for this event.'}, status=400)

        decoded = file_obj.read().decode("utf-8-sig", errors="ignore")
        reader = csv.DictReader(decoded.splitlines())
        created = 0
        skipped = 0
        errors = []
        for idx, row in enumerate(reader, start=2):
            first_name = (row.get("first_name") or "").strip()
            last_name = (row.get("last_name") or "").strip()
            email = (row.get("email") or "").strip().lower()
            # FIX 9: Use CSV column if provided, fall back to UI default
            track_id = (row.get("track_id") or default_track_id or "").strip()
            submission_mode = (row.get("submission_mode") or default_submission_mode or "").strip()

            if not email or "@" not in email:
                skipped += 1
                errors.append({"row": idx, "email": email, "error": "Invalid email"})
                continue

            # Validate track exists if provided (from CSV row or default)
            track = default_track
            if track_id and (not default_track or str(default_track.id) != track_id):
                try:
                    track = EventApplicationTrack.objects.get(id=track_id, event=event)
                except EventApplicationTrack.DoesNotExist:
                    skipped += 1
                    errors.append({"row": idx, "email": email, "error": f"Track {track_id} not found"})
                    continue

            # FIX 11: Duplicate check must include track and submission_mode
            # Same email can be allowed for different tracks or different submission modes
            from django.db.models import Q
            if EventPreApprovalAllowlist.objects.filter(
                Q(track=track) | Q(track__isnull=True),
                Q(submission_mode=submission_mode) | Q(submission_mode=''),
                event=event,
                email=email,
                is_active=True
            ).exists():
                skipped += 1
                continue
            EventPreApprovalAllowlist.objects.create(
                event=event,
                first_name=first_name,
                last_name=last_name,
                email=email,
                track=track,  # Uses CSV value or default
                submission_mode=submission_mode,  # Uses CSV value or default
                created_by=request.user if request.user.is_authenticated else None,
            )
            created += 1
        return Response({"created": created, "skipped": skipped, "errors": errors})

    # ==================== Phase 9: Review Queue ====================

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="review-queue")
    def review_queue(self, request, pk=None):
        """
        Phase 9: List all track applications for review with advanced filtering.
        GET /events/{id}/review-queue/

        Query parameters:
        - track_id: Filter by track
        - submission_mode: Filter by submission mode
        - status: Filter by status (pending, pre_approved, accepted, declined, waitlisted)
        - tier_id: Filter by requested tier
        - reviewer_id: Filter by assigned reviewer
        - search: Search by applicant name/email
        - ordering: Sort field (status, created_at, etc.)
        - page: Pagination
        """
        event = self.get_object()

        # Permission check: must be event staff/admin
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can access review queue.'}, status=403)

        # Base queryset with optimized queries - prevent N+1 on user lookups
        qs = EventApplicationTrackApplication.objects.filter(
            track__event=event
        ).select_related(
            'application',
            'application__user',
            'track',
            'track__event',
            'tier_preference',
            'reviewed_by'
        ).only(
            # Exclude large JSON fields from list view (form_answers, file_uploads)
            'id', 'application_id', 'track_id', 'status',
            'submission_mode', 'tier_preference_id', 'accepted_tier_id',
            'reviewed_by_id', 'reviewed_at', 'created_at', 'updated_at',
            'application__id', 'application__email', 'application__first_name',
            'application__last_name', 'application__user_id',
            'application__user__id', 'application__user__username', 'application__user__email',
            'track__id', 'track__label', 'track__key',
            'track__event__id', 'track__event__title',
            'tier_preference__id', 'tier_preference__label',
            'reviewed_by__id', 'reviewed_by__username'
        )

        # Apply filters
        track_id = request.query_params.get('track_id')
        if track_id:
            qs = qs.filter(track_id=track_id)

        submission_mode = request.query_params.get('submission_mode')
        if submission_mode:
            qs = qs.filter(submission_mode=submission_mode)

        status_param = request.query_params.get('status')
        if status_param:
            qs = qs.filter(status=status_param)

        tier_id = request.query_params.get('tier_id')
        if tier_id:
            qs = qs.filter(tier_preference_id=tier_id)

        reviewer_id = request.query_params.get('reviewer_id')
        if reviewer_id:
            qs = qs.filter(reviewed_by_id=reviewer_id)

        search = request.query_params.get('search', '').strip()
        if search:
            qs = qs.filter(
                Q(application__email__icontains=search) |
                Q(application__first_name__icontains=search) |
                Q(application__last_name__icontains=search)
            )

        # Apply ordering
        ordering = request.query_params.get('ordering', '-created_at')
        qs = qs.order_by(ordering)

        # Paginate
        page = self.paginate_queryset(qs)
        if page is not None:
            from .serializers import EventApplicationTrackApplicationDetailSerializer
            serializer = EventApplicationTrackApplicationDetailSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        from .serializers import EventApplicationTrackApplicationDetailSerializer
        serializer = EventApplicationTrackApplicationDetailSerializer(qs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="review-queue/stats")
    def review_queue_stats(self, request, pk=None):
        """
        Phase 9: Get statistics for review queue.
        GET /events/{id}/review-queue/stats/

        Returns counts grouped by:
        - track
        - submission_mode
        - status
        - tier_preference
        """
        event = self.get_object()

        # Permission check: must be event staff/admin
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can access stats.'}, status=403)

        qs = EventApplicationTrackApplication.objects.filter(track__event=event)

        stats = {
            'by_track': list(qs.values('track__label').annotate(count=Count('id')).order_by('track__label')),
            'by_mode': list(qs.values('submission_mode').annotate(count=Count('id')).order_by('submission_mode')),
            'by_status': list(qs.values('status').annotate(count=Count('id')).order_by('status')),
            'by_tier': list(qs.filter(tier_preference__isnull=False).values('tier_preference__label').annotate(count=Count('id')).order_by('tier_preference__label')),
            'total': qs.count(),
        }
        return Response(stats)

    @action(
        detail=True,
        methods=["get"],
        permission_classes=[IsAuthenticated],
        renderer_classes=[JSONRenderer, ReviewQueueCSVRenderer],
        url_path="review-queue/export",
    )
    def review_queue_export(self, request, pk=None):
        """
        Phase 13: Export review queue data as JSON or CSV (backend-driven).
        GET /events/{id}/review-queue/export/?export_format=json|csv

        Query parameters:
        - export_format: 'json' (default) or 'csv'
        - track_id, submission_mode, status, tier_id, reviewer_id, search: Same filters as review-queue

        Returns:
        - JSON: Array of track applications with all details
        - CSV: Spreadsheet file with key fields

        Performance: Uses streaming for CSV, pagination headers for JSON size awareness.
        """
        event = self.get_object()

        # Permission check: must be event staff/admin
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can export review queue.'}, status=403)

        # Build optimized queryset (same as review-queue endpoint)
        qs = EventApplicationTrackApplication.objects.filter(
            track__event=event
        ).select_related(
            'application', 'track', 'tier_preference', 'reviewed_by', 'accepted_tier'
        )

        # Apply same filters
        track_id = request.query_params.get('track_id')
        if track_id:
            qs = qs.filter(track_id=track_id)

        submission_mode = request.query_params.get('submission_mode')
        if submission_mode:
            qs = qs.filter(submission_mode=submission_mode)

        status_param = request.query_params.get('status')
        if status_param:
            qs = qs.filter(status=status_param)

        tier_id = request.query_params.get('tier_id')
        if tier_id:
            qs = qs.filter(tier_preference_id=tier_id)

        reviewer_id = request.query_params.get('reviewer_id')
        if reviewer_id:
            qs = qs.filter(reviewed_by_id=reviewer_id)

        search = request.query_params.get('search', '').strip()
        if search:
            qs = qs.filter(
                Q(application__email__icontains=search) |
                Q(application__first_name__icontains=search) |
                Q(application__last_name__icontains=search)
            )

        # Default ordering
        qs = qs.order_by('-created_at')

        # Return format
        export_format = request.query_params.get('export_format') or request.query_params.get('format', 'json')
        export_format = export_format.lower()

        if export_format == 'csv':
            import csv
            from io import StringIO

            # Limit CSV export to prevent memory issues (still allow large exports server-side)
            csv_limit = int(request.query_params.get('limit', 5000))
            qs = qs[:csv_limit]
            submission_mode_labels = {
                'self_submission': 'Self Submission',
                'confirmed': 'Confirmed',
                'pre_approved': 'Pre-Approved',
            }

            output = StringIO()
            writer = csv.writer(output)
            writer.writerow([
                'ID', 'Applicant Email', 'Applicant Name', 'Track', 'Submission Mode',
                'Status', 'Tier Preference', 'Accepted Tier', 'Company', 'Job Title',
                'Reviewed By', 'Reviewed At', 'Created At', 'Pre-approved'
            ])

            for track_app in qs:
                writer.writerow([
                    track_app.id,
                    track_app.application.email,
                    f"{track_app.application.first_name} {track_app.application.last_name}",
                    track_app.track.label,
                    submission_mode_labels.get(track_app.submission_mode, track_app.submission_mode),
                    track_app.get_status_display(),
                    track_app.tier_preference.label if track_app.tier_preference else '',
                    track_app.accepted_tier.label if track_app.accepted_tier else '',
                    track_app.application.company_name or '',
                    track_app.application.job_title or '',
                    track_app.reviewed_by.username if track_app.reviewed_by else '',
                    track_app.reviewed_at.isoformat() if track_app.reviewed_at else '',
                    track_app.created_at.isoformat(),
                    'Yes' if track_app.application.is_preapproved else 'No',
                ])

            response = HttpResponse(output.getvalue(), content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="review-queue-export-{event.id}.csv"'
            return response

        else:
            # JSON export with pagination info
            # Limit to prevent memory issues (frontend should use paginated review-queue for interactive browsing)
            json_limit = int(request.query_params.get('limit', 1000))
            qs = qs[:json_limit]

            from .serializers import EventApplicationTrackApplicationDetailSerializer
            serializer = EventApplicationTrackApplicationDetailSerializer(qs, many=True)

            return Response({
                'event_id': event.id,
                'event_name': event.title,
                'export_time': timezone.now().isoformat(),
                'total_count': qs.count(),
                'limit': json_limit,
                'data': serializer.data,
                'note': 'For large exports, use CSV format with ?format=csv&limit=5000'
            })

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="bulk-action")
    def bulk_action(self, request, pk=None):
        """
        Phase 9/10/11/12: Perform bulk actions on track applications.
        POST /events/{id}/bulk-action/

        Request body:
        {
          "action": "accept|decline|waitlist|assign_reviewer",
          "track_application_ids": [1, 2, 3, ...],
          "tier_preference_id": 5,  // For accept action
          "reviewer_id": 10,  // For assign_reviewer action
        }

        For accept action: calls accept_track_application() service for each track app,
        creating registrations, assigning roles, and triggering post-acceptance forms.
        """
        from django.db import transaction
        from events.services.application_decisions import (
            accept_track_application,
            decline_track_application,
            waitlist_track_application
        )

        event = self.get_object()

        # Permission check: must be event staff/admin
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can perform bulk actions.'}, status=403)

        action = request.data.get('action')
        track_app_ids = request.data.get('track_application_ids', [])

        if not action or not track_app_ids:
            return Response({'detail': 'action and track_application_ids are required.'}, status=400)

        # Verify all belong to this event
        qs = EventApplicationTrackApplication.objects.filter(
            id__in=track_app_ids,
            track__event=event
        )

        if not qs.exists():
            return Response({'detail': 'No matching track applications found.'}, status=404)

        updated_count = 0
        skipped_count = 0
        errors = []

        # Use chunking for bulk operations to prevent memory issues
        CHUNK_SIZE = 100
        track_apps_list = list(qs)

        try:
            if action == 'accept':
                tier_id = request.data.get('tier_preference_id')
                accepted_tier = None
                if tier_id:
                    try:
                        accepted_tier = TrackPricingTier.objects.get(id=tier_id)
                    except TrackPricingTier.DoesNotExist:
                        return Response({'detail': 'Tier not found.'}, status=400)

                # FIX: Filter out already-accepted applications
                to_process = [ta for ta in track_apps_list if ta.status != EventApplicationTrackApplication.STATUS_ACCEPTED]
                skipped_count = len(track_apps_list) - len(to_process)

                # Process in chunks
                for chunk_start in range(0, len(to_process), CHUNK_SIZE):
                    chunk = to_process[chunk_start:chunk_start + CHUNK_SIZE]
                    with transaction.atomic():
                        for track_app in chunk:
                            try:
                                accept_track_application(
                                    track_app,
                                    request.user,
                                    accepted_tier=accepted_tier
                                )
                                updated_count += 1
                            except ValueError as e:
                                errors.append(f"Track app {track_app.id}: {str(e)}")
                            except Exception as e:
                                errors.append(f"Track app {track_app.id}: Unexpected error: {str(e)}")

            elif action == 'decline':
                # FIX: Filter out already-declined applications
                to_process = [ta for ta in track_apps_list if ta.status != EventApplicationTrackApplication.STATUS_DECLINED]
                skipped_count = len(track_apps_list) - len(to_process)

                # Process in chunks
                for chunk_start in range(0, len(to_process), CHUNK_SIZE):
                    chunk = to_process[chunk_start:chunk_start + CHUNK_SIZE]
                    with transaction.atomic():
                        for track_app in chunk:
                            try:
                                decline_track_application(track_app, request.user, send_email=True)
                                updated_count += 1
                            except Exception as e:
                                errors.append(f"Track app {track_app.id}: {str(e)}")

            elif action == 'waitlist':
                # FIX: Filter out already-waitlisted applications
                to_process = [ta for ta in track_apps_list if ta.status != EventApplicationTrackApplication.STATUS_WAITLISTED]
                skipped_count = len(track_apps_list) - len(to_process)

                # Process in chunks
                for chunk_start in range(0, len(to_process), CHUNK_SIZE):
                    chunk = to_process[chunk_start:chunk_start + CHUNK_SIZE]
                    with transaction.atomic():
                        for track_app in chunk:
                            try:
                                waitlist_track_application(track_app, request.user, send_email=True)
                                updated_count += 1
                            except Exception as e:
                                errors.append(f"Track app {track_app.id}: {str(e)}")

            elif action == 'assign_reviewer':
                reviewer_id = request.data.get('reviewer_id')
                # Safe bulk update for reviewer assignment (non-status-changing)
                updated_count = qs.update(reviewed_by_id=reviewer_id)

            else:
                return Response({'detail': f'Invalid action: {action}'}, status=400)

        except Exception as e:
            return Response({
                'success': False,
                'detail': f'Bulk action failed: {str(e)}',
                'updated_count': updated_count,
                'errors': errors
            }, status=500)

        response_data = {'success': True, 'updated_count': updated_count}
        if skipped_count > 0:
            response_data['skipped_count'] = skipped_count
            response_data['message'] = f'Processed {updated_count}, skipped {skipped_count} (already in target status)'
        if errors:
            response_data['errors'] = errors
        return Response(response_data)

    # ==================== Phase 10: Accept, Decline, Waitlist ====================

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path=r"applications/(?P<app_id>\d+)/track-applications/(?P<track_app_id>\d+)/accept")
    def accept_track_application(self, request, pk=None, app_id=None, track_app_id=None):
        """
        Phase 10: Accept a track application with tier selection.
        POST /events/{id}/applications/{app_id}/track-applications/{track_app_id}/accept/

        Request body:
        {
          "accepted_tier_id": 5,  // Optional: tier to assign (uses requested or default if omitted)
          "notes": "Optional notes"
        }
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can make decisions.'}, status=403)

        track_app = get_object_or_404(
            EventApplicationTrackApplication,
            id=track_app_id,
            application_id=app_id,
            track__event=event
        )

        # FIX: Check if already accepted
        if track_app.status == EventApplicationTrackApplication.STATUS_ACCEPTED:
            return Response({
                'detail': 'Application is already accepted.',
                'status': track_app.status,
                'accepted_at': track_app.accepted_at
            }, status=400)

        from events.services.application_decisions import accept_track_application

        # Get tier: use provided, or fallback to requested, or use track default
        tier_id = request.data.get('accepted_tier_id')
        accepted_tier = None
        if tier_id:
            try:
                accepted_tier = TrackPricingTier.objects.get(id=tier_id, track=track_app.track)
            except TrackPricingTier.DoesNotExist:
                return Response({'detail': 'Tier not found for this track.'}, status=400)

        notes = request.data.get('notes', '')

        try:
            track_app = accept_track_application(
                track_app,
                request.user,
                accepted_tier=accepted_tier,
                notes=notes
            )
            return Response({
                'success': True,
                'status': track_app.status,
                'accepted_tier': track_app.accepted_tier.id if track_app.accepted_tier else None,
                'accepted_at': track_app.accepted_at,
                'message': 'Application accepted successfully'
            })
        except Exception as e:
            logger.exception(f"Error accepting application {track_app_id}: {e}")
            return Response(
                {'detail': f'Error accepting application: {str(e)}'},
                status=500
            )

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path=r"applications/(?P<app_id>\d+)/track-applications/(?P<track_app_id>\d+)/decline")
    def decline_track_application(self, request, pk=None, app_id=None, track_app_id=None):
        """
        Phase 10: Decline a track application.
        POST /events/{id}/applications/{app_id}/track-applications/{track_app_id}/decline/

        Request body:
        {
          "send_email": true,  // Optional: whether to send decline notification
          "notes": "Optional notes"
        }
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can make decisions.'}, status=403)

        track_app = get_object_or_404(
            EventApplicationTrackApplication,
            id=track_app_id,
            application_id=app_id,
            track__event=event
        )

        # FIX: Check if already declined
        if track_app.status == EventApplicationTrackApplication.STATUS_DECLINED:
            return Response({
                'detail': 'Application is already declined.',
                'status': track_app.status,
                'declined_at': track_app.declined_at
            }, status=400)

        from events.services.application_decisions import decline_track_application

        send_email = request.data.get('send_email', True)
        notes = request.data.get('notes', '')

        try:
            track_app = decline_track_application(
                track_app,
                request.user,
                send_email=send_email,
                notes=notes
            )
            # Refresh parent application to get updated status
            track_app.application.refresh_from_db()
            return Response({
                'success': True,
                'track_application': {
                    'id': track_app.id,
                    'status': track_app.status,
                    'declined_at': track_app.declined_at,
                },
                'application_status': track_app.application.status,
                'message': 'Application declined successfully'
            })
        except Exception as e:
            logger.exception(f"Error declining application {track_app_id}: {e}")
            return Response(
                {'detail': f'Error declining application: {str(e)}'},
                status=500
            )

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path=r"applications/(?P<app_id>\d+)/track-applications/(?P<track_app_id>\d+)/waitlist")
    def waitlist_track_application(self, request, pk=None, app_id=None, track_app_id=None):
        """
        Phase 10: Waitlist a track application.
        POST /events/{id}/applications/{app_id}/track-applications/{track_app_id}/waitlist/

        Request body:
        {
          "send_email": true,  // Optional: whether to send waitlist notification
          "notes": "Optional notes"
        }
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can make decisions.'}, status=403)

        track_app = get_object_or_404(
            EventApplicationTrackApplication,
            id=track_app_id,
            application_id=app_id,
            track__event=event
        )

        # FIX: Check if already waitlisted
        if track_app.status == EventApplicationTrackApplication.STATUS_WAITLISTED:
            return Response({
                'detail': 'Application is already waitlisted.',
                'status': track_app.status,
                'waitlisted_at': track_app.waitlisted_at
            }, status=400)

        from events.services.application_decisions import waitlist_track_application

        send_email = request.data.get('send_email', True)
        notes = request.data.get('notes', '')

        try:
            track_app = waitlist_track_application(
                track_app,
                request.user,
                send_email=send_email,
                notes=notes
            )
            return Response({
                'success': True,
                'status': track_app.status,
                'waitlisted_at': track_app.waitlisted_at,
                'message': 'Application waitlisted successfully'
            })
        except Exception as e:
            logger.exception(f"Error waitlisting application {track_app_id}: {e}")
            return Response(
                {'detail': f'Error waitlisting application: {str(e)}'},
                status=500
            )

    @action(detail=True, methods=["post"], url_path=r"registrations/(?P<reg_id>\d+)/mark-paid", permission_classes=[IsAuthenticated])
    def mark_registration_paid(self, request, pk=None, reg_id=None):
        """
        Phase 11: Manually mark a payment_pending registration as confirmed.
        POST /events/{id}/registrations/{reg_id}/mark-paid/

        Request body:
        {
          "payment_reference": "INV-12345"  // Optional: payment reference
        }

        Only updates registrations with attendee_status='payment_pending'.
        Triggers post-acceptance forms when status transitions to confirmed.
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can mark payments.'}, status=403)

        registration = get_object_or_404(
            EventRegistration,
            id=reg_id,
            event=event
        )

        if registration.attendee_status != 'payment_pending':
            return Response({
                'detail': f'Cannot mark as paid. Attendee status is {registration.attendee_status}, not payment_pending.'
            }, status=400)

        from events.services.attendee_directory import mark_paid

        payment_reference = request.data.get('payment_reference', '')

        try:
            registration = mark_paid(
                registration,
                request.user,
                payment_reference=payment_reference
            )
            return Response({
                'success': True,
                'attendee_status': registration.attendee_status,
                'marked_paid_at': registration.marked_paid_at,
                'message': 'Registration marked as paid successfully'
            })
        except ValueError as e:
            return Response({'detail': str(e)}, status=400)
        except Exception as e:
            logger.exception(f"Error marking registration {reg_id} as paid: {e}")
            return Response(
                {'detail': f'Error marking as paid: {str(e)}'},
                status=500
            )

    @action(detail=True, methods=["get"], url_path="attendee-origins", permission_classes=[IsAuthenticated])
    def attendee_origins(self, request, pk=None):
        """
        List attendee origins for an event, optionally filtered by registration_id.
        Used by Review Queue to show per-track tier/payment status.
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can view attendee origins.'}, status=403)

        qs = EventAttendeeOrigin.objects.filter(
            registration__event=event
        ).select_related('registration', 'role', 'track', 'accepted_tier', 'accepted_by')

        registration_id = request.query_params.get('registration_id')
        if registration_id:
            qs = qs.filter(registration_id=registration_id)

        serializer = EventAttendeeOriginSerializer(qs.order_by('track__label', 'role__label'), many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path=r"attendee-origins/(?P<origin_id>\d+)/mark-paid", permission_classes=[IsAuthenticated])
    def mark_origin_paid(self, request, pk=None, origin_id=None):
        """
        FIX 2: Manually mark a payment_pending origin as confirmed.
        POST /events/{id}/attendee-origins/{origin_id}/mark-paid/

        Request body:
        {
          "payment_reference": "INV-12345"  // Optional: payment reference
        }

        Only updates origins with origin_status='payment_pending'.
        Recalculates registration.attendee_status based on all origins.
        Triggers post-acceptance forms when registration transitions to confirmed.
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({'detail': 'Forbidden. Only event managers can mark payments.'}, status=403)

        origin = get_object_or_404(
            EventAttendeeOrigin,
            id=origin_id,
            registration__event=event
        )

        if origin.origin_status != 'payment_pending':
            return Response({
                'detail': f'Cannot mark as paid. Origin status is {origin.origin_status}, not payment_pending.'
            }, status=400)

        from events.services.attendee_directory import mark_origin_paid as mark_origin_paid_service

        payment_reference = request.data.get('payment_reference', '')

        try:
            origin = mark_origin_paid_service(
                origin,
                request.user,
                payment_reference=payment_reference
            )
            return Response({
                'success': True,
                'origin_status': origin.origin_status,
                'marked_paid_at': origin.marked_paid_at,
                'registration_status': origin.registration.attendee_status,
                'message': 'Origin marked as paid successfully'
            })
        except ValueError as e:
            return Response({'detail': str(e)}, status=400)
        except Exception as e:
            logger.exception(f"Error marking origin {origin_id} as paid: {e}")
            return Response(
                {'detail': f'Error marking as paid: {str(e)}'},
                status=500
            )

    @action(detail=True, methods=["post"], url_path=r"applications/(?P<app_id>\d+)/approve", permission_classes=[IsAuthenticated])
    def approve_application(self, request, pk=None, app_id=None):
        """
        Approve an application and optionally auto-register the applicant.
        Triggers post-acceptance forms for confirmed attendees (in-person/hybrid events).

        FIX 5: For Application Tracks events, routes to per-track acceptance.
        FIX 14: Enforce tier selection for Application Tracks events.
        """
        event = self.get_object()
        if not _is_event_owner(request.user, event):
            return Response({'detail': 'Forbidden. Only the event owner can approve applications.'}, status=403)

        app = get_object_or_404(EventApplication, id=app_id, event=event)

        # FIX 5 & FIX 14: Check if event uses Application Tracks
        has_tracks = EventApplicationTrack.objects.filter(event=event).exists()

        if has_tracks:
            # FIX 14: For Application Tracks, tier selection is required. Direct to review queue.
            return Response({
                'detail': 'For Application Tracks events, use the review queue for tier-based acceptance.',
                'next_action': 'Use /events/{}/review-queue/ endpoint with tier selection'.format(event.id),
            }, status=400)

        # Original logic for non-track events
        app.status = 'approved'
        app.reviewed_at = timezone.now()
        app.reviewed_by = request.user
        app.save()

        # Auto-register authenticated applicants only
        if app.user:
            # Applicant has account - register them directly
            registration, created = EventRegistration.objects.get_or_create(event=event, user=app.user)
            # Set attendee status to confirmed
            registration.attendee_status = 'confirmed'
            registration.save(update_fields=['attendee_status'])

            # Trigger post-acceptance forms for confirmed attendees
            try:
                from events.services import trigger_post_acceptance_forms, send_form_assignment_email
                from events.models import PostAcceptanceFormAssignment

                # Trigger form assignments (emails are sent automatically by service layer)
                created_assignments = trigger_post_acceptance_forms(registration)
                logger.info(f"Triggered {len(created_assignments) if created_assignments else 0} form assignments for user {registration.user.email}")

            except Exception as e:
                logger.error(f"Failed to trigger post-acceptance forms for application {app.id}: {str(e)}", exc_info=True)
                # Do not fail the approval - continue normally
        else:
            # Guest applicant - NO longer create User account
            # Guest will verify via OTP when checking application status on event day
            # GuestAttendee will be created during guest-join (OTP) endpoint
            logger.info(f"Application {app.id} approved for guest {app.email}. Guest will verify via OTP on event day.")

        # Send approval email
        from users.email_utils import send_application_approved_email
        send_application_approved_email(app)

        return Response(EventApplicationSerializer(app).data)

    @action(detail=True, methods=["post"], url_path=r"applications/(?P<app_id>\d+)/decline", permission_classes=[IsAuthenticated])
    def decline_application(self, request, pk=None, app_id=None):
        """
        Decline an application with optional custom rejection message.
        Body: {"rejection_message": "Optional message to applicant"}
        """
        import logging
        logger = logging.getLogger(__name__)

        event = self.get_object()
        if not _is_event_owner(request.user, event):
            return Response({'detail': 'Forbidden. Only the event owner can decline applications.'}, status=403)

        app = get_object_or_404(EventApplication, id=app_id, event=event)
        rejection_message = request.data.get('rejection_message', '')

        logger.info(f"Declining application {app.id} for {app.email}")

        app.status = 'declined'
        app.reviewed_at = timezone.now()
        app.reviewed_by = request.user
        app.rejection_message = rejection_message
        app.save()

        # Send decline email (with host's custom message)
        from users.email_utils import send_application_declined_email
        try:
            logger.info(f"Sending decline email to {app.email} with message: {rejection_message}")
            result = send_application_declined_email(app, custom_message=rejection_message)
            logger.info(f"Decline email result: {result}")
        except Exception as e:
            logger.error(f"Failed to send decline email: {e}")

        return Response(EventApplicationSerializer(app).data)

    @action(detail=True, methods=["post"], url_path=r"applications/bulk-approve", permission_classes=[IsAuthenticated])
    def bulk_approve_applications(self, request, pk=None):
        """
        Approve multiple applications in bulk.

        Body:
        {
            "application_ids": [1, 2, 3],  # Optional: specific application IDs to approve
            "approve_all_pending": false   # Optional: if true, approve all pending applications
        }

        At least one of application_ids or approve_all_pending must be provided.

        FIX 5: For Application Tracks events, route through track-level acceptance.
        """
        import logging
        from django.db import transaction

        logger = logging.getLogger(__name__)

        event = self.get_object()
        if not _is_event_owner(request.user, event):
            return Response({'detail': 'Forbidden. Only the event owner can approve applications.'}, status=403)

        # FIX 5: Check if event uses Application Tracks
        has_tracks = EventApplicationTrack.objects.filter(event=event).exists()
        if has_tracks:
            return Response({
                'detail': 'For Application Tracks events, use bulk-action endpoint with track-level acceptance.',
                'endpoint': f'/events/{event.id}/bulk-action/',
                'example': {
                    'action': 'accept',
                    'track_application_ids': [1, 2, 3],
                    'tier_preference_id': 5
                }
            }, status=400)

        # Parse request data
        application_ids = request.data.get('application_ids', [])
        approve_all_pending = request.data.get('approve_all_pending', False)

        if not application_ids and not approve_all_pending:
            return Response(
                {'detail': 'Either "application_ids" or "approve_all_pending" must be provided.'},
                status=400
            )

        # Build query for applications to approve
        if approve_all_pending:
            applications = EventApplication.objects.filter(
                event=event,
                status='pending'
            )
        else:
            applications = EventApplication.objects.filter(
                event=event,
                id__in=application_ids,
                status='pending'
            )

        if not applications.exists():
            return Response({
                'approved_count': 0,
                'skipped_count': 0,
                'skipped_reasons': [],
                'message': 'No pending applications found to approve.'
            })

        approved_count = 0
        skipped_reasons = []

        try:
            with transaction.atomic():
                for app in applications:
                    try:
                        # Approve the application
                        app.status = 'approved'
                        app.reviewed_at = timezone.now()
                        app.reviewed_by = request.user
                        app.save()

                        # Auto-register authenticated applicants
                        if app.user:
                            EventRegistration.objects.get_or_create(event=event, user=app.user)
                        else:
                            logger.info(f"Application {app.id} approved for guest {app.email}. Guest will verify via OTP on event day.")

                        # Send approval email
                        from users.email_utils import send_application_approved_email
                        try:
                            send_application_approved_email(app)
                        except Exception as e:
                            logger.error(f"Failed to send approval email for application {app.id}: {e}")

                        approved_count += 1

                    except Exception as e:
                        logger.error(f"Error approving application {app.id}: {e}")
                        skipped_reasons.append({
                            'application_id': app.id,
                            'email': app.email,
                            'reason': str(e)
                        })
        except Exception as e:
            logger.error(f"Bulk approval transaction failed: {e}")
            return Response(
                {'detail': f'Bulk approval failed: {str(e)}'},
                status=500
            )

        return Response({
            'approved_count': approved_count,
            'skipped_count': len(skipped_reasons),
            'skipped_reasons': skipped_reasons,
            'message': f'Successfully approved {approved_count} application(s).'
        })

    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="max-price")
    def max_price(self, request):
        """
        Return the maximum price within the currently visible/filtered events.
        ⚡ OPTIMIZED: Skip annotation, use values_list for minimal query.
        """
        qs = self.get_queryset().values('price')  # respects all filters & visibility
        mx = qs.aggregate(mx=Max("price"))["mx"] or 0
        return Response({"max_price": float(mx)})
    
    @action(detail=True, methods=["post"], permission_classes=[AllowAny], url_path="live-status")
    def live_status(self, request, pk=None):
        """
        Start/end a live meeting.
        Body: {"action":"start"} or {"action":"end"}
        Also sets Event.active_speaker_id on start, clears on end.
        """
        action_type = (request.data.get("action") or "").strip().lower()
        if action_type not in {"start", "end"}:
            return Response({"ok": False, "error": "Invalid action"}, status=400)

        # Prefer authenticated user as host; fall back to event.creator if anonymous
        host_user_id = request.user.id if getattr(request, "user", None) and request.user.is_authenticated else None

        with transaction.atomic():
            event = get_object_or_404(self.get_queryset().model.objects.select_for_update(), pk=pk)

            if not _is_event_manager(request.user, event):
                return Response({"detail": "Only the host or admin can update live status."}, status=403)

            if action_type == "start":
                if event.status == "ended":
                    return Response(
                        {"detail": "Meeting already ended. Cannot restart via live-status."},
                        status=409,
                    )

                # Event can go live with or without external streaming
                # RTK interface is hidden in frontend when external_streaming=True
                event.status = "live"
                event.is_live = True
                event.live_started_at = timezone.now()
                event.live_ended_at = None
                event.active_speaker_id = host_user_id or event.created_by_id
                event.attending_count = 0
                event.idle_started_at = None
                event.ended_by_host = False

                # ✅ UPDATED: Lounge participants stay in lounge until host manually admits them
                # No automatic transition - host must manually admit via admitFromLounge action
                if event.waiting_room_enabled and event.lounge_enabled_waiting_room:
                    logger.info(f"✅ Meeting started with lounge enabled. Lounge participants will remain until manually admitted by host for event {event.id}")
            else:  # end
                event.status = "ended"
                event.is_live = False
                event.live_ended_at = timezone.now()
                event.ended_by_host = True

                # If event was on break, clear break state and revoke Celery task
                if event.is_on_break:
                    if event.break_celery_task_id:
                        try:
                            celery_app.control.revoke(event.break_celery_task_id, terminate=True)
                        except Exception as e:
                            logger.warning(f"Failed to revoke break Celery task {event.break_celery_task_id}: {e}")
                    event.is_on_break = False
                    event.break_started_at = None
                    event.break_celery_task_id = None

            event.save(update_fields=[
                "status",
                "is_live",
                "live_started_at",
                "live_ended_at",
                "active_speaker_id",
                "attending_count",
                "idle_started_at",
                "ended_by_host",
                "is_on_break",
                "break_started_at",
                "break_celery_task_id",
                "updated_at",
            ])
            _delete_event_summary_cache(event.id)

        if action_type == "start":
            # Scale out immediately if host starts early (scale up only).
            # In-person events do not need RTK/live-meeting ASG capacity.
            try:
                from events.services.live_meeting_capacity import (
                    event_requires_live_meeting_capacity,
                    scale_asg_if_needed,
                )

                if event_requires_live_meeting_capacity(event):
                    scale_asg_if_needed(
                        reason=f"host_started_event_{event.id}",
                        scale_down_allowed=False,
                    )
                else:
                    logger.info(
                        "Skipping ASG scale-out for in-person event start. event_id=%s format=%s",
                        event.id,
                        getattr(event, "format", None),
                    )
            except Exception as e:
                logger.warning("Live meeting ASG scale-out failed for event %s: %s", event.id, e)

            # 📢 Broadcast meeting start to all participants
            try:
                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.group_send)(
                    f"event_{event.id}",
                    {
                        "type": "meeting_started",
                        "event_id": event.id,
                        "status": "live",
                        "started_at": event.live_started_at.isoformat() if event.live_started_at else timezone.now().isoformat(),
                    }
                )
                logger.info(f"✅ Broadcast meeting_started for event {event.id}")
            except Exception as e:
                logger.warning(f"Failed to broadcast meeting_started to event {event.id}: {e}")

            # 📢 Broadcast change to enforce waiting room on frontend
            if event.waiting_room_enabled:
                try:
                    channel_layer = get_channel_layer()
                    async_to_sync(channel_layer.group_send)(
                        f"event_{event.id}",
                        {
                            "type": "broadcast_message",
                            "payload": {
                                "type": "waiting_room_enforced",
                                "event_id": event.id,
                                "timestamp": timezone.now().isoformat()
                            }
                        }
                    )
                except Exception as e:
                    logger.warning(f"Failed to broadcast waiting_room_enforced: {e}")
        else:  # action_type == "end"
            # Auto-stop any active manual recording when meeting ends.
            if event.is_recording and event.rtk_recording_id:
                success, _msg = _stop_rtk_recording_for_event_manual(event)
                if success:
                    event.is_recording = False
                    event.rtk_recording_id = ""
                    event.recording_paused_at = None
                    event.save(update_fields=["is_recording", "rtk_recording_id", "recording_paused_at", "updated_at"])
                    try:
                        _broadcast_recording_status(event, "stopped")
                    except Exception as e:
                        logger.warning(f"Failed to broadcast recording stop for event {event.id}: {e}")

            # 📢 Broadcast meeting end to all participants via WebSocket
            try:
                channel_layer = get_channel_layer()
                lounge_available = event.lounge_enabled_after
                lounge_closing_time = None
                if lounge_available:
                    lounge_closing_time = (event.live_ended_at + timedelta(minutes=event.lounge_after_buffer)).isoformat()

                async_to_sync(channel_layer.group_send)(
                    f"event_{event.id}",
                    {
                        "type": "meeting_ended",
                        "event_id": event.id,
                        "ended_at": event.live_ended_at.isoformat(),
                        "lounge_available": lounge_available,
                        "lounge_closing_time": lounge_closing_time
                    }
                )
            except Exception as e:
                # Log but don't fail the API response
                logger.warning(f"Failed to broadcast meeting_ended to event {event.id}: {e}")

            # 📧 Send follow-up emails to guests immediately
            try:
                from events.tasks import send_guest_followup_task
                send_guest_followup_task.apply_async(
                    args=[event.id],
                    countdown=0  # Send immediately when host ends meeting
                )
                logger.info(f"Scheduled follow-up email task for event {event.id}")
            except Exception as e:
                logger.warning(f"Failed to schedule follow-up email task for event {event.id}: {e}")

        return Response({
            "ok": True,
            "status": event.status,
            "is_live": event.is_live,
            "active_speaker": event.active_speaker_id,
            "live_started_at": event.live_started_at,
            "live_ended_at": event.live_ended_at,
        })

    @action(
        detail=True,
        methods=["get"],
        permission_classes=[AllowAny],
        url_path="streaming-link",
    )
    def streaming_link(self, request, pk=None):
        """
        Get streaming configuration for the event.
        Returns external platform details if use_external_streaming=True, otherwise native RTK info.
        Passwords/sensitive details only shown to event managers/hosts.
        """
        event = self.get_object()
        is_manager = _is_event_manager(request.user, event)

        if event.use_external_streaming:
            response = {
                "type": "external",
                "platform": event.external_streaming_platform,
                "platform_name": dict(event.STREAMING_PLATFORM_CHOICES).get(event.external_streaming_platform, "Unknown"),
                "join_url": event.external_streaming_url,
                "meeting_id": event.external_streaming_meeting_id or None,
                "instructions": event.external_streaming_other_details or None,
                "host_link": event.external_streaming_host_link or None,
            }

            # Only managers see password
            if is_manager:
                response["password"] = event.external_streaming_password or None
            else:
                response["password"] = None

            return Response(response)
        else:
            # Native RTK streaming
            response = {
                "type": "native",
                "platform": "native",
                "platform_name": "Our Platform (RTK)",
                "meeting_id": event.rtk_meeting_id or None,
            }
            return Response(response)

    @action(
        detail=True,
        methods=["post"],
        permission_classes=[AllowAny],
        url_path="active-speaker",
    )
    def active_speaker(self, request, pk=None):
        """
        Update the `active_speaker` field on the Event whenever RTK reports
        a new active speaker.

        Expected body:
            {"user_id": <int>}   # this is the Django User.id you send as client_specific_id
        """
        event = self.get_object()

        raw_id = request.data.get("user_id")

        # If client sends null / empty → clear current active speaker
        if raw_id in (None, ""):
            event.active_speaker = None
            event.save(update_fields=["active_speaker", "updated_at"])
            return Response({"ok": True, "active_speaker": None})

        try:
            user_id = int(raw_id)
        except (TypeError, ValueError):
            return Response(
                {"ok": False, "error": "invalid_user_id"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return Response(
                {"ok": False, "error": "user_not_found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Only update the pointer; /live-status and /end-meeting control is_live/status.
        event.active_speaker = user
        event.save(update_fields=["active_speaker", "updated_at"])

        return Response(
            {"ok": True, "active_speaker": event.active_speaker_id}
        )
        
    @action(
        detail=True,
        methods=["post"],
        permission_classes=[IsAuthenticated],
        url_path="end-meeting",
    )
    def end_meeting(self, request, pk=None):
        """
        Mark this event's live meeting as ended.

        We trust RTK's own permissions: only the host can click
        "End meeting for all" in the UI. Here we just persist that state.
        Repeated calls from the host are harmless.
        """
        event = self.get_object()

        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host or admin can end the meeting."}, status=403)

        event.status = "ended"
        event.is_live = False
        event.live_ended_at = timezone.now()
        event.ended_by_host = True
        event.save(update_fields=["status", "is_live", "live_ended_at", "ended_by_host", "updated_at"])

        if event.is_recording and event.rtk_recording_id:
            success, _msg = _stop_rtk_recording_for_event_manual(event)
            if success:
                event.is_recording = False
                event.rtk_recording_id = ""
                event.recording_paused_at = None
                event.save(update_fields=["is_recording", "rtk_recording_id", "recording_paused_at", "updated_at"])
                try:
                    _broadcast_recording_status(event, "stopped")
                except Exception as e:
                    logger.warning(f"Failed to broadcast recording stop for event {event.id}: {e}")

        # 📢 Broadcast meeting end to all participants via WebSocket
        # This allows frontend to immediately show PostEventLoungeScreen or redirect as needed
        try:
            channel_layer = get_channel_layer()
            lounge_available = event.lounge_enabled_after
            lounge_closing_time = None
            if lounge_available:
                lounge_closing_time = (event.live_ended_at + timedelta(minutes=event.lounge_after_buffer)).isoformat()

            async_to_sync(channel_layer.group_send)(
                f"event_{event.id}",
                {
                    "type": "meeting_ended",
                    "event_id": event.id,
                    "ended_at": event.live_ended_at.isoformat(),
                    "lounge_available": lounge_available,
                    "lounge_closing_time": lounge_closing_time
                }
            )
        except Exception as e:
            # Log but don't fail the API response
            logger.warning(f"Failed to broadcast meeting_ended to event {event.id}: {e}")

        # 📧 Send follow-up emails to guests immediately
        try:
            from events.tasks import send_guest_followup_task
            send_guest_followup_task.apply_async(
                args=[event.id],
                countdown=0  # Send immediately when host ends meeting
            )
            logger.info(f"Scheduled follow-up email task for event {event.id}")
        except Exception as e:
            logger.warning(f"Failed to schedule follow-up email task for event {event.id}: {e}")

        return Response(
            {"message": "Meeting ended", "status": event.status, "event_id": event.id}
        )

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="start-break")
    def start_break(self, request, pk=None):
        """
        Start a break for a live event.
        Body: {"duration_seconds": 600}
        Only the host may call this.
        """
        with transaction.atomic():
            event = get_object_or_404(
                Event.objects.select_for_update(), pk=pk
            )

            if not _is_event_manager(request.user, event):
                return Response({"detail": "Only the host can start a break."}, status=403)

            # Guard: event must be live
            if not event.is_live or event.status != "live":
                return Response(
                    {"detail": "Cannot start break: meeting is not live."},
                    status=400
                )

            # Guard: already on break
            if event.is_on_break:
                return Response(
                    {"detail": "Event is already on break."},
                    status=409
                )

            # Guard: breakout rooms are active
            if event.breakout_rooms_active:
                return Response(
                    {"detail": "Cannot start break while breakout rooms are active. "
                               "End all breakout rooms first."},
                    status=409
                )

            # Guard: speed networking session is active
            from .models import SpeedNetworkingSession
            active_sn = SpeedNetworkingSession.objects.filter(
                event=event, status='ACTIVE'
            ).first()
            if active_sn:
                return Response(
                    {"detail": "Cannot start break while Speed Networking is active. "
                               "End the Speed Networking session first."},
                    status=409
                )

            # Validate duration
            duration = int(request.data.get("duration_seconds", 600))
            if duration < 30 or duration > 7200:  # 30s min, 2hr max
                return Response(
                    {"detail": "duration_seconds must be between 30 and 7200."},
                    status=400
                )

            # Set break state
            now = timezone.now()
            event.is_on_break = True
            event.break_started_at = now
            event.break_duration_seconds = duration
            event.save(update_fields=[
                "is_on_break", "break_started_at",
                "break_duration_seconds", "updated_at"
            ])

        # Schedule Celery auto-end task
        from .tasks import auto_end_break
        task = auto_end_break.apply_async(
            args=[event.id],
            countdown=duration + 30  # 30s grace after timer expires
        )
        # Store task ID for later revocation
        event.break_celery_task_id = task.id
        event.save(update_fields=["break_celery_task_id"])

        # Broadcast break_started to all participants via WebSocket
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"event_{event.id}",
                {
                    "type": "break_started",
                    "event_id": event.id,
                    "break_started_at": event.break_started_at.isoformat(),
                    "break_duration_seconds": event.break_duration_seconds,
                    "lounge_enabled_breaks": event.lounge_enabled_breaks,
                    "media_lock_active": True,
                }
            )
        except Exception as e:
            logger.warning(f"Failed to broadcast break_started for event {event.id}: {e}")

        return Response({
            "ok": True,
            "is_on_break": True,
            "break_started_at": event.break_started_at.isoformat(),
            "break_duration_seconds": event.break_duration_seconds,
        })

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="end-break")
    def end_break(self, request, pk=None):
        """
        End an active break, returning all participants to the main stage.
        Body: {} (empty)
        Only the host may call this.

        ✅ BUGFIX: When break ends, remove all users from social lounge so they return to main room.
        """
        with transaction.atomic():
            from .models import LoungeParticipant, BreakoutJoiner

            event = get_object_or_404(
                Event.objects.select_for_update(), pk=pk
            )

            if not _is_event_manager(request.user, event):
                return Response({"detail": "Only the host can end a break."}, status=403)

            if not event.is_on_break:
                return Response(
                    {"detail": "Event is not currently on break."},
                    status=409
                )

            # Revoke Celery task if it exists
            if event.break_celery_task_id:
                try:
                    celery_app.control.revoke(event.break_celery_task_id, terminate=True)
                except Exception as e:
                    logger.warning(f"Failed to revoke break Celery task: {e}")

            # Clear break state
            event.is_on_break = False
            event.break_started_at = None
            event.break_celery_task_id = None

            # ✅ BUGFIX: Clear lounge when break ends
            # Remove all participants from lounge tables so they return to main room
            lounge_count = LoungeParticipant.objects.filter(
                table__event_id=event.id
            ).delete()[0]
            logger.info(f"[END_BREAK] Removed {lounge_count} participants from lounge tables")

            # ✅ Clear breakout_rooms_active flag
            event.breakout_rooms_active = False

            # ✅ Expire waiting late joiners
            BreakoutJoiner.objects.filter(
                event_id=event.id,
                status='waiting'
            ).update(status='expired')

            event.save(update_fields=[
                "is_on_break", "break_started_at", "break_celery_task_id",
                "breakout_rooms_active", "updated_at"
            ])

        # Broadcast break_ended to all participants
        try:
            # ✅ Get updated lounge state for frontend so UI refreshes immediately
            lounge_state = _build_lounge_state_sync(event.id)

            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"event_{event.id}",
                {
                    "type": "break_ended",
                    "event_id": event.id,
                    "lounge_enabled_during": event.lounge_enabled_during,
                    "media_lock_active": False,
                    "lounge_state": lounge_state,  # ✅ Include updated lounge state
                }
            )
        except Exception as e:
            logger.warning(f"Failed to broadcast break_ended for event {event.id}: {e}")

        return Response({
            "ok": True,
            "is_on_break": False,
        })

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="start-recording")
    def start_recording(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host or admin can control recording."}, status=403)
        if not event.is_live:
            return Response({"error": "Event must be live to start recording."}, status=400)
        if not event.replay_available:
            return Response({"error": "Replay is disabled for this event. Recording cannot be started."}, status=400)
        if event.is_recording:
            return Response({"error": "Recording already active."}, status=400)
        logger.info(
            "🎛️ Host %s requested start-recording for event=%s",
            request.user.id,
            event.id,
        )

        success, recording_id, msg = _start_rtk_recording_for_event_manual(event)
        if not success:
            return Response({"error": msg}, status=400)

        event.is_recording = True
        event.rtk_recording_id = recording_id
        event.recording_paused_at = None
        event.save(update_fields=["is_recording", "rtk_recording_id", "recording_paused_at", "updated_at"])
        logger.info(
            "✅ Recording state saved in DB for event=%s recording=%s",
            event.id,
            event.rtk_recording_id,
        )
        try:
            _broadcast_recording_status(event, "started")
        except Exception as e:
            logger.warning(f"Failed to broadcast recording start for event {event.id}: {e}")
        return Response({"ok": True, "recording_id": event.rtk_recording_id})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="pause-recording")
    def pause_recording(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host or admin can control recording."}, status=403)
        if not event.is_recording or not event.rtk_recording_id:
            return Response({"error": "No active recording to pause."}, status=400)
        if event.recording_paused_at:
            return Response({"error": "Recording is already paused."}, status=400)
        logger.info(
            "🎛️ Host %s requested pause-recording for event=%s recording=%s",
            request.user.id,
            event.id,
            event.rtk_recording_id,
        )

        success, msg = _pause_rtk_recording_for_event(event)
        if not success:
            return Response({"error": msg}, status=400)

        event.recording_paused_at = timezone.now()
        event.save(update_fields=["recording_paused_at", "updated_at"])
        logger.info("✅ Recording paused state saved in DB for event=%s", event.id)
        try:
            _broadcast_recording_status(event, "paused")
        except Exception as e:
            logger.warning(f"Failed to broadcast recording pause for event {event.id}: {e}")
        return Response({"ok": True})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="resume-recording")
    def resume_recording(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host or admin can control recording."}, status=403)
        if not event.is_recording or not event.rtk_recording_id:
            return Response({"error": "No active recording to resume."}, status=400)
        if not event.recording_paused_at:
            return Response({"error": "Recording is not paused."}, status=400)
        logger.info(
            "🎛️ Host %s requested resume-recording for event=%s recording=%s",
            request.user.id,
            event.id,
            event.rtk_recording_id,
        )

        success, msg = _resume_rtk_recording_for_event(event)
        if not success:
            return Response({"error": msg}, status=400)

        event.recording_paused_at = None
        event.save(update_fields=["recording_paused_at", "updated_at"])
        logger.info("✅ Recording resumed state saved in DB for event=%s", event.id)
        try:
            _broadcast_recording_status(event, "resumed")
        except Exception as e:
            logger.warning(f"Failed to broadcast recording resume for event {event.id}: {e}")
        return Response({"ok": True})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="stop-recording")
    def stop_recording(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host or admin can control recording."}, status=403)
        if not event.is_recording or not event.rtk_recording_id:
            return Response({"error": "No active recording to stop."}, status=400)
        logger.info(
            "🎛️ Host %s requested stop-recording for event=%s recording=%s",
            request.user.id,
            event.id,
            event.rtk_recording_id,
        )

        success, msg = _stop_rtk_recording_for_event_manual(event)
        if not success:
            return Response({"error": msg}, status=400)

        event.is_recording = False
        event.rtk_recording_id = ""
        event.recording_paused_at = None
        event.save(update_fields=["is_recording", "rtk_recording_id", "recording_paused_at", "updated_at"])
        logger.info("✅ Recording state cleared in DB for event=%s", event.id)
        try:
            _broadcast_recording_status(event, "stopped")
        except Exception as e:
            logger.warning(f"Failed to broadcast recording stop for event {event.id}: {e}")
        return Response({"ok": True})

    @action(detail=True, methods=["delete"], permission_classes=[IsAuthenticated], url_path="cancel-recording")
    def cancel_recording(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"error": "Only the host can cancel recording."}, status=403)
        if not event.is_recording and not event.rtk_recording_id:
            return Response({"error": "No active recording to cancel."}, status=400)

        logger.warning(
            "🎛️ Host %s requested CANCEL-recording for event=%s recording=%s",
            request.user.id,
            event.id,
            event.rtk_recording_id,
        )

        recording_id = event.rtk_recording_id
        success, msg = _delete_rtk_recording_for_event(event)
        if not success:
            return Response({"error": msg}, status=400)

        event.is_recording = False
        event.rtk_recording_id = ""
        event.recording_paused_at = None
        event.recording_url = ""
        event.save(update_fields=["is_recording", "rtk_recording_id", "recording_paused_at", "recording_url", "updated_at"])
        logger.warning("✅ Recording cancelled and cleared in DB for event=%s", event.id)

        try:
            _broadcast_recording_status(event, "cancelled")
        except Exception as e:
            logger.warning(f"Failed to broadcast recording cancellation for event {event.id}: {e}")

        logger.warning(
            "🗑️ Recording CANCELLED by user=%s for event=%s recording_id=%s",
            request.user.id,
            event.id,
            recording_id,
        )
        return Response({"ok": True, "message": "Recording permanently deleted", "is_recording": False, "is_paused": False})
    
    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="kick")
    def kick_participant(self, request, pk=None):
        """
        Kick a participant from the meeting (temporary removal).
        Body: {"user_id": <id or "guest_<id>"}>
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host can kick participants."}, status=403)

        target_id = request.data.get("user_id")
        if not target_id:
            return Response({"detail": "user_id required"}, status=400)

        target_str = str(target_id)
        channel_layer = get_channel_layer()

        if target_str.startswith("guest_"):
            # Handle guest kick
            try:
                guest_id = int(target_str.split("_", 1)[1])
            except (ValueError, IndexError):
                return Response({"detail": "Invalid guest ID format"}, status=400)

            if not GuestAttendee.objects.filter(event=event, id=guest_id).exists():
                return Response({"detail": "Guest not found in this event"}, status=404)

            # Notify guest via personal group
            async_to_sync(channel_layer.group_send)(
                f"guest_user_{guest_id}",
                {"type": "broadcast_message", "payload": {"type": "kicked", "event_id": event.id}}
            )
        else:
            # Handle registered user kick (existing logic)
            EventRegistration.objects.filter(event=event, user_id=target_id).update(
                current_mood=None,
                mood_updated_at=timezone.now(),
            )
            async_to_sync(channel_layer.group_send)(
                f"user_{target_id}",
                {"type": "broadcast_message", "payload": {"type": "kicked", "event_id": event.id}}
            )

        # Broadcast to all event participants to refresh participant list
        async_to_sync(channel_layer.group_send)(
            f"event_{event.id}",
            {"type": "broadcast_message", "payload": {"type": "participant_kicked", "kicked_user_id": target_str, "event_id": event.id}}
        )

        return Response({"ok": True, "message": "User kicked"})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="ban")
    def ban_participant(self, request, pk=None):
        """
        Ban a participant from the meeting (permanent removal).
        Body: {"user_id": <id or "guest_<id>"}>
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host can ban participants."}, status=403)

        target_id = request.data.get("user_id")
        if not target_id:
            return Response({"detail": "user_id required"}, status=400)

        target_str = str(target_id)
        channel_layer = get_channel_layer()

        if target_str.startswith("guest_"):
            # Handle guest ban
            try:
                guest_id = int(target_str.split("_", 1)[1])
            except (ValueError, IndexError):
                return Response({"detail": "Invalid guest ID format"}, status=400)

            updated = GuestAttendee.objects.filter(event=event, id=guest_id).update(is_banned=True)
            if not updated:
                return Response({"detail": "Guest not found in this event"}, status=404)

            async_to_sync(channel_layer.group_send)(
                f"guest_user_{guest_id}",
                {"type": "broadcast_message", "payload": {"type": "banned", "event_id": event.id}}
            )
        else:
            # Handle registered user ban (existing logic)
            try:
                reg = EventRegistration.objects.get(event=event, user_id=target_id)
                reg.is_banned = True
                reg.current_mood = None
                reg.mood_updated_at = timezone.now()
                reg.save(update_fields=["is_banned", "current_mood", "mood_updated_at"])
            except EventRegistration.DoesNotExist:
                return Response({"detail": "User not registered for this event"}, status=404)

            async_to_sync(channel_layer.group_send)(
                f"user_{target_id}",
                {"type": "broadcast_message", "payload": {"type": "banned", "event_id": event.id}}
            )

        # Broadcast to all event participants to refresh participant list
        async_to_sync(channel_layer.group_send)(
            f"event_{event.id}",
            {"type": "broadcast_message", "payload": {"type": "participant_banned", "banned_user_id": target_str, "event_id": event.id}}
        )

        return Response({"ok": True, "message": "User banned"})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="unban")
    def unban_participant(self, request, pk=None):
        """
        Unban a participant (registered user or guest).
        Body: {"user_id": <id or "guest_<id>"}>
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host can unban participants."}, status=403)

        target_id = request.data.get("user_id")
        if not target_id:
            return Response({"detail": "user_id required"}, status=400)

        target_str = str(target_id)

        if target_str.startswith("guest_"):
            # Handle guest unban
            try:
                guest_id = int(target_str.split("_", 1)[1])
            except (ValueError, IndexError):
                return Response({"detail": "Invalid guest ID format"}, status=400)

            updated = GuestAttendee.objects.filter(event=event, id=guest_id).update(is_banned=False)
            if not updated:
                return Response({"detail": "Guest not found in this event"}, status=404)
        else:
            # Handle registered user unban
            try:
                reg = EventRegistration.objects.get(event=event, user_id=target_id)
                reg.is_banned = False
                reg.save(update_fields=["is_banned"])
            except EventRegistration.DoesNotExist:
                return Response({"detail": "User not registered"}, status=404)

        return Response({"ok": True, "message": "Participant unbanned"})

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="banned-users")
    def banned_users(self, request, pk=None):
        """
        List all banned users (registered and guests) for this event.
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host can view banned users."}, status=403)

        data = []

        # Add banned registered users
        banned_regs = EventRegistration.objects.filter(event=event, is_banned=True).select_related('user')
        for r in banned_regs:
            data.append({
                "user_id": r.user.id,
                "full_name": r.user.first_name + " " + r.user.last_name,
                "username": r.user.username,
                "avatar": r.user.avatar.url if hasattr(r.user, 'avatar') and r.user.avatar else None
            })

        # Add banned guests with "guest_" prefix
        banned_guests = GuestAttendee.objects.filter(event=event, is_banned=True)
        for g in banned_guests:
            data.append({
                "user_id": f"guest_{g.id}",
                "full_name": g.get_display_name(),
                "username": g.email,
                "avatar": None
            })

        return Response(data)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="assign-host")
    def assign_host(self, request, pk=None):
        """
        Promote a registered participant to host during a live session.
        Body: {"user_id": <integer user ID>}

        - Creates/updates an EventParticipant record with role="host"
        - Sends a WebSocket notification to the target user so their frontend
          re-joins the RTK meeting with a publisher (host) preset
        - Only callable by the current event host
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host can assign host roles."}, status=403)

        user_id = request.data.get("user_id")
        if not user_id:
            return Response({"detail": "user_id is required."}, status=400)

        User = get_user_model()
        try:
            target_user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return Response({"detail": f"User {user_id} not found."}, status=404)

        # Prevent self-assignment (already the host)
        if target_user.id == request.user.id:
            return Response({"detail": "You are already the host."}, status=400)

        # Create or update EventParticipant record for this user as host
        EventParticipant.objects.update_or_create(
            event=event,
            user=target_user,
            participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
            defaults={"role": EventParticipant.ROLE_HOST},
        )

        # Ensure the user has a registration (so they can join with host preset)
        EventRegistration.objects.get_or_create(
            event=event,
            user=target_user,
            defaults={"status": "registered", "admission_status": "admitted"},
        )

        # Build the assigning host's display name
        assigning_host = request.user
        host_profile = getattr(assigning_host, "profile", None)
        host_name = (
            getattr(host_profile, "full_name", "") if host_profile else ""
        ) or assigning_host.get_full_name() or assigning_host.username

        # Notify the target user via WebSocket so they re-join with publisher preset
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"user_{target_user.id}",
                {
                    "type": "host_role_assigned",
                    "assigned_by_user_id": request.user.id,
                    "assigned_by_name": host_name,
                },
            )
        except Exception as e:
            logger.warning(f"[ASSIGN_HOST] Failed to send WS notification to user {target_user.id}: {e}")
            # Don't fail the API call if WS notification fails — DB record is the source of truth

        logger.info(
            f"[ASSIGN_HOST] User {request.user.id} promoted user {target_user.id} to host "
            f"for event {event.id}"
        )
        return Response({
            "ok": True,
            "detail": f"{target_user.get_full_name() or target_user.username} has been assigned as host.",
            "user_id": target_user.id,
        })

    @action(
        detail=True,
        methods=["get"],
        permission_classes=[IsAuthenticated],
        url_path="moods",
    )
    def moods(self, request, pk=None):
        """
        Return current mood state for online/admitted participants in this event.
        """
        event = self.get_object()
        cache_key = f"event:{event.id}:moods:v1"

        is_host = _is_event_manager(request.user, event)
        requester_reg = EventRegistration.objects.filter(event=event, user=request.user).first()
        if not is_host and not requester_reg:
            return Response({"detail": "Not registered for this event."}, status=403)
        if (
            not is_host
            and event.waiting_room_enabled
            and requester_reg
            and requester_reg.admission_status != "admitted"
        ):
            return Response({"detail": "You are not admitted to the live meeting."}, status=403)

        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached)

        rows = (
            EventRegistration.objects.filter(
                event=event,
                current_mood__isnull=False,
                is_banned=False,
                is_online=True,
                admission_status="admitted",
            )
            .select_related("user")
            .values("user_id", "current_mood", "mood_updated_at")
        )

        payload = [
            {
                "user_id": row["user_id"],
                "mood": row["current_mood"],
                "updated_at": row["mood_updated_at"],
            }
            for row in rows
        ]
        data = {"moods": payload, "allowed_moods": MOOD_ALLOWED_EMOJIS}
        cache.set(cache_key, data, 5)
        return Response(data)

    @action(
        detail=True,
        methods=["get"],
        permission_classes=[IsAuthenticated],
        url_path="allowed-moods",
    )
    def allowed_moods(self, request, pk=None):
        """
        Get list of allowed mood emojis for this event.
        Used by frontend to filter emoji picker.
        """
        return Response({"allowed_moods": MOOD_ALLOWED_EMOJIS})

    @action(
        detail=True,
        methods=["put", "delete"],
        permission_classes=[IsAuthenticated],
        throttle_classes=[MoodRateThrottle],
        url_path="mood",
    )
    def mood(self, request, pk=None):
        """
        Set or clear current user's mood for this event.

        PUT /api/events/{id}/mood/
          Request body: {"mood": "😀"}
          Response: {"user_id": ..., "mood": "😀", "allowed_moods": [...]}

        DELETE /api/events/{id}/mood/
          Response: 204 No Content
        """
        event = self.get_object()
        reg = EventRegistration.objects.filter(event=event, user=request.user, is_banned=False).first()
        is_host = _is_event_manager(request.user, event)

        logger.info(
            f"[MOOD API] User {request.user.id} {request.method} mood for event {pk}. "
            f"Registered: {bool(reg)}, Is Host: {is_host}"
        )

        if not reg and not is_host:
            logger.warning(f"[MOOD API] User {request.user.id} not registered for event {pk}")
            return Response({"detail": "Not registered for this event."}, status=403)

        if not reg and is_host:
            reg, _ = EventRegistration.objects.get_or_create(
                event=event,
                user=request.user,
                defaults={"status": "registered", "admission_status": "admitted"},
            )

        if event.waiting_room_enabled and reg.admission_status != "admitted":
            logger.warning(
                f"[MOOD API] User {request.user.id} not admitted for event {pk}. "
                f"Admission status: {reg.admission_status}"
            )
            return Response({"detail": "You are not admitted to the live meeting."}, status=403)

        if request.method == "DELETE":
            reg.current_mood = None
            reg.mood_updated_at = timezone.now()
            reg.save(update_fields=["current_mood", "mood_updated_at"])
            cache.delete(f"event:{event.id}:moods:v1")
            logger.info(f"[MOOD API] User {request.user.id} cleared mood for event {pk}")
            return Response(status=status.HTTP_204_NO_CONTENT)

        # PUT method: set mood
        raw_mood = request.data.get("mood")
        logger.debug(
            f"[MOOD API] PUT request - User {request.user.id}, Event {pk}, "
            f"Raw mood value: {repr(raw_mood)}, Content-Type: {request.content_type}"
        )

        mood, error = _sanitize_mood(raw_mood)
        if not mood:
            logger.warning(
                f"[MOOD API] Mood validation failed for user {request.user.id} on event {pk}. "
                f"Error: {error}, Raw value: {repr(raw_mood)}"
            )
            return Response(
                {
                    "detail": f"Invalid mood: {error}",
                    "error_reason": error,
                    "allowed_moods": MOOD_ALLOWED_EMOJIS,
                },
                status=400,
            )

        reg.current_mood = mood
        reg.mood_updated_at = timezone.now()
        reg.save(update_fields=["current_mood", "mood_updated_at"])
        cache.delete(f"event:{event.id}:moods:v1")

        profile = getattr(request.user, "profile", None)
        if profile is not None:
            history = list(profile.last_used_moods or [])
            history = [m for m in history if m != mood]
            history.insert(0, mood)
            profile.last_used_moods = history[:10]
            profile.save(update_fields=["last_used_moods"])

        logger.info(f"[MOOD API] User {request.user.id} set mood to '{mood}' for event {pk}")
        return Response({"user_id": request.user.id, "mood": mood, "allowed_moods": MOOD_ALLOWED_EMOJIS})

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="download-recording")
    def download_recording(self, request):
        """Generate a pre-signed URL for downloading recording from S3

        Access control:
        - Host can download at any time
        - Participants can only download if replay_visible_to_participants = True
        """
        import boto3
        from botocore.config import Config

        recording_url = request.data.get('recording_url')
        if not recording_url:
            return Response({"error": "recording_url required"}, status=400)

        # Find the event by recording_url
        try:
            event = Event.objects.get(recording_url=recording_url)
        except Event.DoesNotExist:
            return Response({"error": "Recording not found"}, status=404)

        # Check access: host can always download, participants need replay_visible_to_participants
        is_host = _is_event_manager(request.user, event)
        is_participant = EventRegistration.objects.filter(
            event=event,
            user=request.user,
            status__in=["registered", "cancellation_requested"]
        ).exists()

        if not is_host and not (is_participant and event.replay_visible_to_participants):
            return Response({
                "error": "Recording is not yet available. Host is still processing the replay."
            }, status=403)
        
        try:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                region_name=AWS_S3_REGION,          # ✅ fixed
                config=Config(signature_version='s3v4'),
            )
            
            bucket = AWS_S3_BUCKET                 # ✅ fixed
            
            # Generate pre-signed URL that forces download
            download_url = s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': bucket,
                    'Key': recording_url,
                    'ResponseContentDisposition': 'attachment; filename="recording.mp4"',
                },
                ExpiresIn=3600,
            )
            
            logger.info(f"✅ Generated download URL for: {recording_url}")
            
            return Response({
                "download_url": download_url,
                "expires_in": 3600,
            })
            
        except Exception as e:
            logger.exception(f"❌ Failed to generate download URL: {e}")
            return Response(
                {"error": "Failed to generate download URL", "detail": str(e)},
                status=500,
            )

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="generate-replay-upload-url")
    def generate_replay_upload_url(self, request, pk=None):
        """
        Generate a presigned S3 PUT URL for direct browser-to-S3 upload of a manual replay.

        Request body: { "filename": "my-recording.mp4", "content_type": "video/mp4" }
        Response: { "upload_url": "...", "s3_key": "...", "expires_in": 3600 }
        """
        import boto3
        import uuid
        from botocore.config import Config

        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"error": "Permission denied"}, status=403)

        filename = (request.data.get("filename") or "replay.mp4").strip()
        content_type = (request.data.get("content_type") or "video/mp4").strip()

        # Sanitize extension from filename
        _, ext = os.path.splitext(filename)
        ext = ext.lower() if ext else ".mp4"

        # Allowed video types
        ALLOWED_TYPES = {"video/mp4", "video/webm", "video/quicktime", "video/x-msvideo"}
        if content_type not in ALLOWED_TYPES:
            return Response({"error": f"Unsupported content_type: {content_type}"}, status=400)

        bucket = AWS_S3_BUCKET
        if not bucket:
            return Response({"error": "aws_bucket_not_configured"}, status=500)

        s3_key = f"recordings/{event.slug}/manual-replay/{uuid.uuid4().hex}{ext}"

        try:
            s3_client = boto3.client(
                "s3",
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                region_name=AWS_S3_REGION,
                config=Config(signature_version="s3v4"),
            )

            upload_url = s3_client.generate_presigned_url(
                "put_object",
                Params={
                    "Bucket": bucket,
                    "Key": s3_key,
                    "ContentType": content_type,
                },
                ExpiresIn=3600,
            )
        except Exception as e:
            logger.exception(f"[UPLOAD_URL] Failed to generate presigned PUT URL for event {event.id}: {e}")
            return Response({"error": "Failed to generate upload URL", "detail": str(e)}, status=500)

        logger.info(f"[UPLOAD_URL] Generated presigned PUT URL for event={event.id} key={s3_key}")

        return Response({
            "upload_url": upload_url,
            "s3_key": s3_key,
            "expires_in": 3600,
            "content_type": content_type,
        })

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="confirm-replay-upload")
    def confirm_replay_upload(self, request, pk=None):
        """
        Confirm that a manual replay file was successfully uploaded to S3.
        Sets event.recording_url and event.replay_available = True.
        Optionally dispatches replay notification Celery task.

        Request body: {
            "s3_key": "recordings/event-slug/manual-replay/abc123.mp4",
            "send_notifications": true
        }
        """
        from .tasks import send_replay_notifications_task

        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"error": "Permission denied"}, status=403)

        s3_key = (request.data.get("s3_key") or "").strip()
        if not s3_key:
            return Response({"error": "s3_key is required"}, status=400)

        # Validate that s3_key belongs to this event (security: prevent overwriting other events)
        expected_prefix = f"recordings/{event.slug}/manual-replay/"
        if not s3_key.startswith(expected_prefix):
            return Response(
                {"error": f"Invalid s3_key. Must start with: {expected_prefix}"},
                status=400,
            )

        send_notifications = bool(request.data.get("send_notifications", False))

        event.recording_url = s3_key
        event.replay_available = True
        # Auto-publish if mode is auto_publish, otherwise restrict to host until published
        event.replay_visible_to_participants = (event.replay_publishing_mode == "auto_publish")
        event.save(update_fields=["recording_url", "replay_available", "replay_visible_to_participants", "updated_at"])

        logger.info(
            f"[CONFIRM_UPLOAD] event={event.id} s3_key={s3_key} "
            f"send_notifications={send_notifications}"
        )

        if send_notifications:
            # Dispatch Celery task asynchronously
            send_replay_notifications_task.delay(event.id)
            logger.info(f"[CONFIRM_UPLOAD] Queued replay notification task for event {event.id}")

        return Response({
            "ok": True,
            "recording_url": s3_key,
            "replay_available": True,
            "replay_visible_to_participants": event.replay_visible_to_participants,
            "replay_publishing_mode": event.replay_publishing_mode,
            "notifications_queued": send_notifications,
        })

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="publish-replay")
    def publish_replay(self, request, pk=None):
        """
        Host explicitly publishes the recording to all registered participants.
        After this, replay_visible_to_participants=True and participants can see/download.

        Request body: {} (empty)
        Response: { "ok": true, "replay_visible_to_participants": true }
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"error": "Permission denied"}, status=403)

        if not event.replay_available or not event.recording_url:
            # Recording may still be processing if the meeting has ended but no URL yet
            if (event.live_ended_at or event.status == "ended") and not event.recording_url:
                return Response({
                    "error": "Recording is still being processed. Please wait a few minutes and refresh the page."
                }, status=400)
            return Response({"error": "No recording available to publish."}, status=400)

        if event.replay_visible_to_participants:
            return Response({
                "ok": True,
                "already_published": True,
                "replay_visible_to_participants": True
            })

        event.replay_visible_to_participants = True
        event.save(update_fields=["replay_visible_to_participants", "updated_at"])

        logger.info(f"[PUBLISH_REPLAY] event={event.id} published by user={request.user.id}")

        return Response({"ok": True, "replay_visible_to_participants": True})

    @action(detail=True, methods=["post", "get"], permission_classes=[IsAuthenticated], url_path="send-replay-notifications")
    def send_replay_notifications(self, request, pk=None):
        """
        GET: Returns preview counts (no-shows, partial attendees, full attendees).
        POST: Dispatches the Celery notification task (if not already sent).
              Body: { "force": false } — set force=true to resend even if already sent.
        """
        from .tasks import send_replay_notifications_task
        from django.db.models import Sum

        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"error": "Permission denied"}, status=403)

        # Shared: compute preview counts
        event_duration_seconds = None
        if event.start_time and event.end_time:
            event_duration_seconds = (event.end_time - event.start_time).total_seconds()

        attendance_map = {}
        if event_duration_seconds and event_duration_seconds > 0:
            qs = (
                SessionAttendance.objects
                .filter(session__event_id=event.id)
                .values("user_id")
                .annotate(total_seconds=Sum("duration_seconds"))
            )
            attendance_map = {a["user_id"]: a["total_seconds"] for a in qs}

        # ✅ Exclude hosts and admins - only count actual participants
        from django.db.models import Q
        registrations_qs = EventRegistration.objects.filter(
            event=event,
            status__in=["registered", "cancellation_requested"],
        )

        # Exclude event creator
        registrations_qs = registrations_qs.exclude(user_id=event.created_by_id)

        # Exclude community owner (if community exists)
        if event.community and event.community.owner_id:
            registrations_qs = registrations_qs.exclude(user_id=event.community.owner_id)

        registrations = registrations_qs.only("user_id", "joined_live")

        threshold = 0.8 * (event_duration_seconds or 0)
        noshow = 0
        partial = 0
        full = 0

        for reg in registrations:
            if not reg.joined_live:
                noshow += 1
            elif event_duration_seconds and attendance_map.get(reg.user_id, 0) >= threshold:
                full += 1
            else:
                partial += 1

        preview = {
            "noshow_count": noshow,
            "partial_count": partial,
            "full_count": full,
            "total_to_notify": noshow + partial,
            "already_sent": event.replay_notifications_sent_at is not None,
            "sent_at": event.replay_notifications_sent_at,
            "visible_to_participants": event.replay_visible_to_participants,
        }

        if request.method == "GET":
            return Response(preview)

        # POST: dispatch
        force = bool(request.data.get("force", False))

        if event.replay_notifications_sent_at and not force:
            return Response({
                **preview,
                "error": "Notifications already sent. Pass force=true to resend.",
            }, status=409)

        if not event.replay_available or not event.recording_url:
            return Response({"error": "Replay is not available yet."}, status=400)

        if not event.replay_visible_to_participants:
            return Response({
                "error": "Replay is not yet published. Please publish the recording before sending notifications.",
                **preview,
            }, status=400)

        if force:
            # Reset sent_at so the task will proceed
            Event.objects.filter(pk=event.id).update(replay_notifications_sent_at=None)
            event.replay_notifications_sent_at = None

        send_replay_notifications_task.delay(event.id)
        logger.info(f"[SEND_NOTIF] Queued replay notifications for event {event.id} (force={force})")

        return Response({**preview, "queued": True})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="resend-registration-emails")
    def resend_registration_emails(self, request, pk=None):
        """
        Resend registration confirmation emails to all confirmed registered members.
        Only the event owner/manager can trigger this.
        - Excludes the event creator
        - Sends role-specific emails: speakers/hosts/moderators get event_confirmation email,
          regular participants get registration acknowledgement email
        Returns count of successfully sent and failed emails.
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"error": "Permission denied"}, status=403)

        from users.email_utils import send_user_registration_acknowledgement_email, send_event_confirmation_email
        from events.models import EventParticipant

        registrations = EventRegistration.objects.filter(
            event=event,
            status="registered",
            attendee_status="confirmed",
        ).exclude(
            user_id=event.created_by_id
        ).select_related("user")

        success_count = 0
        failed_count = 0

        for reg in registrations:
            if not reg.user or not reg.user.email:
                failed_count += 1
                continue
            try:
                participants = EventParticipant.objects.filter(event=event, user=reg.user)

                if participants.exists():
                    for participant in participants:
                        sent = send_event_confirmation_email(participant)
                        if sent:
                            success_count += 1
                        else:
                            failed_count += 1
                else:
                    sent = send_user_registration_acknowledgement_email(reg.user, event)
                    if sent:
                        success_count += 1
                    else:
                        failed_count += 1
            except Exception as e:
                logger.warning(f"Failed to send registration email to {reg.user.email}: {e}")
                failed_count += 1

        return Response({
            "success_count": success_count,
            "failed_count": failed_count,
            "total_count": success_count + failed_count,
        })

    @action(detail=True, methods=["post"], permission_classes=[AllowAny], url_path="attending")
    def attending(self, request, pk=None):
        op = (request.data.get("op") or "").strip().lower()
        if op not in {"join", "leave", "set"}:
            return Response({"ok": False, "error": "Invalid op"}, status=400)

        with transaction.atomic():
            event = get_object_or_404(Event.objects.select_for_update(), pk=pk)

            # ⛔️ Do NOT decrement after the session has been marked ended
            if op == "leave" and not event.is_live:
                return Response({"ok": True, "attending_count": int(event.attending_count or 0)})

            if op == "set":
                try:
                    new_val = max(0, int(request.data.get("value", 0)))
                except (TypeError, ValueError):
                    return Response({"ok": False, "error": "Bad value"}, status=400)
                event.attending_count = new_val
                event.save(update_fields=["attending_count", "updated_at"])

            elif op == "join":
                Event.objects.filter(pk=event.pk).update(attending_count=F("attending_count") + 1)
                event.refresh_from_db(fields=["attending_count"])
                if request.user.is_authenticated:
                    EventRegistration.objects.filter(event=event, user=request.user).update(joined_live=True)

            elif op == "leave":
                Event.objects.filter(pk=event.pk).update(attending_count=F("attending_count") - 1)
                event.refresh_from_db(fields=["attending_count"])
                if event.attending_count < 0:
                    Event.objects.filter(pk=event.pk).update(attending_count=0)
                    event.attending_count = 0

        return Response({"ok": True, "attending_count": int(event.attending_count or 0)})

    @action(
        detail=True,
        methods=["get"],
        url_path="registrations",
        permission_classes=[IsAuthenticated],
    )
    def registrations(self, request, pk=None):
        """
        Owner-only view: list all members who purchased/registered this event.
        Summary stats always show full event-level counts, independent of pagination and filters.
        """
        event = self.get_object()
        user = request.user

        # allow only event creator (strict ownership)
        if not _is_event_owner(user, event):
            return Response(
                {"detail": "You do not have permission to view registrations. Only the event owner can access this data."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # ✅ Build base_qs: all active registrations (not cancelled/deregistered)
        base_qs = (
            EventRegistration.objects
            .filter(event=event, status__in=["registered", "cancellation_requested"])
            .select_related("user")
            .order_by("-registered_at")
        )

        # Calculate full event stats from base_qs (before applying tab filter)
        # Mutually exclusive categories:
        # - joined_live: True
        # - watched_replay: joined_live=False AND watched_replay=True
        # - did_not_attend: joined_live=False AND watched_replay=False
        stats = {
            'total': base_qs.count(),
            'joined_live': base_qs.filter(joined_live=True).count(),
            'watched_replay': base_qs.filter(joined_live=False, watched_replay=True).count(),
            'did_not_attend': base_qs.filter(joined_live=False, watched_replay=False).count(),
        }

        # Apply tab filter only to the list query (not to stats)
        qs = base_qs
        status_filter = (request.query_params.get("status") or "").strip().lower()
        if status_filter == "joined_live":
            qs = qs.filter(joined_live=True)
        elif status_filter == "watched_replay":
            qs = qs.filter(watched_replay=True)
        elif status_filter == "did_not_attend":
            # Did Not Attend = registered but never joined and never watched replay
            qs = qs.filter(joined_live=False, watched_replay=False)

        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = EventRegistrationSerializer(page, many=True, context={"request": request})
            response = self.get_paginated_response(serializer.data)
            response.data["stats"] = stats
            return response

        serializer = EventRegistrationSerializer(
            qs, many=True, context={"request": request}
        )
        return Response({"results": serializer.data, "stats": stats})

    @action(
        detail=True,
        methods=["get"],
        url_path="participants",
        permission_classes=[IsAuthenticated],
    )
    def participants(self, request, pk=None):
        """
        Return the list of participants for an event, respecting visibility settings.
        - Event organizers/owners/admins always see the full list
        - Regular participants see the list only if visibility is enabled for the current event phase
        """
        event = self.get_object()
        user = request.user

        # Check if user is organizer/owner/admin
        is_organizer = _is_event_manager(user, event)

        if not is_organizer:
            # Check visibility based on event timing
            now = timezone.now()
            
            # Determine event phase
            event_started = event.start_time and event.start_time <= now
            event_ended = event.end_time and event.end_time < now
            
            # If the event is explicitly cancelled, we bypass the "ended" visibility check 
            # so the frontend doesn't throw a 403 when trying to load the page.
            is_cancelled = event.status == "cancelled"
            
            if not is_cancelled:
                # Before event: check show_participants_before_event
                if not event_started and not event.show_participants_before_event:
                    return Response(
                        {"detail": "Participant list is not visible before the event."},
                        status=status.HTTP_403_FORBIDDEN
                    )
                
                # After event: check show_participants_after_event
                elif event_ended and not event.show_participants_after_event:
                    return Response(
                        {"detail": "Participant list is not visible after the event."},
                        status=status.HTTP_403_FORBIDDEN
                    )
            
            # During event (or cancelled): always visible (no restriction during live event)

        # Fetch registrations (only registered status, exclude cancelled)
        qs = (
            EventRegistration.objects
            .filter(event=event, status='registered')
            .exclude(user__is_superuser=True)
            .select_related("user", "user__profile")
            .order_by("-registered_at")
        )
        participant_lookup = build_event_participant_lookup(event)
        is_organizer_view = is_organizer
        rows = []
        hidden_roles_count = 0

        for registration in qs:
            _matched_participants, roles, primary_role = resolve_registration_roles(
                registration,
                participant_lookup,
                event=event,
            )
            public_role_visible = all(
                is_public_role_visible(event, role)
                for role in roles
            )
            hidden_from_public = bool(roles) and not public_role_visible

            if hidden_from_public and not is_organizer_view:
                hidden_roles_count += 1
                continue

            try:
                profile = registration.user.profile
            except Exception:
                profile = None

            mini_user = UserMiniSerializer(registration.user, context={"request": request}).data
            avatar_url = mini_user.get("avatar_url") or ""

            # Get display_order and participant_id from matched EventParticipant records
            display_order = None
            participant_id = None
            if _matched_participants:
                # Use the first matched participant's display_order
                display_order = _matched_participants[0].display_order
                participant_id = _matched_participants[0].id

            rows.append(
                {
                    "registration_id": registration.id,
                    "user_id": registration.user_id,
                    "display_name": mini_user.get("full_name") or registration.user.get_full_name().strip() or registration.user.username or registration.user.email or "Unknown User",
                    "email": registration.user.email or "",
                    "avatar_url": avatar_url or None,
                    "kyc_status": mini_user.get("kyc_status") or getattr(registration.user, "kyc_status", None) or getattr(profile, "kyc_status", "") or "",
                    "profile_url": build_profile_url(registration.user_id),
                    "is_profile_clickable": bool(registration.user_id),
                    "roles": roles,
                    "primary_role": primary_role,
                    "role_labels": [role_label(role) for role in roles],
                    "is_public_role_visible": public_role_visible,
                    "is_hidden_from_public_role_display": hidden_from_public,
                    "registered_at": registration.registered_at,
                    "participant_id": participant_id,
                    "display_order": display_order,
                }
            )

        # Add virtual speakers to the participants list
        virtual_speakers = EventParticipant.objects.filter(
            event=event,
            participant_type=EventParticipant.PARTICIPANT_TYPE_VIRTUAL
        ).select_related("virtual_speaker").order_by("display_order")

        for participant in virtual_speakers:
            if participant.virtual_speaker:
                vs = participant.virtual_speaker
                rows.append(
                    {
                        "registration_id": None,
                        "user_id": None,
                        "display_name": vs.name,
                        "email": "",
                        "avatar_url": vs.profile_image.url if vs.profile_image else None,
                        "kyc_status": "",
                        "profile_url": None,
                        "is_profile_clickable": False,
                        "roles": [participant.role] if participant.role else [],
                        "primary_role": participant.role or "speaker",
                        "role_labels": [role_label(participant.role)] if participant.role else ["Speaker"],
                        "is_public_role_visible": is_public_role_visible(event, participant.role) if participant.role else True,
                        "is_hidden_from_public_role_display": False,
                        "registered_at": None,
                        "participant_id": participant.id,
                        "display_order": participant.display_order,
                    }
                )

        rows.sort(
            key=lambda row: (
                row.get("display_order") if row.get("display_order") is not None else 9999,
                role_priority(row["primary_role"]),
                row["display_name"].lower(),
                row.get("registration_id"),
            )
        )

        public_registered_count = len(rows)

        # Parse and validate limit and offset parameters
        max_limit = 50
        default_limit = 10
        try:
            limit = int(request.query_params.get("limit", default_limit))
            limit = max(1, min(limit, max_limit))
        except (TypeError, ValueError):
            limit = default_limit

        try:
            offset = int(request.query_params.get("offset", 0))
            offset = max(0, offset)
        except (TypeError, ValueError):
            offset = 0

        # Apply pagination
        total_count = len(rows)
        paginated_rows = rows[offset:offset + limit]
        has_next = (offset + limit) < total_count
        next_offset = offset + limit if has_next else None

        serializer = EventParticipantListItemSerializer(paginated_rows, many=True)
        return Response(
            {
                "participants": serializer.data,
                "hidden_roles_count": hidden_roles_count if not is_organizer_view else 0,
                "total_registered_count": qs.count(),
                "public_registered_count": public_registered_count,
                "limit": limit,
                "offset": offset,
                "next_offset": next_offset,
                "has_next": has_next,
            }
        )

    @action(
        detail=True,
        methods=["get"],
        url_path="companion-directory",
        permission_classes=[IsAuthenticated],
    )
    def companion_directory(self, request, pk=None):
        """
        Event Companion V1: Participant Directory for authenticated users.

        Access control:
        - User must be registered for the event (EventRegistration.status='registered'), OR
        - User must have approved application (EventApplication.status='approved'), OR
        - User must be the event manager

        Supports search (name, job_title, company) and role filtering.

        Response includes:
        - event: basic event info
        - filters: available role filters
        - participants: filtered participant data with badge labels
        - count: total participants
        """
        event = self.get_object()
        user = request.user

        # Check access permissions
        is_event_manager = _is_event_manager(user, event)
        is_registered = EventRegistration.objects.filter(
            event=event,
            user=user,
            status='registered'
        ).exists()
        is_approved = EventApplication.objects.filter(
            event=event,
            user=user,
            status='approved'
        ).exists()

        # Allow access only if registered, approved application, or event manager
        if not (is_registered or is_approved or is_event_manager):
            return Response({"detail": "Forbidden. You must be registered or approved to access the companion directory."}, status=403)

        # Block regular users before event start (but allow event managers to preview)
        if event.start_time and timezone.now() < event.start_time and not is_event_manager:
            return Response(
                {
                    "code": "COMPANION_NOT_OPEN",
                    "detail": "Participant Directory will open when the event starts.",
                    "event_start_time": event.start_time.isoformat(),
                    "server_time": timezone.now().isoformat(),
                },
                status=403
            )

        # Fetch registrations (only registered status, exclude superusers)
        qs = (
            EventRegistration.objects
            .filter(event=event, status='registered')
            .exclude(user__is_superuser=True)
            .select_related("user", "user__profile")
            .prefetch_related("badge_labels")
            .order_by("-registered_at")
        )

        participant_lookup = build_event_participant_lookup(event)
        rows = []

        # Process registered users as participants
        for registration in qs:
            _matched_participants, roles, primary_role = resolve_registration_roles(
                registration,
                participant_lookup,
                event=event,
            )

            try:
                profile = registration.user.profile
            except Exception:
                profile = None

            mini_user = UserMiniSerializer(registration.user, context={"request": request}).data
            avatar_url = mini_user.get("avatar_url") or ""

            display_name = mini_user.get("full_name") or registration.user.get_full_name().strip() or registration.user.username or registration.user.email or "Unknown User"

            # Get job_title and company from profile or latest experience
            job_title = ""
            company = ""
            if profile:
                job_title = profile.job_title or ""
                company = profile.company or ""

            # If not in profile, try to get from latest experience
            if not job_title or not company:
                try:
                    from users.models import Experience
                    latest_exp = Experience.objects.filter(
                        user=registration.user
                    ).order_by(
                        '-currently_work_here', '-end_date', '-start_date', '-id'
                    ).first()

                    if latest_exp:
                        if not job_title:
                            job_title = latest_exp.position or ""
                        if not company:
                            company = latest_exp.community_name or ""
                except Exception:
                    pass

            # Badge logic: use primary role if speaker/moderator/host, else "attendee"
            badge_key = primary_role.lower() if primary_role in ['speaker', 'moderator', 'host'] else 'attendee'
            badge_label = role_label(badge_key)

            # Fetch custom badge labels
            custom_badges = [
                {'id': bl.id, 'name': bl.name, 'color': bl.color}
                for bl in registration.badge_labels.all()
            ]

            rows.append({
                "registration_id": registration.id,
                "user_id": registration.user_id,
                "display_name": display_name,
                "job_title": job_title,
                "company": company,
                "avatar_url": avatar_url or None,
                "profile_url": build_profile_url(registration.user_id),
                "badge_key": badge_key,
                "badge_label": badge_label,
                "badge_labels": custom_badges,
                "roles": roles,
                "registered_at": registration.registered_at,
            })

        # Add virtual speakers to participants
        virtual_speakers = EventParticipant.objects.filter(
            event=event,
            participant_type=EventParticipant.PARTICIPANT_TYPE_VIRTUAL
        ).select_related("virtual_speaker").order_by("display_order")

        for participant in virtual_speakers:
            if participant.virtual_speaker:
                vs = participant.virtual_speaker
                badge_key = participant.role.lower() if participant.role in ['speaker', 'moderator', 'host'] else 'speaker'
                badge_label = role_label(badge_key)

                rows.append({
                    "registration_id": None,
                    "user_id": None,
                    "display_name": vs.name,
                    "job_title": vs.job_title or "",
                    "company": vs.company or "",
                    "avatar_url": vs.profile_image.url if vs.profile_image else None,
                    "profile_url": None,
                    "badge_key": badge_key,
                    "badge_label": badge_label,
                    "roles": [participant.role] if participant.role else [],
                    "registered_at": None,
                })

        # Apply search filter
        search_query = request.query_params.get('q', '').lower().strip()
        if search_query:
            rows = [
                row for row in rows
                if any(
                    search_query in str(getattr(row, field, '') or row.get(field, '')).lower()
                    for field in ['display_name', 'job_title', 'company', 'badge_label']
                )
            ]

        # Apply role filter
        role_filter = request.query_params.get('role', 'all').lower().strip()
        if role_filter and role_filter != 'all':
            rows = [
                row for row in rows
                if role_filter in [r.lower() for r in row.get('roles', [])] or (
                    role_filter == 'attendee' and not row.get('roles')
                )
            ]

        # Sort by role priority, display_order (if set), then name
        rows.sort(
            key=lambda row: (
                role_priority(row.get("badge_key", "attendee")),
                row.get("display_name", "").lower(),
            )
        )

        # Build filters list
        filters = [
            {"key": "all", "label": "All"},
            {"key": "speaker", "label": "Speaker"},
            {"key": "host", "label": "Host"},
            {"key": "moderator", "label": "Moderator"},
            {"key": "attendee", "label": "Attendee"},
        ]

        return Response({
            "event": {
                "id": event.id,
                "title": event.title,
                "slug": event.slug,
            },
            "count": len(rows),
            "filters": filters,
            "participants": rows,
        })

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="guest-audit")
    def guest_audit(self, request, pk=None):
        event = self.get_object()
        if not _is_event_owner(request.user, event):
            return Response({"detail": "Only the event owner can view guest audit records."}, status=403)

        guests = (
            GuestAttendee.objects
            .filter(event=event)
            .select_related("converted_user", "converted_user__profile")
            .prefetch_related(
                Prefetch(
                    "audit_logs",
                    queryset=GuestProfileAuditLog.objects.order_by("-changed_at", "-id"),
                )
            )
            .order_by("-created_at", "-id")
        )

        rows = []
        for guest in guests:
            converted_user = guest.converted_user
            change_logs = []
            changed_fields = set()

            for log in guest.audit_logs.all():
                changed_fields.add(log.field_name)
                change_logs.append({
                    "id": log.id,
                    "field_name": log.field_name,
                    "field_label": log.get_field_name_display(),
                    "old_value": log.old_value or "",
                    "new_value": log.new_value or "",
                    "source": log.source,
                    "source_label": log.get_source_display(),
                    "changed_at": log.changed_at,
                })

            rows.append({
                "guest_id": guest.id,
                "name": guest.get_display_name(),
                "first_name": guest.first_name,
                "last_name": guest.last_name,
                "guest_email": guest.email,
                "company": guest.company or "",
                "job_title": guest.job_title or "",
                "email_verified": bool(guest.email_verified),
                "is_banned": bool(guest.is_banned),
                "created_at": guest.created_at,
                "joined_live": bool(guest.joined_live),
                "joined_live_at": guest.joined_live_at,
                "current_location": guest.current_location or "",
                "converted_at": guest.converted_at,
                "change_count": len(change_logs),
                "changed_fields": sorted(changed_fields),
                "converted_user": (
                    {
                        "id": converted_user.id,
                        "email": converted_user.email or "",
                        "name": converted_user.get_full_name().strip() or converted_user.username or converted_user.email or "",
                    }
                    if converted_user else None
                ),
                "registered_email": converted_user.email if converted_user else "",
                "email_changed_on_signup": bool(converted_user and (converted_user.email or "").strip().lower() != (guest.email or "").strip().lower()),
                "changes": change_logs,
            })

        return Response({
            "event_id": event.id,
            "guest_count": len(rows),
            "converted_count": sum(1 for row in rows if row["converted_user"]),
            "guests": rows,
        })

    def _get_lounge_availability(self, event):
        """
        Shared function to determine lounge availability status.
        Used by both lounge_state (GET) and lounge_join_table (POST) endpoints.

        Returns: (status_code, reason, next_change_time)
            - status_code: "OPEN" or "CLOSED"
            - reason: Human-readable explanation
            - next_change_time: When status is expected to change

        CRITICAL: This function checks conditions in order BEFORE → DURING → AFTER
        to prevent race conditions where is_live flag changes between API calls.
        """
        now = timezone.now()

        # ✅ BEFORE event (pre-event lounge window) - Check FIRST
        # This prevents race conditions where is_live flag changes between API calls
        if event.lounge_enabled_before and event.start_time:
            opening = event.start_time - timedelta(minutes=event.lounge_before_buffer)
            if opening <= now < event.start_time:
                return "OPEN", "Pre-event networking", event.start_time
            if now < opening:
                return "CLOSED", f"Lounge opens {event.lounge_before_buffer}m before event", opening

        # ✅ DURING event (is_live = True) - Check SECOND
        if event.is_live:
            logger.info(f"[_get_lounge_availability] Event {event.id}: DURING check - is_live=True, lounge_enabled_during={event.lounge_enabled_during}")

            # Special override: if Speed Networking is active and this setting is enabled,
            # Social Lounge should be available even when regular "during live" lounge is off.
            if getattr(event, "lounge_enabled_speed_networking", False):
                try:
                    from .models import SpeedNetworkingSession
                    sn_active = SpeedNetworkingSession.objects.filter(
                        event_id=event.id,
                        status="ACTIVE",
                    ).exists()
                except Exception:
                    sn_active = False

                if sn_active:
                    return "OPEN", "Speed Networking is active", event.live_ended_at

            if event.is_on_break:
                if event.lounge_enabled_breaks:
                    return "OPEN", "Event is on break", event.end_time
                else:
                    return "CLOSED", "Lounge closed during breaks", None

            if event.lounge_enabled_during:
                return "OPEN", "Event is live", event.live_ended_at
            else:
                logger.info(f"[_get_lounge_availability] Event {event.id}: Returning CLOSED - lounge_enabled_during=False")
                return "CLOSED", "Lounge closed during live sessions", None

        # ✅ AFTER event (event ended within lounge_after_buffer window) - Check THIRD
        if event.live_ended_at:
            logger.info(f"[_get_lounge_availability] Event {event.id}: AFTER check - live_ended_at={event.live_ended_at}, lounge_enabled_after={event.lounge_enabled_after}, lounge_after_buffer={event.lounge_after_buffer}")
            if event.lounge_enabled_after:
                closing = event.live_ended_at + timedelta(minutes=event.lounge_after_buffer)
                logger.info(f"[_get_lounge_availability] Event {event.id}: Post-event window check - now={now}, closing={closing}, in_window={event.live_ended_at <= now < closing}")
                if event.live_ended_at <= now < closing:
                    logger.info(f"[_get_lounge_availability] Event {event.id}: ✅ Returning OPEN - in post-event window ({event.live_ended_at} <= {now} < {closing})")
                    return "OPEN", "Post-event networking", closing
                if now >= closing:
                    logger.info(f"[_get_lounge_availability] Event {event.id}: Lounge window expired ({now} >= {closing})")
                    return "CLOSED", "Lounge is now closed", None
            else:
                logger.info(f"[_get_lounge_availability] Event {event.id}: lounge_enabled_after=False, skipping post-event lounge")

        if event.status == "ended":
            logger.info(f"[_get_lounge_availability] Event {event.id}: Returning CLOSED - event.status='ended'")
            return "CLOSED", "Lounge is closed (event ended)", None

        return "CLOSED", "Lounge is currently closed", event.start_time

    @action(detail=True, methods=["get"], url_path="lounge-state")
    def lounge_state(self, request, pk=None):
        """Fetch the current state of the Social Lounge for this event."""
        event = self.get_object()
        cache_key = f"event:{event.id}:http_lounge_state:v1"

        logger.debug(
            "[lounge_state] Event %s: is_live=%s status=%s live_ended_at=%s "
            "lounge_enabled_after=%s lounge_enabled_during=%s",
            event.id,
            event.is_live,
            event.status,
            event.live_ended_at,
            event.lounge_enabled_after,
            event.lounge_enabled_during,
        )

        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached)

        # ✅ Use shared function to ensure consistency with lounge_join_table
        status_code, reason, next_change = self._get_lounge_availability(event)

        def _avatar_url(user_obj):
            profile = getattr(user_obj, "profile", None)
            img = getattr(profile, "user_image", None) if profile else None
            if not img:
                img = getattr(user_obj, "avatar", None) or getattr(profile, "avatar", None) if profile else None
            if not img:
                return ""
            try:
                url = img.url
            except Exception:
                url = str(img) if img else ""
            if not url:
                return ""
            try:
                return request.build_absolute_uri(url)
            except Exception:
                return url

        def _user_mini(user_obj):
            try:
                return UserMiniSerializer(user_obj, context={"request": request}).data
            except Exception:
                return {}

        tables = LoungeTable.objects.filter(event_id=pk).prefetch_related('participants__user__profile')
        guest_rows = (
            event.guest_attendees
            .filter(converted_at__isnull=True, lounge_table_id__isnull=False)
            .order_by("id")
            .only("id", "first_name", "last_name", "email", "joined_live_at", "lounge_table_id")
        )
        guests_by_table = defaultdict(list)
        for guest in guest_rows:
            guests_by_table[guest.lounge_table_id].append(guest)

        state = []
        for t in tables:
            icon_url = ""
            if getattr(t, "icon", None):
                try:
                    icon_url = request.build_absolute_uri(t.icon.url)
                except Exception:
                    icon_url = t.icon.url
            participants = {
                p.seat_index: {
                    **_user_mini(p.user),
                    "user_id": p.user.id,
                    "username": p.user.username,
                    "full_name": f"{p.user.first_name} {p.user.last_name}".strip() or p.user.username,
                    "avatar_url": _avatar_url(p.user),
                    "joined_at": p.joined_at.isoformat() if p.joined_at else None,
                } for p in t.participants.all()
            }
            seat_start = (max(participants.keys()) + 1) if participants else 0
            for i, g in enumerate(guests_by_table.get(t.id, [])):
                participants[seat_start + i] = {
                    "user_id": f"guest_{g.id}",
                    "username": g.get_display_name(),
                    "full_name": g.get_display_name(),
                    "avatar_url": "",
                    "joined_at": g.joined_live_at.isoformat() if g.joined_live_at else None,
                    "is_guest": True,
                }
            state.append({
                "id": t.id,
                "name": t.name,
                "category": t.category,
                "max_seats": t.max_seats,
                "rtk_meeting_id": t.rtk_meeting_id,
                "icon_url": icon_url,
                "participants": participants
            })
        
        data = {
            "tables": state,
            "lounge_open_status": {
                "status": status_code,
                "reason": reason,
                "next_change": next_change
            }
        }
        cache.set(cache_key, data, 2)
        return Response(data)

    @action(detail=True, methods=["post"], url_path="create-lounge-table")
    def create_lounge_table(self, request, pk=None):
        print(f"DEBUG: create_lounge_table hit for event {pk}")
        """Admin-only: Create a new table in the Social Lounge."""
        event = self.get_object()
        if not _is_event_owner(request.user, event):
            return Response({"detail": "Not authorized. Only the event owner can create lounge tables."}, status=403)

        name = request.data.get("name", "New Table")
        category = request.data.get("category", "LOUNGE")
        max_seats = int(request.data.get("max_seats", 4))
        icon_file = request.FILES.get("icon") if hasattr(request, "FILES") else None

        # Create table with a unique RTK meeting
        payload = {
            "title": f"[{category}] {event.title} - {name}",
            "record_on_start": False,
        }
        try:
            resp = requests.post(f"{RTK_API_BASE}/meetings", headers=_rtk_headers(), json=payload, timeout=10)
            resp.raise_for_status()
            rtk_id = resp.json().get("data", {}).get("id")
        except Exception as e:
            logger.error(f"Failed to create RTK meeting for lounge table: {e}")
            rtk_id = None

        table = LoungeTable.objects.create(
            event=event,
            name=name,
            category=category,
            max_seats=max_seats,
            rtk_meeting_id=rtk_id,
            icon=icon_file,
        )

        icon_url = ""
        if table.icon:
            try:
                icon_url = request.build_absolute_uri(table.icon.url)
            except Exception:
                icon_url = table.icon.url

        return Response({
            "id": table.id,
            "name": table.name,
            "rtk_meeting_id": table.rtk_meeting_id,
            "icon_url": icon_url,
        }, status=201)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="lounge-table-update")
    def lounge_table_update(self, request, pk=None):
        """Admin-only: Update a lounge table (name, seats, icon)."""
        event = self.get_object()
        if not _is_event_owner(request.user, event):
            return Response({"detail": "Not authorized. Only the event owner can update lounge tables."}, status=403)

        table_id = request.data.get("table_id")
        if not table_id:
            return Response({"error": "missing_table_id"}, status=400)

        table = get_object_or_404(LoungeTable, id=table_id, event_id=pk)

        name = request.data.get("name")
        max_seats = request.data.get("max_seats")
        icon_file = request.FILES.get("icon") if hasattr(request, "FILES") else None

        if name is not None:
            table.name = name
        if max_seats is not None:
            try:
                table.max_seats = int(max_seats)
            except (TypeError, ValueError):
                return Response({"error": "invalid_max_seats"}, status=400)
        if icon_file:
            table.icon = icon_file

        table.save()

        icon_url = ""
        if table.icon:
            try:
                icon_url = request.build_absolute_uri(table.icon.url)
            except Exception:
                icon_url = table.icon.url

        return Response({
            "id": table.id,
            "name": table.name,
            "max_seats": table.max_seats,
            "icon_url": icon_url,
        })

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="lounge-table-delete")
    def lounge_table_delete(self, request, pk=None):
        """Admin-only: Delete a lounge table."""
        event = self.get_object()
        if not _is_event_owner(request.user, event):
            return Response({"detail": "Not authorized. Only the event owner can delete lounge tables."}, status=403)

        table_id = request.data.get("table_id")
        if not table_id:
            return Response({"error": "missing_table_id"}, status=400)

        table = get_object_or_404(LoungeTable, id=table_id, event_id=pk)
        
        # Clear previous assignments if this was a breakout room
        if table.category == "BREAKOUT":
             EventRegistration.objects.filter(event=event, last_breakout_table=table).update(last_breakout_table=None)

        LoungeParticipant.objects.filter(table=table).delete()
        table.delete()
        return Response({"ok": True})

    @action(detail=True, methods=["post"], url_path="lounge-table-icon")
    def lounge_table_icon(self, request, pk=None):
        """Admin-only: Update a lounge table's icon."""
        event = self.get_object()
        if not _is_event_owner(request.user, event):
            return Response({"detail": "Not authorized. Only the event owner can update lounge table icons."}, status=403)

        table_id = request.data.get("table_id")
        icon_file = request.FILES.get("icon") if hasattr(request, "FILES") else None
        if not table_id or not icon_file:
            return Response({"error": "missing_table_id_or_icon"}, status=400)

        table = get_object_or_404(LoungeTable, id=table_id, event_id=pk)
        table.icon = icon_file
        table.save(update_fields=["icon"])

        icon_url = ""
        if table.icon:
            try:
                icon_url = request.build_absolute_uri(table.icon.url)
            except Exception:
                icon_url = table.icon.url

        return Response({"id": table.id, "icon_url": icon_url})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="lounge-join-table")
    def lounge_join_table(self, request, pk=None):
        print(f"DEBUG: lounge_join_table hit for event {pk}")
        """
        Get an RTK authToken for a specific Social Lounge or Breakout room table.
        - For BREAKOUT tables: Allow join during live events regardless of lounge settings
        - For LOUNGE tables: Validate that the lounge is currently open before allowing join
        - Supports both registered users and guest participants (via GuestJWTAuthentication)
        """
        table_id = request.data.get("table_id")
        if not table_id:
            return Response({"error": "missing_table_id"}, status=400)
        try:
            table_id = int(table_id)
        except (TypeError, ValueError):
            return Response({"error": "invalid_table_id"}, status=400)

        table = get_object_or_404(LoungeTable, id=table_id, event_id=pk)
        event = table.event
        now = timezone.now()
        user = request.user

        # ──── GUEST BRANCH ──────────────────────────────────────────────────────
        if getattr(user, "is_guest", False):
            # Guest participant (JWT authenticated)
            guest = user.guest

            # Guests can join lounge/breakout tables with host preset (full permissions)
            try:
                meeting_id = _ensure_rtk_meeting_for_event(event)
                rtk_meeting_id = table.rtk_meeting_id if table.rtk_meeting_id else meeting_id
            except RuntimeError as e:
                logger.error(f"RTK meeting error for lounge table {table.id}: {str(e)}")
                return Response(
                    {"error": "rtk_meeting_error", "detail": str(e)},
                    status=500,
                )

            # Add guest as table participant (host preset for lounge tables)
            rtk_participant_id = f"guest_{guest.id}"
            rtk_resp = add_rtk_participant(
                meeting_id=rtk_meeting_id,
                user_id=rtk_participant_id,
                name=guest.get_display_name(),
                preset_name=RTK_PRESET_HOST,  # Host preset for lounge tables
            )
            # add_rtk_participant() returns (token, error_message)
            auth_token = ""
            participant_id = rtk_participant_id
            if isinstance(rtk_resp, tuple):
                auth_token, rtk_error = rtk_resp
                if rtk_error or not auth_token:
                    return Response(
                        {"error": "rtk_participant_error", "detail": rtk_error or "RTK did not return auth token."},
                        status=500,
                    )
            else:
                data = (rtk_resp or {}).get("data", {})
                auth_token = data.get("token", "")
                participant_id = data.get("id", rtk_participant_id)
                if not auth_token:
                    return Response(
                        {"error": "rtk_token_missing", "detail": "RTK did not return auth token."},
                        status=500,
                    )

            # Track guest lounge presence on GuestAttendee (LoungeParticipant has no guest FK)
            guest.current_location = "social_lounge" if table.category == "LOUNGE" else "breakout_room"
            guest.rtk_participant_id = participant_id
            guest.lounge_table = table
            guest.save(update_fields=["current_location", "rtk_participant_id", "lounge_table"])

            logger.info(f"Guest {guest.email} joined lounge table {table.id}")

            return Response({
                # Keep both keys for compatibility across UI call sites.
                "token": auth_token,
                "authToken": auth_token,
                "participant_id": participant_id,
                "meetingId": rtk_meeting_id,
                "presetName": RTK_PRESET_HOST,
                "role": "publisher",
                "isGuest": True,
                "guestName": guest.get_display_name(),
                "table_id": table.id,
            })
        # ──── END GUEST BRANCH ──────────────────────────────────────────────────

        # ✅ FIX #1: Check waiting room status and enforce access control
        is_host = _is_event_manager(user, event)

        # Only enforce waiting room for non-hosts
        if not is_host and event.waiting_room_enabled:
            try:
                registration = EventRegistration.objects.get(event=event, user=user)

                # If user is in waiting room, check if lounge is allowed
                if registration.admission_status == "waiting":
                    if not event.lounge_enabled_waiting_room:
                        logger.warning(
                            f"[LOUNGE_ENFORCE] ❌ Waiting user {user.id} denied lounge access. "
                            f"Event {event.id} has lounge_enabled_waiting_room=False"
                        )
                        return Response({
                            "error": "waiting_room_active",
                            "reason": "You must be admitted by the host before accessing the lounge",
                            "lounge_allowed": False
                        }, status=403)
                    else:
                        logger.info(
                            f"[LOUNGE_ENFORCE] ✅ Waiting user {user.id} allowed lounge access. "
                            f"Event {event.id} has lounge_enabled_waiting_room=True"
                        )

                # If user is rejected, deny all lounge access
                elif registration.admission_status == "rejected":
                    logger.warning(
                        f"[LOUNGE_ENFORCE] ❌ Rejected user {user.id} denied lounge access. "
                        f"Event {event.id} has waiting room enabled"
                    )
                    return Response({
                        "error": "waiting_rejected",
                        "reason": "You have been rejected from this event",
                        "lounge_allowed": False
                    }, status=403)

            except EventRegistration.DoesNotExist:
                # User not registered for event while waiting room is enabled
                # Create registration in waiting state (but NOT in waiting room yet)
                # ✅ IMPORTANT: Do NOT set waiting_started_at here!
                # waiting_started_at should only be set when user ACTUALLY JOINS the event,
                # not just when accessing the pre-event lounge or registering.
                # This ensures they don't appear in host's waiting room list until they actively join.
                registration = EventRegistration.objects.create(
                    event=event,
                    user=user,
                    admission_status="waiting"
                    # waiting_started_at is intentionally left NULL
                )
                logger.info(
                    f"[LOUNGE_ENFORCE] ⚠️ Unregistered user {user.id} auto-registered for event {event.id} "
                    f"(admission_status=waiting, but waiting_started_at NOT set until they join main event)"
                )

                # Check if lounge is allowed for waiting users
                if not event.lounge_enabled_waiting_room:
                    logger.warning(
                        f"[LOUNGE_ENFORCE] ❌ Auto-registered waiting user {user.id} denied lounge access"
                    )
                    return Response({
                        "error": "waiting_room_active",
                        "reason": "You must be admitted by the host before accessing the lounge",
                        "lounge_allowed": False
                    }, status=403)

        # ✅ FIX #2B: Verify user is assigned to breakout rooms before allowing join
        if table.category == "BREAKOUT":
            if not is_host:
                # Regular participant must be assigned to this breakout room
                is_assigned = LoungeParticipant.objects.filter(
                    table=table,
                    user=user
                ).exists()

                if not is_assigned:
                    logger.warning(
                        f"[LOUNGE_JOIN] ❌ User {user.id} attempted to join unassigned breakout "
                        f"room {table_id}. Unauthorized access attempt."
                    )
                    return Response({
                        "error": "not_assigned",
                        "reason": "You are not assigned to this breakout room",
                        "table_id": table_id
                    }, status=403)

                logger.info(
                    f"[LOUNGE_JOIN] ✅ User {user.id} verified assigned to breakout room {table_id}"
                )

            # Breakout rooms are a separate feature from the Social Lounge and should work independently
            if event.is_live:
                # Breakout rooms can be joined during live event
                print(f"[LOUNGE_JOIN] Breakout room access allowed: table={table_id}, event_is_live=True")
            else:
                # Breakout rooms cannot be joined after event ends
                return Response({
                    "error": "breakout_not_available",
                    "reason": "Breakout rooms are only available during the live event"
                }, status=403)
        else:
            # ✅ LOUNGE TABLES: Validate lounge availability based on event state and timing

            if event.status == "ended" and not event.live_ended_at:
                # Event ended but no live_ended_at timestamp (shouldn't happen)
                return Response({
                    "error": "lounge_closed",
                    "reason": "Event has ended but timing is invalid"
                }, status=403)

            # ✅ REFRESH: Ensure we have the latest event state to prevent race conditions
            # between lounge_state GET and lounge_join_table POST requests
            event.refresh_from_db()

            logger.info(f"[LOUNGE_JOIN] Checking lounge availability for event {event.id}. "
                       f"is_live={event.is_live}, is_on_break={event.is_on_break}, "
                       f"lounge_enabled_before={event.lounge_enabled_before}, "
                       f"lounge_enabled_during={event.lounge_enabled_during}, "
                       f"now={now}")

            # ✅ Use shared function to ensure consistency with lounge_state endpoint
            status_code, reason, next_change = self._get_lounge_availability(event)

            if status_code != "OPEN":
                logger.warning(f"[LOUNGE_JOIN] ❌ Lounge not available for user {request.user.id}. "
                             f"Status: {status_code}, Reason: {reason}")
                return Response({
                    "error": "lounge_closed",
                    "reason": reason
                }, status=403)

            logger.info(f"[LOUNGE_JOIN] ✅ Lounge OPEN for user {request.user.id}. Reason: {reason}")

        # ✅ DEFENSIVE: Ensure meeting state is not accidentally reactivated
        # If meeting was ended, it must stay ended (joining lounge doesn't restart meeting)
        if event.status == "ended" and not event.is_live:
            logger.info(f"[LOUNGE_JOIN] User {request.user.id} joining post-event lounge for event {event.id}")
            # Verify from DB that meeting hasn't been reactivated
            event.refresh_from_db()
            if event.is_live:
                # CRITICAL: Meeting state was changed somehow
                logger.critical(f"[CRITICAL] Event {event.id} is_live was True when it should be False! Reverting.")
                event.is_live = False
                event.save(update_fields=["is_live"])

        # Ensure meeting exists for this table
        meeting_id = table.rtk_meeting_id
        if not meeting_id:
             # Try to create one if it somehow went missing
            payload = {"title": f"Table: {table.name}", "record_on_start": False}
            try:
                resp = requests.post(f"{RTK_API_BASE}/meetings", headers=_rtk_headers(), json=payload, timeout=10)
                resp.raise_for_status()
                meeting_id = resp.json().get("data", {}).get("id")
                table.rtk_meeting_id = meeting_id
                table.save(update_fields=["rtk_meeting_id"])
            except Exception as e:
                return Response({"error": "rtk_creation_failed", "detail": str(e)}, status=500)

        # Add participant to the table meeting
        user = request.user

        # ✅ CLEANUP: Remove any stale LoungeParticipant records before joining
        # This prevents 409 conflicts when a user rejoins after leaving
        # NOTE: We only clean up Django DB records here, RTK cleanup happens below if needed
        stale_records = LoungeParticipant.objects.filter(
            table__event_id=event.id,
            user=user
        ).exclude(table_id=table.id)  # Exclude the current table

        for stale in stale_records:
            try:
                # Store RTK info before deleting the record
                rtk_meeting_id = stale.table.rtk_meeting_id
                rtk_participant_id = stale.rtk_participant_id

                # Delete the stale DB record first (quick operation, synchronous)
                stale.delete()
                logger.info(f"[LOUNGE_JOIN] Cleaned up stale LoungeParticipant record for user {user.id}")

                # Enqueue RTK cleanup as async task (don't block user request)
                if rtk_participant_id and rtk_meeting_id:
                    from .tasks import cleanup_rtk_participant_task
                    cleanup_rtk_participant_task.delay(rtk_meeting_id, rtk_participant_id)
                    logger.info(f"[LOUNGE_JOIN] Enqueued RTK cleanup task for participant {rtk_participant_id}")
            except Exception as e:
                logger.warning(f"[LOUNGE_JOIN] Error cleaning stale record: {e}")

        # Check if user already in this meeting (duplicate prevention)
        duplicate_found = False
        try:
            logger.info(f"[LOUNGE_JOIN] Checking for duplicates: user {user.id}")
            check_resp = requests.get(
                f"{RTK_API_BASE}/meetings/{meeting_id}/participants",
                headers=_rtk_headers(),
                params={"limit": 100},
                timeout=8,
            )
            if check_resp.ok:
                existing = check_resp.json().get("data", [])
                for p in existing:
                    cid = p.get("client_specific_id") or p.get("custom_participant_id")
                    if cid == str(user.id):
                        duplicate_found = True
                        logger.warning(f"[LOUNGE_JOIN] Duplicate detected: user {user.id}")
                        # Enqueue async task to remove duplicate from RTK and allow rejoin
                        rtk_id = p.get("id")
                        if rtk_id:
                            from .tasks import cleanup_rtk_participant_task
                            cleanup_rtk_participant_task.delay(meeting_id, rtk_id)
                            logger.info(f"[LOUNGE_JOIN] Enqueued cleanup task for stale participant {rtk_id}, allowing rejoin")
                            duplicate_found = False  # Allow rejoin while cleanup happens async
                            break
        except requests.exceptions.Timeout:
            logger.warning(f"[LOUNGE_JOIN] Duplicate check timed out, proceeding with join")
            # Don't block on timeout, proceed with join
        except Exception as e:
            logger.warning(f"[LOUNGE_JOIN] Duplicate check failed: {e}")
            # Don't block on error, proceed with join

        if duplicate_found:
            return Response({
                "error": "already_in_meeting",
                "detail": "Already in this table. Leave first."
            }, status=409)

        # ✅ FIX #1C: Update or create LoungeParticipant record for tracking
        # This ensures the user is properly tracked in the lounge occupants
        lounge_participant = None
        try:
            # Try to update existing record if joining same table
            lounge_participant, created = LoungeParticipant.objects.get_or_create(
                table=table,
                user=user,
                defaults={"seat_index": 0}  # Placeholder, seat assignment can be optimized later
            )
            if not created:
                logger.info(f"[LOUNGE_JOIN] User {user.id} updated lounge participant record for table {table_id}")
            else:
                logger.info(f"[LOUNGE_JOIN] User {user.id} created new lounge participant record for table {table_id}")
        except Exception as e:
            logger.warning(f"[LOUNGE_JOIN] Failed to create/update lounge participant record: {e}")
            # Don't fail the join, just log warning

        profile = getattr(user, "profile", None)
        name = (getattr(profile, "full_name", "") if profile else "") or getattr(user, "get_full_name", lambda: "")() or user.username
        picture = ""
        try:
            if profile and getattr(profile, "user_image", None):
                picture = profile.user_image.url
        except Exception:
            picture = ""

        # ✅ CRITICAL FIX: Grant full media permissions in lounge for ALL users
        # Hosts get host preset (full control)
        # Participants get host preset in lounge to enable mic/camera toggle
        # This allows participants to have full media capabilities in social lounge/breakout rooms
        # while maintaining participant restrictions in the main stage meeting
        preset = RTK_PRESET_HOST  # Use host preset for all lounge participants for full media control

        body = {
            "name": name or f"User {user.id}",
            "preset_name": preset,
            "client_specific_id": str(user.id),
        }
        if picture:
            body["picture"] = picture
        
        try:
            logger.info(f"[LOUNGE_JOIN] User {user.id} joining table {table_id} (meeting {meeting_id})")
            resp = requests.post(
                f"{RTK_API_BASE}/meetings/{meeting_id}/participants",
                headers=_rtk_headers(),
                json=body,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            # Validate response
            token = data.get("token")
            participant_id = data.get("id")

            if not token:
                logger.error(f"[LOUNGE_JOIN] No token in RTK response for user {user.id}")
                return Response({"error": "rtk_token_missing"}, status=500)

            if participant_id:
                logger.info(f"[LOUNGE_JOIN] Success: user {user.id} -> participant {participant_id}")

                # ✅ Store the RTK participant ID for accurate cleanup on leave
                if lounge_participant:
                    try:
                        lounge_participant.rtk_participant_id = participant_id
                        lounge_participant.save(update_fields=["rtk_participant_id"])
                        logger.info(f"[LOUNGE_JOIN] Stored RTK participant ID {participant_id} for cleanup")
                    except Exception as e:
                        logger.warning(f"[LOUNGE_JOIN] Failed to store RTK participant ID: {e}")

            return Response({"token": token, "participant_id": participant_id})
        except requests.exceptions.HTTPError as e:
            logger.error(f"[LOUNGE_JOIN] RTK API error: {e.response.status_code}")
            return Response({"error": "rtk_api_error"}, status=500)
        except Exception as e:
            logger.error(f"[LOUNGE_JOIN] Exception: {str(e)}")
            return Response({"error": "rtk_join_failed", "detail": str(e)}, status=500)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="lounge-leave-table")
    def lounge_leave_table(self, request, pk=None):
        """
        User leaves a lounge table.
        Removes from both Django DB and RTK meeting to prevent 409 conflicts on rejoin.
        """
        from .models import BreakoutJoiner

        user = request.user
        event = self.get_object()

        if getattr(user, "is_guest", False):
            guest = user.guest
            table = guest.lounge_table
            meeting_id = getattr(table, "rtk_meeting_id", None) if table else None
            rtk_participant_id = guest.rtk_participant_id
            try:
                # Enqueue RTK cleanup as async task (don't block user request)
                if meeting_id and rtk_participant_id:
                    from .tasks import cleanup_rtk_participant_task
                    cleanup_rtk_participant_task.delay(meeting_id, rtk_participant_id)
                    logger.info(f"[LOUNGE_LEAVE][GUEST] Enqueued RTK cleanup for participant {rtk_participant_id}")

                # Update guest state immediately (synchronous, quick)
                # Leaving a table from the live UI means returning to the main room context.
                guest.current_location = "main_room"
                guest.lounge_table = None
                guest.rtk_participant_id = ""
                guest.save(update_fields=["current_location", "lounge_table", "rtk_participant_id"])
                return Response({"ok": True, "left_table": getattr(table, "id", None)})
            except Exception as e:
                logger.error(f"[LOUNGE_LEAVE][GUEST] Exception: {str(e)}")
                return Response({"error": "leave_failed", "detail": str(e)}, status=500)

        try:
            # 1. Find the lounge record
            lounge_record = LoungeParticipant.objects.filter(
                table__event_id=event.id,
                user=user
            ).first()

            if not lounge_record:
                logger.info(f"[LOUNGE_LEAVE] User {user.id} is not at any lounge table")
                return Response({
                    "error": "not_at_table",
                    "detail": "You are not currently at any lounge table"
                }, status=404)

            table = lounge_record.table
            meeting_id = table.rtk_meeting_id
            rtk_participant_id = lounge_record.rtk_participant_id

            # 2. Enqueue RTK cleanup as async task (don't block user request)
            if meeting_id:
                from .tasks import cleanup_rtk_participant_task, cleanup_rtk_participant_by_client_id_task

                if rtk_participant_id:
                    # Main path: we have the participant ID
                    cleanup_rtk_participant_task.delay(meeting_id, rtk_participant_id)
                    logger.info(f"[LOUNGE_LEAVE] Enqueued RTK cleanup for user {user.id} "
                              f"(participant_id: {rtk_participant_id})")
                else:
                    # Fallback: cleanup by client_specific_id (will fetch meeting and find participant)
                    cleanup_rtk_participant_by_client_id_task.delay(meeting_id, str(user.id))
                    logger.info(f"[LOUNGE_LEAVE] Enqueued RTK cleanup for user {user.id} "
                              f"(by client_id)")

            # 3. Delete from Django DB
            lounge_record.delete()

            # ✅ FIX: Set current_location to "social_lounge" so user stays visible
            # to host in lounge participant list (they just left a table, not the lounge)
            EventRegistration.objects.filter(
                event=event, user=user
            ).update(current_location="social_lounge")

            if table.category == "BREAKOUT":
                EventRegistration.objects.filter(
                    event=event,
                    user=user,
                ).update(last_breakout_table=None)

                if event.breakout_rooms_active:
                    joiner, _ = BreakoutJoiner.objects.get_or_create(
                        event=event,
                        user=user,
                        defaults={"status": BreakoutJoiner.STATUS_WAITING},
                    )
                    joiner.status = BreakoutJoiner.STATUS_WAITING
                    joiner.assigned_room = table
                    joiner.host_notified = False
                    joiner.save(update_fields=["status", "assigned_room", "host_notified"])

                    breakout_tables = LoungeTable.objects.filter(
                        event=event,
                        category="BREAKOUT",
                    ).prefetch_related("participants")
                    available_rooms = []
                    for breakout_table in breakout_tables:
                        current = breakout_table.participants.count()
                        if current < breakout_table.max_seats:
                            available_rooms.append({
                                "id": breakout_table.id,
                                "name": breakout_table.name,
                                "current_participants": current,
                                "max_seats": breakout_table.max_seats,
                                "available_seats": breakout_table.max_seats - current,
                                "rtk_meeting_id": breakout_table.rtk_meeting_id,
                            })

                    notification_data = {
                        "late_joiner_id": joiner.id,
                        "participant_id": user.id,
                        "participant_name": user.get_full_name() or user.username,
                        "participant_email": user.email,
                        "available_rooms": available_rooms,
                        "can_auto_assign": bool(available_rooms),
                        "previous_room_id": table.id,
                        "previous_room_name": table.name,
                    }

                    BreakoutJoiner.objects.filter(id=joiner.id).update(
                        host_notified=True,
                        notified_host_at=timezone.now(),
                        notification_sent_count=F("notification_sent_count") + 1,
                    )

                    channel_layer = get_channel_layer()
                    async_to_sync(channel_layer.group_send)(
                        f"event_{event.id}",
                        {"type": "late_joiner_notification", "notification": notification_data},
                    )

            logger.info(f"[LOUNGE_LEAVE] User {user.id} successfully left table {table.id}. "
                       f"Removed from both Django and RTK. Location set to social_lounge.")

            return Response({
                "ok": True,
                "message": "Successfully left the table"
            }, status=200)

        except Exception as e:
            logger.error(f"[LOUNGE_LEAVE] Exception: {str(e)}")
            return Response({
                "error": "leave_failed",
                "detail": str(e)
            }, status=500)

    @action(detail=True, methods=["post"], url_path="lounge-close-and-remove-all")
    def lounge_close_and_remove_all(self, request, pk=None):
        """
        Host closes the lounge and removes ALL participants from lounge tables.
        This happens when the host disables the lounge settings.

        - Removes all users from all lounge tables for this event
        - Removes all users from RTK meetings
        - Returns list of removed user IDs for frontend notification
        """
        event = self.get_object()

        # Check authorization - only event host/creator or staff
        user = request.user
        if not (user.is_staff or event.created_by_id == user.id):
            return Response({"detail": "Not authorized"}, status=403)

        try:
            # Get all lounge participants for this event (not just BREAKOUT, but all tables)
            all_participants = LoungeParticipant.objects.filter(
                table__event_id=event.id
            ).select_related('table', 'user')

            removed_users = []
            failed_users = []

            for lounge_record in all_participants:
                table = lounge_record.table
                meeting_id = table.rtk_meeting_id
                rtk_participant_id = lounge_record.rtk_participant_id
                user_id = lounge_record.user.id
                username = lounge_record.user.username

                try:
                    # Remove from RTK meeting if exists
                    if meeting_id:
                        try:
                            if rtk_participant_id:
                                # Use stored RTK participant ID for direct removal
                                requests.delete(
                                    f"{RTK_API_BASE}/meetings/{meeting_id}/participants/{rtk_participant_id}",
                                    headers=_rtk_headers(),
                                    timeout=10,
                                )
                                logger.info(f"[LOUNGE_CLOSE] Removed user {user_id} from RTK meeting {meeting_id}")
                            else:
                                # Fallback: Query RTK to find the participant
                                resp = requests.get(
                                    f"{RTK_API_BASE}/meetings/{meeting_id}/participants",
                                    headers=_rtk_headers(),
                                    params={"limit": 100},
                                    timeout=10,
                                )
                                if resp.ok:
                                    participants = resp.json().get("data", [])
                                    for p in participants:
                                        cid = p.get("client_specific_id") or p.get("custom_participant_id")
                                        if cid == str(user_id):
                                            participant_id = p.get("id")
                                            requests.delete(
                                                f"{RTK_API_BASE}/meetings/{meeting_id}/participants/{participant_id}",
                                                headers=_rtk_headers(),
                                                timeout=10,
                                            )
                                            logger.info(f"[LOUNGE_CLOSE] Removed user {user_id} from RTK meeting {meeting_id}")
                                            break
                        except Exception as e:
                            logger.warning(f"[LOUNGE_CLOSE] Error removing user {user_id} from RTK: {e}")
                            # Don't fail, continue with DB removal

                    # Remove from Django DB
                    lounge_record.delete()
                    removed_users.append({
                        "user_id": user_id,
                        "username": username
                    })
                    logger.info(f"[LOUNGE_CLOSE] User {user_id} ({username}) removed from lounge table {table.id}")

                except Exception as e:
                    logger.error(f"[LOUNGE_CLOSE] Error removing user {user_id}: {e}")
                    failed_users.append({
                        "user_id": user_id,
                        "username": username,
                        "error": str(e)
                    })

            logger.info(f"[LOUNGE_CLOSE] Event {event.id}: Removed {len(removed_users)} users from lounge. "
                       f"Failed: {len(failed_users)}")

            return Response({
                "ok": True,
                "message": f"Removed {len(removed_users)} users from lounge",
                "removed_users": removed_users,
                "failed_users": failed_users
            }, status=200)

        except Exception as e:
            logger.error(f"[LOUNGE_CLOSE] Exception in lounge_close_and_remove_all: {str(e)}")
            return Response({
                "error": "close_lounge_failed",
                "detail": str(e)
            }, status=500)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="track-replay")
    def track_replay(self, request, pk=None):
        """
        Mark the current user as having watched the replay.
        """
        event = self.get_object()
        EventRegistration.objects.filter(event=event, user=request.user).update(watched_replay=True)
        return Response({"ok": True})

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="export-registrations")
    def export_registrations(self, request, pk=None):
        """
        Export registrations as CSV.
        """
        event = self.get_object()
        user = request.user
        if not (user.is_staff or getattr(user, "is_superuser", False) or event.created_by_id == user.id):
            return Response({"detail": "Permission denied."}, status=403)

        import re
        safe_title = re.sub(r'[^a-zA-Z0-9]', '_', event.title or "Event")
        safe_title = re.sub(r'_+', '_', safe_title).strip('_')
        filename = f"{safe_title}_details.csv"

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        response['X-Filename'] = filename

        writer = csv.writer(response)
        writer.writerow(['User ID', 'Name', 'Email', 'Registered At', 'Joined Live', 'Watched Replay', 'Status'])

        regs = EventRegistration.objects.filter(event=event).select_related('user').order_by('-registered_at')
        has_replay = event.replay_available or bool(event.recording_url)

        for r in regs:
            first = (r.user.first_name or "").strip()
            last = (r.user.last_name or "").strip()
            full_name = f"{first} {last}".strip() or r.user.username

            status_label = "Did Not Attend"
            if r.joined_live and r.watched_replay:
                status_label = "Live & Replay"
            elif r.joined_live:
                status_label = "Joined Live"
            elif r.watched_replay:
                status_label = "Watched Replay"

            watched_replay_value = "No replay available" if not has_replay else ("Yes" if r.watched_replay else "No")

            writer.writerow([
                r.user.id,
                full_name,
                r.user.email,
                r.registered_at.strftime("%Y-%m-%d %H:%M:%S"),
                "Yes" if r.joined_live else "No",
                watched_replay_value,
                status_label
            ])

        return response

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="export-members-csv")
    def export_members_csv(self, request, pk=None):
        """
        Export all registered members as CSV with profile data shown on profile page.
        Each email, phone, and experience gets its own column.
        """
        event = self.get_object()
        user = request.user
        if not (user.is_staff or getattr(user, "is_superuser", False) or event.created_by_id == user.id):
            return Response({"detail": "Permission denied."}, status=403)

        filename = "Registered_Participants_Details.csv"

        response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        response['X-Filename'] = filename

        # First pass: collect all data and find max counts for emails, phones, experiences
        regs_data = []
        max_emails = 0
        max_phones = 0
        max_experiences = 0

        regs = (
            EventRegistration.objects
            .filter(event=event, status__in=['registered', 'cancellation_requested'])
            .exclude(user__is_superuser=True)  # Exclude superusers/hosts
            .select_related('user', 'user__profile')
            .prefetch_related('user__experiences')
            .order_by('-registered_at')
        )

        for reg in regs:
            u = reg.user
            profile = u.profile

            # Extract emails
            all_emails = []
            if u.email:
                all_emails.append(u.email)

            links = profile.links or {}
            if isinstance(links, dict):
                contact = links.get('contact', {})
                if isinstance(contact, dict):
                    emails_list = contact.get('emails', [])
                    if isinstance(emails_list, list):
                        for email_obj in emails_list:
                            if isinstance(email_obj, dict):
                                email_val = email_obj.get('email', '')
                            else:
                                email_val = str(email_obj)
                            if email_val and email_val not in all_emails:  # deduplicate
                                all_emails.append(email_val)

            max_emails = max(max_emails, len(all_emails))

            # Extract phone numbers
            phone_numbers = []
            if isinstance(links, dict):
                contact = links.get('contact', {})
                if isinstance(contact, dict):
                    phones_list = contact.get('phones', [])
                    if isinstance(phones_list, list):
                        for phone_obj in phones_list:
                            if isinstance(phone_obj, dict):
                                phone_val = phone_obj.get('number', '')
                            else:
                                phone_val = str(phone_obj)
                            if phone_val:
                                # Format phone number: +CC NNNNNNNNNN
                                phone_val = phone_val.strip()
                                # Remove any existing spaces or dashes
                                phone_val = phone_val.replace(' ', '').replace('-', '')
                                # Ensure + prefix
                                if phone_val and not phone_val.startswith('+'):
                                    phone_val = '+' + phone_val
                                # Add space after country code (typically 2-3 digits after +)
                                # Common: +1, +44, +91, +886, etc.
                                if phone_val.startswith('+'):
                                    digits_only = phone_val[1:]  # Remove the +
                                    # Find country code length (usually 1-3 digits)
                                    cc_len = 2  # Default to 2 for most countries
                                    if digits_only.startswith('1') and len(digits_only) == 11:
                                        cc_len = 1  # US/Canada: +1 XXXXXXXXXX
                                    elif digits_only.startswith(('7', '8', '9')) and len(digits_only) >= 10:
                                        cc_len = 2  # Most countries: +CC XXXXXXXX
                                    elif digits_only.startswith(('2', '3', '4', '5', '6')):
                                        cc_len = 2  # Most European/African: +CC

                                    # Add space after country code
                                    if len(digits_only) > cc_len:
                                        phone_val = '+' + digits_only[:cc_len] + ' ' + digits_only[cc_len:]
                                phone_numbers.append(phone_val)

            max_phones = max(max_phones, len(phone_numbers))

            # Extract experiences (position + company)
            job_and_company = []
            for exp in u.experiences.all():
                position = (exp.position or '').strip()
                company = (exp.community_name or '').strip()
                if position or company:
                    job_and_company.append(f"{position} / {company}".strip('/ ').strip())

            max_experiences = max(max_experiences, len(job_and_company))

            regs_data.append({
                'reg': reg,
                'user': u,
                'profile': profile,
                'emails': all_emails,
                'phones': phone_numbers,
                'experiences': job_and_company
            })

        # Second pass: build fieldnames dynamically
        fieldnames = [
            # Profile basic fields
            'Full Name', 'First Name', 'Last Name',
        ]

        # Add dynamic email columns (first is Primary Email, rest are Email 2, 3, etc.)
        if max_emails > 0:
            fieldnames.append('Primary Email')
        for i in range(2, max_emails + 1):
            fieldnames.append(f'Email {i}')

        # Add dynamic phone columns
        for i in range(1, max_phones + 1):
            fieldnames.append(f'Phone {i}')

        # Add dynamic experience columns
        for i in range(1, max_experiences + 1):
            fieldnames.append(f'Job Title / Company {i}')

        # Add location column only (no attendance columns)
        fieldnames.append('Country/Region')

        writer = csv.DictWriter(response, fieldnames=fieldnames)
        writer.writeheader()

        # Third pass: write rows
        for data in regs_data:
            reg = data['reg']
            u = data['user']
            profile = data['profile']
            all_emails = data['emails']
            phone_numbers = data['phones']
            job_and_company = data['experiences']

            row = {
                'Full Name': profile.full_name or '',
                'First Name': u.first_name or '',
                'Last Name': u.last_name or '',
            }

            # Add emails (first is Primary Email, rest are Email 2, 3, etc.)
            for i, email in enumerate(all_emails):
                if i == 0:
                    row['Primary Email'] = email
                else:
                    row[f'Email {i + 1}'] = email

            # Add phones
            for i, phone in enumerate(phone_numbers, 1):
                row[f'Phone {i}'] = phone

            # Add experiences
            for i, exp in enumerate(job_and_company, 1):
                row[f'Job Title / Company {i}'] = exp

            # Add location field only
            row['Country/Region'] = profile.location or ''

            writer.writerow(row)

        return response

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated], url_path="mine")
    def mine(self, request):
        """
        List events the current user is registered for OR attended as a guest (newest first).
        Supports view=card for optimized card endpoint with minimal fields and prefetched data.
        """
        from django.db.models import Q, Exists, OuterRef

        user = request.user
        user_email = (getattr(user, "email", "") or "").strip()
        view_mode = (request.query_params.get("view") or "").strip().lower()

        is_platform_admin = bool(getattr(user, "is_superuser", False))

        visibility_q = Q(created_by=user)
        if is_platform_admin:
            visibility_q |= Q(status="draft")

        qs = (
            Event.objects
            .filter(
                visibility_q |
                Q(registrations__user=user, registrations__status__in=['registered', 'cancellation_requested'], status__in=['published', 'live', 'ended', 'cancelled']) |
                Q(guest_attendees__converted_user=user, status__in=['published', 'live', 'ended', 'cancelled'])
            )
            .distinct()
            .annotate(registrations_count=Count('registrations', distinct=True))
            .order_by("-start_time")
        )

        bucket = (request.query_params.get("bucket") or "").strip().lower()
        if bucket:
            qs = _apply_bucket_filter(qs, bucket)

        is_hidden_param = request.query_params.get("is_hidden")
        if is_hidden_param is not None:
            is_hidden_bool = is_hidden_param.lower() == "true"
            qs = qs.filter(is_hidden=is_hidden_bool)

        # ✅ Card mode: Use lightweight serializer with Prefetch optimizations
        if view_mode == "card":
            my_reg_prefetch = Prefetch(
                "registrations",
                EventRegistration.objects.filter(user=user, status__in=['registered', 'cancellation_requested'])
            )
            qs = qs.prefetch_related(my_reg_prefetch, "sessions")

            page = self.paginate_queryset(qs)
            events = page if page is not None else qs

            for event in events:
                event._prefetched_my_registration = (
                    event.registrations.first() if hasattr(event, 'registrations') else None
                )

            ser = MyEventCardSerializer(events, many=True, context={"request": request})
            result = ser.data
            return self.get_paginated_response(result) if page is not None else Response(result)

        # ✅ Default mode: Keep existing behavior for backward compatibility
        page = self.paginate_queryset(qs)
        events = page if page is not None else qs
        ser = EventLiteSerializer(events, many=True, context={"request": request})
        data = ser.data

        result = []
        for event_obj, event_data in zip(events, data):
            d = dict(event_data)
            is_actual_owner = (event_obj.created_by_id == user.id)

            if is_actual_owner:
                d["is_host"] = True
            else:
                host_match = Q(participant_type="staff", user_id=user.id)
                if user_email:
                    host_match = host_match | Q(participant_type="guest", guest_email__iexact=user_email)
                d["is_host"] = event_obj.participants.filter(role="host").filter(host_match).exists()

            result.append(d)

        return self.get_paginated_response(result) if page is not None else Response(result)

    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="replays")
    def replays(self, request):
        """
        List available replays: ended events with replay enabled, visible, and media present.
        Excludes already-registered events for authenticated users.
        Supports same filters as normal event list.
        """
        user = request.user
        is_platform_admin = bool(getattr(user, "is_superuser", False)) or bool(getattr(user, "is_staff", False))

        # Start with base queryset
        qs = Event.objects.select_related("community")

        # Handle hidden events: same visibility rules as get_queryset
        if user.is_authenticated:
            if is_platform_admin:
                pass
            else:
                hidden_accessible_ids = EventRegistration.objects.filter(
                    user_id=user.id,
                    status__in=['registered', 'cancellation_requested']
                ).values_list('event_id', flat=True)
                qs = qs.filter(
                    Q(is_hidden=False) |
                    Q(is_hidden=True, created_by_id=user.id) |
                    Q(is_hidden=True, id__in=hidden_accessible_ids)
                )
        else:
            qs = qs.filter(is_hidden=False)

        # Filter for replay events: must be ended with replay enabled, visible, and have media
        now = timezone.now()
        qs = qs.filter(
            status="ended",
            replay_enabled=True,
            replay_visible_to_participants=True
        ).exclude(
            # Must have actual media (recording_url or replay_video_url)
            recording_url="",
            replay_video_url=""
        )

        # For authenticated users: exclude their own registrations
        if user.is_authenticated:
            user_registered_ids = EventRegistration.objects.filter(
                user_id=user.id,
                status="registered"
            ).values_list('event_id', flat=True)
            qs = qs.exclude(id__in=user_registered_ids)

        # Order newest replay first
        qs = qs.order_by("-end_time")

        # Apply all filter backends (category, location, date_range, event_format, price_range, search)
        qs = self.filter_queryset(qs)

        # Paginate
        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="rtk/join")
    @live_join_queue
    def rtk_join(self, request, pk=None):
        """
        Join this event's RTK meeting.

        - Creates a RTK meeting if one doesn't exist yet.
        - Adds the current user as participant (host or normal member).
        - Returns authToken for the frontend RTK SDK.
        - Supports both registered users and guest participants (via GuestJWTAuthentication)
        """
        event = self._get_join_event_or_404(pk)
        user = request.user

        # Capacity protection before issuing main-room meeting token.
        # If autoscaling is enabled and we are below required capacity, return 202 so frontend can poll.
        is_host = False
        if not getattr(user, "is_guest", False):
            try:
                is_host = _is_event_manager(user, event)
            except Exception:
                is_host = False

        if getattr(settings, "LIVE_MEETING_ASG_AUTOSCALE_ENABLED", False) and not is_host:
            try:
                from events.services.live_meeting_capacity import (
                    acquire_asg_scale_lock,
                    clear_capacity_status_cache,
                    event_requires_live_meeting_capacity,
                    get_capacity_status_cached,
                    scale_asg_if_needed,
                )

                if event_requires_live_meeting_capacity(event):
                    capacity_status = get_capacity_status_cached()
                    required = capacity_status["required"]
                    current = capacity_status["current"]

                    if current["desired"] < required["desired_instances"]:
                        if acquire_asg_scale_lock():
                            try:
                                scale_asg_if_needed(
                                    reason=f"participant_waiting_capacity_event_{event.id}",
                                    scale_down_allowed=False,
                                )
                                clear_capacity_status_cache()
                            except Exception as scale_error:
                                logger.warning(
                                    "Capacity scale trigger failed for event %s: %s",
                                    event.id,
                                    scale_error,
                                )

                        return Response(
                            {
                                "waiting": True,
                                "waiting_room": True,
                                "waiting_room_enabled": True,
                                "reason": "capacity_preparing",
                                "message": "Meeting capacity is preparing. Please wait.",
                                "required": required,
                                "current": current,
                            },
                            status=202,
                        )
                else:
                    logger.info(
                        "Skipping RTK ASG capacity wait for in-person event. event_id=%s format=%s",
                        event.id,
                        getattr(event, "format", None),
                    )
            except Exception as e:
                logger.warning("Capacity check failed for event %s: %s", event.id, e)
                return Response(
                    {
                        "waiting": True,
                        "waiting_room": True,
                        "waiting_room_enabled": True,
                        "reason": "capacity_check_failed",
                        "message": "Meeting capacity is preparing. Please wait.",
                    },
                    status=202,
                )

        # ──── GUEST BRANCH ──────────────────────────────────────────────────────
        if getattr(user, "is_guest", False):
            # Guest participant (JWT authenticated)
            guest = user.guest
            if guest.event_id != event.id:
                return Response({"detail": "Guest token does not match this event."}, status=403)

            # Respect waiting-room gate for guests.
            # Guests may join main room only after host admission toggles them to main_room.
            if event.waiting_room_enabled and guest.current_location != "main_room":
                # Ensure they are explicitly in waiting state for host controls/listing.
                # Do not require joined_live here: joined_live must only be set after
                # frontend confirms RTK roomJoined via rtk/confirm-joined.
                if guest.current_location != "waiting_room":
                    guest.current_location = "waiting_room"
                    guest.lounge_table = None
                    guest.save(update_fields=["current_location", "lounge_table"])
                return Response(
                    {
                        "waiting": True,
                        "waiting_room_enabled": True,
                        "admission_status": "waiting",
                        "lounge_allowed": bool(event.lounge_enabled_waiting_room),
                        "networking_allowed": bool(event.networking_tables_enabled_waiting_room),
                        "detail": "Waiting for host admission.",
                    },
                    status=202,
                )

            # 1) Ensure meeting exists
            try:
                meeting_id = _ensure_rtk_meeting_for_event(event)
            except RuntimeError as e:
                logger.error(f"RTK meeting error for event {event.id}: {str(e)}")
                return Response(
                    {"error": "rtk_meeting_error", "detail": str(e)},
                    status=500,
                )

            # 2) Add guest as participant (always audience preset, never host)
            rtk_participant_id = f"guest_{guest.id}"
            cached_join = _get_cached_rtk_join_payload(
                event.id, f"guest:{guest.id}", "audience", "main_room"
            )
            if cached_join:
                cached_join.update({
                    "isOnBreak": bool(event.is_on_break),
                    "mediaLockActive": bool(event.is_on_break),
                    "admissionStatus": "admitted",
                    "cached": True,
                })
                return Response(cached_join)

            rtk_resp = add_rtk_participant(
                meeting_id=meeting_id,
                user_id=rtk_participant_id,
                name=guest.get_display_name(),
                preset_name=RTK_PRESET_PARTICIPANT,  # Guests never get host preset
            )
            # add_rtk_participant() returns (token, error_message)
            auth_token = ""
            participant_id = rtk_participant_id
            if isinstance(rtk_resp, tuple):
                auth_token, rtk_error = rtk_resp
                if rtk_error or not auth_token:
                    return Response(
                        {"error": "rtk_participant_error", "detail": rtk_error or "RTK did not return auth token."},
                        status=500,
                    )
            else:
                data = (rtk_resp or {}).get("data", {})
                auth_token = data.get("token", "")
                participant_id = data.get("id", rtk_participant_id)
                if not auth_token:
                    return Response(
                        {"error": "rtk_token_missing", "detail": "RTK did not return auth token."},
                        status=500,
                    )

            # 3) Store only RTK identity here. Do NOT mark joined_live in rtk/join.
            # rtk/join means token issued; real presence is confirmed by rtk/confirm-joined
            # after the RTK SDK fires roomJoined.
            guest.rtk_participant_id = participant_id
            guest.save(update_fields=["rtk_participant_id"])

            response_payload = {
                "authToken": auth_token,
                "meetingId": meeting_id,
                "presetName": RTK_PRESET_PARTICIPANT,
                "role": "audience",
                "isGuest": True,
                "guestName": guest.get_display_name(),
                "isOnBreak": bool(event.is_on_break),
                "mediaLockActive": bool(event.is_on_break),
                "admissionStatus": "admitted",
            }
            _set_cached_rtk_join_payload(
                event.id, f"guest:{guest.id}", "audience", response_payload, "main_room"
            )

            logger.info(f"Guest {guest.email} received RTK token for meeting {meeting_id}")

            return Response(response_payload)
        # ──── END GUEST BRANCH ──────────────────────────────────────────────────

        # 1) Ensure meeting exists
        try:
            meeting_id = _ensure_rtk_meeting_for_event(event)
        except RuntimeError as e:
            logger.error(f"RTK meeting error for event {event.id}: {str(e)}")
            return Response(
                {"error": "rtk_meeting_error", "detail": str(e)},
                status=500,
            )

        #  Fetch EventRegistration ONCE with all needed fields
        # Replace 3 separate queries with 1 optimized query
        existing_registration = EventRegistration.objects.filter(
            event=event,
            user=user
        ).only(
            "id", "status", "admission_status", "is_banned",
            "was_ever_admitted", "joined_live", "waiting_started_at",
            "admitted_at", "current_session_started_at", "last_reconnect_at",
            "current_location", "joined_live_at"
        ).first()

        # 1.5) Check if user is BANNED (using fetched registration)
        if existing_registration and existing_registration.is_banned:
            return Response(
                {"error": "banned", "detail": "You are banned from this event."},
                status=403
            )

        # 1.6) Check if user is cancelled/deregistered (using fetched registration)
        if existing_registration and existing_registration.status in ['cancelled', 'deregistered']:
             return Response(
                {"error": "not_registered", "detail": "You are not registered for this event."},
                status=403
            )

        # 1.7) Check if event is cancelled
        if event.status == "cancelled":
            return Response(
                {"error": "event_cancelled", "detail": "This event has been cancelled."},
                status=400
            )

        # 2) Decide host vs participant preset
        is_event_host = _is_event_host(user, event)

        # Basic guard – hosts can always join; others only if live/published
        if not is_event_host and event.status not in ("live", "published"):
            logger.warning(f"User {user.id} tried to join non-live event {event.id} (status: {event.status})")
            return Response(
                {"error": "event_not_live", "detail": f"Event is currently {event.status}. Only hosts can join."},
                status=400,
            )

        # Read requested role from body or query (?role=publisher / audience)
        requested_role = (
            (request.data.get("role") if hasattr(request, "data") else None)
            or request.query_params.get("role")
            or ""
        ).lower()

        # Map role string to boolean flag
        if requested_role in ("host", "publisher"):
            requested_is_host = True
        elif requested_role in ("audience", "participant"):
            requested_is_host = False
        else:
            requested_is_host = None  # no explicit role sent

        if requested_is_host is True and not is_event_host:
            # User asked for host but is not allowed → downgrade to audience
            is_host = False
        elif requested_is_host is None:
            # No explicit role → fall back to automatic rule
            is_host = is_event_host
        else:
            # Explicit role and allowed
            is_host = requested_is_host

        preset_name = RTK_PRESET_HOST if is_host else RTK_PRESET_PARTICIPANT
        role_string = "publisher" if is_host else "audience"
        converted_guest = _get_converted_guest_for_event(user, event)
        converted_guest_was_admitted = bool(
            converted_guest and (
                converted_guest.current_location in {"main_room", "social_lounge", "breakout_room"}
                or converted_guest.joined_live
            )
        )

        #  Handle existing vs new registration efficiently
        # Avoid get_or_create which triggers 2 queries under the hood
        _created = False
        if existing_registration:
            # User exists: reuse the fetched registration
            registration = existing_registration
        else:
            # User doesn't exist: create new registration with defaults
            defaults = {"status": "registered", "admission_status": "admitted"}
            if event.waiting_room_enabled and not is_host:
                should_wait = True  # Default to waiting room

                # Check if within grace period
                if event.start_time:
                    now = timezone.now()
                    grace_minutes = (
                        event.waiting_room_grace_period_minutes
                        if event.waiting_room_grace_period_minutes is not None
                        else 10
                    )
                    grace_period = timedelta(minutes=grace_minutes)

                    # Admit if: start_time <= now < start_time + grace_period
                    # The end boundary is EXCLUSIVE (at exactly grace_period_end, grace period has ended)
                    if event.start_time <= now < (event.start_time + grace_period):
                        should_wait = False  # Within grace period - admit directly

                if should_wait:
                    defaults["admission_status"] = "waiting"
                else:
                    # ✅ NEW: Mark grace period admissions as was_ever_admitted so they auto-rejoin
                    defaults["was_ever_admitted"] = True
                    defaults["current_session_started_at"] = timezone.now()
                if converted_guest_was_admitted:
                    defaults["admission_status"] = "admitted"
                    defaults["was_ever_admitted"] = True
                    defaults["current_session_started_at"] = converted_guest.joined_live_at or timezone.now()
                    defaults["admitted_at"] = converted_guest.joined_live_at or timezone.now()

            registration = EventRegistration(event=event, user=user, **defaults)
            registration.save()  # ✅ CRITICAL: Save new registration immediately with its defaults
            _created = True
            logger.info(f"[RTK_JOIN] Created new registration for user {user.id} on event {event.id} (pk={registration.pk})")
        #  Track field changes to save only once
        fields_to_update = []

        if event.waiting_room_enabled and not is_host:
            if converted_guest_was_admitted:
                if registration.admission_status != "admitted":
                    registration.admission_status = "admitted"
                    fields_to_update.append("admission_status")
                if not registration.was_ever_admitted:
                    registration.was_ever_admitted = True
                    fields_to_update.append("was_ever_admitted")
                if not registration.admitted_at:
                    registration.admitted_at = converted_guest.joined_live_at or timezone.now()
                    fields_to_update.append("admitted_at")
                if not registration.current_session_started_at:
                    registration.current_session_started_at = converted_guest.joined_live_at or timezone.now()
                    fields_to_update.append("current_session_started_at")
                if registration.waiting_started_at is not None:
                    registration.waiting_started_at = None
                    fields_to_update.append("waiting_started_at")
                converted_location = converted_guest.current_location or "main_room"
                if registration.current_location != converted_location:
                    registration.current_location = converted_location
                    fields_to_update.append("current_location")
                if converted_guest.joined_live and not registration.joined_live:
                    registration.joined_live = True
                    fields_to_update.append("joined_live")
                if converted_guest.joined_live_at and not registration.joined_live_at:
                    registration.joined_live_at = converted_guest.joined_live_at
                    fields_to_update.append("joined_live_at")

            # Check if within grace period
            is_in_grace_period = False
            if event.start_time:
                now = timezone.now()
                grace_minutes = (
                    event.waiting_room_grace_period_minutes
                    if event.waiting_room_grace_period_minutes is not None
                    else 10
                )
                grace_period = timedelta(minutes=grace_minutes)
                # Grace period is exclusive on the end boundary
                is_in_grace_period = event.start_time <= now < (event.start_time + grace_period)

            # ✅ NEW: Auto-rejoin logic for previously admitted users
            # If user was ever admitted (either by host or grace period), auto-admit them on rejoin
            auto_readmit_user = False
            if not _created and registration.was_ever_admitted:
                if registration.admission_status != "admitted":
                    registration.admission_status = "admitted"
                    registration.last_reconnect_at = timezone.now()
                    fields_to_update.extend(["admission_status", "last_reconnect_at"])
                    auto_readmit_user = True
                # Continue to RTK token generation for previously admitted users

            # Original grace period + waiting room logic
            elif not _created and not is_in_grace_period:
                # If host hasn't explicitly admitted, keep in waiting
                if registration.admission_status == "admitted" and not registration.admitted_at:
                    registration.admission_status = "waiting"
                    if "admission_status" not in fields_to_update:
                        fields_to_update.append("admission_status")

            if not registration.admission_status:
                registration.admission_status = "waiting"
                if "admission_status" not in fields_to_update:
                    fields_to_update.append("admission_status")

            if registration.admission_status in {"rejected"}:
                return Response(
                    {"error": "waiting_rejected", "detail": "You were not admitted to this event."},
                    status=403,
                )

            if registration.admission_status != "admitted":
                if not registration.waiting_started_at:
                    # ✅ CRITICAL: This is where users enter the waiting room queue!
                    # Set waiting_started_at ONLY when user actively joins (via rtk/join)
                    # This ensures they don't appear in host's waiting room list until they actively join.
                    # Registration alone does NOT add them to the waiting room.
                    registration.waiting_started_at = timezone.now()
                    if "waiting_started_at" not in fields_to_update:
                        fields_to_update.append("waiting_started_at")

                # ✅ CRITICAL: Remove user from lounge when entering waiting room
                # This ensures they don't appear in lounge occupants while waiting for admission
                try:
                    from .models import LoungeParticipant
                    deleted_count, _ = LoungeParticipant.objects.filter(
                        user=user,
                        table__event=event
                    ).delete()
                    if deleted_count > 0:
                        logger.info(f"[WAITING_ROOM] Removed user {user.id} from lounge ({deleted_count} table(s)) when entering waiting room")
                except Exception as e:
                    logger.warning(f"[WAITING_ROOM] Failed to remove user from lounge: {e}")

                #  Save registration with collected updates (new registrations already saved above)
                if fields_to_update:
                    # Remove duplicates from fields_to_update
                    fields_to_update = list(set(fields_to_update))
                    registration.save(update_fields=fields_to_update)
                    logger.info(f"[RTK_JOIN] Updated registration for user {user.id} on event {event.id} (fields: {', '.join(fields_to_update)})")

                    # Log auto-readmission after save
                    if auto_readmit_user:
                        from .models import WaitingRoomAuditLog
                        try:
                            WaitingRoomAuditLog.objects.create(
                                event=event,
                                participant=user,
                                action="auto_readmitted",
                                notes=f"System auto-readmitted previously admitted user on rejoin"
                            )
                            logger.info(f"[WAITING_ROOM] Auto-readmitted user {user.id} to event {event.id}")
                        except Exception as e:
                            logger.warning(f"[WAITING_ROOM] Failed to log auto-readmission: {e}")

                return Response(
                    {
                        "waiting": True,
                        "waiting_room_enabled": True,
                        "admission_status": registration.admission_status,
                        "lounge_allowed": bool(event.lounge_enabled_waiting_room),
                        "networking_allowed": bool(event.networking_tables_enabled_waiting_room),
                    },
                    status=200,
                )

        # 3) Reuse short-lived RTK token for reconnect/refresh bursts.
        # This keeps rtk/join idempotent and avoids repeated external RTK calls.
        cached_join = _get_cached_rtk_join_payload(
            event.id, f"user:{user.id}", role_string, "main_room"
        )
        if cached_join:
            # Preserve the existing side-effect: user leaving lounge to join main room
            # should clear their lounge occupancy even when the RTK token is cached.
            try:
                from .models import LoungeParticipant
                deleted_count, _ = LoungeParticipant.objects.filter(
                    user=user,
                    table__event=event
                ).delete()
                if deleted_count > 0:
                    logger.info(
                        f"[RTK_JOIN] Removed user {user.id} from lounge ({deleted_count} table(s)) using cached RTK token"
                    )
            except Exception as e:
                logger.warning(f"[RTK_JOIN] Failed to remove user from lounge while using cached token: {e}")

            is_grace_period_join = False
            if event.waiting_room_enabled and event.start_time:
                now = timezone.now()
                grace_minutes = (
                    event.waiting_room_grace_period_minutes
                    if event.waiting_room_grace_period_minutes is not None
                    else 10
                )
                grace_period_end = event.start_time + timezone.timedelta(minutes=grace_minutes)
                is_grace_period_join = event.start_time <= now < grace_period_end

            cached_join.update({
                "isOnBreak": bool(event.is_on_break),
                "mediaLockActive": bool(event.is_on_break),
                "gracePeriodAdmitted": is_grace_period_join,
                "admissionStatus": "admitted",
                "cached": True,
            })
            return Response(cached_join)

        # 4) Prepare participant payload
        profile = getattr(user, "profile", None)
        name = (getattr(profile, "full_name", "") if profile else "") or getattr(user, "get_full_name", lambda: "")() or user.username
        picture = ""
        try:
            if profile and getattr(profile, "user_image", None):
                picture = profile.user_image.url
        except Exception:
            picture = ""

        body = {
            "name": name or f"User {user.id}",
            "preset_name": preset_name,
            "client_specific_id": str(user.id),
        }
        if picture:
            body["picture"] = picture

        # 5) Call RTK Add Participant API
        try:
            resp = requests.post(
                f"{RTK_API_BASE}/meetings/{meeting_id}/participants",
                headers=_rtk_headers(),
                json=body,
                timeout=10,
            )
        except requests.RequestException as e:
            logger.exception("❌ RTK add participant exception: %s", e)
            return Response(
                {"error": "rtk_network_error", "detail": str(e)},
                status=500,
            )

        if resp.status_code not in (200, 201):
            logger.error("❌ RTK add participant failed: %s", resp.text[:500])
            return Response(
                {"error": "rtk_participant_error", "detail": resp.text[:500]},
                status=500,
            )

        data = (resp.json() or {}).get("data") or {}
        auth_token = data.get("token")
        if not auth_token:
            return Response(
                {"error": "rtk_token_missing", "detail": "RTK did not return auth token."},
                status=500,
            )

        #  Mark user as joined_live (registration always has pk at this point)
        # Either it existed before or we saved it immediately at line 9211
        if not registration.pk:
            logger.error(f"[RTK_JOIN] CRITICAL: registration has no pk before marking joined_live (user={user.id}, event={event.id})")
            return Response(
                {"error": "registration_error", "detail": "Failed to initialize registration."},
                status=500,
            )

        # DISABLED: Do not mark joined_live=True here
        # Reason: /rtk/join/ only means "backend gave RTK token", not "user entered RTK room"
        # Real joined_live should be marked by frontend after roomJoined event is received
        # See: EventCompanionLiveView and RTK SDK integration for actual joined_live marking
        joined_live_changed = False
        # if not registration.joined_live:
        #     registration.joined_live = True
        #     registration.joined_live_at = timezone.now()
        #     registration.save(update_fields=["joined_live", "joined_live_at"])
        #     joined_live_changed = True
        #     logger.info(f"[RTK_JOIN] Marked user {user.id} as joined_live on event {event.id}")
        # elif not registration.joined_live_at:
        #     # If somehow joined_live is true but joined_live_at is null, update it
        #     registration.joined_live_at = timezone.now()
        #     registration.save(update_fields=["joined_live_at"])
        #     logger.info(f"[RTK_JOIN] Set joined_live_at for user {user.id} on event {event.id}")

        # ✅ CRITICAL: Remove user from lounge when they join main meeting
        # This ensures they don't appear in lounge occupants list after transitioning to main
        # NOTE: This is already done earlier when user enters waiting room, but do it again
        # only if user skipped waiting room (admitted directly or grace period)
        try:
            from .models import LoungeParticipant
            deleted_count, _ = LoungeParticipant.objects.filter(
                user=user,
                table__event=event
            ).delete()
            if deleted_count > 0:
                logger.info(f"[RTK_JOIN] Removed user {user.id} from lounge ({deleted_count} table(s)) when joining main meeting")
        except Exception as e:
            logger.warning(f"[RTK_JOIN] Failed to remove user from lounge: {e}")

        # ✅ Check if user is within grace period (for frontend to trigger immediate refresh)
        is_grace_period_join = False
        if event.waiting_room_enabled and event.start_time:
            now = timezone.now()
            grace_minutes = (
                event.waiting_room_grace_period_minutes
                if event.waiting_room_grace_period_minutes is not None
                else 10
            )
            grace_period_end = event.start_time + timezone.timedelta(minutes=grace_minutes)
            # Grace period is active if: start_time <= now < grace_period_end
            # The end boundary is EXCLUSIVE (at exactly grace_period_end, grace period has ended)
            is_grace_period_join = event.start_time <= now < grace_period_end

        #  Cache event snapshot for next join burst
        _cache_event_join_snapshot(event)

        logger.info(f"[RTK_JOIN] User {user.id} successfully joined event {event.id} (query optimizations: consolidated registration fetches and saves)")

        response_payload = {
            "authToken": auth_token,
            "meetingId": meeting_id,
            "presetName": preset_name,
            "role": role_string,
            "isOnBreak": bool(event.is_on_break),
            "mediaLockActive": bool(event.is_on_break),
            "gracePeriodAdmitted": is_grace_period_join,
            "admissionStatus": "admitted",
        }
        _set_cached_rtk_join_payload(
            event.id, f"user:{user.id}", role_string, response_payload, "main_room"
        )

        return Response(response_payload)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="rtk/confirm-joined")
    def rtk_confirm_joined(self, request, pk=None):
        """
        Confirm that user has actually joined the RTK room.

        Called by frontend after RTK SDK fires the roomJoined event.
        This marks the user as truly joined_live in the database.

        Payload:
            - room_type: str, optional (default "main_room")
                One of: main_room, breakout_room, social_lounge, waiting_room
            - table_id: int, optional
                For breakout_room joins, the table ID

        Returns:
            {
                "ok": true,
                "joined_live": true
            }
        """
        event = self.get_object()
        user = request.user

        room_type = request.data.get("room_type") or "main_room"
        table_id = request.data.get("table_id")

        # ─── GUEST BRANCH ───────────────────────────────────────────────────
        if getattr(user, "is_guest", False):
            guest = user.guest
            if guest.event_id != event.id:
                return Response({"detail": "Guest does not belong to this event."}, status=403)

            guest.joined_live = True
            guest.joined_live_at = guest.joined_live_at or timezone.now()
            guest.current_location = room_type
            update_fields = ["joined_live", "joined_live_at", "current_location"]
            if room_type == "main_room":
                guest.lounge_table = None
                update_fields.append("lounge_table")
            guest.save(update_fields=update_fields)

            logger.info(f"[RTK_CONFIRM_JOINED] Guest {guest.id} confirmed joined in {room_type}")
            return Response({"ok": True, "joined_live": True})

        # ─── REGISTERED USER BRANCH ─────────────────────────────────────────
        registration = EventRegistration.objects.filter(event=event, user=user).first()

        if not registration and not _is_event_host(user, event):
            return Response({"detail": "Not registered."}, status=403)

        if registration:
            update_fields = []

            # Mark joined_live only if not already marked
            if not registration.joined_live:
                registration.joined_live = True
                registration.joined_live_at = timezone.now()
                update_fields += ["joined_live", "joined_live_at"]
            elif not registration.joined_live_at:
                # If somehow joined_live is true but joined_live_at is null, update it
                registration.joined_live_at = timezone.now()
                update_fields.append("joined_live_at")

            # Update reconnect timestamp to now
            registration.last_reconnect_at = timezone.now()
            update_fields.append("last_reconnect_at")

            # Update location if valid room type
            if room_type in ["main_room", "breakout_room", "social_lounge", "waiting_room"]:
                registration.current_location = room_type
                update_fields.append("current_location")

            # Store breakout table ID if provided
            if table_id and room_type == "breakout_room":
                registration.last_breakout_table_id = table_id
                update_fields.append("last_breakout_table_id")

            # Save with deduplicated fields
            registration.save(update_fields=list(set(update_fields)))
            logger.info(f"[RTK_CONFIRM_JOINED] User {user.id} confirmed joined in {room_type} on event {event.id}")

        return Response({"ok": True, "joined_live": True})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="rtk/preview-token")
    def rtk_preview_token(self, request, pk=None):
        """
        Return a main-room RTK token for preview only.

        Unlike rtk/join, this endpoint does NOT:
        - apply waiting-room admission flow,
        - move location to main room,
        - remove participant from social lounge.
        """
        event = self.get_object()
        user = request.user

        # Ensure event meeting exists
        try:
            meeting_id = _ensure_rtk_meeting_for_event(event)
        except RuntimeError as e:
            logger.error(f"RTK preview token meeting error for event {event.id}: {str(e)}")
            return Response(
                {"error": "rtk_meeting_error", "detail": str(e)},
                status=500,
            )

        # Guards: banned / deregistered / event not joinable
        if EventRegistration.objects.filter(event=event, user=user, is_banned=True).exists():
            return Response({"error": "banned", "detail": "You are banned from this event."}, status=403)
        if EventRegistration.objects.filter(event=event, user=user, status__in=["cancelled", "deregistered"]).exists():
            return Response({"error": "not_registered", "detail": "You are not registered for this event."}, status=403)
        if event.status == "cancelled":
            return Response({"error": "event_cancelled", "detail": "This event has been cancelled."}, status=400)
        if (not _is_event_manager(user, event)) and event.status not in ("live", "published"):
            return Response(
                {"error": "event_not_live", "detail": f"Event is currently {event.status}. Only hosts can join."},
                status=400,
            )

        # Preview is always audience/participant
        preset_name = RTK_PRESET_PARTICIPANT

        profile = getattr(user, "profile", None)
        name = (getattr(profile, "full_name", "") if profile else "") or getattr(user, "get_full_name", lambda: "")() or user.username
        picture = ""
        try:
            if profile and getattr(profile, "user_image", None):
                picture = profile.user_image.url
        except Exception:
            picture = ""

        body = {
            "name": name or f"User {user.id}",
            "preset_name": preset_name,
            "client_specific_id": str(user.id),
        }
        if picture:
            body["picture"] = picture

        try:
            resp = requests.post(
                f"{RTK_API_BASE}/meetings/{meeting_id}/participants",
                headers=_rtk_headers(),
                json=body,
                timeout=10,
            )
        except requests.RequestException as e:
            logger.exception("❌ RTK preview add participant exception: %s", e)
            return Response({"error": "rtk_network_error", "detail": str(e)}, status=500)

        if resp.status_code not in (200, 201):
            logger.error("❌ RTK preview add participant failed: %s", resp.text[:500])
            return Response({"error": "rtk_participant_error", "detail": resp.text[:500]}, status=500)

        data = (resp.json() or {}).get("data") or {}
        auth_token = data.get("token")
        if not auth_token:
            return Response(
                {"error": "rtk_token_missing", "detail": "RTK did not return auth token."},
                status=500,
            )

        return Response(
            {
                "authToken": auth_token,
                "meetingId": meeting_id,
                "presetName": preset_name,
                "role": "audience",
                "previewOnly": True,
            }
        )

    @live_rejoin_queue
    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="live/rejoin")
    def live_rejoin(self, request, pk=None):
        """
        Rejoin a live meeting after a WebSocket disconnect.

        Validates that:
        - Event exists and is live or reconnectable
        - User/guest is registered or allowed to join
        - User was not removed, blocked, banned, or explicitly kicked

        Returns normalized live meeting restore payload:
        - event_id, meeting_status, is_live
        - user_role, admission_status, waiting_room_status
        - current_location, room_type (main_room/waiting_room/lounge/breakout/ended)
        - rtk_meeting_id, rtk_token if needed
        - lounge_state, breakout_state, break_state if applicable
        - can_rejoin boolean with reason if false

        Endpoint is idempotent: safe to call multiple times.
        """
        try:
            event = self.get_object()
        except Http404:
            # Event doesn't exist (deleted, never existed, etc.)
            logger.warning(f"[LIVE_REJOIN] event {pk} not found (deleted or doesn't exist)")
            return Response(
                {
                    "can_rejoin": False,
                    "retryable": False,
                    "reason": "event_not_found",
                    "detail": "Event not found.",
                },
                status=404,
            )

        user = request.user

        #  Cache RTK meeting ID to avoid duplicate _ensure_rtk_meeting_for_event calls
        rtk_meeting_id_cache = {}  # Request-scoped cache

        # Log rejoin attempt
        is_guest = getattr(user, "is_guest", False)
        user_identifier = f"guest_{user.guest.id}" if is_guest else str(user.id)
        deny_cache_key = f"event:{event.id}:live_rejoin:deny:{user_identifier}:v1"

        logger.info(f"[LIVE_REJOIN] user={user_identifier} event={event.id} status={event.status}")

        cached_denial = cache.get(deny_cache_key)
        if cached_denial is not None:
            return Response(cached_denial["data"], status=cached_denial["status"])

        def _deny(reason: str, detail: str, status_code: int, *, cacheable: bool = False):
            payload = {
                "can_rejoin": False,
                "retryable": False,
                "reason": reason,
                "detail": detail,
            }
            if cacheable:
                cache.set(
                    deny_cache_key,
                    {"data": payload, "status": status_code},
                    5,
                )
            return Response(payload, status=status_code)

        # ──── VALIDATION ──────────────────────────────────────────────────────

        # Check if event exists and is not cancelled
        if event.status == "cancelled":
            logger.warning(f"[LIVE_REJOIN] event {event.id} is cancelled")
            return _deny("event_cancelled", "This event has been cancelled.", 400, cacheable=True)

        # Check if event is live or ended-but-reopenable
        if event.status not in ("live", "ended"):
            logger.warning(f"[LIVE_REJOIN] event {event.id} status={event.status} (not live/ended)")
            return _deny("event_not_live", f"Event is {event.status}, not live or ended.", 400)

        # ──── GUEST BRANCH ────────────────────────────────────────────────────
        if is_guest:
            guest = user.guest

            # Check guest belongs to this event
            if guest.event_id != event.id:
                logger.warning(f"[LIVE_REJOIN] guest {guest.id} event mismatch")
                return _deny("guest_event_mismatch", "Guest token does not match this event.", 403, cacheable=True)

            # Check if guest is banned
            if guest.is_banned:
                logger.warning(f"[LIVE_REJOIN] guest {guest.id} is banned")
                return _deny("guest_banned", "You have been banned from this event.", 403, cacheable=True)

            # Check if guest has converted to registered user
            if guest.converted_at is not None:
                logger.info(f"[LIVE_REJOIN] guest {guest.id} converted to user")
                return _deny("guest_converted", "You have registered. Please sign in with your account.", 403, cacheable=True)

            # Determine guest location and admission status
            current_location = guest.current_location or "pre_event"
            is_admitted = guest.current_location in ("main_room", "social_lounge", "breakout_room")
            admission_status = "admitted" if is_admitted else "waiting"
            waiting_room_enabled = event.waiting_room_enabled

            # Build response for guest
            response_data = {
                "event_id": event.id,
                "meeting_status": event.status,
                "is_live": event.status == "live",
                "user_role": "guest",
                "admission_status": admission_status,
                "waiting_room_enabled": waiting_room_enabled,
                "current_location": current_location,
                "can_rejoin": True,
            }

            # Add room type
            if event.status == "ended":
                response_data["room_type"] = "ended"
            elif current_location == "waiting_room":
                response_data["room_type"] = "waiting_room"
            elif current_location == "social_lounge":
                response_data["room_type"] = "lounge"
            elif current_location == "breakout_room":
                response_data["room_type"] = "breakout"
                # Include last breakout table if available
                if guest.lounge_table_id:
                    response_data["breakout_table_id"] = guest.lounge_table_id
                    response_data["breakout_table_name"] = guest.lounge_table.name if guest.lounge_table else None
            else:
                response_data["room_type"] = "main_room"

            #  Get RTK meeting ID (cached in request scope)
            if "meeting_id" not in rtk_meeting_id_cache:
                try:
                    rtk_meeting_id_cache["meeting_id"] = _ensure_rtk_meeting_for_event(event)
                except RuntimeError as e:
                    logger.warning(f"[LIVE_REJOIN] RTK meeting error for event {event.id}: {e}")
                    rtk_meeting_id_cache["meeting_id"] = None

            meeting_id = rtk_meeting_id_cache["meeting_id"]
            if meeting_id:
                response_data["rtk_meeting_id"] = meeting_id
            else:
                response_data["rtk_meeting_id"] = None
                response_data["rtk_token"] = None

            response_data["needs_rtk_join"] = bool(
                is_admitted and event.status == "live" and meeting_id
            )
            response_data["rtk_token"] = None

            # Add break state if meeting is on break
            if event.is_on_break and event.break_started_at:
                from django.utils import timezone as django_tz
                elapsed = (django_tz.now() - event.break_started_at).total_seconds()
                break_remaining = max(0, int(event.break_duration_seconds - elapsed))
                response_data["is_on_break"] = True
                response_data["break_duration_seconds"] = event.break_duration_seconds
                response_data["break_remaining_seconds"] = break_remaining

            return Response(response_data, status=200)

        # ──── END GUEST BRANCH ────────────────────────────────────────────────

        # ──── REGISTERED USER BRANCH ──────────────────────────────────────────

        #  Fetch EventRegistration ONCE with all needed fields
        # Replace 3 separate queries with 1 optimized query
        registration = EventRegistration.objects.filter(
            event=event,
            user=user
        ).only(
            "id", "status", "admission_status", "is_banned",
            "was_ever_admitted", "joined_live", "current_location",
            "last_breakout_table_id", "last_reconnect_at"
        ).first()

        # Check if user is banned (using fetched registration)
        if registration and registration.is_banned:
            logger.warning(f"[LIVE_REJOIN] user {user.id} is banned")
            return _deny("user_banned", "You are banned from this event.", 403, cacheable=True)

        # Check if user is cancelled/deregistered (using fetched registration)
        if registration and registration.status in ["cancelled", "deregistered"]:
            logger.warning(f"[LIVE_REJOIN] user {user.id} status not registered")
            return _deny("user_not_registered", "You are not registered for this event.", 403)

        # Allow event host/creator to rejoin even without explicit registration
        if not registration:
            if not _is_event_host(user, event):
                logger.warning(f"[LIVE_REJOIN] user {user.id} not registered for event {event.id}")
                return _deny("user_not_registered", "You are not registered for this event.", 403)
            # Host without registration: continue with None registration

        # Determine admission status and location
        if registration:
            admission_status = registration.admission_status
            current_location = registration.current_location or "pre_event"
        else:
            # Host without registration
            admission_status = "admitted"
            current_location = "main_room"

        # Auto-admit previously admitted users (rejoin grace)
        if registration and registration.was_ever_admitted and admission_status == "waiting":
            registration.admission_status = "admitted"
            registration.last_reconnect_at = timezone.now()
            registration.save(update_fields=["admission_status", "last_reconnect_at"])
            admission_status = "admitted"
            logger.info(f"[LIVE_REJOIN] auto-readmitted user {user.id}")

        # Validate user can access this room
        is_host = _is_event_host(user, event)

        if not is_host and event.waiting_room_enabled and admission_status == "waiting":
            # User is still waiting
            waiting_room_enabled = True
        else:
            waiting_room_enabled = event.waiting_room_enabled

        # Build response for registered user
        response_data = {
            "event_id": event.id,
            "meeting_status": event.status,
            "is_live": event.status == "live",
            "user_role": "host" if is_host else "participant",
            "admission_status": admission_status,
            "waiting_room_enabled": waiting_room_enabled,
            "current_location": current_location,
            "can_rejoin": True,
        }

        # Add room type
        if event.status == "ended":
            response_data["room_type"] = "ended"
        elif current_location == "waiting_room" or (event.waiting_room_enabled and admission_status == "waiting"):
            response_data["room_type"] = "waiting_room"
        elif current_location == "social_lounge":
            response_data["room_type"] = "lounge"
        elif current_location == "breakout_room":
            response_data["room_type"] = "breakout"
            # Include last breakout table if available
            if registration and registration.last_breakout_table_id:
                response_data["breakout_table_id"] = registration.last_breakout_table_id
                response_data["breakout_table_name"] = registration.last_breakout_table.name if registration.last_breakout_table else None
        else:
            response_data["room_type"] = "main_room"

        #  Get RTK meeting ID (cached in request scope)
        if "meeting_id" not in rtk_meeting_id_cache:
            try:
                rtk_meeting_id_cache["meeting_id"] = _ensure_rtk_meeting_for_event(event)
            except RuntimeError as e:
                logger.warning(f"[LIVE_REJOIN] RTK meeting error for event {event.id}: {e}")
                rtk_meeting_id_cache["meeting_id"] = None

        meeting_id = rtk_meeting_id_cache["meeting_id"]
        if meeting_id:
            response_data["rtk_meeting_id"] = meeting_id
        else:
            response_data["rtk_meeting_id"] = None
            response_data["rtk_token"] = None

        response_data["needs_rtk_join"] = bool(
            admission_status == "admitted" and event.status == "live" and meeting_id
        )
        response_data["rtk_token"] = None

        logger.info(
            "[LIVE_REJOIN] response user=%s event=%s room_type=%s admission=%s current_location=%s waiting_room_enabled=%s last_reconnect_at=%s",
            user.id,
            event.id,
            response_data.get("room_type"),
            admission_status,
            current_location,
            waiting_room_enabled,
            registration.last_reconnect_at.isoformat() if registration and registration.last_reconnect_at else None,
        )

        # Add break state if meeting is on break
        if event.is_on_break and event.break_started_at:
            from django.utils import timezone as django_tz
            elapsed = (django_tz.now() - event.break_started_at).total_seconds()
            break_remaining = max(0, int(event.break_duration_seconds - elapsed))
            response_data["is_on_break"] = True
            response_data["break_duration_seconds"] = event.break_duration_seconds
            response_data["break_remaining_seconds"] = break_remaining

        return Response(response_data, status=200)

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="waiting-room/status")
    def waiting_room_status(self, request, pk=None):
        event = self.get_object()
        user = request.user
        if not event.waiting_room_enabled:
            return Response(
                {"waiting_room_enabled": False, "admission_status": "admitted"},
                status=200,
            )

        if getattr(user, "is_guest", False):
            guest = getattr(user, "guest", None)
            if not guest or guest.event_id != event.id:
                return Response({"detail": "not_registered"}, status=403)
            admission_status = "admitted" if guest.current_location == "main_room" else "waiting"
            return Response(
                {
                    "waiting_room_enabled": True,
                    "admission_status": admission_status,
                    "lounge_allowed": bool(event.lounge_enabled_waiting_room),
                    "networking_allowed": bool(event.networking_tables_enabled_waiting_room),
                }
            )

        # Auto-admit if waiting time has elapsed
        auto_seconds = int(event.auto_admit_seconds or 0)
        if auto_seconds > 0:
            cutoff = timezone.now() - timezone.timedelta(seconds=auto_seconds)
            (
                EventRegistration.objects.filter(
                    event=event,
                    user=user,
                    admission_status="waiting",
                    waiting_started_at__isnull=False,
                    waiting_started_at__lte=cutoff,
                ).update(admission_status="admitted", admitted_at=timezone.now())
            )

        reg = EventRegistration.objects.filter(event=event, user=user).first()
        if not reg:
            converted_guest = _get_converted_guest_for_event(user, event)
            if converted_guest:
                converted_guest_is_admitted = bool(
                    converted_guest.current_location in {"main_room", "social_lounge", "breakout_room"}
                    or converted_guest.joined_live
                )
                return Response(
                    {
                        "waiting_room_enabled": True,
                        "admission_status": "admitted" if converted_guest_is_admitted else "waiting",
                        "lounge_allowed": bool(event.lounge_enabled_waiting_room),
                        "networking_allowed": bool(event.networking_tables_enabled_waiting_room),
                    }
                )
        if not reg and event.created_by_id != user.id:
            return Response({"detail": "not_registered"}, status=403)

        admission_status = reg.admission_status if reg else "admitted"
        return Response(
            {
                "waiting_room_enabled": True,
                "admission_status": admission_status,
                "lounge_allowed": bool(event.lounge_enabled_waiting_room),
                "networking_allowed": bool(event.networking_tables_enabled_waiting_room),
            }
        )

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="waiting-room/queue")
    def waiting_room_queue(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host can view the waiting room."}, status=403)

        # Auto-admit anyone whose wait time has elapsed
        auto_seconds = int(event.auto_admit_seconds or 0)
        if auto_seconds > 0:
            cutoff = timezone.now() - timezone.timedelta(seconds=auto_seconds)
            (
                EventRegistration.objects.filter(
                    event=event,
                    admission_status="waiting",
                    waiting_started_at__isnull=False,
                    waiting_started_at__lte=cutoff,
                ).update(admission_status="admitted", admitted_at=timezone.now())
            )

        # ✅ CRITICAL FIX: Only show users who have ACTIVELY JOINED the waiting room
        # Filter by waiting_started_at__isnull=False to exclude users who just registered
        # but haven't clicked "Join Waiting Room" yet.
        waiting_regs = (
            EventRegistration.objects.filter(
                event=event,
                admission_status="waiting",
                waiting_started_at__isnull=False  # ✅ Only users who actually joined
            )
            .select_related("user")
            .order_by("waiting_started_at", "registered_at")
        )
        data = [
            {
                "user_id": r.user_id,
                "user_name": r.user.get_full_name() or r.user.username,
                "user_email": r.user.email,
                "waiting_started_at": r.waiting_started_at,
                "registered_at": r.registered_at,
            }
            for r in waiting_regs
        ]
        guest_waiting = GuestAttendee.objects.filter(
            event=event,
            current_location="waiting_room",
            converted_at__isnull=True,
        ).order_by("created_at")
        for g in guest_waiting:
            data.append(
                {
                    "user_id": f"guest_{g.id}",
                    "user_name": g.get_display_name(),
                    "user_email": g.email,
                    "waiting_started_at": None,
                    "registered_at": g.created_at,
                    "is_guest": True,
                }
            )
        return Response({"count": len(data), "results": data})

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="lounge-participants")
    def lounge_participants(self, request, pk=None):
        """Host-only endpoint: Returns all participants currently in Social Lounge (at table or floating), excluding hosts."""
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Host only"}, status=403)

        # ✅ FIX: Query all participants whose current_location is social_lounge
        # This includes both "floating" users (no table) and users seated at tables
        regs = EventRegistration.objects.filter(
            event=event,
            current_location="social_lounge"
        ).select_related("user")

        # Get table assignments for those users (if any)
        user_ids = [r.user_id for r in regs]
        lounge_map = {
            lp.user_id: lp for lp in LoungeParticipant.objects.filter(
                table__event=event, table__category="LOUNGE", user_id__in=user_ids
            ).select_related("table")
        }

        # ✅ NEW FIX: Exclude hosts from lounge participants list
        # Build data only for non-hosts
        data = []
        for reg in regs:
            user = reg.user
            # Skip if user is a host (staff, superuser, event creator, community owner, or explicitly assigned role)
            if (
                user.is_staff
                or getattr(user, "is_superuser", False)
                or event.created_by_id == user.id
                or getattr(event.community, "owner_id", None) == user.id
            ):
                continue

            # Check if explicitly assigned host role in EventParticipant (ANY participant type)
            # First check by user_id
            if event.participants.filter(role="host", user_id=user.id).exists():
                continue

            # Then check by email for guest participants
            user_email = (getattr(user, "email", "") or "").strip()
            if user_email and event.participants.filter(role="host", guest_email__iexact=user_email).exists():
                continue

            # Include non-hosts
            lp = lounge_map.get(reg.user_id)
            mini_user = UserMiniSerializer(user, context={"request": request}).data
            data.append({
                "user_id": reg.user_id,
                "user_name": mini_user.get("full_name") or user.get_full_name() or user.username,
                "avatar_url": mini_user.get("avatar_url") or "",
                "kyc_status": mini_user.get("kyc_status") or "",
                "job_title": mini_user.get("job_title") or "",
                "company": mini_user.get("company") or "",
                "table_id": lp.table_id if lp else None,
                "table_name": lp.table.name if lp else None,
                "admission_status": reg.admission_status,
                "current_location": reg.current_location,
            })
        return Response({"count": len(data), "results": data})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="waiting-room/admit")
    def waiting_room_admit(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host can admit participants."}, status=403)

        user_ids = request.data.get("user_ids") or []
        user_id = request.data.get("user_id")
        admit_all = bool(request.data.get("admit_all"))
        if user_id:
            user_ids = [user_id]

        if not user_ids and not admit_all:
            return Response({"detail": "Provide user_id, user_ids, or admit_all."}, status=400)

        # ✅ UPDATED: Allow admission from both waiting room and lounge contexts
        # When specific user_ids are provided, admit even if waiting_started_at is null (lounge scenario)
        # When admit_all is used, still require active waiting to exclude registered-but-not-joined users
        guest_ids = []
        normal_user_ids = []
        for raw_id in (user_ids or []):
            raw_str = str(raw_id)
            if raw_str.startswith("guest_"):
                try:
                    guest_ids.append(int(raw_str.split("_", 1)[1]))
                except (TypeError, ValueError):
                    continue
            else:
                try:
                    normal_user_ids.append(int(raw_str))
                except (TypeError, ValueError):
                    continue

        qs = EventRegistration.objects.filter(event=event, admission_status="waiting")
        if not admit_all:
            qs = qs.filter(user_id__in=normal_user_ids)
        else:
            # For admit_all, require active waiting (waiting_started_at set)
            qs = qs.filter(waiting_started_at__isnull=False)

        # Get list of user IDs being admitted BEFORE update (for WebSocket notification)
        admitted_user_ids = list(qs.values_list('user_id', flat=True))

        # ✅ Mark users as was_ever_admitted so they auto-rejoin if they disconnect
        updated_users = qs.update(
            admission_status="admitted",
            admitted_at=timezone.now(),
            admitted_by=request.user,
            rejected_at=None,
            rejected_by=None,
            rejection_reason="",
            was_ever_admitted=True,  # ✅ NEW: Mark for auto-rejoin
            current_location="main_room",  # ✅ NEW: Update location for lounge context
            current_session_started_at=timezone.now(),  # Track session start
        )

        guest_qs = GuestAttendee.objects.filter(
            event=event,
            current_location="waiting_room",
            converted_at__isnull=True,
        )
        if not admit_all:
            guest_qs = guest_qs.filter(id__in=guest_ids)
        guest_ids_admitted = list(guest_qs.values_list("id", flat=True))
        updated_guests = guest_qs.update(
            current_location="main_room",
            lounge_table=None,
        )

        # ✅ NEW: Remove admitted users from LoungeParticipant table (lounge context)
        LoungeParticipant.objects.filter(
            table__event=event, user_id__in=admitted_user_ids
        ).delete()

        # ✅ NEW: Send WebSocket notification to each admitted user in real-time
        try:
            for admitted_user_id in admitted_user_ids:
                send_admission_status_changed(admitted_user_id, "admitted")
                print(f"[WAITING_ROOM] ✅ Sent real-time notification to user {admitted_user_id}: status=admitted")
            if guest_ids_admitted:
                from channels.layers import get_channel_layer
                from asgiref.sync import async_to_sync
                channel_layer = get_channel_layer()
                for guest_id in guest_ids_admitted:
                    async_to_sync(channel_layer.group_send)(
                        f"guest_user_{guest_id}",
                        {"type": "admission_status_changed", "data": {"admission_status": "admitted"}},
                    )
        except Exception as e:
            logger.warning(f"[WAITING_ROOM] Failed to send WebSocket notification: {e}")
            print(f"[WAITING_ROOM] ⚠️ WebSocket notification failed: {e}")

        # Log the admission action
        try:
            from .models import WaitingRoomAuditLog
            admitted_registrations = EventRegistration.objects.filter(
                event=event,
                user_id__in=user_ids if user_ids else None
            ).values_list('user_id', flat=True)

            for reg in qs:
                WaitingRoomAuditLog.objects.create(
                    event=event,
                    participant=reg.user,
                    performed_by=request.user,
                    action="admitted",
                    notes=f"Host admitted participant"
                )
        except Exception as e:
            logger.warning(f"[WAITING_ROOM] Failed to log admissions: {e}")

        return Response({"ok": True, "admitted": int(updated_users) + int(updated_guests)})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="waiting-room/reject")
    def waiting_room_reject(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host can reject participants."}, status=403)

        user_ids = request.data.get("user_ids") or []
        user_id = request.data.get("user_id")
        reason = (request.data.get("reason") or "").strip()
        if user_id:
            user_ids = [user_id]

        if not user_ids:
            return Response({"detail": "Provide user_id or user_ids."}, status=400)

        # ✅ Only allow rejecting users who are ACTIVELY in waiting room
        # Filter by waiting_started_at__isnull=False to exclude registered-but-not-joined users
        qs = EventRegistration.objects.filter(
            event=event,
            admission_status="waiting",
            waiting_started_at__isnull=False,  # ✅ Only users actively waiting
            user_id__in=user_ids
        )
        updated = qs.update(
            admission_status="rejected",
            rejected_at=timezone.now(),
            rejected_by=request.user,
            rejection_reason=reason,
        )
        return Response({"ok": True, "rejected": updated})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="waiting-room/announce")
    def waiting_room_announce(self, request, pk=None):
        """
        ✅ NEW: Host sends announcement/broadcast message to all users in waiting room.

        Endpoint: POST /events/{id}/waiting-room/announce/
        Body: { "message": "Your message here" }

        Only the event host can send announcements.
        Messages are delivered in real-time via WebSocket to waiting participants.
        """
        event = self.get_object()

        # Only host can announce
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host can send announcements."}, status=403)

        message_text = (request.data.get("message") or "").strip()
        if not message_text:
            return Response({"detail": "Message cannot be empty."}, status=400)

        if len(message_text) > 1000:
            return Response(
                {"detail": "Message too long (max 1000 characters)."},
                status=400
            )

        # Get list of waiting room participants
        # ✅ Only send to users ACTIVELY in waiting room
        # Filter by waiting_started_at__isnull=False to exclude registered-but-not-joined users
        waiting_users = EventRegistration.objects.filter(
            event=event,
            admission_status="waiting",
            waiting_started_at__isnull=False  # ✅ Only users actively waiting
        ).select_related("user")

        user_ids = list(waiting_users.values_list("user_id", flat=True))
        user_count = len(user_ids)

        if user_count == 0:
            return Response({
                "ok": True,
                "message": "No users in waiting room",
                "recipients": 0
            })

        # ✅ Create announcement using new WaitingRoomAnnouncement model
        try:
            announcement = WaitingRoomAnnouncement.objects.create(
                event=event,
                message=message_text,
                sender=request.user,
                sender_name=request.user.get_full_name() or request.user.username,
            )
            logger.info(f"[WAITING_ROOM] Host {request.user.id} sent announcement (id={announcement.id}) to {user_count} waiting users in event {event.id}")

        except Exception as e:
            logger.warning(f"[WAITING_ROOM] Failed to create announcement: {e}")
            return Response({"detail": "Failed to create announcement."}, status=500)

        # Broadcast announcement via WebSocket to each waiting user
        try:
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync

            channel_layer = get_channel_layer()

            for user_id in user_ids:
                try:
                    async_to_sync(channel_layer.group_send)(
                        f"user_{user_id}",
                        {
                            "type": "waiting_room.announcement",
                            "event_id": event.id,
                            "announcement_id": announcement.id,  # ✅ Include server ID
                            "message": message_text,
                            "sender_name": announcement.sender_name,
                            "timestamp": announcement.created_at.isoformat(),
                        }
                    )
                except Exception as e:
                    logger.warning(f"[WAITING_ROOM] Failed to send announcement to user {user_id}: {e}")

            logger.info(f"[WAITING_ROOM] Broadcasted announcement to {user_count} waiting participants")

        except Exception as e:
            logger.warning(f"[WAITING_ROOM] Failed to broadcast announcement: {e}")

        return Response({
            "ok": True,
            "announcement_id": announcement.id,  # ✅ Return server ID
            "sender_name": announcement.sender_name,
            "created_at": announcement.created_at.isoformat(),
            "recipients": user_count,
            "message": message_text,
        })

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="waiting-room/announcements")
    def waiting_room_announcements_list(self, request, pk=None):
        """
        ✅ NEW: GET /api/events/{id}/waiting-room/announcements/
        Returns active (non-deleted) announcements for this event.
        Available to both host (for management panel) and waiting participants (on reconnect).
        """
        event = self.get_object()
        announcements = WaitingRoomAnnouncement.objects.filter(
            event=event, is_deleted=False
        ).order_by("-created_at")[:10]

        return Response([{
            "id": a.id,
            "message": a.message,
            "sender_name": a.sender_name,
            "created_at": a.created_at.isoformat(),
            "updated_at": a.updated_at.isoformat(),
            "is_edited": a.updated_at > a.created_at,
        } for a in announcements])

    @action(detail=True, methods=["patch"], permission_classes=[IsAuthenticated], url_path="waiting-room/announcements/(?P<ann_id>[0-9]+)")
    def waiting_room_announcement_edit(self, request, pk=None, ann_id=None):
        """
        ✅ NEW: PATCH /api/events/{id}/waiting-room/announcements/{ann_id}/
        Body: { "message": "updated text" }
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host can edit announcements."}, status=403)

        announcement = get_object_or_404(WaitingRoomAnnouncement, id=ann_id, event=event, is_deleted=False)
        new_message = (request.data.get("message") or "").strip()
        if not new_message:
            return Response({"detail": "Message cannot be empty."}, status=400)
        if len(new_message) > 1000:
            return Response({"detail": "Message too long (max 1000 characters)."}, status=400)

        announcement.message = new_message
        announcement.save()

        # Broadcast update to all currently waiting users
        waiting_user_ids = list(EventRegistration.objects.filter(
            event=event, admission_status="waiting", waiting_started_at__isnull=False
        ).values_list("user_id", flat=True))

        try:
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync

            channel_layer = get_channel_layer()
            for user_id in waiting_user_ids:
                async_to_sync(channel_layer.group_send)(
                    f"user_{user_id}",
                    {
                        "type": "waiting_room.announcement_update",
                        "announcement_id": announcement.id,
                        "message": new_message,
                        "updated_at": announcement.updated_at.isoformat(),
                    }
                )
        except Exception as e:
            logger.warning(f"[WAITING_ROOM] Failed to broadcast announcement update: {e}")

        return Response({
            "ok": True,
            "announcement_id": announcement.id,
            "message": new_message,
            "updated_at": announcement.updated_at.isoformat(),
        })

    @action(detail=True, methods=["delete"], permission_classes=[IsAuthenticated], url_path="waiting-room/announcements/(?P<ann_id>[0-9]+)/delete")
    def waiting_room_announcement_delete(self, request, pk=None, ann_id=None):
        """
        ✅ NEW: DELETE /api/events/{id}/waiting-room/announcements/{ann_id}/delete/
        Soft-deletes the announcement and broadcasts removal to waiting users.
        """
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only the host can delete announcements."}, status=403)

        announcement = get_object_or_404(WaitingRoomAnnouncement, id=ann_id, event=event, is_deleted=False)
        announcement.is_deleted = True
        announcement.save()

        waiting_user_ids = list(EventRegistration.objects.filter(
            event=event, admission_status="waiting", waiting_started_at__isnull=False
        ).values_list("user_id", flat=True))

        try:
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync

            channel_layer = get_channel_layer()
            for user_id in waiting_user_ids:
                async_to_sync(channel_layer.group_send)(
                    f"user_{user_id}",
                    {
                        "type": "waiting_room.announcement_delete",
                        "announcement_id": announcement.id,
                    }
                )
        except Exception as e:
            logger.warning(f"[WAITING_ROOM] Failed to broadcast announcement delete: {e}")

        return Response({"ok": True, "announcement_id": announcement.id})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="lounge/ensure-seated")
    def ensure_seated_in_lounge(self, request, pk=None):
        """
        Ensure user is seated at a lounge table for chat access.
        If not seated, automatically seat them at the first available table.

        Accepts: { "table_id": <optional_id> }
        Returns: { "table_id": <id>, "seat_index": <index>, "status": "seated" }
        """
        from .models import LoungeTable, LoungeParticipant

        event = self.get_object()
        user = request.user

        if getattr(user, "is_guest", False):
            guest = user.guest
            if guest.event_id != event.id:
                return Response({"detail": "Guest token does not match this event."}, status=403)

            if guest.lounge_table_id:
                return Response({
                    "table_id": guest.lounge_table_id,
                    "seat_index": 0,
                    "status": "already_seated",
                    "is_guest": True,
                })

            requested_table_id = request.data.get("table_id")
            table = None
            if requested_table_id:
                try:
                    table = LoungeTable.objects.get(pk=requested_table_id, event=event)
                except LoungeTable.DoesNotExist:
                    table = None
            if table is None:
                table = LoungeTable.objects.filter(event=event).order_by("id").first()
            if table is None:
                return Response({"detail": "No available lounge seats at this time."}, status=400)

            guest.lounge_table = table
            guest.current_location = "social_lounge" if table.category == "LOUNGE" else "breakout_room"
            guest.save(update_fields=["lounge_table", "current_location"])
            return Response({
                "table_id": table.id,
                "seat_index": 0,
                "status": "seated",
                "is_guest": True,
            })

        # Check if user is registered for this event
        is_registered = EventRegistration.objects.filter(
            event=event, user=user
        ).exists() or event.created_by_id == user.id

        if not is_registered:
            return Response(
                {"detail": "You are not registered for this event."},
                status=403,
            )

        # Check if user already seated
        existing = LoungeParticipant.objects.filter(
            user=user, table__event=event
        ).first()

        if existing:
            return Response({
                "table_id": existing.table_id,
                "seat_index": existing.seat_index,
                "status": "already_seated",
            })

        # Try to seat at requested table
        requested_table_id = request.data.get("table_id")
        if requested_table_id:
            try:
                table = LoungeTable.objects.get(pk=requested_table_id, event=event)
                # Find next available seat
                occupied_seats = LoungeParticipant.objects.filter(
                    table=table
                ).values_list("seat_index", flat=True)
                # include guest occupancy for capacity checks
                guest_occupied = set(range(table.guest_attendees.count()))

                next_seat = 0
                while next_seat in occupied_seats or next_seat in guest_occupied:
                    next_seat += 1

                if next_seat >= table.max_seats:
                    # Table is full, use auto-assignment below
                    table = None
                else:
                    lp = LoungeParticipant.objects.create(
                        user=user,
                        table=table,
                        seat_index=next_seat,
                    )
                    return Response({
                        "table_id": table.id,
                        "seat_index": next_seat,
                        "status": "seated",
                    })
            except LoungeTable.DoesNotExist:
                # Requested table not found, use auto-assignment
                pass

        # Auto-assign: Find first available table
        tables = LoungeTable.objects.filter(event=event).order_by("id")
        for table in tables:
            occupied_count = LoungeParticipant.objects.filter(table=table).count()
            occupied_count += table.guest_attendees.count()
            if occupied_count < table.max_seats:
                # This table has space
                lp = LoungeParticipant.objects.create(
                    user=user,
                    table=table,
                    seat_index=occupied_count,
                )
                return Response({
                    "table_id": table.id,
                    "seat_index": occupied_count,
                    "status": "seated",
                })

        # No available seats
        return Response(
            {"detail": "No available lounge seats at this time."},
            status=400,
        )

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="add-participant")
    def add_participant(self, request, pk=None):
        """
        Manually add a participant to the event (bypasses payment).
        Only for Admins/Event Owners.
        """
        event = self.get_object()
        user = request.user

        # Permission check
        if not (user.is_staff or getattr(user, "is_superuser", False) or event.created_by_id == user.id):
            return Response({"detail": "Permission denied."}, status=403)

        user_id = request.data.get("user_id")
        email = request.data.get("email", "").strip().lower()

        if not user_id and not email:
            return Response({"detail": "User ID or Email is required."}, status=400)

        User = get_user_model()
        target_user = None

        # 1. Try by user_id
        if user_id:
            try:
                target_user = User.objects.get(pk=user_id)
            except User.DoesNotExist:
                return Response({"detail": f"User with ID {user_id} not found."}, status=404)

        # 2. Try by email if no user found yet
        if not target_user and email:
            try:
                target_user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({"detail": f"User with email '{email}' not found."}, status=404)
        
        if not target_user:
             return Response({"detail": "User not found."}, status=404)

        # 2. Register them
        initial_admission_status = "waiting" if event.waiting_room_enabled else "admitted"

        reg, created = EventRegistration.objects.get_or_create(
            event=event,
            user=target_user,
            defaults={
                "status": "registered",
                "admission_status": initial_admission_status,
            }
        )

        if not created:
            # User exists but may be cancelled/deregistered - reinstate them
            if reg.status == "registered":
                return Response({"detail": "User is already registered for this event."}, status=400)

            # Re-activate the registration
            reg.status = "registered"
            reg.admission_status = initial_admission_status
            reg.save(update_fields=["status", "admission_status"])
            Event.objects.filter(pk=event.pk).update(attending_count=F("attending_count") + 1)
        else:
            # New registration created
            Event.objects.filter(pk=event.pk).update(attending_count=F("attending_count") + 1)

        return Response({"ok": True, "detail": f"User {target_user.username} added successfully."})

    @action(detail=True, methods=["patch"], permission_classes=[IsAuthenticated], url_path="reorder-speakers")
    def reorder_speakers(self, request, pk=None):
        """
        Reorder speakers/hosts/moderators by updating their display_order.
        Only for Event Owners and Staff.

        Expects a list of dicts: [{"id": participant_id, "display_order": 0}, ...]
        """
        event = self.get_object()
        user = request.user

        # Permission check: only owner or staff can reorder
        if not (user.is_staff or getattr(user, "is_superuser", False) or event.created_by_id == user.id):
            return Response({"detail": "Permission denied."}, status=403)

        items = request.data
        if not isinstance(items, list):
            return Response({"detail": "Expected a list of items."}, status=400)

        try:
            with transaction.atomic():
                for item in items:
                    participant_id = item.get("id")
                    display_order = item.get("display_order")

                    if participant_id is None or display_order is None:
                        return Response(
                            {"detail": "Each item must have 'id' and 'display_order' fields."},
                            status=400
                        )

                    # Update only if the participant belongs to this event
                    updated = EventParticipant.objects.filter(
                        id=participant_id, event=event
                    ).update(display_order=display_order)

                    if updated == 0:
                        return Response(
                            {"detail": f"Participant with id {participant_id} not found in this event."},
                            status=404
                        )

            return Response({"status": "ok"})
        except Exception as e:
            return Response({"detail": str(e)}, status=400)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated], url_path="hosted")
    def hosted(self, request):
        """
        Return events where the current user is a host.
        Used for the 'Recommend another event' dropdown.
        """
        user = request.user
        qs = Event.objects.select_related("community")
        
        if user.is_staff or getattr(user, "is_superuser", False):
            pass # sees all events
        else:
            host_match = Q(participant_type="staff", user_id=user.id)
            user_email = (getattr(user, "email", "") or "").strip()
            if user_email:
                host_match = host_match | Q(participant_type="guest", guest_email__iexact=user_email)
            
            qs = qs.filter(
                Q(created_by_id=user.id) |
                Q(community__owner_id=user.id) |
                (Q(participants__role="host") & host_match)
            ).distinct()
            
        # exclude cancelled, ended, and draft for recommendations
        qs = qs.exclude(status__in=["ended", "cancelled", "draft"])
        qs = qs.order_by("-start_time")
        
        page = self.paginate_queryset(qs)
        ser = EventLiteSerializer(page if page is not None else qs, many=True, context={"request": request})
        return self.get_paginated_response(ser.data) if page is not None else Response(ser.data)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="cancel")
    def cancel(self, request, pk=None):
        """
        Cancel an event. Only allowed by the host.
        """
        event = self.get_object()
        
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Only hosts can cancel this event."}, status=403)
            
        if event.status == "cancelled":
            return Response({"detail": "Event is already cancelled."}, status=400)
            
        message = request.data.get("cancellation_message", "")
        recommended_event_id = request.data.get("recommended_event_id")
        notify_participants = request.data.get("notify_participants", True)
        
        event.status = "cancelled"
        event.cancelled_at = timezone.now()
        event.cancelled_by = request.user
        event.cancellation_message = message
        if recommended_event_id:
            try:
                event.recommended_event = Event.objects.get(id=recommended_event_id)
            except Event.DoesNotExist:
                pass
                
        event.is_live = False # ensure it's not marked live
        event.save(update_fields=["status", "cancelled_at", "cancelled_by", "cancellation_message", "recommended_event", "is_live", "updated_at"])
        
        if notify_participants:
            try:
                from .tasks import send_event_cancelled_task
                send_event_cancelled_task.delay(event.id)
            except ImportError:
                pass
            
        return Response({
            "detail": "Event cancelled successfully.",
            "status": "cancelled",
            "cancelled_at": event.cancelled_at.isoformat() if event.cancelled_at else None,
            "cancellation_message": event.cancellation_message
        })

    @action(detail=True, methods=["post"], url_path="invite-emails", parser_classes=[JSONParser])
    def invite_emails(self, request, pk=None):
        event = self.get_object()
        if not _is_event_manager(request.user, event):
            return Response({"detail": "Forbidden"}, status=403)
            
        from django.core.validators import EmailValidator
        from django.core.exceptions import ValidationError
        from django.core.cache import cache
        from django.core import signing
        import re
        from datetime import datetime
        from django.conf import settings
        from users.email_utils import send_event_invite_email

        emails_raw = request.data.get("emails_text", "")
        if "emails" in request.data and isinstance(request.data["emails"], list):
            emails_raw += "\n".join(request.data["emails"])
            
        parts = re.split(r'[,\n\r\t; ]+', emails_raw)
        validator = EmailValidator()
        emails = []
        for p in parts:
            p = p.strip().lower()
            if p and p not in emails:
                try:
                    validator(p)
                    emails.append(p)
                except ValidationError:
                    pass
                    
        max_per_req = getattr(settings, "INVITE_EMAILS_MAX_PER_REQUEST", 20)
        if len(emails) > max_per_req:
            emails = emails[:max_per_req]
            
        if not emails:
            return Response({"detail": "No valid emails provided"}, status=400)
            
        max_per_day = getattr(settings, "INVITE_EMAILS_MAX_PER_DAY", 100)
        today_str = datetime.now().strftime("%Y-%m-%d")
        cache_key = f"invite_email:event:{request.user.id}:{today_str}"
        current_daily = cache.get(cache_key, 0)
        
        if current_daily >= max_per_day:
            return Response({"detail": f"Daily limit of {max_per_day} invites reached."}, status=429)
            
        frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000").rstrip("/")
        event_id_str = event.slug or str(event.id)

        sent = 0
        failed = []

        for email in emails:
            if current_daily + sent >= max_per_day:
                break

            payload = {
                "kind": "event",
                "event_id": event.id,
                "email": email,
                "invited_by": request.user.id
            }
            token = signing.dumps(payload, salt="event-email-invite")
            invite_url = f"{frontend_url}/events/{event_id_str}/companion?invite_token={token}"
            
            success = send_event_invite_email(email, event, request.user, invite_url)
            if success:
                sent += 1
            else:
                failed.append({"email": email, "error": "Internal send error"})
                
        if sent > 0:
            cache.set(cache_key, current_daily + sent, timeout=86400)
            
        return Response({
            "ok": True,
            "sent": sent,
            "failed": failed,
            "skipped": [],
            "limit": {"per_request": max_per_req, "per_day": max_per_day}
        })

    @action(detail=True, methods=["post"], url_path="invite-emails/accept", parser_classes=[JSONParser])
    def accept_invite_emails(self, request, pk=None):
        event = self.get_object()
        token = request.data.get("token")
        if not token:
            return Response({"detail": "Token required"}, status=400)
            
        from django.core import signing
        from django.conf import settings
        max_age = getattr(settings, "INVITE_EMAIL_TOKEN_MAX_AGE_SECONDS", 30 * 24 * 3600)
        
        try:
            payload = signing.loads(token, salt="event-email-invite", max_age=max_age)
        except signing.BadSignature:
            return Response({"detail": "Invalid or expired token"}, status=400)
            
        if payload.get("kind") != "event" or payload.get("event_id") != event.id:
            return Response({"detail": "Token not for this event"}, status=400)
            
        if not request.user.email or payload.get("email", "").lower() != request.user.email.lower():
            return Response({"detail": "Token belongs to a different email"}, status=403)
            
        # Check capacity
        invited_by_id = payload.get("invited_by")

        if event.max_participants and event.registrations.filter(status="registered").count() >= event.max_participants:
            if not getattr(event, "waitlist_enabled", False):
                return Response({"detail": "Event is at capacity"}, status=400)

        # Handle paid events: don't auto-register, require payment flow instead
        if not event.is_free:
            is_registered = EventRegistration.objects.filter(
                event=event,
                user=request.user,
                status__in=["registered", "waitlisted"]
            ).exists()

            if not is_registered:
                return Response({
                    "ok": True,
                    "status": "requires_payment",
                    "event_id": event.id,
                    "detail": "Paid event requires ticket purchase"
                })

        # Use helper to grant access (creates registration and approves pending apps)
        invited_by_user = None
        if invited_by_id:
            try:
                invited_by_user = User.objects.get(id=invited_by_id)
            except User.DoesNotExist:
                pass

        result = _grant_invited_event_access(event, request.user, invited_by=invited_by_user)

        return Response({
            "ok": True,
            "status": "registered",
            "event_id": event.id,
            "registration_status": "registered"
        })

    # ========== Pinning/Promotion Endpoints ==========
    @action(detail=True, methods=["post"], permission_classes=[IsSuperuserOnly], url_path="pin")
    def pin_event(self, request, pk=None):
        """Pin an event to promote it. Superuser-only."""
        from django.utils import timezone
        event = self.get_object()
        pin_priority = int(request.data.get("pin_priority", 100))
        event.is_pinned = True
        event.pin_priority = pin_priority
        event.pinned_at = timezone.now()
        event.pinned_by = request.user
        event.save(update_fields=["is_pinned", "pin_priority", "pinned_at", "pinned_by", "updated_at"])
        return Response(EventSerializer(event, context={"request": request}).data)

    @action(detail=True, methods=["post"], permission_classes=[IsSuperuserOnly], url_path="unpin")
    def unpin_event(self, request, pk=None):
        """Unpin an event. Superuser-only."""
        event = self.get_object()
        event.is_pinned = False
        event.pin_priority = 100
        event.pinned_at = None
        event.pinned_by = None
        event.save(update_fields=["is_pinned", "pin_priority", "pinned_at", "pinned_by", "updated_at"])
        return Response(EventSerializer(event, context={"request": request}).data)

    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="landing")
    def landing_page_events(self, request):
        """Get hero event and upcoming events sorted for landing page.

        Returns:
        {
            "hero_event": {...},  # featured > pinned > nearest upcoming
            "upcoming_events": [...]  # excludes hero, sorted: pinned first (by priority), then by date
        }
        """
        from django.utils import timezone
        now = timezone.now()

        # Get upcoming events: published, not ended, after now
        qs = self.get_queryset().filter(
            status="published"
        ).exclude(
            status="ended"
        ).exclude(
            end_time__lt=now
        ).filter(
            Q(start_time__isnull=True) | Q(start_time__gt=now)
        ).order_by("is_pinned", "pin_priority", "pinned_at", "start_time")

        events = list(qs)

        # Select hero event: featured > pinned (lowest priority) > nearest upcoming
        hero_event = None

        # Priority 1: Featured event
        featured = next((e for e in events if e.is_featured), None)
        if featured:
            hero_event = featured
        # Priority 2: Pinned event with lowest pin_priority
        elif any(e.is_pinned for e in events):
            pinned = [e for e in events if e.is_pinned]
            hero_event = min(pinned, key=lambda e: (e.pin_priority or 999999, -(e.pinned_at.timestamp() if e.pinned_at else 0)))
        # Priority 3: Nearest upcoming event
        elif events:
            hero_event = events[0]

        # Get remaining events for grid, sorted properly
        upcoming_events = [e for e in events if not hero_event or e.id != hero_event.id]

        # Sort: pinned first (by pin_priority, then pinned_at), then normal by start_time
        def sort_key(event):
            if event.is_pinned:
                # Pinned: (0, pin_priority, -pinned_at_timestamp)
                pinned_time = -(event.pinned_at.timestamp() if event.pinned_at else 0)
                return (0, event.pin_priority or 999999, pinned_time)
            else:
                # Normal: (1, start_time_timestamp)
                start_time = event.start_time.timestamp() if event.start_time else float('inf')
                return (1, start_time)

        upcoming_events.sort(key=sort_key)

        # Serialize
        hero_data = EventSerializer(hero_event, context={"request": request}).data if hero_event else None
        upcoming_data = EventSerializer(upcoming_events[:6], many=True, context={"request": request}).data

        return Response({
            "hero_event": hero_data,
            "upcoming_events": upcoming_data,
        })

    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="pinned")
    def pinned_events(self, request):
        """Get public pinned events. Reuses visibility logic from main queryset."""
        from django.utils import timezone
        now = timezone.now()

        qs = self.get_queryset().filter(is_pinned=True)

        params = request.query_params
        include_ended = (params.get("include_ended") or "").strip().lower() in {"1", "true", "yes", "on"}

        if not include_ended:
            qs = qs.exclude(status="ended").exclude(end_time__lt=now)

        qs = qs.order_by("pin_priority", "-pinned_at", "start_time")

        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = EventListSerializer(page, many=True, context={"request": request})
            return self.get_paginated_response(serializer.data)

        serializer = EventListSerializer(qs, many=True, context={"request": request})
        return Response(serializer.data)

    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="replays")
    def replay_events(self, request):
        """Get past events with replay enabled. Safe for anonymous users."""
        from django.utils import timezone
        now = timezone.now()

        # Build queryset from scratch to allow replay events for all users
        # (bypass standard visibility filters that hide ended events from non-auth users)
        qs = Event.objects.select_related("community")

        # Check if user is platform admin
        user = request.user
        is_platform_admin = bool(getattr(user, "is_superuser", False)) or bool(getattr(user, "is_staff", False)) if user.is_authenticated else False

        # Hide non-hidden events unless user is authenticated & authorized
        if user.is_authenticated:
            # Authenticated user can see hidden events if they're the creator/registered
            if not is_platform_admin:
                hidden_accessible_ids = EventRegistration.objects.filter(
                    user_id=user.id,
                    status__in=['registered', 'cancellation_requested']
                ).values_list('event_id', flat=True)
                qs = qs.filter(
                    Q(is_hidden=False) |
                    Q(is_hidden=True, created_by_id=user.id) |
                    Q(is_hidden=True, id__in=hidden_accessible_ids)
                )
        else:
            # Non-authenticated users: only non-hidden, published events
            qs = qs.filter(is_hidden=False)

        # Core replay filter: must be ended/past, have replay enabled, and recording must be published
        qs = qs.filter(
            replay_enabled=True,
            replay_visible_to_participants=True,
            status__in=["published", "ended"]
        ).filter(
            Q(status="ended") | Q(end_time__lt=now)
        )

        # For authenticated users: exclude events they're already registered for
        # (they have recording/replay access already, no need for signup)
        if user.is_authenticated and not is_platform_admin:
            registered_event_ids = EventRegistration.objects.filter(
                user_id=user.id,
                status__in=['registered', 'cancellation_requested']
            ).values_list('event_id', flat=True)
            qs = qs.exclude(id__in=registered_event_ids)

        params = request.query_params

        # Apply the same filters as regular events
        topicsToSend = params.getlist("category")
        if topicsToSend:
            qs = qs.filter(category__in=topicsToSend)

        location = params.get("location")
        if location:
            qs = qs.filter(location_city=location) | qs.filter(location=location)

        event_format = params.getlist("event_format")
        if event_format:
            qs = qs.filter(format__in=event_format)

        start_date = params.get("start_date")
        if start_date:
            qs = qs.filter(start_time__gte=start_date)

        end_date = params.get("end_date")
        if end_date:
            qs = qs.filter(start_time__lte=end_date)

        min_price = params.get("min_price")
        if min_price is not None:
            try:
                qs = qs.filter(price__gte=float(min_price))
            except (ValueError, TypeError):
                pass

        max_price = params.get("max_price")
        if max_price is not None:
            try:
                qs = qs.filter(price__lte=float(max_price))
            except (ValueError, TypeError):
                pass

        search = params.get("search")
        if search:
            qs = qs.filter(
                Q(title__icontains=search) |
                Q(location__icontains=search) |
                Q(category__icontains=search) |
                Q(description__icontains=search)
            )

        # Order by most recent first
        qs = qs.order_by("-end_time", "-start_time")

        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = PublicEventSerializer(page, many=True, context={"request": request})
            return self.get_paginated_response(serializer.data)

        serializer = PublicEventSerializer(qs, many=True, context={"request": request})
        return Response(serializer.data)

    # ========== Email Template Endpoints ==========
    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="email-templates")
    def email_templates_list(self, request, pk=None):
        event = self.get_object()
        if not user_can_manage_event_email_templates(request.user, event):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        data = [get_event_email_template_payload(event, key) for key in EVENT_EMAIL_TEMPLATE_KEYS]
        data = [item for item in data if item]
        data.sort(key=lambda item: (item.get("category") or "", item.get("label") or ""))
        return Response(data)

    @action(detail=True, methods=["get", "patch", "delete"], permission_classes=[IsAuthenticated], url_path=r"email-templates/(?P<template_key>[^/]+)")
    def email_templates(self, request, pk=None, template_key=None):
        event = self.get_object()
        if not user_can_manage_event_email_templates(request.user, event):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        if template_key not in EVENT_EMAIL_TEMPLATE_KEYS:
            return Response({"detail": "Template not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.method == "GET":
            return Response(get_event_email_template_payload(event, template_key))

        if request.method == "PATCH":
            save_event_email_template(event, template_key, request.data, request.user)
            return Response(get_event_email_template_payload(event, template_key))

        deleted, _ = EventEmailTemplate.objects.filter(event=event, template_key=template_key).delete()
        return Response({"detail": "Template reset." if deleted else "No event override existed."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path=r"email-templates/(?P<template_key>[^/]+)/preview")
    def preview_email_template(self, request, pk=None, template_key=None):
        event = self.get_object()
        if not user_can_manage_event_email_templates(request.user, event):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        payload = get_event_email_template_payload(event, template_key)
        if not payload:
            return Response({"detail": "Template not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(render_event_email_payload(event, template_key, payload, user=request.user, overrides=request.data))

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path=r"email-templates/(?P<template_key>[^/]+)/send-test")
    def send_test_email_template(self, request, pk=None, template_key=None):
        event = self.get_object()
        if not user_can_manage_event_email_templates(request.user, event):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        test_email = (request.data.get("test_email") or "").strip()
        if not test_email:
            return Response({"test_email": "This field is required."}, status=status.HTTP_400_BAD_REQUEST)
        if template_key not in EVENT_EMAIL_TEMPLATE_KEYS:
            return Response({"detail": "Template not found."}, status=status.HTTP_404_NOT_FOUND)
        send_event_email_test(event, template_key, test_email, user=request.user)
        return Response({"detail": "Test email sent."})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path=r"email-templates/(?P<template_key>[^/]+)/reset")
    def reset_email_template(self, request, pk=None, template_key=None):
        event = self.get_object()
        if not user_can_manage_event_email_templates(request.user, event):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        if template_key not in EVENT_EMAIL_TEMPLATE_KEYS:
            return Response({"detail": "Template not found."}, status=status.HTTP_404_NOT_FOUND)
        EventEmailTemplate.objects.filter(event=event, template_key=template_key).delete()
        return Response(get_event_email_template_payload(event, template_key))


# ============================================================
# ================= Public Event Detail View =================
# ============================================================
class PublicEventDetailView(generics.RetrieveAPIView):
    """
    Public-facing endpoint for event landing pages.
    - No authentication required
    - Only returns public event data (no sensitive fields)
    - Available for published/live events, or ended events with replay_enabled=True
    """
    permission_classes = [AllowAny]
    serializer_class = PublicEventSerializer
    lookup_field = "slug"
    lookup_url_kwarg = "slug"

    def get_queryset(self):
        from django.db.models import Q
        return (
            Event.objects
            .filter(
                Q(status__in=["published", "live"]) |
                Q(status="ended", replay_enabled=True)
            )
            .select_related("community")
            .prefetch_related("sessions", "participants__user", "participants__user__profile")
        )


# ============================================================
# ================= Event Registration ViewSet ===============
# ============================================================

def _recalculate_event_attending_count(event_id):
    """
    Safely recalculate attending_count from active confirmed registrations.
    Prevents negative counts and handles race conditions.
    Used when canceling/deregistering to avoid blind decrements.
    """
    with transaction.atomic():
        event = Event.objects.select_for_update().get(pk=event_id)

        true_count = EventRegistration.objects.filter(
            event=event,
            status='registered',
            attendee_status__in=['confirmed', 'payment_pending']
        ).count()

        if event.attending_count != true_count:
            event.attending_count = true_count
            event.save(update_fields=['attending_count'])


class EventRegistrationViewSet(viewsets.ModelViewSet):
    """
    CRUD for a user's event registrations + Actions for cancellation.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = EventRegistrationSerializer

    def destroy(self, request, *args, **kwargs):
        """
        Soft delete registration and cancel related applications:
        - If user -> 'cancelled' + cancel application
        - If admin/owner -> 'deregistered' + cancel application

        Safe cancellation using recalculated attending_count instead of blind decrement.
        Updates EventApplication and EventApplicationTrackApplication to cancelled status.
        Handles edge cases: double cancel, race conditions, corrupt state.
        """
        reg = self.get_object()
        user = request.user

        # Determine strict permissions if not already handled by 'get_queryset' or permission_classes
        is_owner_of_reg = (reg.user_id == user.id)
        is_event_owner = (reg.event.created_by_id == user.id)
        is_staff = user.is_staff or getattr(user, "is_superuser", False)

        if not (is_owner_of_reg or is_event_owner or is_staff):
            return Response({"detail": "Not authorized."}, status=403)

        # Use application cancellation service for consistent state management
        from events.services.application_cancellation import cancel_registration_for_application
        cancel_registration_for_application(
            reg,
            cancellation_reason='registration_cancelled'
        )

        # If admin deregistering, update status to 'deregistered' instead of 'cancelled'
        if not (is_owner_of_reg and not (is_event_owner or is_staff)):
            with transaction.atomic():
                reg.status = "deregistered"
                reg.save(update_fields=["status"])

        # Invalidate event list caches when registration is cancelled/deregistered
        try:
            from .cache_utils import invalidate_event_list_caches
            invalidate_event_list_caches(reg.event_id)
        except Exception as e:
            logger.warning(f"Failed to invalidate event list cache for event {reg.event_id}: {e}")

        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_queryset(self):
        """
        Admins/Staff/Event Owners -> See all relevant.
        Normal users -> See only their own.
        Supports ?event=, ?user=, and ?attendance_status= filters.
        Supports ?ordering= for server-side sorting (registered_at or -registered_at).
        """
        user = self.request.user
        qs = EventRegistration.objects.select_related("event")

        if getattr(user, "is_guest", False):
            return qs.none()

        # Staff / superusers can see all registrations, but we still
        # apply ?event= and ?user= filters if provided so that lookups
        # like ?event=30&user=2 return only what was asked for.
        if not (getattr(user, "is_staff", False) or getattr(user, "is_superuser", False)):
            # Normal users: only see their own registrations OR events they created
            qs = qs.filter(Q(user=user) | Q(event__created_by=user)).distinct()

        # Apply ?event=ID filter for everyone
        event_id = self.request.query_params.get("event")
        if event_id:
            qs = qs.filter(event_id=event_id)

        # Apply ?user=ID filter (staff/owner only; non-staff can only see their own)
        user_id = self.request.query_params.get("user")
        if user_id:
            if getattr(user, "is_staff", False) or getattr(user, "is_superuser", False):
                qs = qs.filter(user_id=user_id)
            # For non-staff, the user filter is already enforced by the Q() above

        # Apply ?attendance_status= filter for attendance categorization
        attendance_status = self.request.query_params.get("attendance_status")
        if attendance_status:
            if attendance_status == "joined_live":
                qs = qs.filter(joined_live=True)
            elif attendance_status == "watched_replay":
                qs = qs.filter(watched_replay=True, joined_live=False)
            elif attendance_status == "did_not_attend":
                qs = qs.filter(joined_live=False, watched_replay=False)

        # Apply ?ordering= for server-side sorting with stable secondary ordering by id
        ordering = self.request.query_params.get("ordering", "-registered_at")
        if ordering == "registered_at":
            qs = qs.order_by("registered_at", "id")
        elif ordering == "-registered_at":
            qs = qs.order_by("-registered_at", "-id")
        else:
            # Default to newest first
            qs = qs.order_by("-registered_at", "-id")

        return qs


    def create(self, request, *args, **kwargs):
        # 1. Custom check for existing registration to handle re-registration
        user = request.user
        if getattr(user, "is_guest", False):
            return Response({"detail": "Guests cannot create user registrations."}, status=403)
        event_id = request.data.get("event_id") or request.data.get("event")

        if event_id and user.is_authenticated:
            try:
                # Use filter().first() to avoid exceptions
                existing_reg = EventRegistration.objects.filter(user=user, event_id=event_id).first()
                if existing_reg:
                    # If previously deregistered or cancelled, reactivate them
                    if existing_reg.status in ['deregistered', 'cancelled']:
                        existing_reg.status = 'registered'
                        existing_reg.save(update_fields=['status'])
                        serializer = self.get_serializer(existing_reg)
                        return Response(serializer.data, status=status.HTTP_200_OK)
                    
                    # If already registered, standard validation will catch it
            except Exception:
                pass

        return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        """
        Force user= current request.user on create.
        """
        if getattr(self.request.user, "is_guest", False):
            raise PermissionDenied("Guests cannot create user registrations.")
        serializer.save(user=self.request.user)

    @action(detail=False, methods=["get"], url_path="mine")
    def mine(self, request):
        """
        Alias to list only my registrations with pagination support.
        Always strict to request.user.
        Uses lightweight serializer and optimized query for fast card footer loads.
        """
        if getattr(request.user, "is_guest", False):
            return Response([])

        qs = self.get_queryset().filter(
            user=request.user,
            status__in=['registered', 'cancellation_requested']
        ).select_related('event', 'user').only(
            'id', 'event_id', 'status', 'attendee_status', 'registered_at',
            'joined_live', 'watched_replay', 'admission_status', 'admitted_at',
            'current_location', 'user_id', 'event__id', 'event__created_by_id',
            'user__email'
        )
        page = self.paginate_queryset(qs)
        ser = EventRegistrationLiteSerializer(page or qs, many=True)
        return self.get_paginated_response(ser.data) if page is not None else Response(ser.data)

    @action(detail=True, methods=["post"], url_path="cancel_request")
    def cancel_request(self, request, pk=None):
        """
        User requests cancellation (for paid events).
        """
        reg = self.get_object()
        if reg.user != request.user:
            return Response({"error": "not_authorized"}, status=403)
        
        # If event is free, they should just DELETE. But if they call this:
        if reg.event.price == 0 or reg.event.is_free:
            # Maybe auto-delete? Or just mark? Let's just mark.
            pass

        if reg.status == "cancelled":
             return Response({"error": "already_cancelled"}, status=400)

        reg.status = "cancellation_requested"
        reg.save(update_fields=["status"])
        return Response({"ok": True, "status": reg.status})

    @action(detail=True, methods=["post"], url_path="approve_cancellation")
    def approve_cancellation(self, request, pk=None):
        """
        Admin/Owner approves cancellation -> sets status=cancelled.
        Uses cancellation service to update applications consistently.
        Uses safe recalculation for attending_count to prevent going negative.
        Future: Trigger refund.
        """
        reg = self.get_object()
        # Check permission: Admins or Event Owner
        is_admin = request.user.is_staff or getattr(request.user, "is_superuser", False)
        is_owner = (reg.event.created_by_id == request.user.id)

        if not (is_admin or is_owner):
            return Response({"error": "permission_denied"}, status=403)

        # Use application cancellation service for consistent state management
        from events.services.application_cancellation import cancel_registration_for_application
        cancel_registration_for_application(
            reg,
            cancellation_reason='registration_cancelled'
        )
        # TODO: Process Refund Logic Here

        # Invalidate event list caches when registration is cancelled
        try:
            from .cache_utils import invalidate_event_list_caches
            invalidate_event_list_caches(reg.event_id)
        except Exception as e:
            logger.warning(f"Failed to invalidate event list cache for event {reg.event_id}: {e}")

        return Response({"ok": True, "status": reg.status})

    @action(detail=True, methods=["post"], url_path="reject_cancellation")
    def reject_cancellation(self, request, pk=None):
        """
        Admin/Owner rejects cancellation -> reverts to registered.
        Restores EventAttendeeOrigin status and recalculates attending_count.
        """
        reg = self.get_object()
        is_admin = request.user.is_staff or getattr(request.user, "is_superuser", False)
        is_owner = (reg.event.created_by_id == request.user.id)

        if not (is_admin or is_owner):
            return Response({"error": "permission_denied"}, status=403)

        with transaction.atomic():
            reg.status = "registered"
            # Restore attendee_status: recalculate based on all origins
            from events.services.attendee_directory import _recalculate_registration_status
            reg.save(update_fields=["status"])

            # Restore EventAttendeeOrigin status from cancelled back to active
            # Origin status was cancelled along with registration - restore it
            # Get the tier info to restore proper origin_status
            for origin in reg.origins.filter(status='cancelled'):
                origin.status = 'active'
                # Restore origin_status based on the tier (if paid, payment_pending; if free, confirmed)
                if origin.accepted_tier and origin.accepted_tier.price and origin.accepted_tier.price > 0:
                    origin.origin_status = 'payment_pending'
                else:
                    origin.origin_status = 'confirmed'
                origin.save(update_fields=['status', 'origin_status'])

            # Recalculate registration attendee_status based on all origins
            _recalculate_registration_status(reg)

        # Recalculate attending_count safely from real data
        _recalculate_event_attending_count(reg.event_id)

        return Response({"ok": True, "status": reg.status})

    @action(detail=True, methods=["post"], url_path="deregister")
    def deregister(self, request, pk=None):
        """
        Admin/Owner deregisters a user -> sets status=deregistered (Soft Delete).
        Uses safe recalculation for attending_count to prevent going negative.
        """
        reg = self.get_object()
        is_admin = request.user.is_staff or getattr(request.user, "is_superuser", False)
        is_owner = (reg.event.created_by_id == request.user.id)

        if not (is_admin or is_owner):
            return Response({"error": "permission_denied"}, status=403)

        with transaction.atomic():
            reg.status = "deregistered"
            reg.attendee_status = "cancelled"
            # Reset admission status so they aren't stuck in "waiting" or "admitted" state if they rejoin later
            reg.admission_status = "waiting" if reg.event.waiting_room_enabled else "admitted"
            reg.joined_live = False
            reg.is_online = False
            reg.save(update_fields=["status", "attendee_status", "admission_status", "joined_live", "is_online"])

            # Mark EventAttendeeOrigin records as cancelled
            reg.origins.filter(status='active').update(
                status='cancelled',
                origin_status='cancelled'
            )

        # Recalculate attending_count safely from real data
        _recalculate_event_attending_count(reg.event_id)

        return Response({"ok": True, "status": reg.status})

    @action(detail=True, methods=["post"], url_path="reinstate")
    def reinstate(self, request, pk=None):
        """
        Admin/Owner reinstates a deregistered/cancelled user -> sets status=registered.
        Restores EventAttendeeOrigin status and recalculates attending_count.
        """
        reg = self.get_object()
        is_admin = request.user.is_staff or getattr(request.user, "is_superuser", False)
        is_owner = (reg.event.created_by_id == request.user.id)

        if not (is_admin or is_owner):
            return Response({"error": "permission_denied"}, status=403)

        with transaction.atomic():
            reg.status = "registered"
            # Re-evaluate admission status
            reg.admission_status = "waiting" if reg.event.waiting_room_enabled else "admitted"
            reg.save(update_fields=["status", "admission_status"])

            # Restore EventAttendeeOrigin status from cancelled back to active
            for origin in reg.origins.filter(status='cancelled'):
                origin.status = 'active'
                # Restore origin_status based on the tier
                if origin.accepted_tier and origin.accepted_tier.price and origin.accepted_tier.price > 0:
                    origin.origin_status = 'payment_pending'
                else:
                    origin.origin_status = 'confirmed'
                origin.save(update_fields=['status', 'origin_status'])

            # Recalculate registration attendee_status based on all origins
            from events.services.attendee_directory import _recalculate_registration_status
            _recalculate_registration_status(reg)

        # Recalculate attending_count safely from real data
        _recalculate_event_attending_count(reg.event_id)

        return Response({"ok": True, "status": reg.status})

    @action(detail=True, methods=["post"], url_path="assign-labels")
    def assign_labels(self, request, pk=None):
        reg = self.get_object()
        is_admin = request.user.is_staff or getattr(request.user, 'is_superuser', False)
        is_owner = (reg.event.created_by_id == request.user.id)
        if not (is_admin or is_owner):
            return Response({"error": "permission_denied"}, status=403)
        label_ids = request.data.get('label_ids', [])
        if not isinstance(label_ids, list):
            return Response({"error": "label_ids must be a list"}, status=400)
        labels = EventBadgeLabel.objects.filter(id__in=label_ids, event=reg.event)
        if labels.count() != len(label_ids):
            return Response({"error": "One or more label IDs are invalid or belong to a different event."}, status=400)
        reg.badge_labels.set(labels)
        return Response({"ok": True, "label_ids": list(reg.badge_labels.values_list('id', flat=True))})

    @action(detail=False, methods=["post"], url_path="bulk-assign-labels")
    def bulk_assign_labels(self, request):
        is_admin = request.user.is_staff or getattr(request.user, 'is_superuser', False)
        registration_ids = request.data.get('registration_ids', [])
        label_ids = request.data.get('label_ids', [])
        mode = request.data.get('mode', 'add')
        if not isinstance(registration_ids, list) or not registration_ids:
            return Response({"error": "registration_ids must be a non-empty list"}, status=400)
        if not isinstance(label_ids, list):
            return Response({"error": "label_ids must be a list"}, status=400)
        if mode not in ('set', 'add', 'remove'):
            return Response({"error": "mode must be 'set', 'add', or 'remove'"}, status=400)
        regs_qs = EventRegistration.objects.filter(id__in=registration_ids)
        if not is_admin:
            regs_qs = regs_qs.filter(event__created_by=request.user)
        regs = list(regs_qs.select_related('event'))
        if len(regs) != len(registration_ids):
            return Response({"error": "Some registration IDs are invalid or not authorized."}, status=403)
        event_ids = {r.event_id for r in regs}
        labels = list(EventBadgeLabel.objects.filter(id__in=label_ids, event_id__in=event_ids))
        updated = 0
        for reg in regs:
            event_labels = [l for l in labels if l.event_id == reg.event_id]
            if mode == 'set':
                reg.badge_labels.set(event_labels)
            elif mode == 'add':
                reg.badge_labels.add(*event_labels)
            elif mode == 'remove':
                reg.badge_labels.remove(*event_labels)
            updated += 1
        return Response({"ok": True, "updated": updated})


class EventBadgeLabelViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = EventBadgeLabelSerializer
    http_method_names = ['get', 'post', 'patch', 'delete', 'head', 'options']

    def get_queryset(self):
        user = self.request.user
        qs = EventBadgeLabel.objects.select_related('event')
        event_id = self.request.query_params.get('event_id') or self.request.query_params.get('event')
        if event_id:
            qs = qs.filter(event_id=event_id)
        if not (getattr(user, 'is_staff', False) or getattr(user, 'is_superuser', False)):
            qs = qs.filter(event__created_by=user)
        return qs

    def _check_permission(self, event):
        user = self.request.user
        if not (user.is_staff or getattr(user, 'is_superuser', False) or event.created_by_id == user.id):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Only the event owner can manage badge labels.")

    def create(self, request, *args, **kwargs):
        from django.shortcuts import get_object_or_404
        event_id = request.data.get('event_id') or request.data.get('event')
        if not event_id:
            return Response({'detail': 'event_id is required.'}, status=400)
        event = get_object_or_404(Event, pk=event_id)
        self._check_permission(event)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(event=event)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        label = self.get_object()
        self._check_permission(label.event)
        serializer = self.get_serializer(label, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        label = self.get_object()
        self._check_permission(label.event)
        label.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class RecordingWebhookView(views.APIView):
    """
    Cloudflare RealtimeKit recording webhook.

    We receive `recording.statusUpdate`, fetch recording details from
    RealtimeKit, download the .mp4 from RealtimeKit's temporary URL and
    upload it into *our* S3 bucket.

    Final S3 key format:
        recordings/<event-slug>/recording/<output_file_name>

    That key is stored in Event.recording_url.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        payload = request.data
        event_type = payload.get("event")

        if event_type != "recording.statusUpdate":
            return Response({"ignored": True}, status=200)

        meeting = payload.get("meeting") or {}
        recording = payload.get("recording") or {}

        meeting_id = meeting.get("id")
        # RealtimeKit may send recordingId or id – handle both
        recording_id = recording.get("recordingId") or recording.get("id")
        status_str = recording.get("status")

        if not (meeting_id and recording_id and status_str):
            logger.error("❌ recording webhook missing_fields")
            return Response({"error": "missing_fields"}, status=400)

        # Only act when RealtimeKit says the recording is fully uploaded on their side
        if status_str != "UPLOADED":
            logger.info(
                "🎥 RealtimeKit recording status=%s | meeting=%s | recording=%s",
                status_str,
                meeting_id,
                recording_id,
            )
            return Response({"ok": True, "status": status_str}, status=200)

        # 1) Find our Event that corresponds to this meeting
        try:
            event = Event.objects.get(rtk_meeting_id=meeting_id)
            logger.info(
                "🔍 Webhook found event: id=%s, replay_publishing_mode=%s",
                event.id,
                event.replay_publishing_mode
            )
        except Event.DoesNotExist:
            logger.error("❌ Event not found for meeting_id=%s", meeting_id)
            return Response({"error": "event_not_found"}, status=404)

        # 2) Fetch full recording details from RealtimeKit
        try:
            headers = _rtk_headers()
        except RuntimeError as exc:
            logger.error("❌ RealtimeKit credentials missing: %s", exc)
            return Response({"error": "rtk_config"}, status=500)

        try:
            r = requests.get(
                f"{RTK_API_BASE}/recordings/{recording_id}",
                headers=headers,
                timeout=20,
            )
            r.raise_for_status()
        except Exception as exc:
            logger.exception("❌ Failed to fetch RealtimeKit recording details")
            return Response({"error": "rtk_fetch_failed", "detail": str(exc)}, status=500)

        data = (r.json() or {}).get("data") or {}

        output_file_name = data.get("output_file_name") or f"{recording_id}.mp4"

        asset_links = data.get("asset_links") or {}
        download_url = (
            asset_links.get("download")
            or data.get("download_url")
            or data.get("url")
        )

        if not download_url:
            logger.error("❌ No download URL in RealtimeKit recording data for %s", recording_id)
            return Response({"error": "no_download_url"}, status=500)

        # 3) Copy from RealtimeKit bucket → our S3 bucket
        import boto3
        from botocore.config import Config

        bucket = AWS_S3_BUCKET
        region = AWS_S3_REGION

        if not bucket:
            logger.error("❌ AWS_S3_BUCKET not configured. Set AWS_S3_BUCKET environment variable or Django setting.")
            return Response({"error": "aws_bucket_not_configured"}, status=500)

        s3_client = boto3.client(
            "s3",
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=region,
            config=Config(signature_version="s3v4"),
        )

        safe_slug = event.slug or f"event-{event.id}"
        # 👇 Final S3 key as requested: recordings/eventname/recording/<file>
        s3_key = f"recordings/{safe_slug}/recording/{output_file_name}"

        try:
            file_resp = requests.get(download_url, stream=True, timeout=120)
            file_resp.raise_for_status()

            s3_client.upload_fileobj(
                file_resp.raw,
                bucket,
                s3_key,
                ExtraArgs={"ContentType": "video/mp4"},
            )
            logger.info(
                "✅ Uploaded RealtimeKit recording to S3: bucket=%s key=%s",
                bucket,
                s3_key,
            )
        except Exception as exc:
            logger.exception("❌ Failed to upload recording to S3")
            return Response({"error": "s3_upload_failed", "detail": str(exc)}, status=500)

        # 4) Store the S3 key on the Event
        event.recording_url = s3_key
        event.replay_available = True
        event.replay_visible_to_participants = (event.replay_publishing_mode == "auto_publish")

        logger.info(
            "🔍 Webhook setting replay_visible_to_participants: replay_publishing_mode=%s, visible=%s",
            event.replay_publishing_mode,
            event.replay_visible_to_participants
        )

        event.save(update_fields=["recording_url", "replay_available", "replay_visible_to_participants", "updated_at"])

        logger.info(
            "✅ Saved recording for event=%s meeting=%s s3_key=%s, replay_available=True",
            event.id,
            meeting_id,
            s3_key,
        )
        return Response({"message": "Recording saved", "event_id": event.id}, status=202)


# ============================================================
# ================ Event Session ViewSet ===================
# ============================================================

class EventSessionViewSet(viewsets.ModelViewSet):
    """ViewSet for managing event sessions."""

    serializer_class = EventSessionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter sessions by event_id from URL."""
        event_id = self.kwargs.get('event_id')
        return EventSession.objects.filter(event_id=event_id).select_related('event').prefetch_related('participants', 'attendances')

    def perform_create(self, serializer):
        """Set event from URL parameter."""
        event_id = self.kwargs.get('event_id')
        try:
            event = Event.objects.get(id=event_id)
        except Event.DoesNotExist:
            raise NotFound("Event not found")

        # Check permission: must be event creator or staff
        if not _is_event_manager(self.request.user, event):
            raise PermissionDenied("Only event creators/staff can add sessions")

        serializer.save(event=event)

    def perform_update(self, serializer):
        """Update session with permission check."""
        session = self.get_object()
        event = session.event

        # Check permission: must be event creator or staff
        if not _is_event_manager(self.request.user, event):
            raise PermissionDenied("Only event creators/staff can update sessions")

        serializer.save()

    def perform_destroy(self, instance):
        """Delete session with permission check."""
        event = instance.event

        # Check permission: must be event creator or staff
        if not _is_event_manager(self.request.user, event):
            raise PermissionDenied("Only event creators/staff can delete sessions")

        instance.delete()

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def start_live(self, request, event_id=None, pk=None):
        """Start a session live (create/use RTK meeting)."""
        session = self.get_object()
        event = session.event

        if not _is_event_manager(request.user, event):
            raise PermissionDenied("Only event hosts can start sessions")

        if session.is_live:
            return Response({'error': 'Session is already live'}, status=400)

        # Create or use RTK meeting
        if session.use_parent_meeting:
            # Use parent event's meeting
            if not event.rtk_meeting_id:
                # Create meeting for event if doesn't exist
                meeting = create_rtk_meeting(event.title)
                event.rtk_meeting_id = meeting['id']
                event.save(update_fields=['rtk_meeting_id'])
            session.rtk_meeting_id = event.rtk_meeting_id
        else:
            # Create separate meeting for this session
            meeting = create_rtk_meeting(session.title)
            session.rtk_meeting_id = meeting['id']

        session.is_live = True
        session.live_started_at = timezone.now()
        session.save(update_fields=['is_live', 'live_started_at', 'rtk_meeting_id'])

        return Response(EventSessionSerializer(session, context={'request': request}).data)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def end_live(self, request, event_id=None, pk=None):
        """End a live session."""
        session = self.get_object()
        event = session.event

        if not _is_event_manager(request.user, event):
            raise PermissionDenied("Only event hosts can end sessions")

        if not session.is_live:
            return Response({'error': 'Session is not live'}, status=400)

        session.is_live = False
        session.live_ended_at = timezone.now()
        session.save(update_fields=['is_live', 'live_ended_at'])

        return Response(EventSessionSerializer(session, context={'request': request}).data)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def join_session(self, request, event_id=None, pk=None):
        """Join a session and track attendance."""
        session = self.get_object()
        event = session.event
        user = request.user

        # Check if user is registered for parent event
        try:
            registration = EventRegistration.objects.get(event=event, user=user)
        except EventRegistration.DoesNotExist:
            raise PermissionDenied("You must be registered for this event to join sessions")

        # Create or update attendance record
        attendance, created = SessionAttendance.objects.get_or_create(
            session=session,
            user=user,
            defaults={'is_online': True}
        )

        if not created:
            # Update existing attendance
            attendance.is_online = True
            attendance.save(update_fields=['is_online'])

        return Response({
            'message': 'Joined session successfully',
            'attendance': SessionAttendanceSerializer(attendance).data
        })

    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated])
    def list_attendances(self, request, event_id=None, pk=None):
        """List attendances for a session (host only)."""
        session = self.get_object()
        event = session.event

        if not _is_event_manager(request.user, event):
            raise PermissionDenied("Only event hosts can view attendances")

        attendances = session.attendances.select_related('user').order_by('-joined_at')
        serializer = SessionAttendanceSerializer(attendances, many=True)
        return Response(serializer.data)


def _build_lounge_state_sync(event_id):
    """
    ✅ Helper function: Build current lounge state for broadcasting.
    Used to include updated lounge state in WebSocket messages so frontend can refresh UI.
    Returns list of table states with current participants.
    """
    try:
        tables = LoungeTable.objects.filter(event_id=event_id).prefetch_related('participants__user__profile')
        guest_rows = (
            GuestAttendee.objects
            .filter(event_id=event_id, converted_at__isnull=True, lounge_table_id__isnull=False)
            .only("id", "first_name", "last_name", "email", "lounge_table_id")
            .order_by("id")
        )
        guests_by_table = defaultdict(list)
        for guest in guest_rows:
            guests_by_table[guest.lounge_table_id].append(guest)

        state = []
        for t in tables:
            participants = {}
            occupied_seats = set()
            for p in t.participants.all():
                profile = getattr(p.user, "profile", None)
                img = getattr(profile, "user_image", None) if profile else None
                if not img:
                    img = getattr(p.user, "avatar", None) or getattr(profile, "avatar", None) if profile else None
                avatar_url = ""
                if img:
                    try:
                        avatar_url = img.url
                    except Exception:
                        avatar_url = str(img) if img else ""
                participants[str(p.seat_index)] = {
                    "user_id": p.user.id,
                    "username": p.user.username,
                    "full_name": f"{p.user.first_name} {p.user.last_name}".strip() or p.user.username,
                    "avatar_url": avatar_url,
                }
                occupied_seats.add(p.seat_index)

            # Include guests seated at this table.
            next_free_seat = 0
            for guest in guests_by_table.get(t.id, []):
                while next_free_seat in occupied_seats:
                    next_free_seat += 1
                if next_free_seat >= max(t.max_seats, 1):
                    break

                guest_name = f"{guest.first_name} {guest.last_name}".strip() or guest.email
                participants[str(next_free_seat)] = {
                    "user_id": f"guest_{guest.id}",
                    "username": f"guest_{guest.id}",
                    "full_name": guest_name,
                    "avatar_url": "",
                    "is_guest": True,
                }
                occupied_seats.add(next_free_seat)
                next_free_seat += 1
            icon_url = ""
            if getattr(t, "icon", None):
                try:
                    icon_url = t.icon.url
                except Exception:
                    icon_url = ""
            state.append({
                "id": t.id,
                "name": t.name,
                "category": t.category,
                "max_seats": t.max_seats,
                "rtk_meeting_id": t.rtk_meeting_id,
                "icon_url": icon_url,
                "participants": participants
            })
        return state
    except Exception as e:
        logger.warning(f"[LOUNGE_STATE] Failed to build lounge state for event {event_id}: {e}")
        return []


# ============================================================
# ================== Saleor Manager Views ====================
class SessionBreakViewSet(viewsets.ModelViewSet):
    """ViewSet for managing session breaks."""

    serializer_class = SessionBreakSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter breaks by session_id from URL."""
        session_id = self.kwargs.get('session_pk')
        return SessionBreak.objects.filter(session_id=session_id)

    def perform_create(self, serializer):
        """Create break with permission check."""
        session_id = self.kwargs.get('session_pk')
        try:
            session = EventSession.objects.get(id=session_id)
        except EventSession.DoesNotExist:
            raise NotFound("Session not found")

        event = session.event
        if not _is_event_manager(self.request.user, event):
            raise PermissionDenied("Only event creators/staff can add breaks")

        serializer.save(session=session)

    def perform_update(self, serializer):
        """Update break with permission check."""
        break_obj = self.get_object()
        event = break_obj.session.event

        if not _is_event_manager(self.request.user, event):
            raise PermissionDenied("Only event creators/staff can update breaks")

        serializer.save()

    def perform_destroy(self, instance):
        """Delete break with permission check."""
        event = instance.session.event

        if not _is_event_manager(self.request.user, event):
            raise PermissionDenied("Only event creators/staff can delete breaks")

        instance.delete()


# ============================================================

def _is_platform_admin(request):
    """Check if user is platform_admin."""
    claims = getattr(request, "cognito_claims", {}) or {}
    raw_groups = claims.get("cognito:groups") or []
    if isinstance(raw_groups, str):
        groups_set = {g.strip().lower() for g in raw_groups.split(",")}
    else:
        groups_set = {str(g).strip().lower() for g in raw_groups}

    is_platform_admin = "platform_admin" in groups_set
    if not is_platform_admin:
        is_platform_admin = request.user.groups.filter(name="platform_admin").exists()
    if not is_platform_admin:
        is_platform_admin = (request.user.is_staff and request.user.is_superuser)

    return is_platform_admin


def _require_saleor_manager_access(request):
    from django.conf import settings
    if not getattr(settings, "SALEOR_ENABLED", False):
        raise PermissionDenied("Saleor integration is currently disabled.")
    if not _is_platform_admin(request):
        raise PermissionDenied("Only platform_admin can access this endpoint.")
    from users.saleor_connection import get_valid_saleor_token_for_user
    if not get_valid_saleor_token_for_user(request.user, required_permissions=["MANAGE_STAFF"]):
        raise PermissionDenied("Connect Saleor SSO first.")


class SaleorChannelListView(generics.ListAPIView):
    """GET /api/events/saleor/channels/ - List cached Saleor channels."""
    queryset = SaleorChannel.objects.all()
    serializer_class = SaleorChannelSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        _require_saleor_manager_access(request)
        return super().get(request, *args, **kwargs)


class SaleorChannelSyncView(views.APIView):
    """POST /api/events/saleor/channels/sync/ - Sync channels from Saleor API."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_saleor_manager_access(request)

        try:
            synced_ids = sync_channels_from_saleor()
            channels = SaleorChannel.objects.filter(saleor_id__in=synced_ids)
            return Response({
                "channels": SaleorChannelSerializer(channels, many=True).data,
                "count": len(synced_ids)
            })
        except Exception as e:
            return Response({"error": str(e)}, status=500)


class SaleorChannelCreateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_saleor_manager_access(request)
        
        try:
            result = create_channel_in_saleor(request.data)
            
            if "errors" in result and not result.get("data"):
                return Response({"errors": result["errors"]}, status=400)
            
            data = result.get("data", {}).get("channelCreate", {})
            if not data:
                return Response({"error": "No data returned from Saleor"}, status=500)

            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)
            
            ch_node = data.get("channel")
            if not ch_node or not ch_node.get("id"):
                return Response({"error": "Channel created but no ID returned"}, status=500)

            # Sync to update local DB
            sync_channels_from_saleor()
            
            try:
                obj = SaleorChannel.objects.get(saleor_id=ch_node["id"])
                return Response(SaleorChannelSerializer(obj).data, status=201)
            except SaleorChannel.DoesNotExist:
                return Response({"error": "Channel created in Saleor but failed to sync locally"}, status=500)
                
        except Exception as e:
            logger.exception(f"Error in SaleorChannelCreateView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorChannelUpdateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        _require_saleor_manager_access(request)
        
        obj = get_object_or_404(SaleorChannel, pk=pk)
        try:
            result = update_channel_in_saleor(obj.saleor_id, request.data)
            
            if "errors" in result and not result.get("data"):
                return Response({"errors": result["errors"]}, status=400)

            data = result.get("data", {}).get("channelUpdate", {})
            if not data:
                return Response({"error": "No data returned from Saleor"}, status=500)

            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)
            
            # Sync to update local DB
            sync_channels_from_saleor()
            obj.refresh_from_db()
            return Response(SaleorChannelSerializer(obj).data)
        except Exception as e:
            logger.exception(f"Error in SaleorChannelUpdateView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorChannelDeleteView(views.APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        _require_saleor_manager_access(request)

        obj = get_object_or_404(SaleorChannel, pk=pk)
        destination_channel_id = request.data.get("destination_channel_id") if request.data else None
        try:
            result = delete_channel_in_saleor(obj.saleor_id, destination_channel_id)
            data = result.get("data", {}).get("channelDelete", {})
            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)

            obj.delete()
            return Response(status=204)
        except Exception as e:
            return Response({"error": str(e)}, status=500)


class SaleorChannelOptionsView(views.APIView):
    """GET /api/events/saleor/channel-options/ - Return countries, currencies, warehouses, shipping zones for channel creation."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require_saleor_manager_access(request)
        try:
            from .saleor_sync import get_saleor_channel_options
            options = get_saleor_channel_options()
            return Response(options)
        except Exception as e:
            logger.exception(f"Error fetching channel options: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorWarehouseListView(generics.ListAPIView):
    """GET /api/events/saleor/warehouses/ - List cached Saleor warehouses."""
    queryset = SaleorWarehouse.objects.all()
    serializer_class = SaleorWarehouseSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        _require_saleor_manager_access(request)
        return super().get(request, *args, **kwargs)


class SaleorWarehouseSyncView(views.APIView):
    """POST /api/events/saleor/warehouses/sync/ - Sync warehouses from Saleor API."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_saleor_manager_access(request)

        try:
            synced_ids = sync_warehouses_from_saleor()
            warehouses = SaleorWarehouse.objects.filter(saleor_id__in=synced_ids)
            return Response({
                "warehouses": SaleorWarehouseSerializer(warehouses, many=True).data,
                "count": len(synced_ids)
            })
        except Exception as e:
            return Response({"error": str(e)}, status=500)


class SaleorWarehouseOptionsView(views.APIView):
    """GET /api/events/saleor/warehouse-options/ - Return countries and shipping zones for warehouse creation."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require_saleor_manager_access(request)
        try:
            from .saleor_sync import get_warehouse_options
            options = get_warehouse_options()
            return Response(options)
        except Exception as e:
            logger.exception(f"Error fetching warehouse options: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorWarehouseCreateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_saleor_manager_access(request)
        
        try:
            result = create_warehouse_in_saleor(request.data)
            
            if "errors" in result and not result.get("data"):
                return Response({"errors": result["errors"]}, status=400)

            data = result.get("data", {}).get("warehouseCreate", {})
            if not data:
                return Response({"error": "No data returned from Saleor"}, status=500)

            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)
            
            wh_node = data.get("warehouse")
            if not wh_node or not wh_node.get("id"):
                return Response({"error": "Warehouse created but no ID returned"}, status=500)

            # Sync to update local DB
            sync_warehouses_from_saleor()
            
            try:
                obj = SaleorWarehouse.objects.get(saleor_id=wh_node["id"])
                return Response(SaleorWarehouseSerializer(obj).data, status=201)
            except SaleorWarehouse.DoesNotExist:
                return Response({"error": "Warehouse created in Saleor but failed to sync locally"}, status=500)

        except Exception as e:
            logger.exception(f"Error in SaleorWarehouseCreateView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorWarehouseUpdateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        _require_saleor_manager_access(request)

        obj = get_object_or_404(SaleorWarehouse, pk=pk)
        try:
            # Extract shipping zone operations
            add_shipping_zone_ids = request.data.get("add_shipping_zone_ids", [])
            remove_shipping_zone_ids = request.data.get("remove_shipping_zone_ids", [])

            # Prepare update data (exclude shipping zone fields)
            update_data = {k: v for k, v in request.data.items()
                          if k not in ["add_shipping_zone_ids", "remove_shipping_zone_ids"]}

            # Update warehouse
            result = update_warehouse_in_saleor(obj.saleor_id, update_data)

            if "errors" in result and not result.get("data"):
                return Response({"errors": result["errors"]}, status=400)

            data = result.get("data", {}).get("warehouseUpdate", {})
            if not data:
                return Response({"error": "No data returned from Saleor"}, status=500)

            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)

            # Handle shipping zone assignments
            all_errors = []
            if add_shipping_zone_ids:
                try:
                    from .saleor_sync import assign_warehouse_shipping_zones
                    sz_result = assign_warehouse_shipping_zones(obj.saleor_id, add_shipping_zone_ids)
                    sz_data = sz_result.get("data", {}).get("assignWarehouseShippingZone", {})
                    sz_errors = sz_data.get("errors", [])
                    if sz_errors:
                        all_errors.extend(sz_errors)
                except Exception as e:
                    all_errors.append({"message": f"Failed to assign shipping zones: {str(e)}"})

            if remove_shipping_zone_ids:
                try:
                    from .saleor_sync import unassign_warehouse_shipping_zones
                    sz_result = unassign_warehouse_shipping_zones(obj.saleor_id, remove_shipping_zone_ids)
                    sz_data = sz_result.get("data", {}).get("unassignWarehouseShippingZone", {})
                    sz_errors = sz_data.get("errors", [])
                    if sz_errors:
                        all_errors.extend(sz_errors)
                except Exception as e:
                    all_errors.append({"message": f"Failed to unassign shipping zones: {str(e)}"})

            if all_errors:
                return Response({"errors": all_errors}, status=400)

            # Sync to update local DB
            sync_warehouses_from_saleor()
            obj.refresh_from_db()
            return Response(SaleorWarehouseSerializer(obj).data)
        except Exception as e:
            logger.exception(f"Error in SaleorWarehouseUpdateView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorWarehouseDeleteView(views.APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        _require_saleor_manager_access(request)
        
        obj = get_object_or_404(SaleorWarehouse, pk=pk)
        try:
            result = delete_warehouse_in_saleor(obj.saleor_id)
            data = result.get("data", {}).get("warehouseDelete", {})
            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)
            
            obj.delete()
            return Response(status=204)
        except Exception as e:
            return Response({"error": str(e)}, status=500)


class SaleorShippingZoneListView(generics.ListAPIView):
    """GET /api/events/saleor/shipping-zones/ - List cached Saleor shipping zones."""
    queryset = SaleorShippingZone.objects.all()
    serializer_class = SaleorShippingZoneSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        _require_saleor_manager_access(request)
        return super().get(request, *args, **kwargs)


class SaleorShippingZoneSyncView(views.APIView):
    """POST /api/events/saleor/shipping-zones/sync/ - Sync shipping zones from Saleor API."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_saleor_manager_access(request)

        try:
            synced_ids = sync_shipping_zones_from_saleor()
            shipping_zones = SaleorShippingZone.objects.filter(saleor_id__in=synced_ids)
            return Response({
                "shipping_zones": SaleorShippingZoneSerializer(shipping_zones, many=True).data,
                "count": len(synced_ids)
            })
        except Exception as e:
            return Response({"error": str(e)}, status=500)


class SaleorShippingZoneCreateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_saleor_manager_access(request)
        
        try:
            result = create_shipping_zone_in_saleor(request.data)
            
            if "errors" in result and not result.get("data"):
                return Response({"errors": result["errors"]}, status=400)

            data = result.get("data", {}).get("shippingZoneCreate", {})
            if not data:
                return Response({"error": "No data returned from Saleor"}, status=500)

            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)
            
            sz_node = data.get("shippingZone")
            if not sz_node or not sz_node.get("id"):
                return Response({"error": "Shipping zone created but no ID returned"}, status=500)

            # Sync to update local DB
            sync_shipping_zones_from_saleor()
            
            try:
                obj = SaleorShippingZone.objects.get(saleor_id=sz_node["id"])
                return Response(SaleorShippingZoneSerializer(obj).data, status=201)
            except SaleorShippingZone.DoesNotExist:
                return Response({"error": "Shipping zone created in Saleor but failed to sync locally"}, status=500)

        except Exception as e:
            logger.exception(f"Error in SaleorShippingZoneCreateView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorShippingZoneUpdateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        _require_saleor_manager_access(request)
        
        obj = get_object_or_404(SaleorShippingZone, pk=pk)
        try:
            result = update_shipping_zone_in_saleor(obj.saleor_id, request.data)
            
            if "errors" in result and not result.get("data"):
                return Response({"errors": result["errors"]}, status=400)

            data = result.get("data", {}).get("shippingZoneUpdate", {})
            if not data:
                return Response({"error": "No data returned from Saleor"}, status=500)

            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)
            
            # Sync to update local DB
            sync_shipping_zones_from_saleor()
            obj.refresh_from_db()
            return Response(SaleorShippingZoneSerializer(obj).data)
        except Exception as e:
            logger.exception(f"Error in SaleorShippingZoneUpdateView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorShippingZoneDeleteView(views.APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        _require_saleor_manager_access(request)
        
        obj = get_object_or_404(SaleorShippingZone, pk=pk)
        try:
            result = delete_shipping_zone_in_saleor(obj.saleor_id)
            data = result.get("data", {}).get("shippingZoneDelete", {})
            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)
            
            obj.delete()
            return Response(status=204)
        except Exception as e:
            logger.exception(f"Error in SaleorShippingZoneDeleteView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorShippingZoneOptionsView(views.APIView):
    """
    GET /api/events/saleor/shipping-zone-options/
    Returns countries (from Saleor GQL), channels, and warehouses (from local DB)
    for populating the shipping zone create/edit form.
    Only accessible by platform admin / superuser.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require_saleor_manager_access(request)

        try:
            options = get_shipping_zone_options()
            return Response(options)
        except Exception as e:
            logger.exception(f"Error in SaleorShippingZoneOptionsView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorProductTypeListView(generics.ListAPIView):
    """GET /api/events/saleor/product-types/ - List cached Saleor product types."""
    queryset = SaleorProductType.objects.all()
    serializer_class = SaleorProductTypeSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        _require_saleor_manager_access(request)
        return super().get(request, *args, **kwargs)


class SaleorProductTypeSyncView(views.APIView):
    """POST /api/events/saleor/product-types/sync/ - Sync product types from Saleor API."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_saleor_manager_access(request)

        try:
            synced_ids = sync_product_types_from_saleor()
            product_types = SaleorProductType.objects.filter(saleor_id__in=synced_ids)
            return Response({
                "product_types": SaleorProductTypeSerializer(product_types, many=True).data,
                "count": len(synced_ids)
            })
        except Exception as e:
            return Response({"error": str(e)}, status=500)


class SaleorProductTypeCreateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_saleor_manager_access(request)

        try:
            result = create_product_type_in_saleor(request.data)

            if "errors" in result and not result.get("data"):
                return Response({"errors": result["errors"]}, status=400)

            data = result.get("data", {}).get("productTypeCreate", {})
            if not data:
                return Response({"error": "No data returned from Saleor"}, status=500)

            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)

            pt_node = data.get("productType")
            if not pt_node or not pt_node.get("id"):
                return Response({"error": "Product type created but no ID returned"}, status=500)

            sync_product_types_from_saleor()

            try:
                obj = SaleorProductType.objects.get(saleor_id=pt_node["id"])
                return Response(SaleorProductTypeSerializer(obj).data, status=201)
            except SaleorProductType.DoesNotExist:
                return Response({"error": "Product type created in Saleor but failed to sync locally"}, status=500)

        except Exception as e:
            logger.exception(f"Error in SaleorProductTypeCreateView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorProductTypeUpdateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        _require_saleor_manager_access(request)

        obj = get_object_or_404(SaleorProductType, pk=pk)
        try:
            result = update_product_type_in_saleor(obj.saleor_id, request.data)

            if "errors" in result and not result.get("data"):
                return Response({"errors": result["errors"]}, status=400)

            data = result.get("data", {}).get("productTypeUpdate", {})
            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)

            sync_product_types_from_saleor()

            obj.refresh_from_db()
            return Response(SaleorProductTypeSerializer(obj).data)
        except Exception as e:
            logger.exception(f"Error in SaleorProductTypeUpdateView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorProductTypeDeleteView(views.APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        _require_saleor_manager_access(request)

        obj = get_object_or_404(SaleorProductType, pk=pk)
        try:
            result = delete_product_type_in_saleor(obj.saleor_id)

            if "errors" in result and not result.get("data"):
                return Response({"errors": result["errors"]}, status=400)

            data = result.get("data", {}).get("productTypeDelete", {})
            errors = data.get("errors", [])
            if errors:
                return Response({"errors": errors}, status=400)

            obj.delete()
            return Response(status=204)
        except Exception as e:
            logger.exception(f"Error in SaleorProductTypeDeleteView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorProductTypeOptionsView(views.APIView):
    """GET /api/events/saleor/product-type-options/ - Get tax classes and product type kinds."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require_saleor_manager_access(request)

        try:
            options = get_product_type_options()
            return Response(options)
        except Exception as e:
            logger.exception(f"Error in SaleorProductTypeOptionsView: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorStaffUserListView(generics.ListAPIView):
    """GET /api/events/saleor/staff-users/ - List cached Saleor staff users."""
    queryset = SaleorStaffUser.objects.all()
    serializer_class = SaleorStaffUserSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        _require_saleor_manager_access(request)
        return super().get(request, *args, **kwargs)


class SaleorStaffUserSyncView(views.APIView):
    """POST /api/events/saleor/staff-users/sync/ - Sync staff users from Saleor API."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_saleor_manager_access(request)

        try:
            synced_ids = sync_staff_users_from_saleor()
            staff_users = SaleorStaffUser.objects.filter(saleor_id__in=synced_ids)
            return Response({
                "staff_users": SaleorStaffUserSerializer(staff_users, many=True).data,
                "count": len(synced_ids)
            })
        except Exception as e:
            return Response({"error": str(e)}, status=500)


class SaleorStaffUserActiveView(views.APIView):
    """PATCH /api/events/saleor/staff-users/<id>/active/ - Activate/deactivate a Saleor staff user."""
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        _require_saleor_manager_access(request)
        obj = get_object_or_404(SaleorStaffUser, pk=pk)
        is_active = request.data.get("is_active")
        if not isinstance(is_active, bool):
            return Response({"detail": "Provide boolean is_active."}, status=400)

        from users.saleor_connection import get_valid_saleor_token_for_user
        saleor_token = get_valid_saleor_token_for_user(request.user, required_permissions=["MANAGE_STAFF"])
        if not saleor_token:
            raise PermissionDenied("Connect Saleor SSO first.")

        mutation = """
        mutation StaffUpdateActive($id: ID!, $input: StaffUpdateInput!) {
          staffUpdate(id: $id, input: $input) {
            user {
              id
              firstName
              lastName
              email
              isStaff
              isActive
              userPermissions {
                code
              }
              metadata {
                key
                value
              }
            }
            errors {
              field
              code
              message
            }
          }
        }
        """
        try:
            response = requests.post(
                settings.SALEOR_API_URL,
                json={"query": mutation, "variables": {"id": obj.saleor_id, "input": {"isActive": is_active}}},
                headers={"Authorization": f"Bearer {saleor_token}", "Content-Type": "application/json"},
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
            if data.get("errors"):
                return Response({"errors": data["errors"]}, status=400)

            payload = (data.get("data") or {}).get("staffUpdate") or {}
            if payload.get("errors"):
                return Response({"errors": payload["errors"]}, status=400)

            user_data = payload.get("user") or {}
            if not user_data:
                return Response({"detail": "Saleor did not return updated staff user."}, status=502)

            obj.first_name = user_data.get("firstName") or ""
            obj.last_name = user_data.get("lastName") or ""
            obj.email = user_data.get("email") or obj.email
            obj.is_staff = user_data.get("isStaff", obj.is_staff)
            obj.is_active = user_data.get("isActive", is_active)
            obj.permissions = [p["code"] for p in user_data.get("userPermissions", []) if p.get("code")]
            obj.metadata = {m["key"]: m["value"] for m in user_data.get("metadata", [])}
            obj.save()
            return Response(SaleorStaffUserSerializer(obj).data)
        except Exception as e:
            logger.exception(f"Error updating Saleor staff user active status: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorStaffUserPermissionGroupsView(views.APIView):
    """GET/PATCH /api/events/saleor/staff-users/<id>/permission-groups/."""
    permission_classes = [IsAuthenticated]

    def _saleor_token(self, request):
        from users.saleor_connection import get_valid_saleor_token_for_user
        saleor_token = get_valid_saleor_token_for_user(request.user, required_permissions=["MANAGE_STAFF"])
        if not saleor_token:
            raise PermissionDenied("Connect Saleor SSO first.")
        return saleor_token

    def _fetch_staff_groups(self, saleor_user_id, saleor_token):
        query = """
        query StaffPermissionGroups($id: ID!) {
          user(id: $id) {
            id
            isActive
            userPermissions {
              code
            }
            permissionGroups {
              id
              name
              permissions {
                code
              }
            }
          }
        }
        """
        response = requests.post(
            settings.SALEOR_API_URL,
            json={"query": query, "variables": {"id": saleor_user_id}},
            headers={"Authorization": f"Bearer {saleor_token}", "Content-Type": "application/json"},
            timeout=20,
        )
        if response.status_code >= 400:
            raise ValueError(response.text)
        data = response.json()
        if data.get("errors"):
            raise ValueError(data["errors"])
        user_data = (data.get("data") or {}).get("user")
        if not user_data:
            raise ValueError("Saleor staff user was not found.")
        return user_data

    def get(self, request, pk):
        _require_saleor_manager_access(request)
        obj = get_object_or_404(SaleorStaffUser, pk=pk)
        saleor_token = self._saleor_token(request)

        try:
            user_data = self._fetch_staff_groups(obj.saleor_id, saleor_token)
            groups = user_data.get("permissionGroups") or []
            selected_ids = [group["id"] for group in groups]
            obj.is_active = user_data.get("isActive", obj.is_active)
            obj.permissions = [p["code"] for p in user_data.get("userPermissions", []) if p.get("code")]
            obj.metadata = {
                **(obj.metadata or {}),
                "permission_group_ids": selected_ids,
                "permission_group_names": [group.get("name", "") for group in groups],
            }
            obj.save()
            return Response(
                {
                    "staff_user": SaleorStaffUserSerializer(obj).data,
                    "selected_saleor_group_ids": selected_ids,
                    "available_groups": SaleorPermissionGroupSerializer(SaleorPermissionGroup.objects.all(), many=True).data,
                }
            )
        except Exception as e:
            logger.exception(f"Error fetching Saleor staff user permission groups: {e}")
            return Response({"error": str(e)}, status=500)

    def patch(self, request, pk):
        _require_saleor_manager_access(request)
        obj = get_object_or_404(SaleorStaffUser, pk=pk)
        if not obj.is_active:
            return Response({"detail": "Activate this staff user before managing permissions."}, status=400)

        selected_ids = request.data.get("saleor_group_ids")
        if not isinstance(selected_ids, list):
            return Response({"detail": "Provide saleor_group_ids as a list."}, status=400)

        allowed_ids = set(SaleorPermissionGroup.objects.values_list("saleor_id", flat=True))
        selected_ids = [str(group_id) for group_id in selected_ids if str(group_id) in allowed_ids]
        saleor_token = self._saleor_token(request)

        mutation = """
        mutation StaffUpdateGroups($id: ID!, $input: StaffUpdateInput!) {
          staffUpdate(id: $id, input: $input) {
            user {
              id
              firstName
              lastName
              email
              isStaff
              isActive
              userPermissions {
                code
              }
              permissionGroups {
                id
                name
              }
              metadata {
                key
                value
              }
            }
            errors {
              field
              code
              message
            }
          }
        }
        """
        try:
            user_data = self._fetch_staff_groups(obj.saleor_id, saleor_token)
            current_ids = {group["id"] for group in user_data.get("permissionGroups") or []}
            selected_id_set = set(selected_ids)
            input_payload = {
                "addGroups": sorted(selected_id_set - current_ids),
                "removeGroups": sorted(current_ids - selected_id_set),
            }
            response = requests.post(
                settings.SALEOR_API_URL,
                json={"query": mutation, "variables": {"id": obj.saleor_id, "input": input_payload}},
                headers={"Authorization": f"Bearer {saleor_token}", "Content-Type": "application/json"},
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
            if data.get("errors"):
                return Response({"errors": data["errors"]}, status=400)

            payload = (data.get("data") or {}).get("staffUpdate") or {}
            if payload.get("errors"):
                return Response({"errors": payload["errors"]}, status=400)

            updated = payload.get("user") or {}
            groups = updated.get("permissionGroups") or []
            obj.first_name = updated.get("firstName") or ""
            obj.last_name = updated.get("lastName") or ""
            obj.email = updated.get("email") or obj.email
            obj.is_staff = updated.get("isStaff", obj.is_staff)
            obj.is_active = updated.get("isActive", obj.is_active)
            obj.permissions = [p["code"] for p in updated.get("userPermissions", []) if p.get("code")]
            obj.metadata = {
                **(obj.metadata or {}),
                "permission_group_ids": [group["id"] for group in groups],
                "permission_group_names": [group.get("name", "") for group in groups],
            }
            obj.save()
            return Response(
                {
                    "staff_user": SaleorStaffUserSerializer(obj).data,
                    "selected_saleor_group_ids": [group["id"] for group in groups],
                }
            )
        except Exception as e:
            logger.exception(f"Error updating Saleor staff user permission groups: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorPermissionGroupListView(generics.ListAPIView):
    """GET /api/events/saleor/permission-groups/ - List cached Saleor permission groups."""
    queryset = SaleorPermissionGroup.objects.all()
    serializer_class = SaleorPermissionGroupSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        _require_saleor_manager_access(request)
        return super().get(request, *args, **kwargs)


class SaleorPermissionGroupSyncView(views.APIView):
    """POST /api/events/saleor/permission-groups/sync/ - Sync permission groups from Saleor API."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_saleor_manager_access(request)

        try:
            synced_ids = sync_permission_groups_from_saleor()
            permission_groups = SaleorPermissionGroup.objects.filter(saleor_id__in=synced_ids)
            return Response({
                "permission_groups": SaleorPermissionGroupSerializer(permission_groups, many=True).data,
                "count": len(synced_ids)
            })
        except Exception as e:
            return Response({"error": str(e)}, status=500)


class SaleorPermissionGroupCreateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require_saleor_manager_access(request)
        name = (request.data.get("name") or "").strip()
        permissions = request.data.get("permissions") or []
        if not name:
            return Response({"detail": "Name is required."}, status=400)
        if not isinstance(permissions, list):
            return Response({"detail": "Permissions must be a list."}, status=400)

        from users.saleor_connection import get_valid_saleor_token_for_user
        saleor_token = get_valid_saleor_token_for_user(request.user, required_permissions=["MANAGE_STAFF"])
        mutation = """
        mutation PermissionGroupCreate($input: PermissionGroupCreateInput!) {
          permissionGroupCreate(input: $input) {
            group {
              id
              name
              permissions { code }
              users { id }
            }
            errors { field code message permissions users channels }
          }
        }
        """
        try:
            response = requests.post(
                settings.SALEOR_API_URL,
                json={"query": mutation, "variables": {"input": {"name": name, "addPermissions": permissions}}},
                headers={"Authorization": f"Bearer {saleor_token}", "Content-Type": "application/json"},
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
            if data.get("errors"):
                return Response({"errors": data["errors"]}, status=400)
            payload = (data.get("data") or {}).get("permissionGroupCreate") or {}
            if payload.get("errors"):
                return Response({"errors": payload["errors"]}, status=400)
            group = payload.get("group") or {}
            obj, _ = SaleorPermissionGroup.objects.update_or_create(
                saleor_id=group["id"],
                defaults={
                    "name": group.get("name", ""),
                    "permissions": [p["code"] for p in group.get("permissions", [])],
                    "user_count": len(group.get("users", [])),
                    "metadata": {},
                },
            )
            return Response(SaleorPermissionGroupSerializer(obj).data, status=201)
        except Exception as e:
            logger.exception(f"Error creating Saleor permission group: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorPermissionGroupUpdateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        _require_saleor_manager_access(request)
        obj = get_object_or_404(SaleorPermissionGroup, pk=pk)
        name = (request.data.get("name") or "").strip()
        permissions = request.data.get("permissions") or []
        if not name:
            return Response({"detail": "Name is required."}, status=400)
        if not isinstance(permissions, list):
            return Response({"detail": "Permissions must be a list."}, status=400)

        from users.saleor_connection import get_valid_saleor_token_for_user
        saleor_token = get_valid_saleor_token_for_user(request.user, required_permissions=["MANAGE_STAFF"])
        current = set(obj.permissions or [])
        requested = set(str(p) for p in permissions)
        mutation = """
        mutation PermissionGroupUpdate($id: ID!, $input: PermissionGroupUpdateInput!) {
          permissionGroupUpdate(id: $id, input: $input) {
            group {
              id
              name
              permissions { code }
              users { id }
            }
            errors { field code message permissions users channels }
          }
        }
        """
        input_payload = {
            "name": name,
            "addPermissions": sorted(requested - current),
            "removePermissions": sorted(current - requested),
        }
        try:
            response = requests.post(
                settings.SALEOR_API_URL,
                json={"query": mutation, "variables": {"id": obj.saleor_id, "input": input_payload}},
                headers={"Authorization": f"Bearer {saleor_token}", "Content-Type": "application/json"},
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
            if data.get("errors"):
                return Response({"errors": data["errors"]}, status=400)
            payload = (data.get("data") or {}).get("permissionGroupUpdate") or {}
            if payload.get("errors"):
                return Response({"errors": payload["errors"]}, status=400)
            group = payload.get("group") or {}
            obj.name = group.get("name", obj.name)
            obj.permissions = [p["code"] for p in group.get("permissions", [])]
            obj.user_count = len(group.get("users", []))
            obj.save()
            return Response(SaleorPermissionGroupSerializer(obj).data)
        except Exception as e:
            logger.exception(f"Error updating Saleor permission group: {e}")
            return Response({"error": str(e)}, status=500)


class SaleorPermissionGroupDeleteView(views.APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        _require_saleor_manager_access(request)
        obj = get_object_or_404(SaleorPermissionGroup, pk=pk)
        from users.saleor_connection import get_valid_saleor_token_for_user
        saleor_token = get_valid_saleor_token_for_user(request.user, required_permissions=["MANAGE_STAFF"])
        mutation = """
        mutation PermissionGroupDelete($id: ID!) {
          permissionGroupDelete(id: $id) {
            group { id name }
            errors { field code message permissions users channels }
          }
        }
        """
        try:
            response = requests.post(
                settings.SALEOR_API_URL,
                json={"query": mutation, "variables": {"id": obj.saleor_id}},
                headers={"Authorization": f"Bearer {saleor_token}", "Content-Type": "application/json"},
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
            if data.get("errors"):
                return Response({"errors": data["errors"]}, status=400)
            payload = (data.get("data") or {}).get("permissionGroupDelete") or {}
            if payload.get("errors"):
                return Response({"errors": payload["errors"]}, status=400)
            obj.delete()
            return Response(status=204)
        except Exception as e:
            logger.exception(f"Error deleting Saleor permission group: {e}")
            return Response({"error": str(e)}, status=500)


# WebinarSeries ViewSet

def _series_child_admission_status(event):
    return "waiting" if event.waiting_room_enabled else "admitted"


def _restore_cancelled_origin(origin):
    origin.status = 'active'
    if origin.accepted_tier and origin.accepted_tier.price and origin.accepted_tier.price > 0:
        origin.origin_status = 'payment_pending'
    else:
        origin.origin_status = 'confirmed'
    origin.save(update_fields=['status', 'origin_status'])


def _sync_series_child_event_registrations(series, user):
    for event in series.child_events.all():
        registration, created = EventRegistration.objects.get_or_create(
            event=event,
            user=user,
            defaults={
                'status': 'registered',
                'attendee_status': 'confirmed',
                'admission_status': _series_child_admission_status(event),
            }
        )

        if not created and registration.status in ['cancelled', 'deregistered']:
            registration.status = 'registered'
            registration.attendee_status = 'confirmed'
            registration.admission_status = _series_child_admission_status(event)
            registration.is_online = False
            registration.save(update_fields=['status', 'attendee_status', 'admission_status', 'is_online'])

            for origin in registration.origins.filter(status='cancelled'):
                _restore_cancelled_origin(origin)

            if registration.origins.filter(status='active').exists():
                from events.services.attendee_directory import _recalculate_registration_status
                _recalculate_registration_status(registration)

        if not registration.badge_labels.exists():
            participant_badge = event.get_or_create_participant_badge()
            registration.badge_labels.add(participant_badge)

        _recalculate_event_attending_count(event.id)


def _cancel_full_series_child_event_registrations(series, user):
    registrations = (
        EventRegistration.objects
        .filter(
            event__series=series,
            user=user,
            status__in=['registered', 'cancellation_requested'],
        )
        .select_related('event')
        .prefetch_related('origins')
    )

    for registration in registrations:
        registration.status = 'cancelled'
        registration.attendee_status = 'cancelled'
        registration.admission_status = _series_child_admission_status(registration.event)
        registration.joined_live = False
        registration.is_online = False
        registration.save(update_fields=[
            'status',
            'attendee_status',
            'admission_status',
            'joined_live',
            'is_online',
        ])

        registration.origins.filter(status='active').update(
            status='cancelled',
            origin_status='cancelled'
        )

        _recalculate_event_attending_count(registration.event_id)


class SeriesViewSet(viewsets.ModelViewSet):
    permission_classes = [IsCreatorOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['status', 'visibility', 'community']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'updated_at', '-created_at']
    ordering = ['-created_at']
    lookup_field = 'pk'

    def get_queryset(self):
        user = self.request.user
        request_action = self.action
        
        if request_action == 'public_detail':
            return EventSeries.objects.filter(status='published', visibility='public')
        
        if not user.is_authenticated:
            return EventSeries.objects.filter(status='published', visibility='public')
        
        if user.is_superuser:
            return EventSeries.objects.all()
        
        return EventSeries.objects.filter(
            Q(status='published', visibility='public') |
            Q(created_by=user) |
            Q(community__in=user.community.all())
        ).distinct()

    def get_serializer_class(self):
        if self.action == 'create' or self.action == 'update' or self.action == 'partial_update':
            return EventSeriesCreateUpdateSerializer
        elif self.action == 'retrieve':
            return EventSeriesDetailSerializer
        elif self.action == 'public_detail':
            return PublicEventSeriesSerializer
        else:
            return EventSeriesListSerializer

    def get_permissions(self):
        if self.action in ['list', 'retrieve', 'public_detail']:
            return [AllowAny()]
        if self.action in ['registrations', 'analytics']:
            return [IsAuthenticated()]
        return super().get_permissions()

    def perform_create(self, serializer):
        org = serializer.validated_data.get('community')
        if not org:
            raise PermissionDenied("community_id is required.")
        if not self.request.user.community.filter(id=org.id).exists():
            raise PermissionDenied("You must be a member of the community to create series.")
        initial_status = 'published' if serializer.validated_data.get('is_free', True) else 'draft'
        serializer.save(
            created_by=self.request.user,
            status=initial_status
        )

    def perform_update(self, serializer):
        if not self._is_owner(self.get_object()):
            raise PermissionDenied("Only the series creator or superuser can update this series.")
        serializer.save()

    def perform_destroy(self, instance):
        if not self._is_owner(instance):
            raise PermissionDenied("Only the series creator or superuser can delete this series.")

        with transaction.atomic():
            instance.child_events.update(
                series=None,
                series_order=None,
                series_session_label=''
            )
            instance.delete()

    def _is_owner(self, obj):
        return bool(
            self.request.user
            and (
                obj.created_by_id == self.request.user.id
                or getattr(self.request.user, 'is_superuser', False)
            )
        )

    @action(detail=True, methods=['post'])
    def publish(self, request, pk=None):
        series = self.get_object()
        if not self._is_owner(series):
            raise PermissionDenied("Only the series creator can publish this series.")
        
        if series.child_events.count() < 1:
            return Response(
                {'error': 'Series must have at least one event to publish.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        series.status = 'published'
        series.save()
        serializer = self.get_serializer(series)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def archive(self, request, pk=None):
        series = self.get_object()
        if not self._is_owner(series):
            raise PermissionDenied("Only the series creator can archive this series.")
        
        series.status = 'archived'
        series.save()
        serializer = self.get_serializer(series)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'])
    def registrations(self, request, pk=None):
        series = self.get_object()
        if not self._is_owner(series):
            raise PermissionDenied("Only the series creator can view registrations.")
        
        registrations = series.series_registrations.all().order_by('-registered_at')
        
        page = self.paginate_queryset(registrations)
        if page is not None:
            serializer = SeriesRegistrationSerializer(page, many=True, context={'request': request})
            return self.get_paginated_response(serializer.data)
        
        serializer = SeriesRegistrationSerializer(registrations, many=True, context={'request': request})
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def analytics(self, request, pk=None):
        series = self.get_object()
        if not self._is_owner(series):
            raise PermissionDenied("Only the series creator can view analytics.")
        
        from django.db.models import Count
        from events.models import EventRegistration
        
        total_registrations = series.series_registrations.filter(status='registered').count()
        child_events = series.child_events.all()
        
        event_attendance = []
        for event in child_events:
            attended = event.registrations.filter(joined_live=True).count()
            registered = event.registrations.filter(status='registered').count()
            event_attendance.append({
                'event_id': event.id,
                'event_title': event.title,
                'registered': registered,
                'attended': attended,
                'attendance_rate': (attended / registered * 100) if registered > 0 else 0
            })
        
        return Response({
            'total_registrations': total_registrations,
            'total_events': child_events.count(),
            'event_attendance': event_attendance
        })

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def register(self, request, pk=None):
        series = self.get_object()
        if series.status != 'published':
            return Response(
                {'error': 'Cannot register for unpublished series.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required to register.'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        with transaction.atomic():
            registration, created = SeriesRegistration.objects.get_or_create(
                series=series,
                user=request.user,
                defaults={'status': 'registered'}
            )
            
            if not created and registration.status == 'cancelled':
                registration.status = 'registered'
                registration.save(update_fields=['status'])
            
            # Preserve existing behavior: series registration grants access to
            # all child events. Re-registering must reactivate cancelled rows.
            _sync_series_child_event_registrations(series, request.user)
        
        serializer = SeriesRegistrationSerializer(registration, context={'request': request})
        return Response(serializer.data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def unregister(self, request, pk=None):
        series = self.get_object()
        
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Authentication required.'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            with transaction.atomic():
                registration = SeriesRegistration.objects.get(series=series, user=request.user)
                registration.status = 'cancelled'
                registration.save(update_fields=['status'])

                # Only full-series mode should cascade to child events. Other
                # modes can contain independently registered event sessions.
                if series.registration_mode == 'full_series_only':
                    _cancel_full_series_child_event_registrations(series, request.user)

            return Response({'message': 'Successfully unregistered from series.'}, status=status.HTTP_200_OK)
        except SeriesRegistration.DoesNotExist:
            return Response(
                {'error': 'Not registered for this series.'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=False, methods=['get'], url_path=r'public/(?P<slug>[-\w]+)')
    def public_detail(self, request, slug=None):
        try:
            series = EventSeries.objects.get(slug=slug, status='published', visibility='public')
            serializer = PublicEventSeriesSerializer(series, context={'request': request})
            return Response(serializer.data)
        except EventSeries.DoesNotExist:
            return Response(
                {'error': 'Series not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=True, methods=['post', 'patch', 'delete'], url_path=r'events(?:/(?P<event_id>\d+))?')
    def events(self, request, pk=None, event_id=None):
        """Add, update, or remove events in a series"""
        series = self.get_object()

        # Check permission - only creator can manage events
        if not self._is_owner(series):
            return Response(
                {'detail': 'You do not have permission to manage events in this series.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # GET, POST for adding events or LIST of events
        if request.method == 'POST':
            event_id = request.data.get('event_id')
            series_order = request.data.get('series_order')
            series_session_label = request.data.get('series_session_label', '')

            if not event_id:
                return Response(
                    {'error': 'event_id is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                event = Event.objects.get(id=event_id)

                # Validate event status: only 'published' or 'live' events can be added
                if event.status not in ['published', 'live']:
                    return Response(
                        {'error': 'Only published or live events can be added to a series.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Validate event has not ended: if not 'live', check end_time
                now = timezone.now()
                if event.status != 'live' and event.end_time and event.end_time < now:
                    return Response(
                        {'error': 'Ended events cannot be added to a series.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                event.series = series
                event.series_order = series_order
                event.series_session_label = series_session_label
                event.save()

                return Response(
                    {'success': True, 'message': 'Event added to series'},
                    status=status.HTTP_201_CREATED
                )
            except Event.DoesNotExist:
                return Response(
                    {'error': 'Event not found'},
                    status=status.HTTP_404_NOT_FOUND
                )

        # PATCH - Update event in series
        elif request.method == 'PATCH':
            if not event_id:
                return Response(
                    {'error': 'event_id is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                event = Event.objects.get(id=event_id, series=series)

                # Update series_order if provided
                if 'series_order' in request.data:
                    event.series_order = request.data.get('series_order')

                # Update series_session_label if provided
                if 'series_session_label' in request.data:
                    event.series_session_label = request.data.get('series_session_label')

                event.save()

                return Response(
                    {'success': True, 'message': 'Event updated in series'},
                    status=status.HTTP_200_OK
                )
            except Event.DoesNotExist:
                return Response(
                    {'error': 'Event not found in this series'},
                    status=status.HTTP_404_NOT_FOUND
                )

        # DELETE - Remove event from series
        elif request.method == 'DELETE':
            if not event_id:
                return Response(
                    {'error': 'event_id is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                event = Event.objects.get(id=event_id, series=series)
                event.series = None
                event.series_order = None
                event.series_session_label = ''
                event.save()

                return Response(
                    {'success': True, 'message': 'Event removed from series'},
                    status=status.HTTP_200_OK
                )
            except Event.DoesNotExist:
                return Response(
                    {'error': 'Event not found in this series'},
                    status=status.HTTP_404_NOT_FOUND
                )


class EventScheduleView(views.APIView):
    """
    GET /api/events/{event_id}/schedule/

    Returns conference schedule grouped by day with speaker info and bookmark status.
    Requires authentication.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, event_id):
        event = get_object_or_404(Event, id=event_id)

        # Get all sessions ordered by date and start time
        sessions = EventSession.objects.filter(event=event).order_by('session_date', 'start_time')

        # Group by date
        grouped = {}
        for session in sessions:
            date_key = session.session_date.isoformat() if session.session_date else 'No Date'
            if date_key not in grouped:
                grouped[date_key] = []
            grouped[date_key].append(session)

        # Build response
        days = []
        for idx, (date_str, session_list) in enumerate(sorted(grouped.items())):
            if date_str == 'No Date':
                day_label = 'TBD'
            else:
                from datetime import datetime
                day_obj = datetime.fromisoformat(date_str)
                day_label = f"Day {idx + 1}"

            serializer = ScheduleSessionSerializer(session_list, many=True, context={'request': request})
            days.append({
                'date': date_str,
                'label': day_label,
                'sessions': serializer.data
            })

        return Response({'days': days})


class SessionBookmarkToggleView(views.APIView):
    """
    POST /api/events/{event_id}/schedule/{session_id}/bookmark/ - Create bookmark
    DELETE /api/events/{event_id}/schedule/{session_id}/bookmark/ - Remove bookmark

    Allows users to bookmark/save sessions they want to attend.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, event_id, session_id):
        event = get_object_or_404(Event, id=event_id)
        session = get_object_or_404(EventSession, id=session_id, event=event)

        bookmark, created = EventSessionBookmark.objects.get_or_create(
            event=event,
            user=request.user,
            session=session
        )

        return Response(
            {'bookmarked': True, 'bookmark_id': bookmark.id},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
        )

    def delete(self, request, event_id, session_id):
        event = get_object_or_404(Event, id=event_id)
        session = get_object_or_404(EventSession, id=session_id, event=event)

        deleted_count, _ = EventSessionBookmark.objects.filter(
            event=event,
            user=request.user,
            session=session
        ).delete()

        if deleted_count == 0:
            return Response(
                {'detail': 'Bookmark not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        return Response({'bookmarked': False}, status=status.HTTP_204_NO_CONTENT)


class PostAcceptanceFormAssignmentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for post-acceptance form assignments.

    Endpoints:
    - GET /api/events/{event_id}/post-acceptance-form-assignments/
      List all assignments for an event (admin only)
    - GET /api/post-acceptance-form-assignments/my/
      List current user's form assignments
    - GET /api/post-acceptance-form-assignments/{id}/
      Retrieve single assignment
    - POST /api/post-acceptance-form-assignments/{id}/start/
      Mark form as in-progress
    - POST /api/post-acceptance-form-assignments/{id}/submit/
      Submit form with answers
    """
    serializer_class = PostAcceptanceFormAssignmentSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['event', 'form_type', 'status']
    ordering_fields = ['-created_at', 'deadline']
    ordering = ['-created_at']

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated:
            return PostAcceptanceFormAssignment.objects.filter(
                event_registration__user=user
            )
        return PostAcceptanceFormAssignment.objects.none()

    @action(detail=False, methods=['get'], url_path='my')
    def my_assignments(self, request):
        """List current user's form assignments."""
        assignments = self.get_queryset().select_related(
            'event', 'form_template', 'event_registration'
        )
        serializer = self.get_serializer(assignments, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='start')
    def start_form(self, request, pk=None):
        """Mark form assignment as in-progress."""
        assignment = self.get_object()

        if assignment.event_registration.user != request.user:
            raise PermissionDenied("You can only start your own forms")

        if assignment.status != PostAcceptanceFormAssignment.STATUS_NOT_STARTED:
            return Response(
                {'error': f'Cannot start form with status {assignment.get_status_display()}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        from events.services import mark_assignment_in_progress
        mark_assignment_in_progress(assignment)

        return Response(
            PostAcceptanceFormAssignmentSerializer(assignment).data,
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['post'], url_path='save-draft')
    def save_draft(self, request, pk=None):
        """Save draft form answers without submitting."""
        assignment = self.get_object()

        if assignment.event_registration.user != request.user:
            raise PermissionDenied("You can only save drafts for your own forms")

        answers_data = request.data.get('answers', {})

        with transaction.atomic():
            from events.models import PostAcceptanceFormDraft

            draft, created = PostAcceptanceFormDraft.objects.get_or_create(
                assignment=assignment
            )
            draft.draft_data = answers_data
            draft.save()

            if assignment.status == PostAcceptanceFormAssignment.STATUS_NOT_STARTED:
                from events.services import mark_assignment_in_progress
                mark_assignment_in_progress(assignment)

        return Response(
            {'detail': 'Draft saved successfully'},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['post'], url_path='submit')
    def submit_form(self, request, pk=None):
        """Submit form with answers and strict validation."""
        assignment = self.get_object()

        if assignment.event_registration.user != request.user:
            raise PermissionDenied("You can only submit your own forms")

        # FIX 9: Allow edits to completed forms if within editable_until deadline
        from django.utils import timezone as dj_timezone
        can_edit_completed = False
        if assignment.status == PostAcceptanceFormAssignment.STATUS_COMPLETED:
            if hasattr(assignment, 'editable_until') and assignment.editable_until:
                if dj_timezone.now() <= assignment.editable_until:
                    can_edit_completed = True
            else:
                # Fallback: allow edit if before event start
                event = assignment.event
                if event.start_time and dj_timezone.now() <= event.start_time:
                    can_edit_completed = True

        if assignment.status not in [
            PostAcceptanceFormAssignment.STATUS_NOT_STARTED,
            PostAcceptanceFormAssignment.STATUS_IN_PROGRESS,
        ] and not can_edit_completed:
            return Response(
                {'error': f'Cannot submit form with status {assignment.get_status_display()}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Handle both JSON and multipart FormData submissions
        # For FormData, answers come as answers.fieldname or just fieldname with files in request.FILES
        answers_data = {}

        if request.content_type and 'multipart/form-data' in request.content_type:
            # Parse multipart FormData: answers.fieldname or direct fields
            for key, value in request.data.items():
                if key.startswith('answers.'):
                    # answers.fieldname format
                    field_name = key[8:]  # Remove 'answers.' prefix
                    answers_data[field_name] = value
                elif key not in ['answers']:
                    # Direct field format (could be file or data)
                    answers_data[key] = value

            # Also check request.FILES for uploaded files
            for file_key, file_obj in request.FILES.items():
                if file_key.startswith('answers.'):
                    field_name = file_key[8:]
                    answers_data[field_name] = file_obj
                else:
                    answers_data[file_key] = file_obj
        else:
            # JSON format
            answers_data = request.data.get('answers', {})

        # Validate required fields
        validation_errors = self._validate_form_submission(assignment, answers_data)
        if validation_errors:
            return Response(validation_errors, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            from events.services import mark_assignment_completed
            from events.models import PostAcceptanceFormSubmission, PostAcceptanceFormAnswer, PostAcceptanceFormAnswerFile
            from django.core.files.uploadedfile import UploadedFile

            submission, created = PostAcceptanceFormSubmission.objects.get_or_create(
                assignment=assignment
            )

            for question_key, answer_value in answers_data.items():
                # FIX 5: Do NOT store files in answer_value here
                # Files are handled separately via request.FILES below
                if isinstance(answer_value, UploadedFile):
                    # Skip file uploads in this loop - they'll be handled in request.FILES section
                    continue
                else:
                    # Standard text/data handling
                    # Parse JSON strings (from FormData multi-select arrays)
                    parsed_value = answer_value
                    if isinstance(answer_value, str) and answer_value.startswith('['):
                        try:
                            import json
                            parsed_value = json.loads(answer_value)
                        except (json.JSONDecodeError, ValueError):
                            # If not valid JSON, treat as string
                            parsed_value = answer_value

                    defaults = {
                        'answer_text': str(parsed_value) if isinstance(parsed_value, (str, int, float)) else '',
                        'answer_data': parsed_value if isinstance(parsed_value, (list, dict)) else {},
                        'form_type': assignment.form_type  # FIX 11: Save form_type
                    }
                    PostAcceptanceFormAnswer.objects.update_or_create(
                        submission=submission,
                        question_key=question_key,
                        form_type=assignment.form_type,  # FIX 11: Include in lookup
                        defaults=defaults
                    )

            # Handle multiple files per question (for deliverables, founder_photos, etc.)
            for file_key in request.FILES.keys():
                # Parse question_key from file_key (e.g., "answers.deliverables" or "deliverables")
                question_key = file_key.replace('answers.', '') if file_key.startswith('answers.') else file_key

                # Get all files for this key (handles multiple uploads)
                file_list = request.FILES.getlist(file_key)

                # Get or create answer for this question (FIX 11: Include form_type)
                answer, _ = PostAcceptanceFormAnswer.objects.get_or_create(
                    submission=submission,
                    question_key=question_key,
                    form_type=assignment.form_type,  # FIX 11: Include in lookup
                    defaults={'answer_text': '', 'answer_data': {}, 'form_type': assignment.form_type}
                )

                # Save each file to PostAcceptanceFormAnswerFile
                for idx, file_obj in enumerate(file_list):
                    PostAcceptanceFormAnswerFile.objects.create(
                        answer=answer,
                        file=file_obj,
                        file_order=idx
                    )

            mark_assignment_completed(assignment)

            # Write back form data based on form type
            if assignment.form_type == 'participant_information':
                from events.services import writeback_participant_information_form
                writeback_participant_information_form(assignment)
            elif assignment.form_type == 'promotional_profile':
                from events.services.post_acceptance_forms import writeback_promotional_profile_module
                from events.services.promotional_profile_service import mark_module_completed

                # FIX 6: Write back each module with correct module type (not generic 'promotional_profile')
                # Writeback must be called with actual module names (speaker, sponsor_staff, etc.)
                for module in assignment.active_modules or []:
                    mark_module_completed(assignment, module)
                    # Call writeback with actual module name to ensure prefix mapping works correctly
                    writeback_promotional_profile_module(assignment, module)

        return Response(
            PostAcceptanceFormSubmissionSerializer(submission).data,
            status=status.HTTP_201_CREATED
        )

    def _validate_form_submission(self, assignment, answers_data):
        """Validate form submission against schema with comprehensive checks."""
        from events.services.post_acceptance_forms import (
            is_online_event, is_in_person_event, is_hybrid_event, should_show_physical_sections
        )

        errors = {}
        event = assignment.event
        schema = assignment.form_template.question_schema

        # Route to form-type-specific validation
        if assignment.form_type == 'participant_information':
            return self._validate_participant_information(assignment, answers_data)
        elif assignment.form_type == 'promotional_profile':
            return self._validate_promotional_profile(assignment, answers_data)

        # Fallback: generic schema validation
        return self._validate_generic_form(assignment, answers_data)

    def _validate_participant_information(self, assignment, answers_data):
        """Validate Participant Information form (event attendance focused)."""
        from events.services.post_acceptance_forms import (
            is_online_event, is_in_person_event, is_hybrid_event, should_show_physical_sections
        )

        errors = {}
        event = assignment.event
        schema = assignment.form_template.question_schema

        # Check if form is for virtual/online-only event
        if is_online_event(event):
            return {'errors': {'detail': 'Participant Information Form is only available for in-person and hybrid events'}}

        # Determine event format and visibility
        attendance_mode = answers_data.get('attendance_mode', 'in_person' if is_in_person_event(event) else None)
        show_physical_sections = should_show_physical_sections(event, attendance_mode)

        # Always required fields (regardless of event format)
        always_required = ['accessibility_support_needs', 'share_contact_details', 'photo_video_consent']
        for field_id in always_required:
            field_value = answers_data.get(field_id)
            if not field_value or field_value == '':
                field_label = field_id.replace('_', ' ').title()
                errors[field_id] = f'{field_label} is required'

        # Hybrid events require attendance mode selection
        if is_hybrid_event(event):
            if not attendance_mode or attendance_mode == '':
                errors['attendance_mode'] = 'Please select your attendance mode'

        # Physical sections require emergency contact fields
        if show_physical_sections:
            emergency_contact_required = ['emergency_contact_name', 'emergency_contact_phone', 'emergency_contact_relationship']
            for field_id in emergency_contact_required:
                field_value = answers_data.get(field_id)
                if not field_value or field_value == '':
                    field_label = field_id.replace('_', ' ').title()
                    errors[field_id] = f'{field_label} is required'

        # Validate each field in schema
        for section in schema.get('sections', []):
            section_id = section.get('id')

            # Skip sections not visible to user
            if section.get('showOnlyForHybrid') and not is_hybrid_event(event):
                continue
            if section.get('showOnlyForPhysical') and not show_physical_sections:
                continue

            for field in section.get('fields', []):
                # Skip fields not visible
                if field.get('showOnlyForHybrid') and not is_hybrid_event(event):
                    continue
                if self._is_field_hidden(field, answers_data):
                    continue

                field_id = field['id']
                field_value = answers_data.get(field_id)
                field_type = field.get('type')
                is_required = field.get('required', False)

                # Required field validation - only validate visible fields
                if is_required:
                    if field_type == 'multi_select':
                        # Check for empty multi-select
                        if not field_value or (isinstance(field_value, list) and len(field_value) == 0):
                            errors[field_id] = 'This field is required'
                        # Validate "None" mutual-exclusion for food-related fields
                        elif isinstance(field_value, list) and field_id in ['food_allergies', 'dietary_restrictions']:
                            if 'none' in field_value and len(field_value) > 1:
                                errors[field_id] = '"None" cannot be selected with other options'
                    else:
                        # Check for empty text/select fields (but skip always-required, already checked above)
                        if field_id not in always_required and field_id != 'attendance_mode':
                            if not field_value or field_value == '':
                                errors[field_id] = 'This field is required'

                # Enforce "None" mutual-exclusion even if not required (for data integrity)
                if field_type == 'multi_select' and field_id in ['food_allergies', 'dietary_restrictions']:
                    if isinstance(field_value, list) and 'none' in field_value and len(field_value) > 1:
                        errors[field_id] = '"None" cannot be selected with other options'

                # Validate conditional "Other" fields
                if field.get('showIfIncludes') or field.get('showIfValue'):
                    # Field is visible due to conditional, check if it's required
                    if field.get('required'):
                        if field_type == 'multi_select':
                            if not field_value or (isinstance(field_value, list) and len(field_value) == 0):
                                errors[field_id] = 'This field is required'
                        else:
                            if not field_value or field_value == '':
                                errors[field_id] = 'This field is required'

                # Validate visa support details if visa support is selected
                if field_id == 'visa_support' and field_value in ['required', 'not_yet_sure']:
                    detail_value = answers_data.get('visa_support_details')
                    if not detail_value or detail_value == '':
                        errors['visa_support_details'] = 'Please describe what visa support you need'

        # Validate "Other" field dependencies (independent of schema conditional logic)
        # If food_allergies includes "other", require food_allergies_other
        food_allergies = answers_data.get('food_allergies', [])
        if isinstance(food_allergies, list) and 'other' in food_allergies:
            food_allergies_other = answers_data.get('food_allergies_other', '')
            if not food_allergies_other or food_allergies_other == '':
                errors['food_allergies_other'] = 'Please specify other allergies'

        # If dietary_restrictions includes "other", require dietary_restrictions_other
        dietary_restrictions = answers_data.get('dietary_restrictions', [])
        if isinstance(dietary_restrictions, list) and 'other' in dietary_restrictions:
            dietary_restrictions_other = answers_data.get('dietary_restrictions_other', '')
            if not dietary_restrictions_other or dietary_restrictions_other == '':
                errors['dietary_restrictions_other'] = 'Please specify other dietary restrictions'

        # If emergency_contact_relationship = "other", require emergency_contact_relationship_other
        emergency_contact_relationship = answers_data.get('emergency_contact_relationship', '')
        if emergency_contact_relationship == 'other':
            emergency_contact_relationship_other = answers_data.get('emergency_contact_relationship_other', '')
            if not emergency_contact_relationship_other or emergency_contact_relationship_other == '':
                errors['emergency_contact_relationship_other'] = 'Please specify relationship'

        return {'errors': errors} if errors else None

    def _validate_promotional_profile(self, assignment, answers_data):
        """Validate Promotional Profile form (module-based validation)."""
        errors = {}
        schema = assignment.form_template.question_schema

        # Get active modules for this assignment
        active_modules = assignment.active_modules or []

        def _is_section_visible(section):
            """Check if section should be shown based on active_modules."""
            condition = section.get('showIfIncludes')
            if not condition:
                return True

            field_name = condition.get('field')
            expected_value = condition.get('value')

            if field_name == 'active_modules':
                return expected_value in active_modules

            return True

        def _is_field_visible(field):
            """Check if field should be shown based on active_modules."""
            condition = field.get('showIfIncludes')
            if not condition:
                return True

            field_name = condition.get('field')
            expected_value = condition.get('value')

            if field_name == 'active_modules':
                return expected_value in active_modules

            return True

        # Validate only fields in active modules
        for section in schema.get('sections', []):
            # Skip sections not visible for active modules
            if not _is_section_visible(section):
                continue

            for field in section.get('fields', []):
                # Support both 'id' (new) and 'key' (old/legacy) for backward compatibility
                field_key = field.get('id') or field.get('key')
                field_value = answers_data.get(field_key)
                field_type = field.get('type')
                is_required = field.get('required', False)

                # Skip fields hidden by module conditions
                if not _is_field_visible(field):
                    continue

                # Required field validation
                if is_required:
                    if field_type == 'multi_select':
                        if not field_value or (isinstance(field_value, list) and len(field_value) == 0):
                            errors[field_key] = 'This field is required'
                    elif field_type in ('file_upload', 'file_upload_multiple', 'file'):
                        # File fields: required means at least one file must be uploaded
                        if not field_value:
                            errors[field_key] = 'This field is required'
                    else:
                        if not field_value or field_value == '':
                            errors[field_key] = 'This field is required'

        return {'errors': errors} if errors else None

    def _validate_generic_form(self, assignment, answers_data):
        """Generic validation for forms without specific handlers."""
        errors = {}
        schema = assignment.form_template.question_schema

        # Validate required fields only
        for section in schema.get('sections', []):
            for field in section.get('fields', []):
                if field.get('required'):
                    field_value = answers_data.get(field['id'])
                    if not field_value or field_value == '':
                        errors[field['id']] = 'This field is required'

        return {'errors': errors} if errors else None

    def _is_field_hidden(self, field, answers_data):
        """Check if field is hidden based on conditional logic."""
        if field.get('showIfValue'):
            condition = field['showIfValue']
            if answers_data.get(condition['field']) != condition['value']:
                return True

        if field.get('showIfIncludes'):
            condition = field['showIfIncludes']
            field_value = answers_data.get(condition['field'], [])
            if not isinstance(field_value, list) or condition['value'] not in field_value:
                return True

        if field.get('showIfInList'):
            condition = field['showIfInList']
            if answers_data.get(condition['field']) not in condition.get('values', []):
                return True

        return False


class PostAcceptanceFormAssignmentAdminViewSet(viewsets.ModelViewSet):
    """
    Admin ViewSet for managing form assignments per event.

    Endpoints:
    - GET /api/events/{event_id}/post-acceptance-form-assignments-admin/
      List all assignments for event (admin only)
    - GET /api/events/{event_id}/post-acceptance-form-assignments-admin/{id}/
      Get assignment details (admin only)
    - GET /api/events/{event_id}/post-acceptance-form-assignments-admin/{id}/details/
      Get full submission details for modal (admin only)
    - POST /api/events/{event_id}/post-acceptance-form-assignments-admin/send-reminders/
      Send reminders to selected assignments
    - POST /api/events/{event_id}/post-acceptance-form-assignments-admin/{id}/mark-complete/
      Mark assignment as complete
    - POST /api/events/{event_id}/post-acceptance-form-assignments-admin/export/
      Export assignments to CSV
    """
    serializer_class = PostAcceptanceFormAssignmentSerializer
    permission_classes = [IsAuthenticated, IsEventAdminOrSuperuser]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['form_type', 'status']
    search_fields = [
        'event_registration__user__email',
        'event_registration__user__first_name',
        'event_registration__user__last_name',
        'event_registration__user__username'
    ]
    custom_filter_fields = [
        'attendee_role', 'attendance_mode', 'visa_support_requested',
        'accessibility_need_declared', 'photo_consent_denied'
    ]
    ordering_fields = [
        '-created_at', 'deadline', '-updated_at',
        'event_registration__user__email',
        'reminders_sent', 'completed_at'
    ]
    ordering = ['-created_at']

    def get_serializer_class(self):
        """Use admin detail serializer for admin list/detail views."""
        if self.action in ['list', 'retrieve', 'details']:
            from events.serializers import PostAcceptanceFormAssignmentAdminDetailSerializer
            return PostAcceptanceFormAssignmentAdminDetailSerializer
        return self.serializer_class

    def get_queryset(self):
        event_id = self.kwargs.get('event_id')
        user = self.request.user

        if not event_id:
            return PostAcceptanceFormAssignment.objects.none()

        event = get_object_or_404(Event, id=event_id)

        if event.created_by != user and not user.is_superuser and not user.is_staff:
            raise PermissionDenied("You can only view assignments for events you created")

        from django.db.models import Prefetch
        from events.models import PostAcceptanceFormSubmission, PostAcceptanceFormAnswer

        # Prefetch submission and answers for efficient admin list/detail views
        submission_prefetch = Prefetch(
            'submission',
            PostAcceptanceFormSubmission.objects.prefetch_related(
                Prefetch('answers', queryset=PostAcceptanceFormAnswer.objects.all())
            )
        )

        queryset = PostAcceptanceFormAssignment.objects.filter(event=event).select_related(
            'event', 'form_template', 'event_registration', 'event_registration__user', 'manual_completed_by'
        ).prefetch_related(submission_prefetch)

        # FIX 7: Filter by form_type if provided
        form_type = self.request.query_params.get('form_type')
        if form_type:
            queryset = queryset.filter(form_type=form_type)

        # Handle filters using direct ORM (all fields exist on EventRegistration)
        # FIX 10: Filter by attendee_role using new EventRole model instead of old EventParticipant
        attendee_role = self.request.query_params.get('attendee_role')
        if attendee_role and attendee_role != 'all':
            # Use new EventRole system via event_registration__roles
            queryset = queryset.filter(event_registration__roles__key=attendee_role).distinct()

        # Filter by visa_support_requested (direct field on EventRegistration)
        visa_support = self.request.query_params.get('visa_support_requested')
        if visa_support and visa_support != 'all':
            visa_bool = visa_support.lower() == 'true'
            queryset = queryset.filter(event_registration__visa_support_requested=visa_bool)

        # Filter by accessibility_need_declared (direct field on EventRegistration)
        accessibility = self.request.query_params.get('accessibility_need_declared')
        if accessibility and accessibility != 'all':
            acc_bool = accessibility.lower() == 'true'
            queryset = queryset.filter(event_registration__accessibility_need_declared=acc_bool)

        # Filter by photo_video_consent (direct field on EventRegistration)
        photo_consent = self.request.query_params.get('photo_consent_denied')
        if photo_consent and photo_consent != 'all':
            # photo_consent_denied=true means photo_video_consent != "yes"
            if photo_consent.lower() == 'true':
                queryset = queryset.exclude(event_registration__photo_video_consent='yes')
            else:
                queryset = queryset.filter(event_registration__photo_video_consent='yes')

        # Filter by attendance_mode (from submission answers - in-memory only for this one)
        attendance_mode = self.request.query_params.get('attendance_mode')
        if attendance_mode and attendance_mode != 'all':
            # For hybrid events, attendee selects attendance_mode in the form
            # For in-person events, attendance_mode is always "in_person"
            # For online events, no form is shown (filtered at event creation)
            assignments_list = list(queryset)
            filtered_list = []

            for assignment in assignments_list:
                try:
                    if assignment.submission and assignment.submission.answers.all():
                        mode = next(
                            (a.answer_text for a in assignment.submission.answers.all()
                             if a.question_key == 'attendance_mode'),
                            None
                        )
                    else:
                        # No submission = not started, skip in-person/online filter
                        mode = None

                    if mode == attendance_mode:
                        filtered_list.append(assignment)
                except:
                    pass

            queryset = PostAcceptanceFormAssignment.objects.filter(
                id__in=[a.id for a in filtered_list]
            ).select_related(
                'event', 'form_template', 'event_registration', 'event_registration__user', 'manual_completed_by'
            ).prefetch_related(submission_prefetch)

        return queryset

    @action(detail=False, methods=['get'], url_path='summary')
    def summary(self, request, event_id=None):
        """Get summary statistics for form completions."""
        event = get_object_or_404(Event, id=event_id)
        self.check_object_permissions(request, event)

        queryset = self.get_queryset()

        # Calculate counts by status
        summary_data = {
            'total': queryset.count(),
            'completed': queryset.filter(status=PostAcceptanceFormAssignment.STATUS_COMPLETED).count(),
            'in_progress': queryset.filter(status=PostAcceptanceFormAssignment.STATUS_IN_PROGRESS).count(),
            'not_started': queryset.filter(status=PostAcceptanceFormAssignment.STATUS_NOT_STARTED).count(),
            'lapsed': queryset.filter(status=PostAcceptanceFormAssignment.STATUS_LAPSED).count(),
        }

        # Calculate completion percentage
        if summary_data['total'] > 0:
            summary_data['completion_percentage'] = round(
                (summary_data['completed'] / summary_data['total']) * 100, 1
            )
        else:
            summary_data['completion_percentage'] = 0

        return Response(summary_data)

    @action(detail=False, methods=['post'], url_path='send-reminders')
    def send_reminders(self, request, event_id=None):
        """Send reminders to selected assignments."""
        event = get_object_or_404(Event, id=event_id)
        self.check_object_permissions(request, event)

        assignment_ids = request.data.get('assignment_ids', [])
        if not assignment_ids:
            # Send to all incomplete assignments
            assignments = self.get_queryset().filter(
                status__in=[PostAcceptanceFormAssignment.STATUS_NOT_STARTED, PostAcceptanceFormAssignment.STATUS_IN_PROGRESS]
            )
        else:
            assignments = self.get_queryset().filter(id__in=assignment_ids)

        from events.services.post_acceptance_forms import send_form_reminder_email
        from events.models import AdminAuditLog, PostAcceptanceReminderLog

        sent_count = 0
        sent_ids = []
        skipped_count = 0
        for assignment in assignments:
            try:
                # Only send reminder if assignment is NOT completed
                if assignment.status == PostAcceptanceFormAssignment.STATUS_COMPLETED:
                    logger.info(f"Skipping reminder for assignment {assignment.id} - already completed")
                    skipped_count += 1
                    continue

                send_form_reminder_email(assignment)

                # Increment reminders_sent counter
                assignment.reminders_sent += 1
                assignment.last_reminder_sent_at = timezone.now()
                assignment.save(update_fields=['reminders_sent', 'last_reminder_sent_at'])

                # Create reminder log entry with updated counter
                PostAcceptanceReminderLog.objects.create(
                    assignment=assignment,
                    reminder_number=assignment.reminders_sent,
                    sent_at=timezone.now()
                )

                sent_count += 1
                sent_ids.append(assignment.id)
            except Exception as e:
                logger.error(f"Failed to send reminder for assignment {assignment.id}: {str(e)}")

        # Create audit log entry for bulk reminder send
        if sent_ids:
            AdminAuditLog.objects.create(
                event=event,
                performed_by=request.user,
                action='send_reminders',
                details={'assignment_ids': sent_ids, 'count': sent_count}
            )

        response_msg = f'Reminders sent to {sent_count} participant(s)'
        if skipped_count > 0:
            response_msg += f' ({skipped_count} skipped - already completed)'

        return Response({
            'sent_count': sent_count,
            'skipped_count': skipped_count,
            'assignment_ids': sent_ids,
            'message': response_msg
        })

    @action(detail=True, methods=['post'], url_path='mark-complete')
    def mark_complete(self, request, pk=None, event_id=None):
        """Admin manually marks assignment as complete."""
        assignment = self.get_object()
        self.check_object_permissions(request, assignment)

        assignment.status = PostAcceptanceFormAssignment.STATUS_COMPLETED
        assignment.completed_at = timezone.now()
        assignment.manual_completed_by = request.user
        assignment.manual_completed_at = timezone.now()
        assignment.save()

        # Create audit log
        from events.models import AdminAuditLog
        AdminAuditLog.objects.create(
            event=assignment.event,
            performed_by=request.user,
            assignment=assignment,
            action='manual_mark_complete',
            details={'assignment_id': assignment.id}
        )

        return Response(PostAcceptanceFormAssignmentSerializer(assignment).data)

    @action(detail=True, methods=['get'], url_path='details')
    def details(self, request, pk=None, event_id=None):
        """Get full submission details for modal view."""
        assignment = self.get_object()
        self.check_object_permissions(request, assignment)

        # Check if user has permission to view restricted data
        has_restricted_access = (
            request.user.is_superuser or
            request.user.groups.filter(name='view_restricted_attendee_data').exists()
        )

        # Create audit log if viewing restricted data
        if has_restricted_access and assignment.status == PostAcceptanceFormAssignment.STATUS_COMPLETED:
            from events.models import AdminAuditLog
            AdminAuditLog.objects.create(
                event=assignment.event,
                performed_by=request.user,
                assignment=assignment,
                action='view_restricted',
                details={'assignment_id': assignment.id}
            )

        # Use detail serializer
        from events.serializers import PostAcceptanceFormAssignmentAdminDetailSerializer
        serializer = PostAcceptanceFormAssignmentAdminDetailSerializer(
            assignment,
            context={'request': request, 'has_restricted_access': has_restricted_access}
        )
        return Response(serializer.data)

    @action(detail=False, methods=['post'], url_path='export')
    def export(self, request, event_id=None):
        """Export assignments to CSV."""
        event = get_object_or_404(Event, id=event_id)
        self.check_object_permissions(request, event)

        restricted = request.data.get('restricted', False)

        # Get assignments for export
        assignments = self.get_queryset()
        export_count = assignments.count()

        # Check permission for restricted export
        if restricted:
            has_permission = (
                request.user.is_superuser or
                request.user.groups.filter(name='view_restricted_attendee_data').exists()
            )
            if not has_permission:
                raise PermissionDenied("You do not have permission to export restricted data")

            # Create audit log with row count
            from events.models import AdminAuditLog
            AdminAuditLog.objects.create(
                event=event,
                performed_by=request.user,
                action='export_restricted',
                details={'export_type': 'csv', 'restricted': True, 'row_count': export_count}
            )

        csv_data = self._generate_csv(assignments, restricted)

        response = HttpResponse(csv_data, content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="form-assignments-{event.id}.csv"'
        return response

    def _generate_csv(self, assignments, include_restricted=False):
        """Generate CSV for assignments with proper handling of array fields."""
        import csv
        from io import StringIO
        import json

        output = StringIO()
        writer = csv.writer(output)

        # Header
        headers = [
            'Assignment ID', 'Attendee Name', 'Email', 'Form Type', 'Status',
            'Deadline', 'Started At', 'Completed At', 'Reminders Sent',
            'Visa Support', 'Photo Consent', 'Directory Visibility'
        ]

        if include_restricted:
            headers.extend([
                'Emergency Contact Name', 'Emergency Contact Phone', 'Relationship',
                'Relationship Other', 'Accessibility Needs', 'Accessibility Details',
                'Mobility Requirements', 'Medical Info', 'Food Allergies',
                'Allergies Other', 'Dietary Restrictions', 'Restrictions Other', 'Food Notes'
            ])

        writer.writerow(headers)

        def get_answer_value(answer):
            """Extract value from answer, handling both text and array (multi_select) fields."""
            if not answer:
                return ''
            # For multi_select fields, use answer_data; otherwise use answer_text
            if answer.answer_data and isinstance(answer.answer_data, list):
                return ', '.join(str(v) for v in answer.answer_data)
            return answer.answer_text or ''

        # Rows
        for assignment in assignments:
            row = [
                assignment.id,
                assignment.event_registration.user.get_full_name() or assignment.event_registration.user.username,
                assignment.event_registration.user.email,
                assignment.get_form_type_display(),
                assignment.get_status_display(),
                assignment.deadline.isoformat() if assignment.deadline else '',
                assignment.started_at.isoformat() if assignment.started_at else '',
                assignment.completed_at.isoformat() if assignment.completed_at else '',
                assignment.reminders_sent,
                'Yes' if assignment.event_registration.visa_support_requested else 'No',
                assignment.event_registration.photo_video_consent or 'N/A',
                'Yes' if assignment.event_registration.directory_visibility else 'No'
            ]

            if include_restricted and assignment.submission:
                try:
                    answers = {ans.question_key: ans for ans in assignment.submission.answers.all()}
                    row.extend([
                        get_answer_value(answers.get('emergency_contact_name')),
                        get_answer_value(answers.get('emergency_contact_phone')),
                        get_answer_value(answers.get('emergency_contact_relationship')),
                        get_answer_value(answers.get('emergency_contact_relationship_other')),
                        get_answer_value(answers.get('accessibility_support_needs')),
                        get_answer_value(answers.get('accessibility_needs_detail')),
                        get_answer_value(answers.get('mobility_seating_requirements')),
                        get_answer_value(answers.get('medical_info_emergency')),
                        get_answer_value(answers.get('food_allergies')),
                        get_answer_value(answers.get('food_allergies_other')),
                        get_answer_value(answers.get('dietary_restrictions')),
                        get_answer_value(answers.get('dietary_restrictions_other')),
                        get_answer_value(answers.get('food_notes'))
                    ])
                except Exception as e:
                    logger.error(f"Error extracting restricted data for assignment {assignment.id}: {str(e)}")
                    row.extend([''] * 13)
            elif include_restricted:
                row.extend([''] * 13)

            writer.writerow(row)

        return output.getvalue()

    @action(detail=False, methods=['post'], url_path='export-promotional')
    def export_promotional(self, request, event_id=None):
        """Export promotional profiles in CSV, JSON, or ZIP format.

        Query parameters:
            format: 'csv' | 'json' | 'zip' (default: zip)
            role: Optional role filter (speaker, sponsor, startup, investor)
            include_internal: Include profiles with display_consent='no'
            include_incomplete: Include in_progress assignments

        Body:
            {
                "format": "csv",
                "role": "speaker",
                "include_internal": false,
                "include_incomplete": false
            }
        """
        from events.services.promotional_profile_export_service import (
            generate_csv_export,
            generate_json_export,
            generate_zip_export,
            build_export_queryset
        )

        event = get_object_or_404(Event, id=event_id)
        self.check_object_permissions(request, event)

        # Get parameters
        export_format = request.data.get('format', 'zip').lower()
        role = request.data.get('role')
        include_internal = request.data.get('include_internal', False)
        include_incomplete = request.data.get('include_incomplete', False)

        # Permission check for internal export
        if include_internal:
            has_permission = (
                request.user.is_superuser or
                request.user.groups.filter(name='view_restricted_attendee_data').exists()
            )
            if not has_permission:
                raise PermissionDenied(
                    "Permission denied for internal promotional profile export"
                )

        # Build queryset
        assignments = self.get_queryset().filter(
            event=event,
            form_type='promotional_profile'
        )
        assignments = build_export_queryset(
            assignments,
            include_internal=include_internal,
            include_incomplete=include_incomplete,
            role=role
        )

        row_count = assignments.count()

        # Generate export
        try:
            if export_format == 'csv':
                export_data = generate_csv_export(assignments, include_internal, role)
                content_type = 'text/csv'
                filename = f'promotional-profiles-{event_id}.csv'
                response = HttpResponse(export_data, content_type=content_type)

            elif export_format == 'json':
                export_data = generate_json_export(assignments, include_internal, role)
                content_type = 'application/json'
                filename = f'promotional-profiles-{event_id}.json'
                response = HttpResponse(export_data, content_type=content_type)

            elif export_format == 'zip':
                export_data = generate_zip_export(
                    event, assignments, include_internal, role
                )
                content_type = 'application/zip'
                filename = f'promotional-profiles-{event_id}.zip'
                response = HttpResponse(export_data, content_type=content_type)

            else:
                return Response(
                    {'error': f"Unsupported format: {export_format}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Set download header
            response['Content-Disposition'] = f'attachment; filename="{filename}"'

            # Log to audit trail
            from events.models import AdminAuditLog
            AdminAuditLog.objects.create(
                event=event,
                performed_by=request.user,
                action='export_promotional',
                details={
                    'format': export_format,
                    'role': role,
                    'include_internal': include_internal,
                    'include_incomplete': include_incomplete,
                    'row_count': row_count,
                    'filename': filename
                }
            )

            return response

        except Exception as e:
            logger.error(f"Error exporting promotional profiles: {e}", exc_info=True)
            return Response(
                {'error': f"Export failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'], url_path='export-promotional-completed')
    def export_promotional_completed(self, request, event_id=None):
        """Quick export of completed profiles with display_consent=yes in ZIP format.

        Query parameters:
            format: 'csv' | 'json' | 'zip' (default: zip)
        """
        from events.services.promotional_profile_export_service import (
            generate_csv_export,
            generate_json_export,
            generate_zip_export,
            build_export_queryset
        )

        event = get_object_or_404(Event, id=event_id)
        self.check_object_permissions(request, event)

        export_format = request.query_params.get('format', 'zip').lower()

        # Get completed, public profiles only
        assignments = self.get_queryset().filter(
            event=event,
            form_type='promotional_profile'
        )
        assignments = build_export_queryset(
            assignments,
            include_internal=False,
            include_incomplete=False,
            role=None
        )

        row_count = assignments.count()

        try:
            if export_format == 'csv':
                export_data = generate_csv_export(assignments, False, None)
                content_type = 'text/csv'
                filename = f'promotional-profiles-completed-{event_id}.csv'
                response = HttpResponse(export_data, content_type=content_type)

            elif export_format == 'json':
                export_data = generate_json_export(assignments, False, None)
                content_type = 'application/json'
                filename = f'promotional-profiles-completed-{event_id}.json'
                response = HttpResponse(export_data, content_type=content_type)

            else:  # Default to ZIP
                export_data = generate_zip_export(event, assignments, False, None)
                content_type = 'application/zip'
                filename = f'promotional-profiles-completed-{event_id}.zip'
                response = HttpResponse(export_data, content_type=content_type)

            response['Content-Disposition'] = f'attachment; filename="{filename}"'

            # Log to audit trail
            from events.models import AdminAuditLog
            AdminAuditLog.objects.create(
                event=event,
                performed_by=request.user,
                action='export_promotional',
                details={
                    'format': export_format,
                    'role': None,
                    'include_internal': False,
                    'include_incomplete': False,
                    'row_count': row_count,
                    'filename': filename
                }
            )

            return response

        except Exception as e:
            logger.error(f"Error exporting completed profiles: {e}", exc_info=True)
            return Response(
                {'error': f"Export failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _export_by_role_helper(self, request, event_id, role, role_display):
        """Helper method to export profiles by specific role."""
        from events.services.promotional_profile_export_service import (
            generate_zip_export,
            build_export_queryset
        )

        event = get_object_or_404(Event, id=event_id)
        self.check_object_permissions(request, event)

        # Get profiles for this role only
        assignments = self.get_queryset().filter(
            event=event,
            form_type='promotional_profile'
        )
        assignments = build_export_queryset(
            assignments,
            include_internal=False,
            include_incomplete=False,
            role=role
        )

        row_count = assignments.count()

        try:
            export_data = generate_zip_export(event, assignments, False, role)
            filename = f'{role_display}-{event_id}.zip'
            response = HttpResponse(export_data, content_type='application/zip')
            response['Content-Disposition'] = f'attachment; filename="{filename}"'

            # Log to audit trail
            from events.models import AdminAuditLog
            AdminAuditLog.objects.create(
                event=event,
                performed_by=request.user,
                action='export_promotional',
                details={
                    'format': 'zip',
                    'role': role,
                    'include_internal': False,
                    'include_incomplete': False,
                    'row_count': row_count,
                    'filename': filename
                }
            )

            return response

        except Exception as e:
            logger.error(f"Error exporting {role} profiles: {e}", exc_info=True)
            return Response(
                {'error': f"Export failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'], url_path='export-promotional-speakers')
    def export_speakers(self, request, event_id=None):
        """Quick export of speaker profiles in ZIP format."""
        return self._export_by_role_helper(request, event_id, 'speaker', 'speakers')

    @action(detail=False, methods=['get'], url_path='export-promotional-sponsors')
    def export_sponsors(self, request, event_id=None):
        """Quick export of sponsor profiles in ZIP format."""
        return self._export_by_role_helper(request, event_id, 'sponsor', 'sponsors')

    @action(detail=False, methods=['get'], url_path='export-promotional-startups')
    def export_startups(self, request, event_id=None):
        """Quick export of startup profiles in ZIP format."""
        return self._export_by_role_helper(request, event_id, 'startup', 'startups')

    @action(detail=False, methods=['get'], url_path='export-promotional-investors')
    def export_investors(self, request, event_id=None):
        """Quick export of investor profiles in ZIP format."""
        return self._export_by_role_helper(request, event_id, 'investor', 'investors')


def _publish_draft_application_event_if_tracks_ready(event):
    """
    Publish an Application Required event once at least one valid open track exists.

    This intentionally does not unpublish events if tracks later become invalid.
    """
    if event.registration_type == 'apply' and event.status == 'draft' and event.has_valid_application_tracks():
        Event.objects.filter(pk=event.pk, status='draft').update(status='published')
        event.status = 'published'
        return True
    return False


class EventApplicationTrackViewSet(viewsets.ModelViewSet):
    """ViewSet for managing EventApplicationTrack - application track configuration per event."""

    serializer_class = EventApplicationTrackSerializer

    def get_permissions(self):
        """Allow unauthenticated users to LIST/RETRIEVE tracks, but require auth for CREATE/UPDATE/DELETE."""
        if self.action in ['list', 'retrieve']:
            # Anyone (authenticated or guest) can view application tracks
            return []
        # Require authentication for create, update, delete, etc.
        return [permissions.IsAuthenticated()]

    def get_queryset(self):
        """Filter tracks by event_id from URL parameter."""
        event_id = self.kwargs.get('event_id')
        if event_id:
            # Only return active tracks that are visible to applicants
            return EventApplicationTrack.objects.filter(event_id=event_id, is_active=True).order_by('sort_order', 'label')
        return EventApplicationTrack.objects.none()

    def perform_create(self, serializer):
        """Create track for specified event."""
        event_id = self.kwargs.get('event_id')
        event = Event.objects.get(pk=event_id)
        serializer.save(event=event)
        _publish_draft_application_event_if_tracks_ready(event)

    def perform_update(self, serializer):
        """Update track and auto-publish draft Application Required events when ready."""
        track = serializer.save()
        _publish_draft_application_event_if_tracks_ready(track.event)

    @action(detail=True, methods=['get'], url_path='form-schema')
    def form_schema(self, request, *args, **kwargs):
        """Return form schema with required fields per submission mode."""
        track = self.get_object()

        mode_required_fields = {
            'self_submission': ['first_name', 'last_name', 'email'],
            'confirmed': ['first_name', 'last_name', 'email', 'sponsor_organization', 'pre_approval_code'],
            'self_nomination': ['first_name', 'last_name', 'email'],
            'third_party_nomination': ['nominator_name', 'nominator_email', 'nominee_name', 'nominee_email'],
        }

        # Get enabled modes for this track
        enabled_modes = track.enabled_submission_modes or []

        # Build schema with required fields for each mode
        schema_with_requirements = {
            'id': track.id,
            'key': track.key,
            'label': track.label,
            'form_schema': track.form_schema or {},
            'enabled_submission_modes': enabled_modes,
            'required_fields_by_mode': {}
        }

        for mode in enabled_modes:
            schema_with_requirements['required_fields_by_mode'][mode] = mode_required_fields.get(mode, [])

        return Response(schema_with_requirements)


class EventRoleViewSet(viewsets.ModelViewSet):
    """ViewSet for managing EventRole - attendee role catalog per event."""

    serializer_class = EventRoleSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Filter roles by event_id from URL parameter, with fallback seeding."""
        event_id = self.kwargs.get('event_id')
        if event_id:
            # FIX: Fallback role seeding for existing events without roles
            from .services.role_seeding import get_or_seed_event_roles
            try:
                event = Event.objects.get(pk=event_id)
                return get_or_seed_event_roles(event)
            except Event.DoesNotExist:
                return EventRole.objects.none()
        return EventRole.objects.none()

    def perform_create(self, serializer):
        """Create role for specified event."""
        event_id = self.kwargs.get('event_id')
        event = Event.objects.get(pk=event_id)
        serializer.save(event=event)


# FIX 3: Track Pricing Tier ViewSet for UI/API management
class TrackPricingTierViewSet(viewsets.ModelViewSet):
    """ViewSet for managing TrackPricingTier - pricing options per track."""

    serializer_class = TrackPricingTierSerializer

    def get_permissions(self):
        """Allow unauthenticated users to LIST/RETRIEVE tiers, but require auth for CREATE/UPDATE/DELETE."""
        if self.action in ['list', 'retrieve']:
            # Anyone (authenticated or guest) can view pricing tiers
            return []
        # Require authentication for create, update, delete, etc.
        return [permissions.IsAuthenticated()]

    def get_queryset(self):
        """Filter pricing tiers by track_id from URL parameter."""
        event_id = self.kwargs.get('event_id')
        track_id = self.kwargs.get('track_id')

        if event_id and track_id:
            # Only return active tiers
            return TrackPricingTier.objects.filter(
                track_id=track_id,
                track__event_id=event_id,
                is_active=True
            ).order_by('sort_order', 'label')
        return TrackPricingTier.objects.none()

    def perform_create(self, serializer):
        """Create pricing tier for specified track with duplicate prevention."""
        track_id = self.kwargs.get('track_id')
        track = EventApplicationTrack.objects.get(pk=track_id)

        # Prevent duplicate tiers with same key for this track
        tier_key = serializer.validated_data.get('key')
        if tier_key and TrackPricingTier.objects.filter(track=track, key=tier_key).exists():
            from rest_framework.exceptions import ValidationError
            raise ValidationError({
                'key': f'Pricing tier with key "{tier_key}" already exists for this track',
                'detail': f'Pricing tier "{tier_key}" already exists. Please use a different key or edit the existing tier.'
            })

        serializer.save(track=track)
        _publish_draft_application_event_if_tracks_ready(track.event)

    def perform_update(self, serializer):
        """Update pricing tier."""
        tier = serializer.save()
        _publish_draft_application_event_if_tracks_ready(tier.track.event)


# Phase 5: Form Schema Primitives and Shared Question Library

class SharedQuestionCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for shared question categories (read-only)."""

    serializer_class = SharedQuestionCategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = SharedQuestionCategory.objects.all()

    def get_queryset(self):
        """Return all categories ordered by sort_order."""
        return SharedQuestionCategory.objects.all().order_by('sort_order', 'name')


class SharedQuestionViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for shared questions (read-only)."""

    serializer_class = SharedQuestionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Filter by category_id if provided."""
        queryset = SharedQuestion.objects.all()
        category_id = self.request.query_params.get('category_id')
        if category_id:
            queryset = queryset.filter(category_id=category_id)
        return queryset.order_by('category__sort_order', 'id')


class FormFieldViewSet(viewsets.ModelViewSet):
    """ViewSet for form fields in application tracks."""

    serializer_class = FormFieldSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Filter form fields by track_id from URL parameter."""
        event_id = self.kwargs.get('event_id')
        track_id = self.kwargs.get('track_id')

        if event_id and track_id:
            return FormField.objects.filter(
                track_id=track_id,
                track__event_id=event_id
            ).order_by('sort_order', 'id')
        return FormField.objects.none()

    def perform_create(self, serializer):
        """Create form field for specified track."""
        track_id = self.kwargs.get('track_id')
        track = EventApplicationTrack.objects.get(pk=track_id)
        serializer.save(track=track)

    def perform_update(self, serializer):
        """Update form field and maintain sort order."""
        serializer.save()
