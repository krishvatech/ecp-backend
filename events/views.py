"""
ViewSets for the events app.

Users can list, create, retrieve, update, and delete events belonging to
community they are members of. Creation is restricted to users
belonging to the target community.
"""

# ============================================================
# ================ Standard Library / Third-Party ============
# ============================================================
from datetime import timedelta
import logging
import csv
from django.http import HttpResponse
import os                          # NOTE: intentionally kept even if duplicated later
import base64                      # NOTE: currently unused; kept as requested
import requests
import time
import random
import threading
import unicodedata
from ecp_backend.celery import app as celery_app

# ============================================================
# ======================= Django Imports =====================
# ============================================================
from django.db import transaction
from django.db.models import Q, F, Max, Count
from django.db.models.functions import Lower
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model

# ============================================================
# ================= DRF (Django REST Framework) ==============
# ============================================================
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework import permissions, viewsets, status, views, generics   # NOTE: permissions, views may be unused; kept
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.pagination import LimitOffsetPagination

from rest_framework.permissions import (
    AllowAny,
    BasePermission,
    SAFE_METHODS,
    IsAuthenticatedOrReadOnly,      # NOTE: currently unused; kept as requested
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

# ============================================================
# ===================== Local App Imports ====================
# ============================================================

from .models import Event, EventRegistration, LoungeTable, LoungeParticipant, EventSession, SessionAttendance, WaitingRoomAuditLog, WaitingRoomAnnouncement
from friends.models import Notification
from groups.models import Group, GroupMembership
from .serializers import (
    EventSerializer,
    PublicEventSerializer,
    EventLiteSerializer,
    EventRegistrationSerializer,
    EventSessionSerializer,
    SessionAttendanceSerializer,
)
from .utils import (
    DYTE_API_BASE,
    DYTE_AUTH_HEADER,
    DYTE_PRESET_HOST,
    DYTE_PRESET_PARTICIPANT,
    _dyte_headers,
    create_dyte_meeting,
    send_admission_status_changed,  # ✅ NEW: For real-time admission status updates
)
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

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
MOOD_ALLOWED_SET = set(MOOD_ALLOWED_EMOJIS)


class MoodRateThrottle(UserRateThrottle):
    scope = "mood"


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


def _ensure_dyte_meeting_for_event(event: Event) -> str:
    """
    Ensure this Event has a Dyte meeting.
    If not, create one via Dyte API and persist dyte_meeting_id.
    """
    if event.dyte_meeting_id:
        return event.dyte_meeting_id

    payload = {
        "title": event.title or f"Event {event.id}",
        "record_on_start": True,
    }
    try:
        resp = requests.post(
            f"{DYTE_API_BASE}/meetings",
            headers=_dyte_headers(),
            json=payload,
            timeout=10,
        )
    except requests.RequestException as e:
        logger.exception("❌ Dyte meeting create exception: %s", e)
        raise RuntimeError(str(e))

    if resp.status_code not in (200, 201):
        logger.error("❌ Dyte meeting create failed: %s", resp.text[:500])
        raise RuntimeError(f"Dyte meeting create failed ({resp.status_code})")

    data = (resp.json() or {}).get("data") or {}
    meeting_id = data.get("id")
    if not meeting_id:
        raise RuntimeError("Dyte response missing meeting id")

    event.dyte_meeting_id = meeting_id
    event.dyte_meeting_title = data.get("title", event.title)
    event.save(update_fields=["dyte_meeting_id", "dyte_meeting_title", "updated_at"])
    return meeting_id

def _start_rtk_recording_for_event(event: Event) -> None:
    """
    Ask Cloudflare RealtimeKit to start a recording for this event's meeting.

    We do NOT raise errors to the caller; we just log, because
    live-status should still succeed even if recording fails.
    """
    # Meeting id is the Dyte meeting id stored on the Event
    meeting_id = event.dyte_meeting_id
    if not meeting_id:
        try:
            meeting_id = _ensure_dyte_meeting_for_event(event)
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
    meeting_id = event.dyte_meeting_id
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
    meeting_id = event.dyte_meeting_id
    if not meeting_id:
        try:
            meeting_id = _ensure_dyte_meeting_for_event(event)
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
    max_limit = 50


class IsCreatorOrReadOnly(BasePermission):
    """
    - SAFE_METHODS (GET/HEAD/OPTIONS) are open.
    - Mutations allowed only for:
        * the event creator (created_by)
        * staff users
    """
    def has_permission(self, request, view):
        # Anyone can read; must be authenticated to write
        if request.method in SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        # Read is open; writes allowed to creator or staff
        if request.method in SAFE_METHODS:
            return True
        return bool(
            request.user
            and (request.user.is_staff or obj.created_by_id == request.user.id)
        )

def _is_event_host(user, event) -> bool:
    if not (user and user.is_authenticated and event):
        return False

    # Creator / platform staff / community owner are always hosts.
    if (
        user.is_staff
        or getattr(user, "is_superuser", False)
        or event.created_by_id == user.id
        or getattr(event.community, "owner_id", None) == user.id
    ):
        return True

    # Event participants explicitly assigned Host role should also get host access.
    host_match = Q(participant_type="staff", user_id=user.id)
    user_email = (getattr(user, "email", "") or "").strip()
    if user_email:
        host_match = host_match | Q(participant_type="guest", guest_email__iexact=user_email)

    return event.participants.filter(role="host").filter(host_match).exists()


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

class EventViewSet(viewsets.ModelViewSet):
    """
    Full CRUD over events with:
    - Search & ordering
    - Filter helpers (format, category, date range, price)
    - Utility endpoints (categories, formats, locations, max-price, mine)
    - Registration helpers (register, register-bulk)
    - Dyte meeting join (/dyte/join) and live status (/live-status)
    """
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    serializer_class = EventSerializer
    permission_classes = [IsCreatorOrReadOnly]
    pagination_class = EventLimitOffsetPagination
    throttle_classes = []  # NOTE: no throttling by default

    # 🔎 Search & ordering
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ["title", "location", "category", "description", "community__name"]
    ordering_fields = ["start_time", "created_at", "title"]
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
        qs = Event.objects.select_related("community")

        # Base visibility
        if not user.is_authenticated:
            qs = qs.filter(status__in=["published", "live"])
        else:
            qs = qs.filter(
                Q(status__in=["published", "live"]) |
                Q(community__members=user) |
                Q(created_by_id=user.id) |
                Q(community__owner_id=user.id) |  # owner can see all events in their community
                Q(registrations__user_id=user.id, registrations__status="registered")  # registered participants can see event even after it ends (for post-event lounge)
            ).distinct()

        # ---- Filters (applied only when provided) ----
        params = self.request.query_params

        # Bucket filter (upcoming / live / past) - applies to both list & mine
        bucket = (params.get("bucket") or "").strip().lower()
        if bucket:
            qs = _apply_bucket_filter(qs, bucket)

        created_by_param = params.get("created_by")
        if created_by_param:
            if created_by_param == "me":
                if not self.request.user.is_authenticated:
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
        if min_price:
            qs = qs.filter(price__gte=min_price)
        if max_price:
            qs = qs.filter(price__lte=max_price)

        qs = qs.annotate(
            registrations_count=Count(
                'registrations',
                filter=Q(registrations__status__in=['registered', 'cancellation_requested']),
                distinct=True
            )
        )
        return qs
    

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
            serializer.save(created_by=self.request.user, status="published")

    def perform_update(self, serializer):
        """
        Custom update to broadcast lounge settings changes.
        """
        instance = serializer.instance
        
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
        Otherwise, restrict deletion indicating soft cancellation should be used.
        """
        instance = self.get_object()
        
        # Superusers or staff can always delete
        is_staff = getattr(request.user, "is_staff", False) or getattr(request.user, "is_superuser", False)
        
        if instance.status != "draft" and not is_staff:
            from rest_framework import status
            return Response(
                {"detail": "Only draft events can be hard deleted. For published events, please use the cancel functionality."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        return super().destroy(request, *args, **kwargs)

    # ------------------ Dictionary Endpoints -----------------
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
        Only staff users can perform this action.
        """
        if not request.user.is_staff:
            return Response({"detail": "Only staff users can invite users."}, status=403)

        event = self.get_object()
        user_ids = request.data.get("user_ids", [])
        group_ids = request.data.get("group_ids", [])
        
        invited_users = set()

        # 1. Process individual users
        if user_ids:
            users = User.objects.filter(id__in=user_ids)
            for u in users:
                invited_users.add(u)

        # 2. Process groups
        if group_ids:
            # Fetch members of these groups
            memberships = GroupMembership.objects.filter(
                group_id__in=group_ids,
                status="active"
            ).select_related("user")
            for m in memberships:
                invited_users.add(m.user)

        # 3. Send Notifications
        # Filter out the actor themselves if they selected themselves (optional but good UX)
        if request.user in invited_users:
            invited_users.remove(request.user)

        notifications_to_create = []
        for recipient in invited_users:
            # Check if already invited or registered? 
            # For now, we utilize Notification system which usually allows duplicates unless logic prevents it.
            # We will just send the notification.
            
            notifications_to_create.append(
                Notification(
                    recipient=recipient,
                    actor=request.user,
                    kind="event",
                    title=f"Invitation: {event.title}",
                    description=f"You have been invited to {event.title}.",
                    data={"event_id": event.id},
                    is_read=False
                )
            )

        if notifications_to_create:
            Notification.objects.bulk_create(notifications_to_create)

        return Response({
            "ok": True, 
            "invited_count": len(invited_users),
            "message": f"Sent invitations to {len(invited_users)} users."
        })


    # POST /api/events/{id}/register/
    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="register")
    def register(self, request, pk=None):
        """
        Register the current user for a single event.
        """
        event = self.get_object()

        if event.status == "cancelled":
            return Response({"detail": "Cannot register for a cancelled event."}, status=400)

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

        if not event.is_free:
            is_already_registered = event.registrations.filter(user=request.user, status__in=["registered", "waitlisted"]).exists()
            if not is_already_registered:
                return Response({"detail": "This is a paid event. Please purchase a ticket to register.", "code": "requires_payment"}, status=402)

        # ✅ NEW: Set admission_status based on event's waiting_room_enabled setting
        # If waiting room is enabled, new users start as "waiting" for host admission
        # If waiting room is disabled, new users are automatically "admitted"
        #
        # ⚠️ IMPORTANT: This REGISTERS the user, but does NOT add them to the waiting room queue yet!
        # - admission_status="waiting" means they MIGHT need to wait (policy), but
        # - waiting_started_at is intentionally left NULL because they haven't JOINED yet
        #
        # Users are only added to the waiting room list when they actually JOIN the event
        # via the dyte/join endpoint, which sets waiting_started_at=now()
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

        if was_created:
             Event.objects.filter(pk=event.pk).update(attending_count=F("attending_count") + 1)
             
        return Response({"ok": True, "created": was_created, "event_id": event.id})

    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="max-price")
    def max_price(self, request):
        """
        Return the maximum price within the currently visible/filtered events.
        """
        qs = self.get_queryset()  # respects all current filters & visibility
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

            if not _is_event_host(request.user, event):
                return Response({"detail": "Only the host can update live status."}, status=403)

            if action_type == "start":
                if event.status == "ended":
                    return Response(
                        {"detail": "Meeting already ended. Cannot restart via live-status."},
                        status=409,
                    )
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

        if action_type == "start":
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
        methods=["post"],
        permission_classes=[AllowAny],
        url_path="active-speaker",
    )
    def active_speaker(self, request, pk=None):
        """
        Update the `active_speaker` field on the Event whenever Dyte reports
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

        We trust Dyte's own permissions: only the host can click
        "End meeting for all" in the UI. Here we just persist that state.
        Repeated calls from the host are harmless.
        """
        event = self.get_object()

        if not _is_event_host(request.user, event):
            return Response({"detail": "Only the host can end the meeting."}, status=403)

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

            if not _is_event_host(request.user, event):
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

            if not _is_event_host(request.user, event):
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
        if not _is_event_host(request.user, event):
            return Response({"detail": "Only the host can control recording."}, status=403)
        if not event.is_live:
            return Response({"error": "Event must be live to start recording."}, status=400)
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
        if not _is_event_host(request.user, event):
            return Response({"detail": "Only the host can control recording."}, status=403)
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
        if not _is_event_host(request.user, event):
            return Response({"detail": "Only the host can control recording."}, status=403)
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
        if not _is_event_host(request.user, event):
            return Response({"detail": "Only the host can control recording."}, status=403)
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
        if not _is_event_host(request.user, event):
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
        Body: {"user_id": <id>}
        """
        event = self.get_object()
        if not _is_event_host(request.user, event):
            return Response({"detail": "Only the host can kick participants."}, status=403)

        target_id = request.data.get("user_id")
        if not target_id:
            return Response({"detail": "user_id required"}, status=400)

        EventRegistration.objects.filter(event=event, user_id=target_id).update(
            current_mood=None,
            mood_updated_at=timezone.now(),
        )

        # Notify via WebSocket
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"user_{target_id}",
            {
                "type": "broadcast_message",
                "payload": {"type": "kicked", "event_id": event.id}
            }
        )

        return Response({"ok": True, "message": "User kicked"})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="ban")
    def ban_participant(self, request, pk=None):
        """
        Ban a participant from the meeting (permanent removal).
        Body: {"user_id": <id>}
        """
        event = self.get_object()
        if not _is_event_host(request.user, event):
            return Response({"detail": "Only the host can ban participants."}, status=403)

        target_id = request.data.get("user_id")
        if not target_id:
            return Response({"detail": "user_id required"}, status=400)

        # 1. Update registration to banned
        try:
            reg = EventRegistration.objects.get(event=event, user_id=target_id)
            reg.is_banned = True
            reg.current_mood = None
            reg.mood_updated_at = timezone.now()
            reg.save(update_fields=["is_banned", "current_mood", "mood_updated_at"])
        except EventRegistration.DoesNotExist:
            return Response({"detail": "User not registered for this event"}, status=404)

        # 2. Notify via WebSocket
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"user_{target_id}",
            {
                "type": "broadcast_message",
                "payload": {"type": "banned", "event_id": event.id}
            }
        )

        return Response({"ok": True, "message": "User banned"})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="unban")
    def unban_participant(self, request, pk=None):
        """
        Unban a participant.
        Body: {"user_id": <id>}
        """
        event = self.get_object()
        if not _is_event_host(request.user, event):
            return Response({"detail": "Only the host can unban participants."}, status=403)

        target_id = request.data.get("user_id")
        if not target_id:
            return Response({"detail": "user_id required"}, status=400)

        try:
            reg = EventRegistration.objects.get(event=event, user_id=target_id)
            reg.is_banned = False
            reg.save(update_fields=["is_banned"])
        except EventRegistration.DoesNotExist:
            return Response({"detail": "User not registered"}, status=404)

        return Response({"ok": True, "message": "User unbanned"})

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="banned-users")
    def banned_users(self, request, pk=None):
        """
        List all banned users for this event.
        """
        event = self.get_object()
        if not _is_event_host(request.user, event):
            return Response({"detail": "Only the host can view banned users."}, status=403)

        banned_regs = EventRegistration.objects.filter(event=event, is_banned=True).select_related('user')
        data = [{
            "user_id": r.user.id,
            "full_name": r.user.first_name + " " + r.user.last_name,
            "username": r.user.username,
            "avatar": r.user.avatar.url if hasattr(r.user, 'avatar') and r.user.avatar else None
        } for r in banned_regs]

        return Response(data)

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

        is_host = _is_event_host(request.user, event)
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
        return Response({"moods": payload, "allowed_moods": MOOD_ALLOWED_EMOJIS})

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
        is_host = _is_event_host(request.user, event)

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

        profile = getattr(request.user, "profile", None)
        if profile is not None:
            history = list(profile.last_used_moods or [])
            history = [m for m in history if m != mood]
            history.insert(0, mood)
            profile.last_used_moods = history[:10]
            profile.save(update_fields=["last_used_moods"])

        logger.info(f"[MOOD API] User {request.user.id} set mood to '{mood}' for event {pk}")
        return Response({"user_id": request.user.id, "mood": mood, "allowed_moods": MOOD_ALLOWED_EMOJIS})

    def download_recording(self, request):
        """Generate a pre-signed URL for downloading recording from S3"""
        import boto3
        from botocore.config import Config
        
        recording_url = request.data.get('recording_url')
        if not recording_url:
            return Response({"error": "recording_url required"}, status=400)
        
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
        """
        event = self.get_object()
        user = request.user

        # allow only event creator, staff or superuser
        if not (
            user.is_staff
            or getattr(user, "is_superuser", False)
            or event.created_by_id == user.id
        ):
            return Response(
                {"detail": "You do not have permission to view registrations."},
                status=status.HTTP_403_FORBIDDEN,
            )

        qs = (
            EventRegistration.objects
            .filter(event=event)
            .select_related("user")
            .order_by("-registered_at")
        )
        # Filter by status if provided: ?status=joined_live or ?status=watched_replay
        status_filter = (request.query_params.get("status") or "").strip().lower()
        if status_filter == "joined_live":
            qs = qs.filter(joined_live=True)
        elif status_filter == "watched_replay":
            qs = qs.filter(watched_replay=True)
        elif status_filter == "did_not_attend":
            qs = qs.filter(joined_live=False, watched_replay=False)

        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = EventRegistrationSerializer(page, many=True, context={"request": request})
            return self.get_paginated_response(serializer.data)

        serializer = EventRegistrationSerializer(
            qs, many=True, context={"request": request}
        )
        return Response(serializer.data)

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
        is_organizer = _is_event_host(user, event)

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
            .select_related("user")
            .order_by("-registered_at")
        )

        serializer = EventRegistrationSerializer(
            qs, many=True, context={"request": request}
        )
        return Response(serializer.data)

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

        # DEBUG: Log event state when lounge-state is called
        logger.info(f"[lounge_state] Event {event.id}: is_live={event.is_live}, status={event.status}, live_ended_at={event.live_ended_at}, lounge_enabled_after={event.lounge_enabled_after}, lounge_enabled_during={event.lounge_enabled_during}")

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

        tables = LoungeTable.objects.filter(event_id=pk).prefetch_related('participants__user')
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
                    "user_id": p.user.id,
                    "username": p.user.username,
                    "full_name": f"{p.user.first_name} {p.user.last_name}".strip() or p.user.username,
                    "avatar_url": _avatar_url(p.user),
                    "joined_at": p.joined_at.isoformat() if p.joined_at else None,
                } for p in t.participants.all()
            }
            state.append({
                "id": t.id,
                "name": t.name,
                "category": t.category,
                "max_seats": t.max_seats,
                "dyte_meeting_id": t.dyte_meeting_id,
                "icon_url": icon_url,
                "participants": participants
            })
        
        return Response({
            "tables": state,
            "lounge_open_status": {
                "status": status_code,
                "reason": reason,
                "next_change": next_change
            }
        })

    @action(detail=True, methods=["post"], url_path="create-lounge-table")
    def create_lounge_table(self, request, pk=None):
        print(f"DEBUG: create_lounge_table hit for event {pk}")
        """Admin-only: Create a new table in the Social Lounge."""
        event = self.get_object()
        if not (request.user.is_staff or event.created_by_id == request.user.id):
            return Response({"detail": "Not authorized"}, status=403)

        name = request.data.get("name", "New Table")
        category = request.data.get("category", "LOUNGE")
        max_seats = int(request.data.get("max_seats", 4))
        icon_file = request.FILES.get("icon") if hasattr(request, "FILES") else None

        # Create table with a unique Dyte meeting
        payload = {
            "title": f"[{category}] {event.title} - {name}",
            "record_on_start": False,
        }
        try:
            resp = requests.post(f"{DYTE_API_BASE}/meetings", headers=_dyte_headers(), json=payload, timeout=10)
            resp.raise_for_status()
            dyte_id = resp.json().get("data", {}).get("id")
        except Exception as e:
            logger.error(f"Failed to create Dyte meeting for lounge table: {e}")
            dyte_id = None

        table = LoungeTable.objects.create(
            event=event,
            name=name,
            category=category,
            max_seats=max_seats,
            dyte_meeting_id=dyte_id,
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
            "dyte_meeting_id": table.dyte_meeting_id,
            "icon_url": icon_url,
        }, status=201)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="lounge-table-update")
    def lounge_table_update(self, request, pk=None):
        """Admin-only: Update a lounge table (name, seats, icon)."""
        event = self.get_object()
        if not (request.user.is_staff or event.created_by_id == request.user.id):
            return Response({"detail": "Not authorized"}, status=403)

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
        if not (request.user.is_staff or event.created_by_id == request.user.id):
            return Response({"detail": "Not authorized"}, status=403)

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
        if not (request.user.is_staff or event.created_by_id == request.user.id):
            return Response({"detail": "Not authorized"}, status=403)

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
        Get a Dyte authToken for a specific Social Lounge or Breakout room table.
        - For BREAKOUT tables: Allow join during live events regardless of lounge settings
        - For LOUNGE tables: Validate that the lounge is currently open before allowing join
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

        # ✅ FIX #1: Check waiting room status and enforce access control
        is_host = _is_event_host(user, event)

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
        meeting_id = table.dyte_meeting_id
        if not meeting_id:
             # Try to create one if it somehow went missing
            payload = {"title": f"Table: {table.name}", "record_on_start": False}
            try:
                resp = requests.post(f"{DYTE_API_BASE}/meetings", headers=_dyte_headers(), json=payload, timeout=10)
                resp.raise_for_status()
                meeting_id = resp.json().get("data", {}).get("id")
                table.dyte_meeting_id = meeting_id
                table.save(update_fields=["dyte_meeting_id"])
            except Exception as e:
                return Response({"error": "dyte_creation_failed", "detail": str(e)}, status=500)

        # Add participant to the table meeting
        user = request.user

        # ✅ CLEANUP: Remove any stale LoungeParticipant records before joining
        # This prevents 409 conflicts when a user rejoins after leaving
        # NOTE: We only clean up Django DB records here, Dyte cleanup happens below if needed
        stale_records = LoungeParticipant.objects.filter(
            table__event_id=event.id,
            user=user
        ).exclude(table_id=table.id)  # Exclude the current table

        for stale in stale_records:
            try:
                # Store Dyte info before deleting the record
                dyte_meeting_id = stale.table.dyte_meeting_id
                dyte_participant_id = stale.dyte_participant_id

                # Delete the stale DB record first (quick operation)
                stale.delete()
                logger.info(f"[LOUNGE_JOIN] Cleaned up stale LoungeParticipant record for user {user.id}")

                # Try to remove from Dyte asynchronously (don't block if it fails)
                if dyte_participant_id and dyte_meeting_id:
                    try:
                        requests.delete(
                            f"{DYTE_API_BASE}/meetings/{dyte_meeting_id}/participants/{dyte_participant_id}",
                            headers=_dyte_headers(),
                            timeout=5,  # Shorter timeout for cleanup, don't block
                        )
                        logger.info(f"[LOUNGE_JOIN] Cleaned up stale Dyte participant {dyte_participant_id}")
                    except Exception as e:
                        logger.warning(f"[LOUNGE_JOIN] Failed to remove stale Dyte participant (non-blocking): {e}")
            except Exception as e:
                logger.warning(f"[LOUNGE_JOIN] Error cleaning stale record: {e}")

        # Check if user already in this meeting (duplicate prevention)
        duplicate_found = False
        try:
            logger.info(f"[LOUNGE_JOIN] Checking for duplicates: user {user.id}")
            check_resp = requests.get(
                f"{DYTE_API_BASE}/meetings/{meeting_id}/participants",
                headers=_dyte_headers(),
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
                        # Try to remove them from Dyte and allow rejoin
                        try:
                            dyte_id = p.get("id")
                            if dyte_id:
                                requests.delete(
                                    f"{DYTE_API_BASE}/meetings/{meeting_id}/participants/{dyte_id}",
                                    headers=_dyte_headers(),
                                    timeout=5,
                                )
                                logger.info(f"[LOUNGE_JOIN] Removed stale participant {dyte_id} from Dyte, allowing rejoin")
                                duplicate_found = False  # Successfully removed, proceed with join
                                break
                        except Exception as e:
                            logger.warning(f"[LOUNGE_JOIN] Failed to remove stale Dyte participant: {e}")
                            # Don't block, try to join anyway
                            duplicate_found = False
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
        preset = DYTE_PRESET_HOST  # Use host preset for all lounge participants for full media control

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
                f"{DYTE_API_BASE}/meetings/{meeting_id}/participants",
                headers=_dyte_headers(),
                json=body,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            # Validate response
            token = data.get("token")
            participant_id = data.get("id")

            if not token:
                logger.error(f"[LOUNGE_JOIN] No token in Dyte response for user {user.id}")
                return Response({"error": "dyte_token_missing"}, status=500)

            if participant_id:
                logger.info(f"[LOUNGE_JOIN] Success: user {user.id} -> participant {participant_id}")

                # ✅ Store the Dyte participant ID for accurate cleanup on leave
                if lounge_participant:
                    try:
                        lounge_participant.dyte_participant_id = participant_id
                        lounge_participant.save(update_fields=["dyte_participant_id"])
                        logger.info(f"[LOUNGE_JOIN] Stored Dyte participant ID {participant_id} for cleanup")
                    except Exception as e:
                        logger.warning(f"[LOUNGE_JOIN] Failed to store Dyte participant ID: {e}")

            return Response({"token": token, "participant_id": participant_id})
        except requests.exceptions.HTTPError as e:
            logger.error(f"[LOUNGE_JOIN] Dyte API error: {e.response.status_code}")
            return Response({"error": "dyte_api_error"}, status=500)
        except Exception as e:
            logger.error(f"[LOUNGE_JOIN] Exception: {str(e)}")
            return Response({"error": "dyte_join_failed", "detail": str(e)}, status=500)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="lounge-leave-table")
    def lounge_leave_table(self, request, pk=None):
        """
        User leaves a lounge table.
        Removes from both Django DB and Dyte meeting to prevent 409 conflicts on rejoin.
        """
        user = request.user
        event = self.get_object()

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
            meeting_id = table.dyte_meeting_id
            dyte_participant_id = lounge_record.dyte_participant_id

            # 2. Remove from Dyte meeting
            if meeting_id:
                try:
                    # If we have the Dyte participant ID, use it directly for faster removal
                    if dyte_participant_id:
                        delete_resp = requests.delete(
                            f"{DYTE_API_BASE}/meetings/{meeting_id}/participants/{dyte_participant_id}",
                            headers=_dyte_headers(),
                            timeout=10,
                        )
                        if delete_resp.ok:
                            logger.info(f"[LOUNGE_LEAVE] Removed user {user.id} from Dyte meeting {meeting_id} "
                                      f"(participant_id: {dyte_participant_id})")
                        else:
                            logger.warning(f"[LOUNGE_LEAVE] Failed to remove user from Dyte: {delete_resp.status_code}")
                    else:
                        # Fallback: Query Dyte to find the participant by client_specific_id
                        resp = requests.get(
                            f"{DYTE_API_BASE}/meetings/{meeting_id}/participants",
                            headers=_dyte_headers(),
                            params={"limit": 100},
                            timeout=10,
                        )
                        if resp.ok:
                            participants = resp.json().get("data", [])
                            for p in participants:
                                cid = p.get("client_specific_id") or p.get("custom_participant_id")
                                if cid == str(user.id):
                                    # Found the user in Dyte, now remove them
                                    participant_id = p.get("id")
                                    delete_resp = requests.delete(
                                        f"{DYTE_API_BASE}/meetings/{meeting_id}/participants/{participant_id}",
                                        headers=_dyte_headers(),
                                        timeout=10,
                                    )
                                    if delete_resp.ok:
                                        logger.info(f"[LOUNGE_LEAVE] Removed user {user.id} from Dyte meeting {meeting_id}")
                                    else:
                                        logger.warning(f"[LOUNGE_LEAVE] Failed to remove user from Dyte: {delete_resp.status_code}")
                                    break
                except Exception as e:
                    logger.warning(f"[LOUNGE_LEAVE] Error removing from Dyte: {e}")
                    # Don't fail the entire leave operation if Dyte removal fails

            # 3. Delete from Django DB
            lounge_record.delete()

            logger.info(f"[LOUNGE_LEAVE] User {user.id} successfully left table {table.id}. "
                       f"Removed from both Django and Dyte.")

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
        - Removes all users from Dyte meetings
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
                meeting_id = table.dyte_meeting_id
                dyte_participant_id = lounge_record.dyte_participant_id
                user_id = lounge_record.user.id
                username = lounge_record.user.username

                try:
                    # Remove from Dyte meeting if exists
                    if meeting_id:
                        try:
                            if dyte_participant_id:
                                # Use stored Dyte participant ID for direct removal
                                requests.delete(
                                    f"{DYTE_API_BASE}/meetings/{meeting_id}/participants/{dyte_participant_id}",
                                    headers=_dyte_headers(),
                                    timeout=10,
                                )
                                logger.info(f"[LOUNGE_CLOSE] Removed user {user_id} from Dyte meeting {meeting_id}")
                            else:
                                # Fallback: Query Dyte to find the participant
                                resp = requests.get(
                                    f"{DYTE_API_BASE}/meetings/{meeting_id}/participants",
                                    headers=_dyte_headers(),
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
                                                f"{DYTE_API_BASE}/meetings/{meeting_id}/participants/{participant_id}",
                                                headers=_dyte_headers(),
                                                timeout=10,
                                            )
                                            logger.info(f"[LOUNGE_CLOSE] Removed user {user_id} from Dyte meeting {meeting_id}")
                                            break
                        except Exception as e:
                            logger.warning(f"[LOUNGE_CLOSE] Error removing user {user_id} from Dyte: {e}")
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
        response['X-Filename'] = filename  # Expose filename to frontend if needed

        writer = csv.writer(response)
        writer.writerow(['User ID', 'Name', 'Email', 'Registered At', 'Joined Live', 'Watched Replay', 'Status'])

        regs = EventRegistration.objects.filter(event=event).select_related('user').order_by('-registered_at')
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

            writer.writerow([
                r.user.id,
                full_name,
                r.user.email,
                r.registered_at.strftime("%Y-%m-%d %H:%M:%S"),
                "Yes" if r.joined_live else "No",
                "Yes" if r.watched_replay else "No",
                status_label
            ])

        return response

    # ------------------------ My Events ----------------------
    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated], url_path="mine")
    def mine(self, request):
        """
        List events the current user is registered for (newest first).
        """
        qs = (
            Event.objects
            .filter(registrations__user=request.user, registrations__status__in=['registered', 'cancellation_requested'])
            .distinct()
            .annotate(registrations_count=Count('registrations', distinct=True))
            .order_by("-start_time")
        )

        # Apply bucket filter here too if needed
        bucket = (request.query_params.get("bucket") or "").strip().lower()
        if bucket:
            qs = _apply_bucket_filter(qs, bucket)

        page = self.paginate_queryset(qs)
        ser = EventLiteSerializer(page or qs, many=True)
        return self.get_paginated_response(ser.data) if page is not None else Response(ser.data)

    

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="dyte/join")
    def dyte_join(self, request, pk=None):
        """
        Join this event's Dyte meeting.

        - Creates a Dyte meeting if one doesn't exist yet.
        - Adds the current user as participant (host or normal member).
        - Returns authToken for the frontend Dyte SDK.
        """
        event = self.get_object()
        user = request.user

        # 1) Ensure meeting exists
        try:
            meeting_id = _ensure_dyte_meeting_for_event(event)
        except RuntimeError as e:
            logger.error(f"Dyte meeting error for event {event.id}: {str(e)}")
            return Response(
                {"error": "dyte_meeting_error", "detail": str(e)},
                status=500,
            )

        # 1.5) Check if user is BANNED
        if EventRegistration.objects.filter(event=event, user=user, is_banned=True).exists():
            return Response(
                {"error": "banned", "detail": "You are banned from this event."},
                status=403
            )

        # 1.6) Check if user is cancelled/deregistered
        if EventRegistration.objects.filter(event=event, user=user, status__in=['cancelled', 'deregistered']).exists():
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
        is_creator_or_staff = _is_event_host(user, event)

        # Basic guard – hosts can always join; others only if live/published
        if not is_creator_or_staff and event.status not in ("live", "published"):
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

        if requested_is_host is True and not is_creator_or_staff:
            # User asked for host but is not allowed → downgrade to audience
            is_host = False
        elif requested_is_host is None:
            # No explicit role → fall back to automatic rule
            is_host = is_creator_or_staff
        else:
            # Explicit role and allowed
            is_host = requested_is_host

        preset_name = DYTE_PRESET_HOST if is_host else DYTE_PRESET_PARTICIPANT
        role_string = "publisher" if is_host else "audience"

        # Waiting room gating (only for non-hosts)
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
        registration, _created = EventRegistration.objects.get_or_create(
            event=event,
            user=user,
            defaults=defaults,
        )
        if event.waiting_room_enabled and not is_host:
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
            if not _created and registration.was_ever_admitted:
                if registration.admission_status != "admitted":
                    registration.admission_status = "admitted"
                    registration.last_reconnect_at = timezone.now()
                    registration.save(update_fields=["admission_status", "last_reconnect_at"])

                    # Log auto-readmission
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
                # Continue to Dyte token generation for previously admitted users

            # Original grace period + waiting room logic
            elif not _created and not is_in_grace_period:
                # If host hasn't explicitly admitted, keep in waiting
                if registration.admission_status == "admitted" and not registration.admitted_at:
                    registration.admission_status = "waiting"
                    registration.save(update_fields=["admission_status"])

            if not registration.admission_status:
                registration.admission_status = "waiting"
                registration.save(update_fields=["admission_status"])

            if registration.admission_status in {"rejected"}:
                return Response(
                    {"error": "waiting_rejected", "detail": "You were not admitted to this event."},
                    status=403,
                )

            if registration.admission_status != "admitted":
                if not registration.waiting_started_at:
                    # ✅ CRITICAL: This is where users enter the waiting room queue!
                    # Set waiting_started_at ONLY when user actively joins (via dyte/join)
                    # This ensures they don't appear in host's waiting room list until they actively join.
                    # Registration alone does NOT add them to the waiting room.
                    registration.waiting_started_at = timezone.now()
                    registration.save(update_fields=["waiting_started_at"])

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

        # 3) Prepare participant payload
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

        # 4) Call Dyte Add Participant API
        try:
            resp = requests.post(
                f"{DYTE_API_BASE}/meetings/{meeting_id}/participants",
                headers=_dyte_headers(),
                json=body,
                timeout=10,
            )
        except requests.RequestException as e:
            logger.exception("❌ Dyte add participant exception: %s", e)
            return Response(
                {"error": "dyte_network_error", "detail": str(e)},
                status=500,
            )

        if resp.status_code not in (200, 201):
            logger.error("❌ Dyte add participant failed: %s", resp.text[:500])
            return Response(
                {"error": "dyte_participant_error", "detail": resp.text[:500]},
                status=500,
            )

        data = (resp.json() or {}).get("data") or {}
        auth_token = data.get("token")
        if not auth_token:
            return Response(
                {"error": "dyte_token_missing", "detail": "Dyte did not return auth token."},
                status=500,
            )

        # ✅ Mark user as joined_live
        EventRegistration.objects.filter(event=event, user=user).update(
            joined_live=True,
            joined_live_at=timezone.now(),
        )

        # ✅ CRITICAL: Remove user from lounge when they join main meeting
        # This ensures they don't appear in lounge occupants list after transitioning to main
        try:
            from .models import LoungeParticipant
            deleted_count, _ = LoungeParticipant.objects.filter(
                user=user,
                table__event=event
            ).delete()
            if deleted_count > 0:
                logger.info(f"[DYTE_JOIN] Removed user {user.id} from lounge ({deleted_count} table(s)) when joining main meeting")
        except Exception as e:
            logger.warning(f"[DYTE_JOIN] Failed to remove user from lounge: {e}")

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

        return Response(
            {
                "authToken": auth_token,
                "meetingId": meeting_id,
                "presetName": preset_name,
                "role": role_string,
                "isOnBreak": bool(event.is_on_break),
                "mediaLockActive": bool(event.is_on_break),
                "gracePeriodAdmitted": is_grace_period_join,
                "admissionStatus": "admitted",
            }
        )

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="waiting-room/status")
    def waiting_room_status(self, request, pk=None):
        event = self.get_object()
        user = request.user
        if not event.waiting_room_enabled:
            return Response(
                {"waiting_room_enabled": False, "admission_status": "admitted"},
                status=200,
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
        if not _is_event_host(request.user, event):
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
        return Response({"count": len(data), "results": data})

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated], url_path="lounge-participants")
    def lounge_participants(self, request, pk=None):
        """Host-only endpoint: Returns all participants currently in Social Lounge tables."""
        event = self.get_object()
        if not _is_event_host(request.user, event):
            return Response({"detail": "Host only"}, status=403)

        lounge_occupants = LoungeParticipant.objects.filter(
            table__event=event, table__category="LOUNGE"
        ).select_related("user", "table")

        user_ids = [lp.user_id for lp in lounge_occupants]
        regs = {
            r.user_id: r for r in EventRegistration.objects.filter(event=event, user_id__in=user_ids)
        }

        data = []
        for lp in lounge_occupants:
            reg = regs.get(lp.user_id)
            # Enforce single source of truth: only users whose authoritative
            # current_location is social_lounge are shown in lounge participants.
            if reg and reg.current_location != "social_lounge":
                continue
            data.append({
                "user_id": lp.user_id,
                "user_name": lp.user.get_full_name() or lp.user.username,
                "table_id": lp.table_id,
                "table_name": lp.table.name,
                "admission_status": reg.admission_status if reg else "unknown",
                "current_location": reg.current_location if reg else "social_lounge",
            })
        return Response({"count": len(data), "results": data})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="waiting-room/admit")
    def waiting_room_admit(self, request, pk=None):
        event = self.get_object()
        if not _is_event_host(request.user, event):
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
        qs = EventRegistration.objects.filter(event=event, admission_status="waiting")
        if not admit_all:
            qs = qs.filter(user_id__in=user_ids)
        else:
            # For admit_all, require active waiting (waiting_started_at set)
            qs = qs.filter(waiting_started_at__isnull=False)

        # Get list of user IDs being admitted BEFORE update (for WebSocket notification)
        admitted_user_ids = list(qs.values_list('user_id', flat=True))

        # ✅ Mark users as was_ever_admitted so they auto-rejoin if they disconnect
        updated = qs.update(
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

        # ✅ NEW: Remove admitted users from LoungeParticipant table (lounge context)
        LoungeParticipant.objects.filter(
            table__event=event, user_id__in=admitted_user_ids
        ).delete()

        # ✅ NEW: Send WebSocket notification to each admitted user in real-time
        try:
            for admitted_user_id in admitted_user_ids:
                send_admission_status_changed(admitted_user_id, "admitted")
                print(f"[WAITING_ROOM] ✅ Sent real-time notification to user {admitted_user_id}: status=admitted")
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

        return Response({"ok": True, "admitted": updated})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="waiting-room/reject")
    def waiting_room_reject(self, request, pk=None):
        event = self.get_object()
        if not _is_event_host(request.user, event):
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
        if not _is_event_host(request.user, event):
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
        if not _is_event_host(request.user, event):
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
        if not _is_event_host(request.user, event):
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

                next_seat = 0
                while next_seat in occupied_seats:
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
        if EventRegistration.objects.filter(event=event, user=target_user).exists():
            return Response({"detail": "User is already registered for this event."}, status=400)

        # ✅ NEW: Set admission_status based on event's waiting_room_enabled setting
        # If waiting room is enabled, new users start as "waiting" for host admission
        # If waiting room is disabled, new users are automatically "admitted"
        initial_admission_status = "waiting" if event.waiting_room_enabled else "admitted"

        EventRegistration.objects.create(
            event=event,
            user=target_user,
            status="registered",  # Directly registered
            admission_status=initial_admission_status,
            # joined_live / watched_replay defaults are False
        )
        
        # Optionally update attending count immediately if you want them counted strictly
        Event.objects.filter(pk=event.pk).update(attending_count=F("attending_count") + 1)
        return Response({"ok": True, "detail": f"User {target_user.username} added successfully."})

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
        
        if not _is_event_host(request.user, event):
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
        if not _is_event_host(request.user, event):
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
            invite_url = f"{frontend_url}/events/{event_id_str}?invite_token={token}"
            
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
            
        # Check waitlist / capacity
        invited_by_id = payload.get("invited_by")
        
        status_val = "registered"
        if event.max_participants and event.registrations.filter(status="registered").count() >= event.max_participants:
            if getattr(event, "waitlist_enabled", False):
                status_val = "waitlisted"
            else:
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
                
        registration, created = EventRegistration.objects.get_or_create(
            event=event,
            user=request.user,
            defaults={
                "status": status_val,
            }
        )
        if not created and registration.status not in ["registered", "waitlisted"]:
            registration.status = status_val
            registration.save(update_fields=["status"])
            status_msg = "created"
        elif not created:
            status_msg = "already_registered"
        else:
            status_msg = "created"
            
        return Response({
            "ok": True,
            "status": status_msg,
            "event_id": event.id,
            "registration_status": registration.status
        })


# ============================================================
# ================= Public Event Detail View =================
# ============================================================
class PublicEventDetailView(generics.RetrieveAPIView):
    """
    Public-facing endpoint for event landing pages.
    - No authentication required
    - Only returns public event data (no sensitive fields)
    - Only available for published/live events
    """
    permission_classes = [AllowAny]
    serializer_class = PublicEventSerializer
    queryset = Event.objects.filter(
        status__in=["published", "live"]
    ).select_related("community").prefetch_related("sessions")
    lookup_field = "slug"
    lookup_url_kwarg = "slug"


# ============================================================
# ================= Event Registration ViewSet ===============
# ============================================================
class EventRegistrationViewSet(viewsets.ModelViewSet):
    """
    CRUD for a user's event registrations + Actions for cancellation.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = EventRegistrationSerializer

    def destroy(self, request, *args, **kwargs):
        """
        Soft delete:
        - If user -> 'cancelled'
        - If admin/owner -> 'deregistered'
        """
        reg = self.get_object()
        user = request.user
        
        # Determine strict permissions if not already handled by 'get_queryset' or permission_classes
        is_owner_of_reg = (reg.user_id == user.id)
        is_event_owner = (reg.event.created_by_id == user.id)
        is_staff = user.is_staff or getattr(user, "is_superuser", False)

        if not (is_owner_of_reg or is_event_owner or is_staff):
            return Response({"detail": "Not authorized."}, status=403)

        if is_owner_of_reg and not (is_event_owner or is_staff):
            # User cancelling their own
            reg.status = "cancelled"
            reg.save(update_fields=["status"])
            Event.objects.filter(pk=reg.event_id).update(attending_count=F("attending_count") - 1)
            return Response(status=status.HTTP_204_NO_CONTENT)
        
        # Host/Admin deregistering
        reg.status = "deregistered"
        reg.save(update_fields=["status"])
        Event.objects.filter(pk=reg.event_id).update(attending_count=F("attending_count") - 1)
        
        # Optional: Kick from live meeting if active?
        # Use helper from EventViewSet if needed, or just rely on 'status' check in join/poll APIs.
        
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_queryset(self):
        """
        Admins/Staff/Event Owners -> See all relevant.
        Normal users -> See only their own.
        """
        user = self.request.user
        qs = EventRegistration.objects.select_related("event").order_by("-registered_at")

        # If strict permissions desired:
        if user.is_staff or getattr(user, "is_superuser", False):
            return qs
        
        # If user is event owner, they need access to registrations for that event
        # Logic: Show if (I am the registrant) OR (I created the event)
        qs = qs.filter(Q(user=user) | Q(event__created_by=user)).distinct()

        # Manual filter support for ?event=ID
        event_id = self.request.query_params.get("event")
        if event_id:
            qs = qs.filter(event_id=event_id)

        return qs

    def create(self, request, *args, **kwargs):
        # 1. Custom check for existing registration to handle re-registration
        user = request.user
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
        serializer.save(user=self.request.user)

    @action(detail=False, methods=["get"], url_path="mine")
    def mine(self, request):
        """
        Alias to list only my registrations with pagination support.
        Always strict to request.user.
        """
        qs = self.get_queryset().filter(
            user=request.user,
            status__in=['registered', 'cancellation_requested']
        )
        page = self.paginate_queryset(qs)
        ser = self.get_serializer(page or qs, many=True)
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
        Future: Trigger refund.
        """
        reg = self.get_object()
        # Check permission: Admins or Event Owner
        is_admin = request.user.is_staff or getattr(request.user, "is_superuser", False)
        is_owner = (reg.event.created_by_id == request.user.id)
        
        if not (is_admin or is_owner):
            return Response({"error": "permission_denied"}, status=403)

        reg.status = "cancelled"
        reg.save(update_fields=["status"])
        Event.objects.filter(pk=reg.event_id).update(attending_count=F("attending_count") - 1)
        # TODO: Process Refund Logic Here
        
        return Response({"ok": True, "status": reg.status})

    @action(detail=True, methods=["post"], url_path="reject_cancellation")
    def reject_cancellation(self, request, pk=None):
        """
        Admin/Owner rejects cancellation -> reverts to registered.
        """
        reg = self.get_object()
        is_admin = request.user.is_staff or getattr(request.user, "is_superuser", False)
        is_owner = (reg.event.created_by_id == request.user.id)
        
        if not (is_admin or is_owner):
            return Response({"error": "permission_denied"}, status=403)

        reg.status = "registered"
        reg.save(update_fields=["status"])
        return Response({"ok": True, "status": reg.status})

    @action(detail=True, methods=["post"], url_path="deregister")
    def deregister(self, request, pk=None):
        """
        Admin/Owner deregisters a user -> sets status=deregistered (Soft Delete).
        """
        reg = self.get_object()
        is_admin = request.user.is_staff or getattr(request.user, "is_superuser", False)
        is_owner = (reg.event.created_by_id == request.user.id)

        if not (is_admin or is_owner):
            return Response({"error": "permission_denied"}, status=403)

        reg.status = "deregistered"
        # Reset admission status so they aren't stuck in "waiting" or "admitted" state if they rejoin later
        reg.admission_status = "waiting" if reg.event.waiting_room_enabled else "admitted"
        reg.joined_live = False
        reg.is_online = False
        reg.save(update_fields=["status", "admission_status", "joined_live", "is_online"])
        Event.objects.filter(pk=reg.event_id).update(attending_count=F("attending_count") - 1)
        
        return Response({"ok": True, "status": reg.status})

    @action(detail=True, methods=["post"], url_path="reinstate")
    def reinstate(self, request, pk=None):
        """
        Admin/Owner reinstates a deregistered/cancelled user -> sets status=registered.
        """
        reg = self.get_object()
        is_admin = request.user.is_staff or getattr(request.user, "is_superuser", False)
        is_owner = (reg.event.created_by_id == request.user.id)

        if not (is_admin or is_owner):
            return Response({"error": "permission_denied"}, status=403)

        reg.status = "registered"
        # Re-evaluate admission status
        reg.admission_status = "waiting" if reg.event.waiting_room_enabled else "admitted"
        reg.save(update_fields=["status", "admission_status"])
        Event.objects.filter(pk=reg.event_id).update(attending_count=F("attending_count") + 1)
        
        return Response({"ok": True, "status": reg.status})
    
    

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
            event = Event.objects.get(dyte_meeting_id=meeting_id)
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
        event.save(update_fields=["recording_url", "updated_at"])

        logger.info(
            "✅ Saved recording for event=%s meeting=%s s3_key=%s",
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
        if not _is_event_host(self.request.user, event):
            raise PermissionDenied("Only event creators/staff can add sessions")

        serializer.save(event=event)

    def perform_update(self, serializer):
        """Update session with permission check."""
        session = self.get_object()
        event = session.event

        # Check permission: must be event creator or staff
        if not _is_event_host(self.request.user, event):
            raise PermissionDenied("Only event creators/staff can update sessions")

        serializer.save()

    def perform_destroy(self, instance):
        """Delete session with permission check."""
        event = instance.event

        # Check permission: must be event creator or staff
        if not _is_event_host(self.request.user, event):
            raise PermissionDenied("Only event creators/staff can delete sessions")

        instance.delete()

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def start_live(self, request, event_id=None, pk=None):
        """Start a session live (create/use Dyte meeting)."""
        session = self.get_object()
        event = session.event

        if not _is_event_host(request.user, event):
            raise PermissionDenied("Only event hosts can start sessions")

        if session.is_live:
            return Response({'error': 'Session is already live'}, status=400)

        # Create or use Dyte meeting
        if session.use_parent_meeting:
            # Use parent event's meeting
            if not event.dyte_meeting_id:
                # Create meeting for event if doesn't exist
                meeting = create_dyte_meeting(event.title)
                event.dyte_meeting_id = meeting['id']
                event.save(update_fields=['dyte_meeting_id'])
            session.dyte_meeting_id = event.dyte_meeting_id
        else:
            # Create separate meeting for this session
            meeting = create_dyte_meeting(session.title)
            session.dyte_meeting_id = meeting['id']

        session.is_live = True
        session.live_started_at = timezone.now()
        session.save(update_fields=['is_live', 'live_started_at', 'dyte_meeting_id'])

        return Response(EventSessionSerializer(session, context={'request': request}).data)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def end_live(self, request, event_id=None, pk=None):
        """End a live session."""
        session = self.get_object()
        event = session.event

        if not _is_event_host(request.user, event):
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

        if not _is_event_host(request.user, event):
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
        tables = LoungeTable.objects.filter(event_id=event_id).prefetch_related('participants__user')
        state = []
        for t in tables:
            participants = {}
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
                "dyte_meeting_id": t.dyte_meeting_id,
                "icon_url": icon_url,
                "participants": participants
            })
        return state
    except Exception as e:
        logger.warning(f"[LOUNGE_STATE] Failed to build lounge state for event {event_id}: {e}")
        return []
