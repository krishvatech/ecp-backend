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
import os                          # NOTE: intentionally kept even if duplicated later
import base64                      # NOTE: currently unused; kept as requested
import requests      
import time
import random

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
from rest_framework import permissions, viewsets, status, views   # NOTE: permissions, views may be unused; kept
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
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

# ============================================================
# ===================== Local App Imports ====================
# ============================================================

from .models import Event, EventRegistration
from .serializers import (
    EventSerializer,                 # If you use it in this file for create/update/detail
    EventLiteSerializer,             # For lighter list/mine responses
    EventRegistrationSerializer,     # Used by EventRegistrationViewSet
)

# ============================================================
# ================== Env / Settings Bootstrap ================
# ============================================================
import os  # NOTE: duplicate import retained intentionally

from pathlib import Path
from dotenv import load_dotenv

# Resolve project root and load .env so AGORA_* variables work locally as well
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(os.path.join(BASE_DIR, ".env"))

User = get_user_model()

logger = logging.getLogger("events")

# --- Dyte configuration ---
DYTE_API_BASE = os.getenv("DYTE_API_BASE", "https://api.dyte.io/v2")
DYTE_AUTH_HEADER = os.getenv("DYTE_AUTH_HEADER", "")
DYTE_PRESET_HOST = os.getenv("DYTE_PRESET_NAME_HOST", os.getenv("DYTE_PRESET_NAME", "group_call_host"))
DYTE_PRESET_PARTICIPANT = os.getenv("DYTE_PRESET_NAME_MEMBER", "group_call_participant")
AWS_S3_BUCKET = os.getenv("AWS_BUCKET_NAME", "events-agora-recordings")
AWS_S3_REGION = os.getenv("AWS_S3_REGION", "eu-central-1") 
logger = logging.getLogger(__name__)

# --- Cloudflare RealtimeKit recording config ---
RTK_API_BASE = os.getenv("RTK_API_BASE", "https://api.realtime.cloudflare.com/v2")
RTK_ORG_ID = os.getenv("RTK_ORG_ID", "")
RTK_API_KEY = os.getenv("RTK_API_KEY", "")


def _rtk_headers():
    """
    HTTP headers for Cloudflare RealtimeKit REST API.
    Uses Basic auth with base64("<ORG_ID>:<API_KEY>").
    """
    if not (RTK_ORG_ID and RTK_API_KEY):
        raise RuntimeError("RTK_ORG_ID / RTK_API_KEY are not configured")
    token_bytes = f"{RTK_ORG_ID}:{RTK_API_KEY}".encode("utf-8")
    basic_token = base64.b64encode(token_bytes).decode("ascii")
    return {
        "Authorization": f"Basic {basic_token}",
        "Content-Type": "application/json",
    }

def _dyte_headers():
    """HTTP headers for Dyte REST API."""
    if not DYTE_AUTH_HEADER:
        raise RuntimeError("DYTE_AUTH_HEADER is not configured")
    return {
        "Authorization": DYTE_AUTH_HEADER,
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


# ============================================================
# ======================== Event ViewSet =====================
# ============================================================
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
                Q(created_by_id=user.id)
            ).distinct()

        # ---- Filters (applied only when provided) ----
        params = self.request.query_params
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
            qs = qs.exclude(status="ended")
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

        qs = qs.annotate(registrations_count=Count('registrations', distinct=True))
        return qs
    

    # ---------------------- Permissions ----------------------
    def get_permissions(self):
        """
        Allow anonymous access to list/retrieve. All other actions require auth.
        """
        if self.action in ["list", "retrieve"]:
            return [AllowAny()]
        return super().get_permissions()

    # ---------------------- Create Hook ----------------------
    def perform_create(self, serializer):
        """
        Enforce that:
          - request includes an 'community' (via serializer validated_data)
          - the authenticated user is a member of that community
        Then set created_by to the current user.
        """
        # With the serializer fix below, validated_data has 'community' (a model instance)
        org = serializer.validated_data.get("community")
        if not org:
            raise PermissionDenied("community_id is required.")
        # Ensure the user is a member of that org
        if not self.request.user.community.filter(id=org.id).exists():
            raise PermissionDenied("You must be a member of the community to create events.")
        # Attach creator automatically
        serializer.save(created_by=self.request.user, status="published")

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
                obj, was_created = EventRegistration.objects.get_or_create(user=request.user, event=ev)
                if was_created:
                    # keep a running count on Event (optional, commented out until you add the field)
                    # Event.objects.filter(pk=ev.pk).update(attending_count=F("attending_count") + 1)
                    created.append(ev.id)

        return Response({"ok": True, "created": created, "count": len(created)})


    # POST /api/events/{id}/register/
    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="register")
    def register(self, request, pk=None):
        """
        Register the current user for a single event.
        """
        event = self.get_object()
        obj, was_created = EventRegistration.objects.get_or_create(user=request.user, event=event)
        # if was_created:
        #     Event.objects.filter(pk=event.pk).update(attending_count=F("attending_count") + 1)
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

            if action_type == "start":
                event.status = "live"
                event.is_live = True
                event.live_started_at = timezone.now()
                event.live_ended_at = None
                event.active_speaker_id = host_user_id or event.created_by_id
                event.attending_count = 0
            else:  # end
                event.status = "ended"
                event.is_live = False
                event.live_ended_at = timezone.now()

            event.save(update_fields=[
                "status",
                "is_live",
                "live_started_at",
                "live_ended_at",
                "active_speaker_id",
                "attending_count",
                "updated_at",
            ])

        # 🔴 NEW: start Cloudflare recording when meeting goes live
        if action_type == "start":
            try:
                _start_rtk_recording_for_event(event)
            except Exception:
                # Already logged inside helper; do not break the API
                pass

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
        Any authenticated participant may hit this; repeated calls are harmless.
        """
        event = self.get_object()

        event.status = "ended"
        event.is_live = False
        event.live_ended_at = timezone.now()
        event.save(update_fields=["status", "is_live", "live_ended_at", "updated_at"])

        return Response(
            {"message": "Meeting ended", "status": event.status, "event_id": event.id}
        )
    
    
    @action(detail=False, methods=["post"], url_path="download-recording")
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
        serializer = EventRegistrationSerializer(
            qs, many=True, context={"request": request}
        )
        return Response(serializer.data)

    # ------------------------ My Events ----------------------
    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated], url_path="mine")
    def mine(self, request):
        """
        List events the current user is registered for (newest first).
        """
        qs = (
            Event.objects
            .filter(registrations__user=request.user)
            .distinct()
            .annotate(registrations_count=Count('registrations', distinct=True))
            .order_by("-start_time")
        )
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

        # Basic guard – adjust if you want stricter checks
        if event.status not in ("live", "published"):
            return Response(
                {"error": "event_not_live", "detail": "Event is not live yet."},
                status=400,
            )

        # 1) Ensure meeting exists
        try:
            meeting_id = _ensure_dyte_meeting_for_event(event)
        except RuntimeError as e:
            return Response(
                {"error": "dyte_meeting_error", "detail": str(e)},
                status=500,
            )

        # 2) Decide host vs participant preset
        community_owner_id = getattr(event.community, "owner_id", None)
        # Who is *allowed* to be host?
        is_creator_or_staff = (
            event.created_by_id == user.id
            or user.is_staff
            or community_owner_id == user.id
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

        # 3) Prepare participant payload
        name = (getattr(user, "full_name", "") or getattr(user, "get_full_name", lambda: "")()) or user.username
        picture = ""
        try:
            profile = getattr(user, "profile", None)
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

        return Response(
            {
                "authToken": auth_token,
                "meetingId": meeting_id,
                "presetName": preset_name,
                "role": role_string,
            }
        )


# ============================================================
# ================= Event Registration ViewSet ===============
# ============================================================
class EventRegistrationViewSet(viewsets.ModelViewSet):
    """
    CRUD for a user's event registrations.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = EventRegistrationSerializer

    def get_queryset(self):
        """
        Only return the current user's registrations, newest first.
        """
        return (
            EventRegistration.objects
            .select_related("event")
            .filter(user=self.request.user)
            .order_by("-registered_at")
        )

    def perform_create(self, serializer):
        """
        Force user= current request.user on create.
        """
        serializer.save(user=self.request.user)

    @action(detail=False, methods=["get"], url_path="mine")
    def mine(self, request):
        """
        Alias to list only my registrations with pagination support.
        """
        qs = self.get_queryset()
        page = self.paginate_queryset(qs)
        ser = self.get_serializer(page or qs, many=True)
        return self.get_paginated_response(ser.data) if page is not None else Response(ser.data)
    
    

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
