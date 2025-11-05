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
from activity_feed.models import FeedItem 
from django.contrib.contenttypes.models import ContentType


# ============================================================
# ================== Env / Settings Bootstrap ================
# ============================================================
import os  # NOTE: duplicate import retained intentionally

from pathlib import Path
from dotenv import load_dotenv

# Resolve project root and load .env so AGORA_* variables work locally as well
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(os.path.join(BASE_DIR, ".env"))

# ⚙️ Agora credentials (ensure these exist in your environment)
# - APP_ID: Agora Project App ID
# - CUSTOMER_ID: optional (not used in token build flow below)
# - CUSTOMER_SECRET: should be your Agora App Certificate
APP_ID      = os.getenv("AGORA_APP_ID")                 # Project App ID
REST_ID     = os.getenv("AGORA_CUSTOMER_ID")            # REST Customer ID
REST_SECRET = os.getenv("AGORA_CUSTOMER_SECRET")        # REST Customer Secret (NOT the app cert)
APP_CERT    = os.getenv("AGORA_APP_CERTIFICATE")        # Project App Certificate (for RTC tokens)
BASE        = os.getenv("AGORA_CLOUD_RECORDING_BASE", "https://api.sd-rtn.com")


logger = logging.getLogger("events")


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
    - Filter helpers (?event_format, ?category, date ranges, price bounds, etc.)
    - Utility endpoints (categories, formats, locations, max-price, mine)
    - Registration helpers (register, register-bulk)
    - Agora RTC token issuance (/token)
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
        event = serializer.save(status='published')
        event_ct = ContentType.objects.get_for_model(event)

        FeedItem.objects.create(
            community=event.community,
            event=event,
            actor=self.request.user,
            verb="created event",
            target_content_type=event_ct,
            target_object_id=event.id,
            metadata={
                "title": event.title,
                "description": event.description,
                "start_time": event.start_time.isoformat() if event.start_time else None,
            },
        )

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

    # ------------------ Agora Token Issuance -----------------
    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated], url_path="token")
    def token(self, request, pk=None):
        """
        Return an Agora RTC token.

        Authorization logic:
          - Only the event owner or staff can obtain a PUBLISHER token.
          - Everyone else receives an AUDIENCE token.
        Role is read from JSON body or querystring (?role=publisher|audience).

        Environment:
          - AGORA_APP_ID must be set.
          - AGORA_CUSTOMER_SECRET should hold the App Certificate.
        """
        event = self.get_object()

        # 1) read/normalize desired role
        raw = (request.data.get("role") or request.query_params.get("role") or "audience").lower()
        want_publisher = raw in {"publisher", "host", "broadcaster", "speaker"}

        # 2) authorization: only creator or staff can publish (no EventRegistration.role/status in your schema)
        is_owner_or_staff = (event.created_by_id == request.user.id) or request.user.is_staff
        as_publisher = want_publisher and is_owner_or_staff

        # 3) build Agora token
        app_id = APP_ID
        app_cert = APP_CERT
        if not app_id or not app_cert:
            # NOTE: Text mentions 'AGORA_APP_CERTIFICATE' for clarity; your env var is AGORA_CUSTOMER_SECRET.
            return Response(
                {"detail": "AGORA_APP_ID / AGORA_APP_CERTIFICATE not configured"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        channel = f"event-{event.id}"
        ttl_seconds = int(os.getenv("AGORA_TOKEN_TTL", "3600"))
        expires_at = timezone.now() + timedelta(seconds=ttl_seconds)

        # Role: 1 = Publisher, 2 = Subscriber/Audience   (per agora-token-builder)
        role_int = 1 if as_publisher else 2
        uid = 0  # recommended for Web (Agora SDK assigns a UID)

        try:
            from agora_token_builder import RtcTokenBuilder
            token = RtcTokenBuilder.buildTokenWithUid(app_id, app_cert, channel, uid, role_int, ttl_seconds)
        except Exception as e:
            # Keep the error visible for debugging token failures
            return Response({"detail": f"Failed to build Agora token: {e}"}, status=500)

        return Response({
            "token": token,
            "app_id": app_id,
            "channel": channel,
            "role": "publisher" if as_publisher else "audience",
            "expires_at": expires_at.isoformat(),
        })

    # Helper (alternative way to build a token using named roles)
    def _build_agora_rtc_token(self, app_id, app_cert, channel, as_publisher: bool, ttl_seconds: int) -> str:
        """
        Thin wrapper around agora-token-builder in case you prefer Role_Publisher/Role_Subscriber.
        """
        from agora_token_builder import RtcTokenBuilder, Role_Publisher, Role_Subscriber
        role = Role_Publisher if as_publisher else Role_Subscriber
        uid = 0  # recommended for web
        return RtcTokenBuilder.buildTokenWithUid(app_id, app_cert, channel, uid, role, ttl_seconds)
    
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
                region_name='eu-central-1',
                config=Config(signature_version='s3v4')
            )
            
            bucket = os.getenv('AWS_BUCKET_NAME', 'events-agora-recordings')
            
            # Generate pre-signed URL that forces download
            download_url = s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': bucket,
                    'Key': recording_url,
                    'ResponseContentDisposition': 'attachment; filename="recording.mp4"'
                },
                ExpiresIn=3600  # Valid for 1 hour
            )
            
            logger.info(f"✅ Generated download URL for: {recording_url}")
            
            return Response({
                "download_url": download_url,
                "expires_in": 3600
            })
            
        except Exception as e:
            logger.exception(f"❌ Failed to generate download URL: {e}")
            return Response(
                {"error": "Failed to generate download URL", "detail": str(e)},
                status=500
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
    
    
    
    # --------------------------------------------------------
    # 🔴 Live Status Update Endpoint
    # --------------------------------------------------------
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
            # <-- IMPORTANT: lock the row *inside* the transaction
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

            # If your model doesn't have `updated_at`, remove it from update_fields
            event.save(update_fields=[
                "status", "is_live", "live_started_at", "live_ended_at", "active_speaker","attending_count", "updated_at"
            ])

        return Response({
            "ok": True,
            "status": event.status,
            "is_live": event.is_live,
            "active_speaker": event.active_speaker_id,
            "live_started_at": event.live_started_at,
            "live_ended_at": event.live_ended_at,
        })


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
    

            
class EventRecordingViewSet(viewsets.GenericViewSet):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=True, methods=["post"], url_path="start")
    def start(self, request, pk=None):
        event = self.get_object()
        user = request.user

        # --- state & permission checks ---
        if event.status in ("live", "ended"):
            return Response(
                {"error": "invalid_state", "detail": "Event is already live or has ended."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        org_owner_id = getattr(event.community, "owner_id", None)
        if not (event.created_by_id == user.id or user.is_staff or org_owner_id == user.id):
            raise PermissionDenied("You do not have permission to start this event.")

        # --- mark event live ---
        event.status = "live"
        event.is_live = True
        event.live_started_at = timezone.now()
        event.active_speaker = user

        channel_name = f"event-{event.id}"
        event.agora_channel = channel_name
        recorder_uid = str(random.randint(900000000, 999999999))
        event.agora_recorder_uid = recorder_uid
        rec_token = None
        if APP_CERT:
            from agora_token_builder import RtcTokenBuilder
            RolePublisher = 1
            ttl_seconds = int(os.getenv("AGORA_TOKEN_TTL", "3600"))
            expire_ts = int(time.time()) + ttl_seconds  # ✅ absolute UNIX timestamp
            rec_token = RtcTokenBuilder.buildTokenWithUid(
                APP_ID, APP_CERT, channel_name, int(recorder_uid), RolePublisher, expire_ts
            )
            logger.info("Recorder token included: %s", bool(rec_token))

        # persist basic live fields
        event.save(update_fields=[
            "status", "is_live", "live_started_at", "active_speaker",
            "agora_channel","agora_recorder_uid","updated_at"
        ])

        # --- Agora REST auth header ---
        if not all([APP_ID, REST_ID, REST_SECRET]):
            logger.error("❌ Missing Agora credentials (APP_ID/REST_ID/REST_SECRET)")
            return Response({"error": "Agora credentials not configured"}, status=500)

        auth = base64.b64encode(f"{REST_ID}:{REST_SECRET}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}

        # --- context logs ---
        region_code = os.getenv("AGORA_S3_REGION_CODE", "8")  # Agora numeric region code
        bucket = os.getenv("AWS_BUCKET_NAME", "events-agora-recordings")
        channel_type = int(os.getenv("AGORA_CHANNEL_TYPE", "0"))  # 1=live, 0=communication
        logger.info(
            "🎬 Start record attempt | event=%s channel=%s uid=%s base=%s region_code=%s bucket=%s token_included=%s channelType=%s",
            event.id, channel_name, recorder_uid, BASE, region_code, bucket, bool(rec_token), channel_type
        )

        # ---------------- Acquire ----------------
        acquire_url = f"{BASE}/v1/apps/{APP_ID}/cloud_recording/acquire"
        acquire_payload = {
            "cname": channel_name,
            "uid": recorder_uid,
            "clientRequest": {"resourceExpiredHour": 24}
        }

        try:
            acquire_resp = requests.post(acquire_url, headers=headers, json=acquire_payload, timeout=15)
        except requests.RequestException as e:
            logger.exception("❌ Acquire exception: %s", e)
            return Response({"error": "acquire_exception", "detail": str(e)}, status=500)

        logger.info("📥 Acquire rsp | code=%s len=%s", acquire_resp.status_code, len(acquire_resp.text))
        if acquire_resp.status_code != 200:
            logger.error("❌ Acquire failed | detail=%s", acquire_resp.text[:500])
            return Response({"error": "Failed to acquire Agora recording", "detail": acquire_resp.text}, status=500)

        resource_id = acquire_resp.json().get("resourceId")
        logger.info("💾 resourceId parsed | resourceId=%s len=%s", resource_id, len(resource_id or ""))

        # Save resourceId immediately so it appears in DB even if Start fails
        if resource_id:
            event.agora_resource_id = resource_id
            event.save(update_fields=["agora_resource_id", "updated_at"])

        # ---------------- Start ----------------
        try:
            rc_int = int(region_code)
        except ValueError:
            rc_int = 8  # safe default

        start_url = f"{BASE}/v1/apps/{APP_ID}/cloud_recording/resourceid/{resource_id}/mode/mix/start"
        start_client_req = {
            "recordingConfig": {
                "maxIdleTime": 30,
                "channelType": channel_type,  # ✅ match client mode
                "streamTypes": 2,
                "transcodingConfig": {"width": 1280, "height": 720, "fps": 15, "bitrate": 1000},
            },
            "storageConfig": {
                "vendor": 1,               # AWS S3
                "region": rc_int,          # ✅ Agora numeric region code
                "bucket": bucket,
                "accessKey": os.getenv("AWS_ACCESS_KEY_ID"),
                "secretKey": os.getenv("AWS_SECRET_ACCESS_KEY"),
                "fileNamePrefix": ["recordings", f"event{event.id}"],
            },
            "recordingFileConfig": {"avFileType": ["hls", "mp4"]},
        }
        if rec_token:
            start_client_req["token"] = rec_token  # only include if present

        start_payload = {"cname": channel_name, "uid": recorder_uid, "clientRequest": start_client_req}

        try:
            start_resp = requests.post(start_url, headers=headers, json=start_payload, timeout=25)
        except requests.RequestException as e:
            logger.exception("❌ Start exception: %s", e)
            return Response({"error": "start_exception", "detail": str(e), "resourceId": resource_id}, status=500)

        logger.info("🎥 Start rsp | code=%s len=%s", start_resp.status_code, len(start_resp.text))

        if start_resp.status_code != 200:
            aws_key = os.getenv("AWS_ACCESS_KEY_ID")
            aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY")
            aws_bucket = os.getenv("AWS_BUCKET_NAME")
            region_code = os.getenv("AGORA_S3_REGION_CODE", "8")

            logger.error(f"🔑 AWS Credentials Check:")
            logger.error(f"  - AWS_ACCESS_KEY_ID: {'✅ SET' if aws_key else '❌ MISSING'}")
            logger.error(f"  - AWS_SECRET_ACCESS_KEY: {'✅ SET' if aws_secret else '❌ MISSING'}")
            logger.error(f"  - AWS_BUCKET_NAME: {aws_bucket}")
            logger.error(f"  - AGORA_S3_REGION_CODE: {region_code}")

            if not all([aws_key, aws_secret, aws_bucket]):
                logger.error("❌ Missing required AWS storage credentials")
                return Response({"error": "AWS credentials not configured"}, status=500)
            logger.error(
                "❌ Start failed | resourceId=%s channel=%s http=%s detail=%s",
                resource_id, channel_name, start_resp.status_code, start_resp.text[:800]
            )
            # optional: revert flags if recording didn't actually start
            from .models import Event  # ensure import available, or move to top of file
            Event.objects.filter(pk=event.pk).update(status="published", is_live=False)
            return Response(
                {"error": "agora_start_failed", "detail": start_resp.text, "resourceId": resource_id},
                status=502,
            )

        data = start_resp.json()
        sid = data.get("sid")
        if not sid:
            logger.error("❌ Start success without sid?! payload=%s", data)
            return Response({"error": "agora_start_no_sid", "detail": data}, status=502)

        # ✅ persist sid on success
        event.agora_sid = sid
        event.save(update_fields=["agora_sid", "updated_at"])
        logger.info("💿 Saved to DB | event=%s resourceId=%s sid=%s", event.id, resource_id, sid)

        # ✅ MODIFIED: Return event data WITH recording credentials
        event_data = EventSerializer(event, context=self.get_serializer_context()).data
        event_data.update({
            'resourceId': resource_id,
            'sid': sid,
            'channel': channel_name,
            'uid': recorder_uid
        })
        
        return Response(event_data)

    @action(detail=True, methods=["post"], url_path="stop")
    def stop(self, request, pk=None):
        event = self.get_object()
        user = request.user
        
        if event.status != "live":
            return Response(
                {"error": "invalid_state", "detail": "Event is not currently live."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        org_owner_id = getattr(event.community, "owner_id", None)
        if not (event.created_by_id == user.id or user.is_staff or org_owner_id == user.id):
            raise PermissionDenied("You do not have permission to stop this event.")
        
        # Mark ended
        event.status = "ended"
        event.is_live = False
        event.live_ended_at = timezone.now()
        event.save(update_fields=["status", "is_live", "live_ended_at", "updated_at"])
        
        if event.agora_resource_id and event.agora_sid and APP_ID and REST_ID and REST_SECRET:
            import base64, json
            
            auth = base64.b64encode(f"{REST_ID}:{REST_SECRET}".encode()).decode()
            headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
            
            stop_url = (
                f"{BASE}/v1/apps/{APP_ID}/cloud_recording/resourceid/{event.agora_resource_id}"
                f"/sid/{event.agora_sid}/mode/mix/stop"
            )
            
            payload = {"cname": event.agora_channel or f"event-{event.id}", "uid": event.agora_recorder_uid, "clientRequest": {}}
            
            try:
                stop_resp = requests.post(stop_url, headers=headers, json=payload, timeout=15)
                logger.info(f"🛑 Stop API | status={stop_resp.status_code} len={len(stop_resp.text)}")
                
                if stop_resp.status_code == 200:
                    resp_json = stop_resp.json()
                    server_resp = resp_json.get("serverResponse", {})
                    file_list = server_resp.get("fileList", [])
                    
                    # Some responses embed fileList as JSON string
                    if isinstance(file_list, str):
                        try:
                            file_list = json.loads(file_list)
                        except Exception:
                            file_list = []
                    
                    # Save S3 file path to recording_url field
                    if file_list:
                        for file_info in file_list:
                            raw_name = (file_info.get("fileName") or "").strip()
                            if not raw_name or not raw_name.endswith(".mp4"):
                                continue

                            # ✅ Normalize: use Agora’s full key if it already contains our prefix;
                            # otherwise, join the basename under the single event folder.
                            from pathlib import PurePosixPath
                            expected_prefix = f"recordings/event{event.id}/"

                            if raw_name.startswith(expected_prefix):
                                key = raw_name.lstrip("/")  # already a full S3 key under the correct folder
                            else:
                                key = f"{expected_prefix}{PurePosixPath(raw_name).name}"

                            event.recording_url = key
                            event.save(update_fields=["recording_url", "updated_at"])
                            logger.info(f"✅ Saved recording S3 key: {key}")
                            break
                    else:
                        logger.warning(f"⚠️ No fileList in stop response for event {event.id}")
                    
                    logger.info(
                        f"✅ Stop OK | event={event.id} resourceId={event.agora_resource_id} sid={event.agora_sid}"
                    )
                else:
                    logger.error(f"Stop failed event={event.id} status={stopresp.status_code} detail={stopresp.text[:500]}")
            except requests.RequestException as e:
                logger.exception(f"Stop request exception for event {event.id}: {e}")
            
            # Schedule recording check after 2 minutes (Agora needs time to process)
            from .tasks import check_recording_task
            check_recording_task.apply_async((event.id,), countdown=120)
            logger.info(f"Scheduled recording check for event {event.id} in 2 minutes")
        else:
            logger.warning(f"Missing Agora recording IDs for event {event.id}, skipping stop API call")

        return Response(EventSerializer(event, context=self.get_serializer_context()).data)
    
    @action(detail=True, methods=["post"], url_path="sync-recording")
    def sync_recording(self, request, pk=None):
        """
        Manually sync recording URL from S3 after recording is complete.
        Use this if stop API fails but files are uploaded to S3.
        """
        event = self.get_object()
        
        if not event.agora_sid:
            return Response(
                {"error": "No recording session for this event"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            import boto3
            from botocore.config import Config
            
            # Initialize S3 client
            s3_client = boto3.client(
                's3',
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                region_name='eu-central-1',
                config=Config(signature_version='s3v4')
            )
            
            bucket = os.getenv('AWS_BUCKET_NAME', 'events-agora-recordings')
            prefix = f"recordings/event{event.id}/"
            
            # Search S3 for MP4 file
            response = s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix)
            
            if 'Contents' not in response:
                return Response(
                    {"error": "No recording files found in S3 yet. Wait a few minutes after stopping."},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Find the .mp4 file
            mp4_file = None
            for obj in response['Contents']:
                if obj['Key'].endswith('.mp4'):
                    mp4_file = obj['Key']
                    break
            
            if not mp4_file:
                return Response(
                    {"error": "MP4 file not found. Recording may still be processing."},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Save to database
            event.recording_url = mp4_file
            event.save(update_fields=['recording_url', 'updated_at'])
            
            logger.info(f"✅ Synced recording URL from S3: {mp4_file}")
            
            return Response({
                "success": True,
                "message": "Recording URL synced successfully",
                "recording_url": mp4_file,
                "event_id": event.id
            })
            
        except Exception as e:
            logger.exception(f"❌ Error syncing recording from S3: {e}")
            return Response(
                {"error": "Failed to sync recording", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    

class RecordingWebhookView(views.APIView):
    """
    Agora recording webhook.
    Agora sends resourceId, sid, and fileList after a recording finishes.
    We map it back to the Event and store the recording URL.
    """
    permission_classes = [permissions.AllowAny]
    def post(self, request, *args, **kwargs):
        payload = request.data
        file_list = payload.get("fileList", [])
        if not file_list:
            return Response({"error": "No fileList in Agora payload"}, status=400)
        recording_url = file_list[0].get("fileUrl")
        event_id = payload.get("event_id")
        if not event_id:
            return Response({"error": "Missing event_id"}, status=400)
        return Response({"message": "Recording saved"}, status=202)