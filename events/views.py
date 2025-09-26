"""
ViewSets for the events app.
Users can list, create, retrieve, update, and delete events belonging to
organizations they are members of.  Creation is restricted to users
belonging to the target organization.
"""
from rest_framework import permissions, viewsets, status, views
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.exceptions import PermissionDenied
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, BasePermission, SAFE_METHODS
from rest_framework.pagination import LimitOffsetPagination
from django.db.models import Q
from rest_framework.response import Response
import requests, base64, os, logging
from .models import Event
from .serializers import EventSerializer
from .tasks import download_event_recording
from django.utils import timezone
from datetime import timedelta
from django.utils.dateparse import parse_date
from django.db.models.functions import Lower
import logging
from django.db.models import Max


logger = logging.getLogger("events")
# 🔑 Agora credentials from env
APP_ID = os.getenv("AGORA_APP_ID")
CUSTOMER_ID = os.getenv("AGORA_CUSTOMER_ID")
CUSTOMER_SECRET = os.getenv("AGORA_CUSTOMER_SECRET")

class EventLimitOffsetPagination(LimitOffsetPagination):
    default_limit = 9           # 9 per page
    limit_query_param = "limit"
    offset_query_param = "offset"
    max_limit = 50
    
class IsCreatorOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        # Anyone can read; must be authenticated to write
        if request.method in SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_authenticated)
    def has_object_permission(self, request, view, obj):
        # Read is open; writes allowed to creator or staff
        if request.method in SAFE_METHODS:
            return True
        return bool(request.user and (request.user.is_staff or obj.created_by_id == request.user.id))

class EventViewSet(viewsets.ModelViewSet):
    """CRUD operations for events."""
    serializer_class = EventSerializer
    permission_classes = [IsCreatorOrReadOnly]
    pagination_class = EventLimitOffsetPagination
    throttle_classes = []
    
    # 🔎 ADD THIS
    filter_backends = [SearchFilter, OrderingFilter]
    # Search across title, location, and category (topic). Add more if you want.
    search_fields = ["title", "location", "category", "description", "organization__name"]
    # (Optional) ordering support
    ordering_fields = ["start_time", "created_at", "title"]
    ordering = ["-start_time"]
    
    def get_queryset(self):
        user = self.request.user
        qs = Event.objects.select_related("organization")

        # Base visibility
        if not user.is_authenticated:
            qs = qs.filter(status="published")
        else:
            qs = qs.filter(Q(status="published") | Q(organization__members=user)).distinct()

        # ---- Filters (applied only when provided) ----
        params = self.request.query_params

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
            

        dr = params.get("date_range")
        if dr in {"This Week", "This Month", "Next 90 days"}:
            now = timezone.now()

            if dr == "This Week":
                # Monday 00:00 to next Monday 00:00 (half-open interval)
                start_win = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
                end_win = start_win + timedelta(days=7)

            elif dr == "This Month":
                # 1st day 00:00 to 1st of next month 00:00
                start_win = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                # next month first day 00:00
                if start_win.month == 12:
                    end_win = start_win.replace(year=start_win.year + 1, month=1)
                else:
                    end_win = start_win.replace(month=start_win.month + 1)

            else:  # "next_90_days"
                start_win = now
                end_win = now + timedelta(days=90)

            # Simple rule: show events whose *start* falls inside the window
            qs = qs.filter(start_time__gte=start_win, start_time__lt=end_win)
            
        loc = self.request.query_params.get("location", "").strip()
        if loc:
            qs = qs.filter(location__iexact=loc)   
            
        start_date = params.get("start_date")
        end_date   = params.get("end_date")

        if start_date or end_date:
            s = parse_date(start_date) if start_date else None
            e = parse_date(end_date)   if end_date   else None
            if s and e and s > e:
                s, e = e, s  # swap if user inverted

            if s and e:
                qs = qs.filter(start_time__date__gte=s, start_time__date__lte=e)
            elif s:
                qs = qs.filter(start_time__date__gte=s)
            elif e:
                qs = qs.filter(start_time__date__lte=e)
                
        min_price = params.get("min_price")
        max_price = params.get("max_price")
        if min_price:
            qs = qs.filter(price__gte=min_price)
        if max_price:
            qs = qs.filter(price__lte=max_price)

        return qs

    def get_permissions(self):
        if self.action in ["list", "retrieve"]:
            return [AllowAny()]
        return super().get_permissions()
    
    def perform_create(self, serializer):
        # With the serializer fix below, validated_data has 'organization' (a model instance)
        org = serializer.validated_data.get("organization")
        if not org:
            raise PermissionDenied("organization_id is required.")
        # Ensure the user is a member of that org
        if not self.request.user.organizations.filter(id=org.id).exists():
            raise PermissionDenied("You must be a member of the organization to create events.")
        # Attach creator automatically
        serializer.save(created_by=self.request.user)
    @action(detail=True, methods=["post"], permission_classes=[permissions.IsAuthenticated], url_path="start")
    def start_event(self, request, pk=None):
        event = self.get_object()
        user = request.user
        if event.status in {"live", "ended"}:
            return Response({"error": "invalid_state", "detail": "Event is already live or has ended."},
                            status=status.HTTP_400_BAD_REQUEST)
        if not (event.created_by_id == user.id or event.organization.owner_id == user.id):
            raise PermissionDenied("You do not have permission to start this event.")
        
        event.status = "live"
        event.is_live = True
        event.live_started_at = timezone.now()
        event.active_speaker = user
        channel_name = f"event_{event.id}"
        logger.info(f"[Agora Start] Using APP_ID={APP_ID}, CUSTOMER_ID={CUSTOMER_ID}, channel={channel_name}")
        # Agora auth header
        auth = base64.b64encode(f"{CUSTOMER_ID}:{CUSTOMER_SECRET}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
        # 1️⃣ Acquire
        acquire_url = f"https://api.agora.io/v1/apps/{APP_ID}/cloud_recording/acquire"
        acquire_payload = {"cname": channel_name, "uid": "1", "clientRequest": {}}
        acquire_resp = requests.post(acquire_url, headers=headers, json=acquire_payload)
        logger.info(f"[Agora Acquire] {acquire_resp.status_code} {acquire_resp.text}")
        if acquire_resp.status_code != 200:
            return Response({"error": "Failed to acquire Agora recording"}, status=500)
        resource_id = acquire_resp.json().get("resourceId")
        # 2️⃣ Start
        start_url = f"https://api.agora.io/v1/apps/{APP_ID}/cloud_recording/resourceid/{resource_id}/mode/mix/start"
        start_payload = {
            "cname": channel_name,
            "uid": "1",
            "clientRequest": {
                "recordingConfig": {"maxIdleTime": 30, "channelType": 1, "streamTypes": 2},
                "storageConfig": {
                    "vendor": 1,
                    "region": 0,
                    "bucket": os.getenv("RECORDING_STORAGE_BUCKET"),
                    "accessKey": os.getenv("AGORA_ACCESS_KEY"),
                    "secretKey": os.getenv("AGORA_SECRET_KEY"),
                    "fileNamePrefix": ["recordings", f"event_{event.id}"],
                }
            }
        }
        start_resp = requests.post(start_url, headers=headers, json=start_payload)
        logger.info(f"[Agora Start] {start_resp.status_code} {start_resp.text}")
        if start_resp.status_code != 200:
            return Response({"error": "Failed to start Agora recording"}, status=500)
        sid = start_resp.json().get("sid")
        # ✅ Save in DB
        event.agora_resource_id = resource_id
        event.agora_sid = sid
        event.agora_channel = channel_name
        event.save()
        logger.info(f"✅ Saved Event {event.id}: resourceId={resource_id}, sid={sid}, channel={channel_name}")
        return Response(EventSerializer(event, context=self.get_serializer_context()).data)
    
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
    def formats(self, request):
        """
        Return distinct event format values (e.g., In-Person, Virtual, Hybrid, …).
        """
        qs = self.get_queryset()
        # ⚠️ If your field is named 'event_format' instead of 'format', change below to 'event_format'
        fmts = (
            qs.exclude(format__isnull=True)
            .exclude(format__exact="")
            .values_list("format", flat=True)
            .distinct()
            .order_by(Lower("format"))
        )
        return Response({"results": list(fmts)})
    
    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="locations")
    def locations(self, request):
        qs = self.get_queryset()
        locs = (
            qs.exclude(location__isnull=True)        # ← if your field is named differently,
            .exclude(location__exact="")           #    replace 'location' with that name
            .values_list("location", flat=True)
            .distinct()
            .order_by(Lower("location"))
        )
        return Response({"results": list(locs)})
    
    @action(detail=False, methods=["get"], permission_classes=[AllowAny], url_path="max-price")
    def max_price(self, request):
        qs = self.get_queryset()  # respects all current filters & visibility
        mx = qs.aggregate(mx=Max("price"))["mx"] or 0
        return Response({"max_price": float(mx)})
        
    @action(detail=True, methods=["post"], permission_classes=[permissions.IsAuthenticated], url_path="stop")
    def stop_event(self, request, pk=None):
        event = self.get_object()
        user = request.user
        if event.status != "live":
            return Response({"error": "invalid_state", "detail": "Event is not currently live."},
                            status=status.HTTP_400_BAD_REQUEST)
        if not (event.created_by_id == user.id or event.organization.owner_id == user.id):
            raise PermissionDenied("You do not have permission to stop this event.")
        from django.utils import timezone
        event.status = "ended"
        event.is_live = False
        event.live_ended_at = timezone.now()
        event.save()
        if event.agora_resource_id and event.agora_sid:
            auth = base64.b64encode(f"{CUSTOMER_ID}:{CUSTOMER_SECRET}".encode()).decode()
            url = f"https://api.agora.io/v1/apps/{APP_ID}/cloud_recording/resourceid/{event.agora_resource_id}/sid/{event.agora_sid}/mode/mix/query"
            headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
            r = requests.get(url, headers=headers)
            logger.info(f"[Agora Query] {r.status_code} {r.text}")
            if r.status_code == 200:
                file_list = r.json().get("serverResponse", {}).get("fileList", [])
                if file_list:
                    recording_url = file_list[0].get("fileUrl") or file_list[0].get("fileName")
                    event.recording_url = recording_url
                    event.save()
                    logger.info(f"✅ Event {event.id} recording saved: {recording_url}")
        return Response(EventSerializer(event, context=self.get_serializer_context()).data)

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
        download_event_recording.delay(event_id, recording_url)
        return Response({"message": "Recording saved"}, status=202)
