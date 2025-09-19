"""
ViewSets for the events app.

Users can list, create, retrieve, update, and delete events belonging to
organizations they are members of.  Creation is restricted to users
belonging to the target organization.
"""
from rest_framework import permissions, viewsets, status, views
from rest_framework.exceptions import PermissionDenied
from rest_framework.decorators import action
from rest_framework.response import Response
import requests, base64, os, logging

from .models import Event
from .serializers import EventSerializer

from .tasks import download_event_recording
import logging
logger = logging.getLogger("events")
# 🔑 Agora credentials from env
APP_ID = os.getenv("AGORA_APP_ID")
CUSTOMER_ID = os.getenv("AGORA_CUSTOMER_ID")
CUSTOMER_SECRET = os.getenv("AGORA_CUSTOMER_SECRET")

class EventViewSet(viewsets.ModelViewSet):
    """CRUD operations for events."""
    serializer_class = EventSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = Event.objects.all().select_related("organization")
        mine = self.request.query_params.get("mine")
        if mine: 
            qs = qs.filter(created_by=self.request.user)
        return qs.order_by("-start_time")
    
    def perform_create(self, serializer):
        org_id = serializer.validated_data["organization_id"]
        # Ensure the user is a member of the organization they are creating an event for
        if not self.request.user.organizations.filter(id=org_id).exists():
            raise PermissionDenied("You must be a member of the organization to create events.")
        serializer.save()

    @action(detail=True, methods=["post"], permission_classes=[permissions.IsAuthenticated], url_path="start")
    def start_event(self, request, pk=None):
        event = self.get_object()
        user = request.user

        if event.status in {"live", "ended"}:
            return Response({"error": "invalid_state", "detail": "Event is already live or has ended."},
                            status=status.HTTP_400_BAD_REQUEST)

        if not (event.created_by_id == user.id or event.organization.owner_id == user.id):
            raise PermissionDenied("You do not have permission to start this event.")

        from django.utils import timezone
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

        from .tasks import download_event_recording
        download_event_recording.delay(event_id, recording_url)

        return Response({"message": "Recording saved"}, status=202)