# realtime/views.py
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status

from events.models import Event
from .services import AgoraService

class EventStreamTokenView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk=None, *args, **kwargs):
        pk = pk or kwargs.get("pk")
        if pk is None:
            return Response({"error": "Missing event id (pk)"}, status=400)

        event = get_object_or_404(Event, pk=pk)

        # 👇 Decide role server-side:
        # Replace "event.owner" with your actual owner/creator field.
        is_host = (getattr(event, "owner", None) == request.user) or \
                  (hasattr(event, "hosts") and request.user in getattr(event, "hosts").all())

        role = "publisher" if is_host else "audience"

        channel = f"event-{event.id}"  # or event.slug, just use same on client
        svc = AgoraService()
        token, expire_at = svc.generate_token(channel_name=channel, role=role, uid=0)

        return Response({
            "token": token,                 # may be None when cert disabled
            "app_id": svc.app_id,
            "channel": channel,
            "role": role,                   # 👈 return the final role
            "expires_at": expire_at.isoformat(),
        }, status=200)
