# realtime/views.py
import time
from typing import Any

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticatedOrReadOnly

from .serializers import EventTokenRequestSerializer
from .services import AgoraService, AgoraConfig

class EventRtcTokenView(APIView):
    """
    POST /api/events/<event_id>/token/
    Body: {"role": "publisher" | "audience", "uid": 1234}
    """
    permission_classes = [IsAuthenticatedOrReadOnly]

    def post(self, request, event_id: int, *args: Any, **kwargs: Any):
        ser = EventTokenRequestSerializer(data=request.data or {})
        ser.is_valid(raise_exception=True)

        role = ser.validated_data.get("role") or "audience"
        uid = ser.validated_data.get("uid")  # may be None; service will randomize if absent

        cfg = AgoraConfig.from_env()
        svc = AgoraService(cfg)
        token, signed_uid, expires_at, channel = svc.build_uid_token(
            event_id=int(event_id),
            role=role,
            uid=uid,
        )

        # IMPORTANT: return numbers, not ISO strings
        return Response(
            {
                "app_id": cfg.app_id,
                "token": token,
                "channel": channel,
                "uid": int(signed_uid),
                "expires_at": int(expires_at),   # epoch seconds
                "server_time": int(time.time()), # epoch seconds
                "role": role,
            },
            status=status.HTTP_200_OK,
        )


class AgoraDiagnosticView(APIView):
    """
    GET /api/agora/diag/
    """
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get(self, request, *args: Any, **kwargs: Any):
        payload = {}
        try:
            cfg = AgoraConfig.from_env()
            svc = AgoraService(cfg)
            payload = {
                "has_env": True,
                "app_id_prefix": cfg.app_id[:8],
                "cert_set": bool(cfg.app_certificate),
                "now": int(time.time()),
                "sample": svc.diagnostic_sample(),
            }
        except Exception as e:
            payload = {"has_env": False, "error": str(e)}
        return Response(payload)
