# events/webhooks.py
import json
import logging

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from messaging.services import import_chat_csv_from_url

logger = logging.getLogger(__name__)


@csrf_exempt
def realtime_webhook(request):
    """
    Webhook endpoint for RealtimeKit.

    We care about: meeting.chatSynced
    """
    if request.method != "POST":
        return HttpResponse(status=405)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return HttpResponse(status=400)

    event_type = payload.get("event")

    if event_type == "meeting.chatSynced":
        # ⚠️ Check exact keys in their docs; commonly "meetingId" & "chatDownloadUrl"
        meeting_id = payload.get("meetingId")
        chat_url = payload.get("chatDownloadUrl")

        if not meeting_id or not chat_url:
            logger.warning("chatSynced without meetingId/chatDownloadUrl: %s", payload)
            return JsonResponse({"ok": False, "reason": "missing_fields"}, status=400)

        imported = import_chat_csv_from_url(chat_url, meeting_id)
        return JsonResponse({"ok": True, "imported": imported})

    # Ignore other events or handle them if you want.
    return JsonResponse({"ok": True})
