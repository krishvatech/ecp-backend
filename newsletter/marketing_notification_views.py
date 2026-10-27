"""Marketing Hub notifications: the admin's own ECP system notifications whose
data.type starts with "marketing_" (e.g. a finished contact export). They are
ordinary ECP notifications, so they also appear on IMAA Connect's page."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from friends.models import Notification

from .contact_export_services import list_user_jobs
from .marketing_permissions import HasMarketingHubAccess

LIMIT = 20


def marketing_notifications(user):
    return Notification.objects.filter(recipient=user, kind="system", data__type__startswith="marketing_")


def _serialize(notification: Notification) -> dict:
    data = notification.data if isinstance(notification.data, dict) else {}
    return {
        "id": notification.id,
        "title": notification.title,
        "description": notification.description,
        "is_read": notification.is_read,
        "created_at": notification.created_at.isoformat(),
        "type": data.get("type", ""),
        "data": {key: data.get(key) for key in ("job_id", "status", "filename", "rows", "url") if key in data},
    }


class NewsletterAdminMarketingNotificationListView(APIView):
    """The admin's latest marketing notifications and how many are unread."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        # Settles any of this admin's exports that will never finish, so they
        # are reported here without anyone having to open the export dialog.
        list_user_jobs(request.user)
        notifications = marketing_notifications(request.user)
        response = Response({
            "unread": notifications.filter(is_read=False).count(),
            "results": [_serialize(n) for n in notifications.order_by("-created_at", "-id")[:LIMIT]],
        })
        response["Cache-Control"] = "no-store"
        return response


class NewsletterAdminMarketingNotificationReadView(APIView):
    """Mark some ({"ids": [...]}) or all ({"all": true}) marketing notifications read."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request):
        data = request.data if hasattr(request.data, "get") else {}
        notifications = marketing_notifications(request.user).filter(is_read=False)
        if data.get("all") is True:
            updated = notifications.update(is_read=True)
        else:
            ids = data.get("ids")
            if not isinstance(ids, list) or not ids or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
                return Response({"detail": "Send ids (a list of notification IDs) or all: true.", "code": "invalid_payload"},
                                status=status.HTTP_400_BAD_REQUEST)
            updated = notifications.filter(id__in=ids).update(is_read=True)
        return Response({"updated": updated, "unread": marketing_notifications(request.user).filter(is_read=False).count()})
