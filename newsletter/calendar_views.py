"""Marketing Hub calendar: the dated marketing work, in one view.

Mautic 7 has no calendar, so ECP builds one from what is already recorded:
Broadcast sends from ECP's own data, and from Mautic (through the bridge)
campaign steps waiting to run, publish/unpublish dates of landing pages, forms
and assets, and the next email of scheduled reports. Read-only; times are UTC.

When Mautic cannot be read the Broadcasts still show, with a warning, so the
page stays useful during a Mautic outage.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, time, timedelta, timezone as dt_timezone

from django.db.models import Q
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .models import NewsletterCampaign

logger = logging.getLogger(__name__)

MAX_DAYS = 93
MAX_BROADCASTS = 500
MAUTIC_KINDS = {
    "campaign_step", "page_publish", "page_unpublish", "form_publish", "form_unpublish",
    "asset_publish", "asset_unpublish", "report_email",
}


class CalendarError(ValueError):
    pass


def parse_window(raw_from, raw_to) -> tuple[date, date]:
    try:
        start = date.fromisoformat(str(raw_from or ""))
        end = date.fromisoformat(str(raw_to or ""))
    except ValueError as exc:
        raise CalendarError("from and to must be dates in YYYY-MM-DD format.") from exc
    if start > end:
        raise CalendarError("from must be on or before to.")
    if (end - start).days >= MAX_DAYS:
        raise CalendarError(f"Choose at most {MAX_DAYS} days.")
    return start, end


def _iso(value: datetime) -> str:
    return value.astimezone(dt_timezone.utc).isoformat()


def broadcast_items(start: date, end: date) -> list[dict]:
    """Scheduled, sending, sent and failed Broadcasts dated inside the window."""
    lower = datetime.combine(start, time.min, tzinfo=dt_timezone.utc)
    upper = datetime.combine(end + timedelta(days=1), time.min, tzinfo=dt_timezone.utc)
    window = lambda field: Q(**{f"{field}__gte": lower, f"{field}__lt": upper})  # noqa: E731
    S = NewsletterCampaign.Status
    rows = (
        NewsletterCampaign.objects.filter(
            (Q(status=S.SCHEDULED) & window("scheduled_at"))
            | (Q(status=S.SENDING) & (window("send_started_at") | window("scheduled_at")))
            | (Q(status=S.SENT) & window("sent_at"))
            | (Q(status=S.FAILED) & (window("send_started_at") | window("scheduled_at")))
        )
        .prefetch_related("audiences")
        .order_by("id")[:MAX_BROADCASTS]
    )
    items = []
    for row in rows:
        when = {
            S.SCHEDULED: row.scheduled_at,
            S.SENDING: row.send_started_at or row.scheduled_at,
            S.SENT: row.sent_at,
            S.FAILED: row.send_started_at or row.scheduled_at,
        }.get(row.status)
        if when is None or not (lower <= when < upper):
            continue
        items.append({
            "kind": f"broadcast_{row.status}",
            "id": f"broadcast-{row.uuid}",
            "at": _iso(when),
            "allDay": False,
            "title": row.name,
            "subtitle": row.subject,
            "resourceId": str(row.uuid),
            "lists": [audience.name for audience in row.audiences.all()],
        })
    return items


class NewsletterAdminCalendarView(APIView):
    """GET ?from=YYYY-MM-DD&to=YYYY-MM-DD (UTC, at most 93 days)."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            start, end = parse_window(request.query_params.get("from"), request.query_params.get("to"))
        except CalendarError as exc:
            return Response({"detail": str(exc), "code": "invalid_window"}, status=status.HTTP_400_BAD_REQUEST)

        items = broadcast_items(start, end)
        warning = ""
        truncated = False
        try:
            data = MauticClient().get_marketing_calendar(start.isoformat(), end.isoformat())
            items.extend(item for item in data["items"] if isinstance(item, dict) and item.get("kind") in MAUTIC_KINDS)
            truncated = bool(data.get("truncated"))
        except (TemporaryMauticError, PermanentMauticError):
            logger.warning("Marketing calendar could not read Mautic", exc_info=True)
            warning = "Mautic could not be read, so only Broadcasts are shown. Try again in a moment."

        items.sort(key=lambda item: (str(item.get("at") or ""), str(item.get("kind") or "")))
        response = Response({
            "from": start.isoformat(),
            "to": end.isoformat(),
            "items": items,
            "truncated": truncated,
            "warning": warning,
        })
        response["Cache-Control"] = "no-store"
        return response
