"""Mautic-backed Marketing Hub dashboard data.

The dashboard is an operational surface. It intentionally returns compact
recent entities, upcoming work, and attention items without duplicating the
full Analytics or Settings pages.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any, Callable

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic_analytics_services import parse_date_range
from .mautic_diagnostics_services import get_mautic_diagnostics
from .models import NewsletterCampaignTrackingEvent


DEFAULT_RECENT_LIMIT = 5
DEFAULT_ACTIVITY_LIMIT = 8
DEFAULT_UPCOMING_LIMIT = 5
DEFAULT_CHART_DAYS = 30
MAX_CHART_CONTACTS = 1000


def get_dashboard_data(params=None) -> dict[str, Any]:
    date_range = _dashboard_date_range(params)
    sections = {
        "contacts_created": _section(lambda: _contacts_created(MauticClient(), date_range)),
        "recent_campaigns": _section(lambda: _recent_campaigns(MauticClient())),
        "recent_contacts": _section(lambda: _recent_contacts(MauticClient())),
        "upcoming_emails": _section(lambda: _upcoming_emails(MauticClient())),
        "attention": _section(_attention),
    }
    activity = _section(
        lambda: _recent_activity(
            sections["recent_campaigns"],
            sections["recent_contacts"],
        )
    )
    sections["recent_activity"] = activity
    return {"source": "mautic", **sections}


def _section(loader: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return {"status": "ok", **loader()}
    except (TemporaryMauticError, PermanentMauticError) as exc:
        return _unavailable(str(exc))


def _unavailable(detail: str) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "results": [],
        "count": 0,
        "detail": detail or "Provider data is unavailable.",
    }


def _dashboard_date_range(params=None) -> dict[str, Any]:
    parsed = parse_date_range(params or {})
    if parsed.get("from") and parsed.get("to"):
        return parsed
    end = date.fromisoformat(parsed["to"]) if parsed.get("to") else timezone.localdate()
    start = date.fromisoformat(parsed["from"]) if parsed.get("from") else end - timedelta(days=DEFAULT_CHART_DAYS - 1)
    if start > end:
        raise ValueError("from must be before or equal to to.")
    return {"from": start.isoformat(), "to": end.isoformat()}


def _contacts_created(client: MauticClient, date_range: dict[str, Any]) -> dict[str, Any]:
    start = date.fromisoformat(date_range["from"])
    end = date.fromisoformat(date_range["to"])
    buckets = {}
    cursor = start
    while cursor <= end:
        buckets[cursor.isoformat()] = 0
        cursor += timedelta(days=1)

    contacts = _fetch_contacts_created(client, date_range)
    for contact in contacts:
        added_at = _parse_provider_datetime(contact.get("dateAdded") or contact.get("date_added"))
        if not added_at:
            continue
        bucket = added_at.date()
        if start <= bucket <= end:
            buckets[bucket.isoformat()] += 1

    return {
        "from": date_range["from"],
        "to": date_range["to"],
        "series": [{"date": key, "count": value} for key, value in buckets.items()],
    }


def _fetch_contacts_created(client: MauticClient, date_range: dict[str, Any]) -> list[dict[str, Any]]:
    contacts = []
    start = 0
    limit = 100
    while start < MAX_CHART_CONTACTS:
        data = client.list_contacts(
            start=start,
            limit=min(limit, MAX_CHART_CONTACTS - start),
            orderBy="date_added",
            orderByDir="asc",
            **_date_added_where_params(date_range),
        )
        page_contacts = _items(data.get("contacts"))
        contacts.extend(page_contacts)
        try:
            total = max(0, int(data.get("total", len(contacts))))
        except (TypeError, ValueError):
            total = len(contacts)
        if not page_contacts or len(contacts) >= total or len(contacts) >= MAX_CHART_CONTACTS:
            break
        start += len(page_contacts)
    return contacts


def _date_added_where_params(date_range: dict[str, Any]) -> dict[str, Any]:
    return {
        "where[0][col]": "dateAdded",
        "where[0][expr]": "gte",
        "where[0][val]": f"{date_range['from']} 00:00:00",
        "where[1][col]": "dateAdded",
        "where[1][expr]": "lte",
        "where[1][val]": f"{date_range['to']} 23:59:59",
    }


def _recent_campaigns(client: MauticClient, limit: int = DEFAULT_RECENT_LIMIT) -> dict[str, Any]:
    data = client.list_campaigns(start=0, limit=limit, orderBy="dateModified", orderByDir="desc")
    rows = [_normalize_campaign(row) for row in _items(data.get("campaigns"))]
    rows.sort(key=lambda row: str(row.get("dateModified") or row.get("dateAdded") or ""), reverse=True)
    return {"results": rows[:limit], "count": len(rows[:limit])}


def _recent_contacts(client: MauticClient, limit: int = DEFAULT_RECENT_LIMIT) -> dict[str, Any]:
    data = client.list_contacts(start=0, limit=limit, orderBy="date_added", orderByDir="desc")
    rows = [_normalize_contact(row) for row in _items(data.get("contacts"))]
    rows.sort(key=lambda row: str(row.get("dateAdded") or ""), reverse=True)
    return {"results": rows[:limit], "count": len(rows[:limit])}


def _upcoming_emails(client: MauticClient, limit: int = DEFAULT_UPCOMING_LIMIT) -> dict[str, Any]:
    data = client.list_emails(start=0, limit=100, orderBy="publishUp", orderByDir="asc")
    now = timezone.now()
    rows = []
    for email in _items(data.get("emails")):
        scheduled_at = _future_schedule(email, now)
        if not scheduled_at:
            continue
        rows.append(_normalize_upcoming_email(email, scheduled_at))
    rows.sort(key=lambda row: str(row.get("scheduledAt") or ""))
    return {"results": rows[:limit], "count": len(rows[:limit])}


def _attention() -> dict[str, Any]:
    diagnostics = get_mautic_diagnostics()
    warnings = [str(item) for item in (diagnostics.get("diagnostics") or {}).get("warnings", []) if item]
    return {
        "status_label": "attention" if warnings else "healthy",
        "warning_count": len(warnings),
        "warnings": warnings[:5],
    }


def _recent_activity(
    recent_campaigns: dict[str, Any],
    recent_contacts: dict[str, Any],
    limit: int = DEFAULT_ACTIVITY_LIMIT,
) -> dict[str, Any]:
    rows = []
    if recent_contacts.get("status") == "ok":
        rows.extend(_contact_activity_rows(recent_contacts.get("results", [])))
    if recent_campaigns.get("status") == "ok":
        rows.extend(_campaign_activity_rows(recent_campaigns.get("results", [])))
    rows.extend(_tracking_activity_rows(limit=limit))
    rows.sort(key=lambda row: str(row.get("timestamp") or ""), reverse=True)
    return {
        "results": rows[:limit],
        "count": len(rows[:limit]),
        "detail": "Recent provider entity changes and recognized Mautic webhook events.",
    }


def _contact_activity_rows(contacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for contact in contacts:
        timestamp = contact.get("dateAdded")
        if not timestamp:
            continue
        rows.append(
            {
                "id": f"contact:{contact.get('id')}:created",
                "event_type": "contact_created",
                "description": "Contact created",
                "entity": contact.get("name") or contact.get("email") or "Contact",
                "timestamp": timestamp,
                "contact_id": contact.get("id"),
            }
        )
    return rows


def _campaign_activity_rows(campaigns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for campaign in campaigns:
        timestamp = campaign.get("dateModified") or campaign.get("dateAdded")
        if not timestamp:
            continue
        rows.append(
            {
                "id": f"campaign:{campaign.get('id')}:updated",
                "event_type": "campaign_updated",
                "description": "Campaign updated",
                "entity": campaign.get("name") or "Campaign",
                "timestamp": timestamp,
                "campaign_id": campaign.get("id"),
            }
        )
    return rows


def _tracking_activity_rows(limit: int = DEFAULT_ACTIVITY_LIMIT) -> list[dict[str, Any]]:
    rows = []
    events = NewsletterCampaignTrackingEvent.objects.filter(source="mautic").select_related("campaign").order_by(
        "-occurred_at", "-created_at", "-id"
    )[:limit]
    for event in events:
        rows.append(
            {
                "id": f"tracking:{event.id}",
                "event_type": f"email_{event.event_type}",
                "description": f"Email {event.get_event_type_display().lower()}",
                "entity": event.campaign.name,
                "timestamp": event.occurred_at.isoformat(),
                "campaign_id": event.campaign.mautic_email_id or "",
                "contact_id": event.mautic_contact_id,
                "email": event.recipient_email,
            }
        )
    return rows


def _future_schedule(email: dict[str, Any], now) -> str:
    for field in ("dateToSend", "date_to_send", "publishUp", "publish_up", "scheduledAt", "scheduled_at"):
        value = email.get(field)
        if not value:
            continue
        parsed = _parse_provider_datetime(value)
        if parsed and parsed > now:
            return value
    return ""


def _parse_provider_datetime(value) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        parsed = parse_datetime(text)
        if parsed is None:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


def _normalize_campaign(campaign: dict[str, Any]) -> dict[str, Any]:
    campaign_id = campaign.get("id")
    return {
        "id": str(campaign_id) if campaign_id is not None else "",
        "name": str(campaign.get("name") or "").strip(),
        "status": "Published" if _bool(campaign.get("isPublished")) else "Draft",
        "isPublished": _bool(campaign.get("isPublished")),
        "dateAdded": campaign.get("dateAdded"),
        "dateModified": campaign.get("dateModified") or campaign.get("dateAdded"),
    }


def _normalize_contact(contact: dict[str, Any]) -> dict[str, Any]:
    contact_id = contact.get("id")
    email = _field_value(contact, "email") or contact.get("email")
    first_name = _field_value(contact, "firstname") or contact.get("firstname")
    last_name = _field_value(contact, "lastname") or contact.get("lastname")
    name = " ".join(part for part in [str(first_name or "").strip(), str(last_name or "").strip()] if part)
    return {
        "id": str(contact_id) if contact_id is not None else "",
        "name": name or str(email or "").strip() or "Contact",
        "email": str(email or "").strip(),
        "stage": _stage_name(contact),
        "dateAdded": contact.get("dateAdded") or contact.get("date_added"),
    }


def _normalize_upcoming_email(email: dict[str, Any], scheduled_at: str) -> dict[str, Any]:
    email_id = email.get("id")
    return {
        "id": str(email_id) if email_id is not None else "",
        "name": str(email.get("name") or "").strip(),
        "subject": str(email.get("subject") or ""),
        "status": "Published" if _bool(email.get("isPublished")) else "Draft",
        "scheduledAt": scheduled_at,
        "emailType": str(email.get("emailType") or ""),
    }


def _field_value(contact: dict[str, Any], alias: str):
    fields = contact.get("fields")
    if not isinstance(fields, dict):
        return None
    core = fields.get("core")
    if not isinstance(core, dict):
        return None
    field = core.get(alias)
    if isinstance(field, dict):
        return field.get("value")
    return field


def _stage_name(contact: dict[str, Any]) -> str:
    stage = contact.get("stage")
    if isinstance(stage, dict):
        return str(stage.get("name") or stage.get("label") or "").strip()
    return str(stage or "").strip()


def _items(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [item for item in value.values() if isinstance(item, dict)]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}
