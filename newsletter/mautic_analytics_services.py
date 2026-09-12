"""Mautic-backed Marketing Hub analytics.

This module is intentionally separate from the legacy ECP newsletter campaign
analytics service. Mautic remains the marketing source of truth here; ECP-owned
newsletter consent can be reported separately when needed.
"""

from __future__ import annotations

import math
from datetime import date, datetime
from typing import Any

from .contact_services import get_admin_stage_analytics
from .mautic import MauticClient


DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100


def parse_date_range(params) -> dict[str, Any]:
    start = _parse_date(params.get("from"), "from")
    end = _parse_date(params.get("to"), "to")
    if start and end and start > end:
        raise ValueError("from must be before or equal to to.")
    return {
        "from": start.isoformat() if start else None,
        "to": end.isoformat() if end else None,
    }


def normalize_paging(params) -> tuple[int, int]:
    try:
        page = max(1, int(params.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = int(params.get("page_size", DEFAULT_PAGE_SIZE))
    except (TypeError, ValueError):
        page_size = DEFAULT_PAGE_SIZE
    return page, max(1, min(page_size, MAX_PAGE_SIZE))


def get_overview_analytics(date_range: dict[str, Any]) -> dict[str, Any]:
    client = MauticClient()
    contacts = client.list_contacts(start=0, limit=1)
    campaigns = client.list_campaigns(start=0, limit=100)
    emails = client.list_emails(start=0, limit=100)
    segments = client.list_segments(start=0, limit=1)

    campaign_rows = _items(campaigns.get("campaigns"))
    email_rows = _items(emails.get("emails"))
    totals = _aggregate_email_metrics(client, email_rows)

    new_contacts = _count_new_contacts(client, date_range)

    return {
        "source": "mautic",
        "date_range": date_range,
        "metrics": [
            _metric("total_contacts", "Total Contacts", _total(contacts), "lifetime"),
            _metric("new_contacts", "New Contacts", new_contacts, "date_range"),
            _metric("total_campaigns", "Total Campaigns", _total(campaigns, campaign_rows), "lifetime"),
            _metric(
                "published_campaigns",
                "Published Campaigns",
                sum(1 for row in campaign_rows if _bool(row.get("isPublished"))),
                "lifetime",
                note="Based on the first 100 campaigns returned by Mautic REST.",
            ),
            _metric("total_segments", "Segments", _total(segments), "lifetime"),
            _metric("emails_sent", "Emails Sent", totals["sent"], "lifetime"),
            _metric("opens", "Opens", totals["opens"], "lifetime"),
            _metric("clicks", "Clicks", totals["clicks"], "lifetime"),
            _metric("bounces", "Bounces", totals["bounces"], "lifetime"),
            _metric("unsubscribes", "Unsubscribes", totals["unsubscribes"], "lifetime"),
        ],
        "notes": [
            "Lifetime email metrics come from Mautic email list/stat responses.",
            "Date range is applied only to New Contacts in this batch.",
            "Mautic DNC is not mixed with ECP newsletter consent.",
        ],
    }


def list_campaign_analytics(params) -> dict[str, Any]:
    page, page_size = normalize_paging(params)
    search = str(params.get("search", "") or "").strip()
    query = {"start": (page - 1) * page_size, "limit": page_size}
    if search:
        query["search"] = search
    data = MauticClient().list_campaigns(**query)
    rows = [_normalize_campaign(row) for row in _items(data.get("campaigns"))]
    count = _total(data, rows)
    return _page(rows, count, page, page_size)


def list_email_analytics(params) -> dict[str, Any]:
    page, page_size = normalize_paging(params)
    search = str(params.get("search", "") or "").strip()
    query = {"start": (page - 1) * page_size, "limit": page_size}
    if search:
        query["search"] = search
    client = MauticClient()
    data = client.list_emails(**query)
    rows = [_normalize_email(client, row) for row in _items(data.get("emails"))]
    count = _total(data, rows)
    return _page(rows, count, page, page_size)


def get_contact_analytics(date_range: dict[str, Any]) -> dict[str, Any]:
    client = MauticClient()
    contacts = client.list_contacts(start=0, limit=1)
    stage_analytics = get_admin_stage_analytics()
    return {
        "source": "mautic",
        "date_range": date_range,
        "metrics": [
            _metric("total_contacts", "Total Contacts", _total(contacts), "lifetime"),
            _metric("new_contacts", "New Contacts", _count_new_contacts(client, date_range), "date_range"),
            _metric("dnc", "Mautic DNC", None, "not_available", available=False),
        ],
        "stage_distribution": stage_analytics,
        "notes": [
            "Mautic DNC is separate from ECP newsletter consent and is deferred until a reliable aggregate source is available.",
        ],
    }


def list_segment_analytics(params) -> dict[str, Any]:
    page, page_size = normalize_paging(params)
    search = str(params.get("search", "") or "").strip()
    query = {"start": (page - 1) * page_size, "limit": page_size}
    if search:
        query["search"] = search
    client = MauticClient()
    data = client.list_segments(**query)
    rows = [_normalize_segment(client, row) for row in _items(data.get("lists") or data.get("segments"))]
    count = _total(data, rows)
    return _page(rows, count, page, page_size)


def _parse_date(value, field_name: str) -> date | None:
    if value in (None, ""):
        return None
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DD.") from exc


def _items(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [item for item in value.values() if isinstance(item, dict)]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _total(data: dict[str, Any], rows: list[dict[str, Any]] | None = None) -> int:
    try:
        return max(0, int(data.get("total")))
    except (TypeError, ValueError):
        return len(rows or [])


def _page(rows, count, page, page_size):
    return {
        "source": "mautic",
        "count": count,
        "page": page,
        "page_size": page_size,
        "num_pages": math.ceil(count / page_size) if count else 0,
        "results": rows,
    }


def _metric(key, label, value, scope, *, available=True, note=""):
    return {
        "key": key,
        "label": label,
        "value": value if available else None,
        "available": available,
        "scope": scope,
        "note": note,
    }


def _bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _count_new_contacts(client: MauticClient, date_range: dict[str, Any]) -> int | None:
    if not date_range.get("from") and not date_range.get("to"):
        return None
    parts = []
    if date_range.get("from"):
        parts.append(f"date_added:gte:{date_range['from']}")
    if date_range.get("to"):
        parts.append(f"date_added:lte:{date_range['to']}")
    data = client.list_contacts(start=0, limit=1, search=" ".join(parts))
    return _total(data)


def _aggregate_email_metrics(client: MauticClient, emails: list[dict[str, Any]]) -> dict[str, int]:
    totals = {"sent": 0, "opens": 0, "clicks": 0, "bounces": 0, "unsubscribes": 0}
    for email in emails:
        normalized = _normalize_email(client, email)
        totals["sent"] += normalized["sent"] or 0
        totals["opens"] += normalized["opened"] or 0
        totals["clicks"] += normalized["clicked"] or 0
        totals["bounces"] += normalized["bounced"] or 0
        totals["unsubscribes"] += normalized["unsubscribed"] or 0
    return totals


def _normalize_campaign(campaign: dict[str, Any]) -> dict[str, Any]:
    events = _items(campaign.get("events"))
    return {
        "id": str(campaign.get("id") or ""),
        "name": str(campaign.get("name") or "").strip(),
        "status": "published" if _bool(campaign.get("isPublished")) else "unpublished",
        "isPublished": _bool(campaign.get("isPublished")),
        "contactCount": _int_or_none(campaign.get("contactCount")),
        "eventCount": len(events),
        "dateModified": campaign.get("dateModified"),
        "dateAdded": campaign.get("dateAdded"),
    }


def _normalize_email(client: MauticClient, email: dict[str, Any]) -> dict[str, Any]:
    sent = _int_or_none(email.get("sentCount"))
    opened = _int_or_none(email.get("readCount"))
    clicked = _int_or_none(email.get("clickCount") or email.get("clickedCount"))
    bounced = _int_or_none(email.get("bounceCount") or email.get("bouncedCount"))
    unsubscribed = _int_or_none(email.get("unsubscribeCount") or email.get("unsubscribedCount"))

    stats = _email_stats_summary(client, email.get("id"))
    opened = stats.get("opened", opened)
    clicked = stats.get("clicked", clicked)
    bounced = stats.get("bounced", bounced)
    unsubscribed = stats.get("unsubscribed", unsubscribed)

    return {
        "id": str(email.get("id") or ""),
        "name": str(email.get("name") or "").strip(),
        "subject": str(email.get("subject") or ""),
        "emailType": str(email.get("emailType") or ""),
        "status": "published" if _bool(email.get("isPublished")) else "unpublished",
        "isPublished": _bool(email.get("isPublished")),
        "sent": sent,
        "opened": opened,
        "clicked": clicked,
        "bounced": bounced,
        "unsubscribed": unsubscribed,
        "openRate": _rate(opened, sent),
        "clickRate": _rate(clicked, sent),
        "dateModified": email.get("dateModified"),
        "dateAdded": email.get("dateAdded"),
        "lastActivity": stats.get("lastActivity") or email.get("dateModified"),
    }


def _email_stats_summary(client: MauticClient, email_id) -> dict[str, Any]:
    if not email_id:
        return {}
    data = client.get_email_stats(email_id)
    rows = _items(data.get("data") or data.get("stats"))
    summary = {"opened": 0, "clicked": 0, "bounced": 0, "unsubscribed": 0, "lastActivity": None}
    for row in rows:
        if _bool(row.get("is_read") or row.get("isRead")) or row.get("date_read") or row.get("dateRead"):
            summary["opened"] += 1
        if _bool(row.get("is_failed")) or _bool(row.get("failed")):
            summary["bounced"] += 1
        if _bool(row.get("is_unsubscribed")) or _bool(row.get("unsubscribed")):
            summary["unsubscribed"] += 1
        if row.get("date_clicked") or row.get("dateClicked") or _bool(row.get("clicked")):
            summary["clicked"] += 1
        activity = row.get("date_sent") or row.get("dateSent") or row.get("last_opened") or row.get("lastOpened")
        if activity and (summary["lastActivity"] is None or str(activity) > str(summary["lastActivity"])):
            summary["lastActivity"] = activity
    return summary


def _normalize_segment(client: MauticClient, segment: dict[str, Any]) -> dict[str, Any]:
    counts = client.get_segment_count_via_bridge(segment.get("id"))
    filters = segment.get("filters")
    return {
        "id": str(segment.get("id") or ""),
        "name": str(segment.get("name") or "").strip(),
        "alias": str(segment.get("alias") or ""),
        "isPublished": _bool(segment.get("isPublished")),
        "isDynamic": bool(filters),
        "segmentType": "dynamic" if filters else "static",
        "totalContacts": _int_or_none(counts.get("total")),
        "activeContacts": _int_or_none(counts.get("active")),
        "dateModified": segment.get("dateModified"),
        "dateAdded": segment.get("dateAdded"),
    }


def _int_or_none(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _rate(numerator, denominator) -> float | None:
    if numerator is None or denominator in (None, 0):
        return None
    return numerator / denominator
