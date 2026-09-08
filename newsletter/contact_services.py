"""Admin-facing Mautic contact directory helpers.

The contact directory is provider-backed so it can include contacts that exist
only in Mautic. ECP remains authoritative for newsletter consent; current
subscription-list membership is therefore enriched from NewsletterSubscription
rather than inferred from provider segment membership.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Any

from django.utils import timezone

from .mautic import MauticClient, TemporaryMauticError
from .models import MauticContactMapping, NewsletterCategory, NewsletterSubscription


def _contacts_from_response(data: dict[str, Any]) -> list[dict[str, Any]]:
    contacts = data.get("contacts")
    if isinstance(contacts, dict):
        return [item for item in contacts.values() if isinstance(item, dict)]
    if isinstance(contacts, list):
        return [item for item in contacts if isinstance(item, dict)]
    return []


def _field_value(value):
    if isinstance(value, dict):
        return value.get("value")
    return value


def _contact_field(contact: dict[str, Any], alias: str):
    direct = _field_value(contact.get(alias))
    if direct not in (None, ""):
        return direct

    fields = contact.get("fields")
    if not isinstance(fields, dict):
        return None

    for group_name in ("all", "core"):
        group = fields.get(group_name)
        if not isinstance(group, dict):
            continue
        value = _field_value(group.get(alias))
        if value not in (None, ""):
            return value
    return None


def _contact_name(contact: dict[str, Any], *, fallback_user=None) -> str:
    first_name = str(_contact_field(contact, "firstname") or "").strip()
    last_name = str(_contact_field(contact, "lastname") or "").strip()
    name = " ".join(part for part in (first_name, last_name) if part)
    if name:
        return name

    if fallback_user is not None:
        local_name = " ".join(
            part
            for part in (
                str(getattr(fallback_user, "first_name", "") or "").strip(),
                str(getattr(fallback_user, "last_name", "") or "").strip(),
            )
            if part
        )
        if local_name:
            return local_name

    email = str(_contact_field(contact, "email") or "").strip()
    if email:
        return email
    contact_id = str(contact.get("id") or "").strip()
    return f"Contact #{contact_id}" if contact_id else "Unnamed contact"


def _contact_location(contact: dict[str, Any]) -> str:
    parts = []
    for alias in ("city", "state", "country"):
        value = str(_contact_field(contact, alias) or "").strip()
        if value and value not in parts:
            parts.append(value)
    return ", ".join(parts)


def _contact_info(contact: dict[str, Any]) -> dict[str, Any]:
    return {
        "first_name": str(_contact_field(contact, "firstname") or "").strip(),
        "last_name": str(_contact_field(contact, "lastname") or "").strip(),
        "email": str(_contact_field(contact, "email") or "").strip(),
        "phone": str(_contact_field(contact, "phone") or "").strip(),
        "mobile": str(_contact_field(contact, "mobile") or "").strip(),
        "address1": str(_contact_field(contact, "address1") or "").strip(),
        "address2": str(_contact_field(contact, "address2") or "").strip(),
        "city": str(_contact_field(contact, "city") or "").strip(),
        "state": str(_contact_field(contact, "state") or "").strip(),
        "zipcode": str(_contact_field(contact, "zipcode") or "").strip(),
        "country": str(_contact_field(contact, "country") or "").strip(),
    }


def _contact_stage(contact: dict[str, Any]) -> dict[str, Any] | None:
    stage = contact.get("stage")
    if not isinstance(stage, dict):
        return None

    stage_id = stage.get("id")
    if stage_id in (None, ""):
        return None

    weight = stage.get("weight")
    try:
        weight = int(weight) if weight not in (None, "") else None
    except (TypeError, ValueError):
        weight = None

    category = stage.get("category")
    return {
        "id": str(stage_id),
        "name": str(stage.get("name") or "").strip(),
        "description": str(stage.get("description") or ""),
        "weight": weight,
        "category": category if isinstance(category, dict) else None,
    }


def move_admin_contact_to_stage(
    mautic_contact_id,
    stage_id,
) -> dict[str, Any]:
    """Move one Mautic contact to one Mautic lifecycle stage."""
    contact_id = str(mautic_contact_id or "").strip()
    target_stage_id = str(stage_id or "").strip()
    if not contact_id:
        raise ValueError("Mautic contact ID is required.")
    if not target_stage_id:
        raise ValueError("stage_id is required.")

    client = MauticClient()
    contact = client.get_contact(contact_id)
    client.get_stage(target_stage_id)

    current_stage = _contact_stage(contact)
    if current_stage is not None and current_stage["id"] == target_stage_id:
        return current_stage

    client.add_contact_to_stage(target_stage_id, contact_id)
    updated_contact = client.get_contact(contact_id)
    updated_stage = _contact_stage(updated_contact)
    if updated_stage is None or updated_stage["id"] != target_stage_id:
        raise TemporaryMauticError(
            "Mautic did not confirm the requested contact stage change."
        )
    return updated_stage


def clear_admin_contact_stage(mautic_contact_id) -> None:
    """Remove one contact from its current Mautic lifecycle stage."""
    contact_id = str(mautic_contact_id or "").strip()
    if not contact_id:
        raise ValueError("Mautic contact ID is required.")

    client = MauticClient()
    contact = client.get_contact(contact_id)
    current_stage = _contact_stage(contact)
    if current_stage is None:
        return

    client.remove_contact_from_stage(current_stage["id"], contact_id)
    updated_contact = client.get_contact(contact_id)
    if _contact_stage(updated_contact) is not None:
        raise TemporaryMauticError(
            "Mautic did not confirm removal of the contact stage."
        )


def get_admin_contact(mautic_contact_id) -> dict[str, Any]:
    """Return one Mautic contact enriched with ECP identity and consent state."""
    contact = MauticClient().get_contact(mautic_contact_id)
    contact_id = str(contact.get("id") or mautic_contact_id or "").strip()

    mapping = (
        MauticContactMapping.objects.filter(mautic_contact_id=contact_id)
        .select_related("user")
        .first()
    )
    user = mapping.user if mapping is not None else None
    info = _contact_info(contact)
    if not info["email"] and user is not None:
        info["email"] = str(getattr(user, "email", "") or "").strip()

    subscription_lists = []
    if user is not None:
        existing = {
            subscription.category_id: subscription
            for subscription in NewsletterSubscription.objects.filter(user=user)
        }
        categories = NewsletterCategory.objects.filter(is_active=True).order_by("name", "id")
        for category in categories:
            subscription = existing.get(category.id)
            subscription_lists.append(
                {
                    "slug": category.slug,
                    "name": category.name,
                    "mautic_segment_id": category.mautic_segment_id or None,
                    "is_subscribed": bool(
                        subscription is not None and subscription.is_subscribed
                    ),
                    "subscribed_at": (
                        subscription.subscribed_at if subscription is not None else None
                    ),
                    "unsubscribed_at": (
                        subscription.unsubscribed_at if subscription is not None else None
                    ),
                    "source": subscription.source if subscription is not None else None,
                }
            )

    points = contact.get("points", 0)
    try:
        points = int(points or 0)
    except (TypeError, ValueError):
        points = 0

    return {
        "mautic_contact_id": contact_id,
        "name": _contact_name(contact, fallback_user=user),
        "email": info["email"],
        "location": _contact_location(contact),
        "points": points,
        "current_stage": _contact_stage(contact),
        "last_active_at": (
            contact.get("lastActive")
            or contact.get("last_active")
            or contact.get("dateModified")
            or contact.get("date_modified")
        ),
        "date_added": contact.get("dateAdded") or contact.get("date_added"),
        "date_modified": contact.get("dateModified") or contact.get("date_modified"),
        "is_published": bool(
            contact.get("isPublished", contact.get("is_published", True))
        ),
        "mapped_in_ecp": mapping is not None,
        "ecp_user_id": mapping.user_id if mapping is not None else None,
        "ecp_username": (
            str(getattr(user, "username", "") or "").strip() if user is not None else ""
        ),
        "last_synced_at": mapping.last_synced_at if mapping is not None else None,
        "contact_info": info,
        "subscription_lists": subscription_lists,
    }


def _activity_events(data: dict[str, Any]) -> list[dict[str, Any]]:
    events = data.get("events")
    if isinstance(events, dict):
        return [event for event in events.values() if isinstance(event, dict)]
    if isinstance(events, list):
        return [event for event in events if isinstance(event, dict)]
    return []


def _normalized_activity_event(
    event: dict[str, Any],
    index: int = 0,
) -> dict[str, Any]:
    timestamp = event.get("timestamp") or event.get("dateAdded") or event.get("date_added")
    code = str(event.get("event") or "").strip()
    event_type = str(event.get("eventType") or event.get("event_type") or code).strip()

    raw_label = event.get("eventLabel") or event.get("event_label")
    href = ""
    if isinstance(raw_label, dict):
        href = str(raw_label.get("href") or "").strip()
        raw_label = raw_label.get("label")
    label = str(raw_label or event_type or code or "Activity").strip()

    return {
        "id": str(
            event.get("eventId")
            or event.get("event_id")
            or f"{code}:{timestamp}:{index}"
        ),
        "event": code,
        "label": label,
        "event_type": event_type or code or "Activity",
        "timestamp": timestamp,
        "featured": bool(event.get("featured", False)),
        "icon": str(event.get("icon") or "").strip(),
        "href": href,
    }


def _parse_activity_date(value, *, field_name):
    if value in (None, ""):
        return None
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DD format.") from exc


def list_admin_contact_activity(
    mautic_contact_id,
    *,
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    """Return one provider-backed page of normalized Mautic contact events."""
    page = max(1, int(page))
    page_size = max(1, min(int(page_size), 100))

    data = MauticClient().get_contact_activity(
        mautic_contact_id,
        page=page,
        limit=page_size,
    )
    events = [
        _normalized_activity_event(event, index)
        for index, event in enumerate(_activity_events(data))
    ]
    events.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)

    try:
        count = max(0, int(data.get("total") or len(events)))
    except (TypeError, ValueError):
        count = len(events)
    try:
        raw_pages = data.get("maxPages")
        num_pages = max(
            1,
            int(float(raw_pages))
            if raw_pages not in (None, "")
            else math.ceil(count / page_size),
        )
    except (TypeError, ValueError):
        num_pages = max(1, math.ceil(count / page_size)) if count else 1

    return {
        "count": count,
        "page": page,
        "page_size": page_size,
        "num_pages": num_pages,
        "results": events,
    }


def get_admin_contact_engagement(
    mautic_contact_id,
    *,
    from_value=None,
    to_value=None,
) -> dict[str, Any]:
    """Build a cumulative engagement graph from real Mautic contact activity."""
    today = timezone.localdate()
    end_date = _parse_activity_date(to_value, field_name="to") or today
    start_date = (
        _parse_activity_date(from_value, field_name="from")
        or (end_date - timedelta(days=179))
    )
    if start_date > end_date:
        raise ValueError("from must be on or before to.")
    if (end_date - start_date).days + 1 > 366:
        raise ValueError("Date range cannot exceed 366 days.")

    client = MauticClient()
    page_size = 25
    first = client.get_contact_activity(
        mautic_contact_id,
        page=1,
        limit=page_size,
    )
    events = _activity_events(first)
    try:
        max_pages = max(1, int(float(first.get("maxPages") or 1)))
    except (TypeError, ValueError):
        max_pages = 1

    page_cap = 50
    truncated = max_pages > page_cap
    for page in range(2, min(max_pages, page_cap) + 1):
        page_data = client.get_contact_activity(
            mautic_contact_id,
            page=page,
            limit=page_size,
        )
        events.extend(_activity_events(page_data))

    daily = defaultdict(int)
    tz = timezone.get_current_timezone()
    for event in events:
        raw_timestamp = (
            event.get("timestamp")
            or event.get("dateAdded")
            or event.get("date_added")
        )
        if not raw_timestamp:
            continue
        try:
            occurred = datetime.fromisoformat(
                str(raw_timestamp).replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            continue
        if timezone.is_naive(occurred):
            occurred = timezone.make_aware(occurred, tz)
        local_day = timezone.localtime(occurred, tz).date()
        if start_date <= local_day <= end_date:
            daily[local_day] += 1

    series = []
    running = 0
    current = start_date
    while current <= end_date:
        day_count = daily[current]
        running += day_count
        series.append(
            {
                "date": current.isoformat(),
                "events": day_count,
                "engagements": running,
            }
        )
        current += timedelta(days=1)

    return {
        "from": start_date.isoformat(),
        "to": end_date.isoformat(),
        "event_count": sum(daily.values()),
        "truncated": truncated,
        "series": series,
    }


def _provider_total(data: dict[str, Any], *, start: int, returned: int) -> int:
    raw = data.get("total")
    try:
        total = int(raw)
    except (TypeError, ValueError):
        total = start + returned
    return max(0, total)


def list_admin_contacts(
    *,
    page: int = 1,
    page_size: int = 25,
    search: str = "",
) -> dict[str, Any]:
    """List all Mautic contacts and enrich mapped contacts with ECP state."""
    page = max(1, int(page))
    page_size = max(1, min(int(page_size), 100))
    start = (page - 1) * page_size

    params = {
        "start": start,
        "limit": page_size,
    }
    normalized_search = str(search or "").strip()
    if normalized_search:
        params["search"] = normalized_search

    provider_data = MauticClient().list_contacts(**params)
    provider_contacts = _contacts_from_response(provider_data)
    contact_ids = [
        str(contact.get("id"))
        for contact in provider_contacts
        if contact.get("id") not in (None, "")
    ]

    mappings = {
        str(mapping.mautic_contact_id): mapping
        for mapping in MauticContactMapping.objects.filter(
            mautic_contact_id__in=contact_ids
        ).select_related("user")
    }
    mapped_user_ids = [mapping.user_id for mapping in mappings.values()]

    subscriptions_by_user: dict[int, list[dict[str, Any]]] = {}
    subscriptions = (
        NewsletterSubscription.objects.filter(
            user_id__in=mapped_user_ids,
            is_subscribed=True,
        )
        .select_related("category")
        .order_by("category__name", "category__id")
    )
    for subscription in subscriptions:
        subscriptions_by_user.setdefault(subscription.user_id, []).append(
            {
                "slug": subscription.category.slug,
                "name": subscription.category.name,
                "mautic_segment_id": subscription.category.mautic_segment_id or None,
                "subscribed_at": subscription.subscribed_at,
            }
        )

    results = []
    for contact in provider_contacts:
        contact_id = str(contact.get("id") or "").strip()
        mapping = mappings.get(contact_id)
        user = mapping.user if mapping is not None else None
        email = str(_contact_field(contact, "email") or "").strip()
        if not email and user is not None:
            email = str(getattr(user, "email", "") or "").strip()

        points = contact.get("points", 0)
        try:
            points = int(points or 0)
        except (TypeError, ValueError):
            points = 0

        results.append(
            {
                "mautic_contact_id": contact_id,
                "name": _contact_name(contact, fallback_user=user),
                "email": email,
                "location": _contact_location(contact),
                "points": points,
                "current_stage": _contact_stage(contact),
                "last_active_at": (
                    contact.get("lastActive")
                    or contact.get("last_active")
                    or contact.get("dateModified")
                    or contact.get("date_modified")
                ),
                "date_added": contact.get("dateAdded") or contact.get("date_added"),
                "date_modified": (
                    contact.get("dateModified") or contact.get("date_modified")
                ),
                "is_published": bool(
                    contact.get("isPublished", contact.get("is_published", True))
                ),
                "mapped_in_ecp": mapping is not None,
                "ecp_user_id": mapping.user_id if mapping is not None else None,
                "last_synced_at": (
                    mapping.last_synced_at if mapping is not None else None
                ),
                "subscription_lists": (
                    subscriptions_by_user.get(mapping.user_id, [])
                    if mapping is not None
                    else []
                ),
            }
        )

    count = _provider_total(provider_data, start=start, returned=len(provider_contacts))
    return {
        "count": count,
        "page": page,
        "page_size": page_size,
        "num_pages": max(1, math.ceil(count / page_size)) if count else 1,
        "results": results,
    }
