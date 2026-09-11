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

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .models import MauticContactMapping, NewsletterCategory, NewsletterSubscription


CORE_CONTACT_FIELDS = {
    "firstname",
    "lastname",
    "email",
    "phone",
    "mobile",
    "company",
    "city",
    "state",
    "zipcode",
    "country",
    "timezone",
    "preferred_locale",
}


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
        "company": str(_contact_field(contact, "company") or "").strip(),
        "address1": str(_contact_field(contact, "address1") or "").strip(),
        "address2": str(_contact_field(contact, "address2") or "").strip(),
        "city": str(_contact_field(contact, "city") or "").strip(),
        "state": str(_contact_field(contact, "state") or "").strip(),
        "zipcode": str(_contact_field(contact, "zipcode") or "").strip(),
        "country": str(_contact_field(contact, "country") or "").strip(),
        "timezone": str(_contact_field(contact, "timezone") or "").strip(),
        "preferred_locale": str(
            _contact_field(contact, "preferred_locale")
            or _contact_field(contact, "preferredLocale")
            or ""
        ).strip(),
    }


def _tags_from_contact(contact: dict[str, Any]) -> list[dict[str, Any]]:
    raw_tags = contact.get("tags")
    if isinstance(raw_tags, dict):
        candidates = raw_tags.values()
    elif isinstance(raw_tags, list):
        candidates = raw_tags
    else:
        return []
    tags = []
    for tag in candidates:
        if isinstance(tag, dict):
            label = str(tag.get("tag") or tag.get("name") or tag.get("label") or "").strip()
            tag_id = tag.get("id")
        else:
            label = str(tag or "").strip()
            tag_id = None
        if label:
            tags.append({"id": str(tag_id) if tag_id not in (None, "") else "", "tag": label})
    return tags


def _dnc_from_contact(contact: dict[str, Any]) -> list[dict[str, Any]]:
    raw = (
        contact.get("doNotContact")
        or contact.get("do_not_contact")
        or contact.get("dnc")
        or []
    )
    if isinstance(raw, dict):
        candidates = raw.values()
    elif isinstance(raw, list):
        candidates = raw
    else:
        return []
    restrictions = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        channel = str(item.get("channel") or item.get("channelName") or "").strip()
        if not channel:
            continue
        restrictions.append(
            {
                "channel": channel,
                "reason": item.get("reason"),
                "comments": str(item.get("comments") or "").strip(),
                "dateAdded": item.get("dateAdded") or item.get("date_added"),
            }
        )
    return restrictions


def _dict_values(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    values = data.get(key)
    if isinstance(values, dict):
        return [item for item in values.values() if isinstance(item, dict)]
    if isinstance(values, list):
        return [item for item in values if isinstance(item, dict)]
    return []


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
        "custom_fields": _custom_field_values(contact),
        "tags": _tags_from_contact(contact),
        "communication_restrictions": _dnc_from_contact(contact),
        "subscription_lists": subscription_lists,
    }


def _custom_field_values(contact: dict[str, Any]) -> dict[str, Any]:
    fields = contact.get("fields")
    if not isinstance(fields, dict):
        return {}
    custom_fields = {}
    for group_name, group in fields.items():
        if group_name in {"core", "social"} or not isinstance(group, dict):
            continue
        for alias, raw_value in group.items():
            value = _field_value(raw_value)
            custom_fields[str(alias)] = value
    return custom_fields


def _normalize_contact_payload(payload: dict[str, Any], *, partial: bool) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Contact payload must be an object.")
    allowed = CORE_CONTACT_FIELDS | {"custom_fields"}
    unsupported = sorted(set(payload.keys()) - allowed)
    if unsupported:
        raise ValueError("Unsupported contact field(s): " + ", ".join(unsupported))

    data = {}
    for field in CORE_CONTACT_FIELDS:
        if field in payload:
            data[field] = str(payload.get(field) or "").strip()

    if not partial and not data.get("email"):
        raise ValueError("email is required.")
    if data.get("email") and "@" not in data["email"]:
        raise ValueError("email must be valid.")

    custom_fields = payload.get("custom_fields", {})
    if custom_fields in (None, ""):
        custom_fields = {}
    if not isinstance(custom_fields, dict):
        raise ValueError("custom_fields must be an object.")
    for alias, value in custom_fields.items():
        normalized_alias = str(alias or "").strip()
        if not normalized_alias:
            raise ValueError("custom field aliases cannot be empty.")
        data[normalized_alias] = value

    if partial and not data:
        raise ValueError("At least one contact field is required.")
    return data


def create_admin_contact(payload: dict[str, Any]) -> dict[str, Any]:
    contact = MauticClient().create_contact(_normalize_contact_payload(payload, partial=False))
    return get_admin_contact(contact.get("id"))


def update_admin_contact(mautic_contact_id, payload: dict[str, Any]) -> dict[str, Any]:
    contact_id = str(mautic_contact_id or "").strip()
    if not contact_id:
        raise ValueError("Mautic contact ID is required.")
    MauticClient().update_contact(
        contact_id,
        _normalize_contact_payload(payload, partial=True),
    )
    return get_admin_contact(contact_id)


def _normalize_field(field: dict[str, Any]) -> dict[str, Any]:
    properties = field.get("properties") if isinstance(field.get("properties"), dict) else {}
    options = (
        properties.get("list")
        or properties.get("options")
        or field.get("list")
        or field.get("options")
        or []
    )
    return {
        "id": str(field.get("id") or ""),
        "label": str(field.get("label") or field.get("name") or "").strip(),
        "alias": str(field.get("alias") or "").strip(),
        "type": str(field.get("type") or "").strip(),
        "group": str(field.get("group") or field.get("groupName") or "").strip(),
        "required": bool(field.get("isRequired", field.get("required", False))),
        "published": bool(field.get("isPublished", field.get("published", True))),
        "default_value": field.get("defaultValue", field.get("default_value")),
        "choices": options if isinstance(options, list) else [],
        "readable": True,
        "writable": not bool(field.get("isReadOnly", field.get("readOnly", False))),
    }


def list_admin_contact_field_metadata() -> dict[str, Any]:
    data = MauticClient().list_contact_fields()
    field_source = data.get("fields") if isinstance(data.get("fields"), (dict, list)) else data
    fields = [_normalize_field(field) for field in _dict_values({"fields": field_source}, "fields")]
    fields = [field for field in fields if field["alias"]]
    return {"count": len(fields), "results": fields}


def list_admin_tags(*, search: str = "", limit: int = 100) -> dict[str, Any]:
    params = {"limit": max(1, min(int(limit), 100))}
    if str(search or "").strip():
        params["search"] = str(search).strip()
    data = MauticClient().list_tags(**params)
    tags = []
    for tag in _dict_values(data, "tags"):
        label = str(tag.get("tag") or tag.get("name") or "").strip()
        if label:
            tags.append({"id": str(tag.get("id") or ""), "tag": label})
    return {"count": len(tags), "results": tags}


def set_admin_contact_tag(mautic_contact_id, tag_name: str, *, remove: bool = False) -> dict[str, Any]:
    contact_id = str(mautic_contact_id or "").strip()
    tag = str(tag_name or "").strip()
    if not contact_id:
        raise ValueError("Mautic contact ID is required.")
    if not tag:
        raise ValueError("tag is required.")
    client = MauticClient()
    contact = client.get_contact(contact_id)
    current = [item["tag"] for item in _tags_from_contact(contact)]
    if remove:
        next_tags = [item for item in current if item.lower() != tag.lower()]
    elif any(item.lower() == tag.lower() for item in current):
        next_tags = current
    else:
        next_tags = current + [tag]
    client.update_contact(contact_id, {"tags": next_tags})
    return get_admin_contact(contact_id)


def list_admin_contact_notes(mautic_contact_id, *, page: int = 1, page_size: int = 25, search: str = "") -> dict[str, Any]:
    page = max(1, int(page))
    page_size = max(1, min(int(page_size), 100))
    start = (page - 1) * page_size
    params = {"start": start, "limit": page_size}
    if str(search or "").strip():
        params["search"] = str(search).strip()
    data = MauticClient().list_contact_notes(mautic_contact_id, **params)
    notes = []
    for note in _dict_values(data, "notes"):
        notes.append(
            {
                "id": str(note.get("id") or ""),
                "text": str(note.get("text") or note.get("note") or "").strip(),
                "type": str(note.get("type") or "").strip(),
                "createdByUser": note.get("createdByUser"),
                "dateAdded": note.get("dateAdded") or note.get("date_added"),
                "dateModified": note.get("dateModified") or note.get("date_modified"),
            }
        )
    count = _provider_total(data, start=start, returned=len(notes))
    return {
        "count": count,
        "page": page,
        "page_size": page_size,
        "num_pages": max(1, math.ceil(count / page_size)) if count else 1,
        "results": notes,
    }


def create_admin_contact_note(mautic_contact_id, payload: dict[str, Any]) -> dict[str, Any]:
    text = str(payload.get("text") or payload.get("note") or "").strip()
    if not text:
        raise ValueError("text is required.")
    note_type = str(payload.get("type") or "general").strip()
    note = MauticClient().create_note(
        {
            "lead": str(mautic_contact_id),
            "text": text,
            "type": note_type,
        }
    )
    return {
        "id": str(note.get("id") or ""),
        "text": str(note.get("text") or note.get("note") or text).strip(),
        "type": str(note.get("type") or note_type).strip(),
        "createdByUser": note.get("createdByUser"),
        "dateAdded": note.get("dateAdded") or note.get("date_added"),
        "dateModified": note.get("dateModified") or note.get("date_modified"),
    }


def add_admin_contact_dnc(mautic_contact_id, payload: dict[str, Any]) -> dict[str, Any]:
    channel = str(payload.get("channel") or "email").strip()
    reason = payload.get("reason", 3)
    comments = str(payload.get("comments") or "").strip()
    MauticClient().add_contact_dnc(mautic_contact_id, channel, reason=reason, comments=comments)
    return get_admin_contact(mautic_contact_id)


def remove_admin_contact_dnc(mautic_contact_id, channel: str = "email") -> dict[str, Any]:
    MauticClient().remove_contact_dnc(mautic_contact_id, channel)
    return get_admin_contact(mautic_contact_id)


def list_admin_contact_companies(mautic_contact_id) -> dict[str, Any]:
    data = MauticClient().list_contact_companies(mautic_contact_id)
    companies = []
    for company in _dict_values(data, "companies"):
        companies.append(
            {
                "id": str(company.get("id") or ""),
                "name": str(company.get("companyname") or company.get("name") or "").strip(),
                "email": str(company.get("companyemail") or company.get("email") or "").strip(),
                "city": str(company.get("companycity") or company.get("city") or "").strip(),
                "country": str(company.get("companycountry") or company.get("country") or "").strip(),
                "is_primary": bool(company.get("is_primary", company.get("isPrimary", False))),
            }
        )
    return {"count": len(companies), "results": companies}


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


def _normalize_stage_filter(stage_id) -> str:
    normalized = str(stage_id or "").strip()
    if not normalized:
        return ""
    if normalized.lower() in {"none", "unstaged"}:
        return "none"
    if not normalized.isdigit() or int(normalized) <= 0:
        raise ValueError("stage_id must be a positive integer or 'none'.")
    return str(int(normalized))


def _stage_contact_filter_params(stage_id) -> dict[str, Any]:
    normalized = _normalize_stage_filter(stage_id)
    if not normalized:
        return {}
    params = {
        "where[0][col]": "stage_id",
    }
    if normalized == "none":
        params["where[0][expr]"] = "isNull"
    else:
        params["where[0][expr]"] = "eq"
        params["where[0][val]"] = normalized
    return params


def list_admin_contacts(
    *,
    page: int = 1,
    page_size: int = 25,
    search: str = "",
    stage_id: str = "",
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
    params.update(_stage_contact_filter_params(stage_id))

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


def _normalize_bulk_contact_ids(contact_ids) -> list[str]:
    if not isinstance(contact_ids, (list, tuple)):
        raise ValueError("contact_ids must be a list.")

    normalized_ids = []
    seen = set()
    for raw_id in contact_ids:
        contact_id = str(raw_id or "").strip()
        if not contact_id or not contact_id.isdigit() or int(contact_id) <= 0:
            raise ValueError("Every contact ID must be a positive integer.")
        contact_id = str(int(contact_id))
        if contact_id in seen:
            continue
        seen.add(contact_id)
        normalized_ids.append(contact_id)

    if not normalized_ids:
        raise ValueError("At least one contact ID is required.")
    if len(normalized_ids) > 100:
        raise ValueError("A maximum of 100 contacts can be updated at once.")
    return normalized_ids


def _stage_reference(stage) -> dict[str, Any] | None:
    if not isinstance(stage, dict):
        return None
    stage_id = stage.get("id")
    if stage_id in (None, ""):
        return None
    try:
        weight = int(stage.get("weight")) if stage.get("weight") not in (None, "") else None
    except (TypeError, ValueError):
        weight = None
    return {
        "id": str(stage_id),
        "name": str(stage.get("name") or ""),
        "weight": weight,
    }


def bulk_update_admin_contact_stage(
    contact_ids,
    *,
    stage_id=None,
    clear: bool = False,
) -> dict[str, Any]:
    """Move or clear up to 100 Mautic contacts with per-contact results."""
    normalized_ids = _normalize_bulk_contact_ids(contact_ids)

    target_stage_id = ""
    if clear:
        if str(stage_id or "").strip():
            raise ValueError("stage_id must not be provided when clearing stages.")
    else:
        target_stage_id = _normalize_stage_filter(stage_id)
        if not target_stage_id or target_stage_id == "none":
            raise ValueError("A valid stage_id is required for bulk move.")

    client = MauticClient()
    target_stage = client.get_stage(target_stage_id) if not clear else None

    results = []
    changed = 0
    failed = 0

    for contact_id in normalized_ids:
        try:
            contact = client.get_contact(contact_id)
            current_stage = _contact_stage(contact)

            if clear:
                if current_stage is None:
                    results.append(
                        {
                            "mautic_contact_id": contact_id,
                            "success": True,
                            "changed": False,
                            "current_stage": None,
                        }
                    )
                    continue

                client.remove_contact_from_stage(current_stage["id"], contact_id)
                updated_contact = client.get_contact(contact_id)
                updated_stage = _contact_stage(updated_contact)
                if updated_stage is not None:
                    raise TemporaryMauticError(
                        "Mautic did not confirm removal of the contact stage."
                    )
                changed += 1
                results.append(
                    {
                        "mautic_contact_id": contact_id,
                        "success": True,
                        "changed": True,
                        "current_stage": None,
                    }
                )
                continue

            if current_stage is not None and current_stage["id"] == target_stage_id:
                results.append(
                    {
                        "mautic_contact_id": contact_id,
                        "success": True,
                        "changed": False,
                        "current_stage": current_stage,
                    }
                )
                continue

            client.add_contact_to_stage(target_stage_id, contact_id)
            updated_contact = client.get_contact(contact_id)
            updated_stage = _contact_stage(updated_contact)
            if updated_stage is None or updated_stage["id"] != target_stage_id:
                raise TemporaryMauticError(
                    "Mautic did not confirm the requested contact stage change."
                )
            changed += 1
            results.append(
                {
                    "mautic_contact_id": contact_id,
                    "success": True,
                    "changed": True,
                    "current_stage": updated_stage,
                }
            )
        except (PermanentMauticError, TemporaryMauticError, ValueError) as exc:
            failed += 1
            results.append(
                {
                    "mautic_contact_id": contact_id,
                    "success": False,
                    "changed": False,
                    "error": str(exc) or "Mautic contact stage update failed.",
                }
            )

    return {
        "action": "clear" if clear else "move",
        "stage_id": None if clear else target_stage_id,
        "requested": len(normalized_ids),
        "succeeded": len(normalized_ids) - failed,
        "failed": failed,
        "changed": changed,
        "results": results,
        "target_stage": _stage_reference(target_stage),
    }


def get_admin_stage_analytics() -> dict[str, Any]:
    """Return provider-backed current contact distribution across Mautic stages."""
    client = MauticClient()
    all_contacts = client.list_contacts(start=0, limit=1)
    total_contacts = _provider_total(
        all_contacts,
        start=0,
        returned=len(_contacts_from_response(all_contacts)),
    )

    stages = []
    start = 0
    page_size = 100
    while True:
        data = client.list_stages(start=start, limit=page_size)
        raw_stages = data.get("stages") or []
        if isinstance(raw_stages, dict):
            page_stages = [item for item in raw_stages.values() if isinstance(item, dict)]
        elif isinstance(raw_stages, list):
            page_stages = [item for item in raw_stages if isinstance(item, dict)]
        else:
            page_stages = []
        stages.extend(page_stages)
        try:
            stage_total = max(0, int(data.get("total", len(page_stages))))
        except (TypeError, ValueError):
            stage_total = start + len(page_stages)
        start += len(page_stages)
        if not page_stages or start >= stage_total:
            break

    rows = []
    staged_contacts = 0
    for stage in stages:
        raw_stage_id = stage.get("id")
        if raw_stage_id in (None, ""):
            continue
        normalized_stage_id = str(raw_stage_id)
        stage_contacts = client.list_contacts(
            start=0,
            limit=1,
            **_stage_contact_filter_params(normalized_stage_id),
        )
        count = _provider_total(
            stage_contacts,
            start=0,
            returned=len(_contacts_from_response(stage_contacts)),
        )
        staged_contacts += count
        try:
            weight = int(stage.get("weight")) if stage.get("weight") not in (None, "") else None
        except (TypeError, ValueError):
            weight = None
        rows.append(
            {
                "id": normalized_stage_id,
                "name": str(stage.get("name") or ""),
                "weight": weight,
                "count": count,
                "percentage": round((count / total_contacts) * 100, 2) if total_contacts else 0.0,
            }
        )

    rows.sort(
        key=lambda item: (
            item["weight"] is None,
            item["weight"] if item["weight"] is not None else 0,
            item["name"].lower(),
            item["id"],
        )
    )
    staged_contacts = min(total_contacts, staged_contacts)
    return {
        "total_contacts": total_contacts,
        "staged_contacts": staged_contacts,
        "unstaged_contacts": max(0, total_contacts - staged_contacts),
        "staged_percentage": (
            round((staged_contacts / total_contacts) * 100, 2)
            if total_contacts
            else 0.0
        ),
        "unstaged_percentage": (
            round(((total_contacts - staged_contacts) / total_contacts) * 100, 2)
            if total_contacts
            else 0.0
        ),
        "stages": rows,
    }
