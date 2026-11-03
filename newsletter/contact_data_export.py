"""Everything Mautic holds about one contact, as a ZIP, for a data-access request.

Mautic's own "Export" on a contact writes its profile fields only. This adds what
an admin needs to answer a GDPR access request: tags, segments, campaigns,
companies, Do Not Contact records, stage, points, notes and the activity
timeline. Built on request from service-account reads (one contact is small);
nothing is stored. CSV cells are protected against spreadsheet formulas.

Files: profile.csv (alias, label, value, as Mautic's export), notes.csv,
activity.csv and data.json (everything, machine-readable).
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any

from .contact_export_services import _cell
from .contact_services import contact_notes_page
from .mautic import MauticClient

NOTE_PAGE = 100
NOTE_MAX = 2000
ACTIVITY_PAGE = 100
ACTIVITY_MAX = 5000


def _rows(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = list(value.values())
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _profile(contact: dict[str, Any]) -> list[dict[str, Any]]:
    fields = contact.get("fields") if isinstance(contact.get("fields"), dict) else {}
    labels: dict[str, str] = {}
    for group, group_fields in fields.items():
        if group == "all" or not isinstance(group_fields, dict):
            continue
        for alias, field in group_fields.items():
            if isinstance(field, dict):
                labels[alias] = str(field.get("label") or alias)
    values = fields.get("all") if isinstance(fields.get("all"), dict) else {}
    return [{"alias": alias, "label": labels.get(alias, alias), "value": value} for alias, value in values.items()]


def _notes(client: MauticClient, contact_id) -> tuple[list[dict[str, Any]], bool]:
    notes: list[dict[str, Any]] = []
    start = 0
    while len(notes) < NOTE_MAX:
        data = contact_notes_page(client, contact_id, start=start, limit=NOTE_PAGE)
        batch = _rows(data.get("notes"))
        notes.extend(batch)
        start += len(batch)
        if len(batch) < NOTE_PAGE or start >= int(data.get("total") or 0):
            return notes, False
    return notes, True


def _activity(client: MauticClient, contact_id) -> tuple[list[dict[str, Any]], bool]:
    events: list[dict[str, Any]] = []
    page = 1
    while len(events) < ACTIVITY_MAX:
        data = client.get_contact_activity(contact_id, page=page, limit=ACTIVITY_PAGE)
        batch = _rows(data.get("events"))
        events.extend(batch)
        if len(batch) < ACTIVITY_PAGE or page >= int(data.get("maxPages") or page):
            return events, False
        page += 1
    return events, True


def _csv(headers: list[str], rows: list[list[Any]]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(headers)
    writer.writerows([[_cell(value) for value in row] for row in rows])
    return ("﻿" + buffer.getvalue()).encode("utf-8")


def build_contact_data_export(contact_id, *, client: MauticClient | None = None) -> tuple[str, bytes, dict[str, Any]]:
    """(filename, ZIP bytes, summary). Raises the client's errors."""
    client = client or MauticClient()
    contact = client.get_contact(contact_id)
    profile = _profile(contact)
    notes, notes_capped = _notes(client, contact_id)
    events, events_capped = _activity(client, contact_id)
    companies = _rows(client.list_contact_companies(contact_id).get("companies"))
    now = datetime.now(timezone.utc)
    data = {
        "exportedAt": now.isoformat(),
        "contactId": str(contact.get("id") or contact_id),
        "profile": {row["alias"]: row["value"] for row in profile},
        "tags": [str(tag.get("tag") if isinstance(tag, dict) else tag) for tag in contact.get("tags") or []],
        "utmTags": contact.get("utmtags") or [],
        "doNotContact": contact.get("doNotContact") or [],
        "stage": contact.get("stage"),
        "points": contact.get("points"),
        "owner": contact.get("owner"),
        "ipAddresses": contact.get("ipAddresses") or [],
        "frequencyRules": contact.get("frequencyRules") or [],
        "dateAdded": contact.get("dateAdded"),
        "dateIdentified": contact.get("dateIdentified"),
        "lastActive": contact.get("lastActive"),
        "segments": [{"id": row.get("id"), "name": row.get("name")} for row in client.get_contact_segments(contact_id)],
        "campaigns": [{"id": row.get("id"), "name": row.get("name")} for row in client.get_contact_campaigns(contact_id)],
        "companies": [{"id": row.get("company_id") or row.get("id"), "name": row.get("companyname") or row.get("name"),
                       "primary": row.get("is_primary")} for row in companies],
        "notes": notes,
        "activity": events,
        "truncated": {"notes": notes_capped, "activity": events_capped},
    }
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("profile.csv", _csv(["alias", "label", "value"], [[r["alias"], r["label"], r["value"]] for r in profile]))
        bundle.writestr("notes.csv", _csv(["added", "by", "type", "text", "note_date", "edited", "edited_by"], [
            [n.get("dateAdded"), n.get("createdByUser"), n.get("type"), n.get("text"), n.get("dateTime"), n.get("dateModified"),
             n.get("modifiedByUser")] for n in notes]))
        bundle.writestr("activity.csv", _csv(["timestamp", "type", "event"], [
            [e.get("timestamp"), e.get("eventType") or e.get("event"), e.get("eventLabel") if not isinstance(e.get("eventLabel"), dict)
             else e["eventLabel"].get("label")] for e in events]))
        bundle.writestr("data.json", json.dumps(data, indent=2, default=str, ensure_ascii=False))
    summary = {"fields": len(profile), "notes": len(notes), "events": len(events), "truncated": notes_capped or events_capped}
    return f"contact-{data['contactId']}-data-{now:%Y%m%d}.zip", archive.getvalue(), summary
