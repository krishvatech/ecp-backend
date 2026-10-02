"""Duplicate a native Mautic campaign as an independent, unpublished draft.

Mautic's own API clone (POST /api/campaigns/clone/{id}) is not a usable copy:
``Campaign::__clone`` empties the events, segments and forms and keeps the
source's canvas, whose nodes still name the *source's* event IDs. So the copy is
built here from the source's own event graph and created through the ordinary
campaign create call, in one request:

* every active event is re-sent under a fresh temporary ID (``new_N``), parents
  first, with its parent and YES/NO path remapped to those temporary IDs;
* the canvas is the source's, with every event node and connection remapped the
  same way (Mautic reads parents and paths from canvas connections, and swaps
  each ``new_N`` for the real ID it creates);
* the configuration is copied verbatim — properties (canonical tag names
  included) and every timing field Mautic returns; runtime state is not, so the
  copy starts unpublished with no members, logs or schedule.

Nothing is copied unless the source graph is proven sound first, and the copy is
read back and compared with the source afterwards; this module holds those
rules and performs no I/O.
"""

from __future__ import annotations

import json
from typing import Any

from .campaign_services import DUPLICATE_NAME_SUFFIX
from .mautic_campaign_canvas_audit import (
    BRANCH_PATHS,
    BRANCHING_EVENT_TYPES,
    SOURCE_NODE_IDS,
    _as_list,
    _event_parent,
    _source_anchor,
    audit_campaign,
)

# varchar(191) in Mautic's campaigns table.
MAUTIC_CAMPAIGN_NAME_MAX_LENGTH = 191
EVENT_TYPES = ("action", "condition", "decision")

# Authored event configuration, exactly as Mautic's campaign API returns it.
# ``channel``/``channelId`` are left to Mautic, which derives them from the
# properties (its own Event::__clone resets them too).
COPIED_EVENT_FIELDS = (
    "name",
    "description",
    "type",
    "eventType",
    "order",
    "properties",
    "triggerMode",
    "triggerInterval",
    "triggerIntervalUnit",
    "triggerDate",
    "triggerHour",
    "triggerRestrictedStartHour",
    "triggerRestrictedStopHour",
    "triggerRestrictedDaysOfWeek",
)
# Authored campaign settings. ``isPublished`` is always false on a copy, and
# the publish window is not carried over: the source's dates belong to its own
# run, and a draft copy must not inherit an activation window by surprise.
COPIED_CAMPAIGN_FIELDS = ("description", "allowRestart", "republishBehavior")


class DuplicateBlocked(ValueError):
    def __init__(self, reasons: list[str]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def duplicate_name(name: Any) -> str:
    base = str(name or "").strip()
    base = base[: MAUTIC_CAMPAIGN_NAME_MAX_LENGTH - len(DUPLICATE_NAME_SUFFIX)].rstrip()
    return f"{base}{DUPLICATE_NAME_SUFFIX}"


def active_events(campaign: dict[str, Any], active_event_ids: Any) -> list[dict[str, Any]]:
    """The campaign's live events: Mautic's campaign API also returns deleted ones."""
    events = [event for event in _as_list(campaign.get("events")) if isinstance(event, dict)]
    if not isinstance(active_event_ids, list):
        raise DuplicateBlocked(["Mautic did not say which of the campaign's events are still active."])
    active = {str(event_id) for event_id in active_event_ids}
    return [event for event in events if str(event.get("id")) in active]


def _source_ids(value: Any) -> list[int]:
    ids = []
    for item in _as_list(value):
        item_id = item.get("id") if isinstance(item, dict) else item
        try:
            ids.append(int(item_id))
        except (TypeError, ValueError):
            continue
    return sorted(set(ids))


def _depths(events: list[dict[str, Any]]) -> dict[str, int]:
    """Depth of every event below the campaign source; raises on a cycle."""
    parents = {str(event.get("id")): _event_parent(event) for event in events}
    depths: dict[str, int] = {}
    for event_id in parents:
        seen, cursor, depth = {event_id}, parents[event_id], 0
        while cursor is not None:
            if cursor in seen:
                raise DuplicateBlocked([f"event {event_id} sits in a parent cycle"])
            seen.add(cursor)
            cursor, depth = parents.get(cursor), depth + 1
        depths[event_id] = depth
    return depths


def duplicate_blockers(
    campaign: dict[str, Any],
    events: list[dict[str, Any]],
    capabilities: dict[tuple[str, str], Any] | None,
) -> list[str]:
    """Why this campaign's graph cannot be copied faithfully (empty when it can)."""
    if not events:
        return ["The campaign has no active events to copy."]

    audit = audit_campaign({**campaign, "events": events})
    if not audit.classification.startswith("HEALTHY"):
        if audit.repairable:
            return [
                "Mautic refuses changes to this campaign until its stored canvas is repaired "
                "(open it in Mautic, Launch Campaign Builder, Close Builder, then Save & Close); "
                "duplicate it after that."
            ] + audit.reasons
        return [f"The campaign's stored canvas is not safe to copy ({audit.classification})."] + audit.reasons

    problems: list[str] = []
    by_id = {str(event.get("id")): event for event in events}
    for event in events:
        event_id = str(event.get("id"))
        event_type = str(event.get("eventType") or "")
        provider = str(event.get("type") or "")
        if event_type not in EVENT_TYPES or not provider:
            problems.append(f"event {event_id} has an unknown type")
        elif capabilities is not None and (event_type, provider) not in capabilities:
            problems.append(f"event {event_id} ({provider}) is not offered by this Mautic's Campaign Builder")
        elif capabilities is not None:
            # The same property rules ECP's own create applies (required fields,
            # offered choices, numbers): a copy may not carry what a save refuses.
            from .native_campaign_views import _validate_builder_properties

            properties = event.get("properties")
            try:
                _validate_builder_properties(
                    event_index=event_id,
                    properties=properties if isinstance(properties, dict) else {},
                    capability=capabilities[(event_type, provider)],
                )
            except ValueError as exc:
                problems.append(str(exc).replace("Native Mautic Campaign event #", "event "))

        parent_id = _event_parent(event)
        path = event.get("decisionPath") or None
        if path not in (None, *BRANCH_PATHS):
            problems.append(f"event {event_id} has an unknown path {path!r}")
        if parent_id is None:
            if path is not None:
                problems.append(f"event {event_id} has a {path} path but no parent")
            continue
        parent = by_id.get(parent_id)
        if parent is None:
            problems.append(f"event {event_id} follows event {parent_id}, which is not an active event of this campaign")
            continue
        branching = str(parent.get("eventType") or "") in BRANCHING_EVENT_TYPES
        if branching and path is None:
            problems.append(f"event {event_id} follows {parent.get('eventType')} {parent_id} without a YES/NO path")
        if not branching and path is not None:
            problems.append(f"event {event_id} is on a {path} path of an action")

    try:
        _depths(events)
    except DuplicateBlocked as exc:
        problems.extend(exc.reasons)

    problems.extend(_canvas_disagreements(campaign, events))
    return problems


def _canvas_disagreements(campaign: dict[str, Any], events: list[dict[str, Any]]) -> list[str]:
    """The copy's connections are the source's: they must say what the events say."""
    canvas = campaign.get("canvasSettings")
    nodes = [n for n in _as_list(canvas.get("nodes"))] if isinstance(canvas, dict) else []
    if not nodes:
        return []
    connections = [c for c in _as_list(canvas.get("connections")) if isinstance(c, dict)]
    node_ids = {str(node.get("id")) for node in nodes if isinstance(node, dict)}
    problems = []
    for event in events:
        event_id = str(event.get("id"))
        if event_id not in node_ids:
            problems.append(f"event {event_id} is not on Mautic's canvas")
            continue
        incoming = [c for c in connections if str(c.get("targetId")) == event_id]
        from_events = [c for c in incoming if str(c.get("sourceId")) not in SOURCE_NODE_IDS]
        parent_id = _event_parent(event)
        path = event.get("decisionPath") or None
        if parent_id is None:
            if from_events or not incoming:
                problems.append(f"event {event_id} starts the workflow but is not drawn from the campaign source")
            continue
        if len(from_events) != 1 or len(incoming) != 1 or str(from_events[0].get("sourceId")) != parent_id:
            problems.append(f"event {event_id} follows {parent_id} but is not drawn from it alone")
            continue
        anchor = _source_anchor(from_events[0])
        if path is not None and anchor != path:
            problems.append(f"event {event_id} is on the {path} path but drawn from {anchor or 'no outlet'}")
        if path is None and anchor in BRANCH_PATHS:
            problems.append(f"event {event_id} has no path but is drawn from a {anchor} outlet")
    return problems


def build_duplicate_payload(
    campaign: dict[str, Any],
    events: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, str]]:
    """The create payload for the copy, and the source-ID -> temporary-ID map."""
    depths = _depths(events)
    ordered = sorted(
        events,
        key=lambda e: (depths[str(e.get("id"))], int(e.get("order") or 0), int(str(e.get("id")))),
    )
    temp_ids = {str(event.get("id")): f"new_{index}" for index, event in enumerate(ordered, start=1)}

    payload_events = []
    for event in ordered:
        item = {"id": temp_ids[str(event.get("id"))]}
        for field in COPIED_EVENT_FIELDS:
            value = event.get(field)
            if value is None or value == "":
                continue
            item[field] = value
        parent_id = _event_parent(event)
        if parent_id is not None:
            item["parent"] = temp_ids[parent_id]
        if event.get("decisionPath") in BRANCH_PATHS:
            item["decisionPath"] = event["decisionPath"]
        payload_events.append(item)

    lists, forms = _source_ids(campaign.get("lists")), _source_ids(campaign.get("forms"))
    payload: dict[str, Any] = {
        "name": duplicate_name(campaign.get("name")),
        "isPublished": False,
        "lists": [{"id": source_id} for source_id in lists],
        "forms": [{"id": source_id} for source_id in forms],
        "events": payload_events,
        "canvasSettings": _remapped_canvas(campaign, payload_events, temp_ids, lists, forms),
    }
    for field in COPIED_CAMPAIGN_FIELDS:
        if campaign.get(field) is not None:
            payload[field] = campaign[field]
    category = campaign.get("category")
    category_id = category.get("id") if isinstance(category, dict) else category
    if category_id not in (None, ""):
        payload["category"] = category_id
    return payload, temp_ids


def _remapped_canvas(campaign, payload_events, temp_ids, lists, forms) -> dict[str, Any]:
    canvas = campaign.get("canvasSettings")
    nodes = [n for n in _as_list(canvas.get("nodes")) if isinstance(n, dict)] if isinstance(canvas, dict) else []
    if not nodes:
        # No stored canvas: draw the same graph the way ECP's create does.
        from .native_campaign_views import _build_campaign_canvas_settings

        return _build_campaign_canvas_settings(
            payload_events,
            None,
            lists=[{"id": i} for i in lists],
            forms=[{"id": i} for i in forms],
        )

    def remap(node_id):
        node_id = str(node_id)
        return node_id if node_id in SOURCE_NODE_IDS else temp_ids.get(node_id)

    remapped_nodes = []
    for node in nodes:
        new_id = remap(node.get("id"))
        if new_id is not None:
            remapped_nodes.append({**node, "id": new_id})
    remapped_connections = []
    for connection in _as_list(canvas.get("connections")):
        if not isinstance(connection, dict):
            continue
        source, target = remap(connection.get("sourceId")), remap(connection.get("targetId"))
        if source is not None and target is not None:
            remapped_connections.append({**connection, "sourceId": source, "targetId": target})
    return {"nodes": remapped_nodes, "connections": remapped_connections}


def created_event_ids(payload: dict[str, Any], created: dict[str, Any]) -> dict[str, str]:
    """Temporary ID -> real ID: Mautic swaps each ``new_N`` canvas node in place."""
    sent = [str(node.get("id")) for node in payload["canvasSettings"].get("nodes", [])]
    canvas = created.get("canvasSettings") if isinstance(created.get("canvasSettings"), dict) else {}
    stored = [str(node.get("id")) for node in _as_list(canvas.get("nodes")) if isinstance(node, dict)]
    if len(sent) != len(stored):
        return {}
    return {temp: real for temp, real in zip(sent, stored) if temp.startswith("new_")}


def _without_empty_lists(value: Any) -> Any:
    """ECP sends campaigns form-encoded, which cannot carry an empty list, so
    ``remove_tags: []`` arrives as no key at all — as on every ECP save. Mautic's
    providers read both the same (``!empty(...)``, ``?? []``); any non-empty
    difference still counts."""
    if isinstance(value, dict):
        return {k: _without_empty_lists(v) for k, v in value.items() if v != []}
    if isinstance(value, list):
        return [_without_empty_lists(v) for v in value]
    return value


def _normalized(event: dict[str, Any], field: str) -> Any:
    value = event.get(field)
    if field == "triggerRestrictedDaysOfWeek":
        return sorted(str(day) for day in _as_list(value))
    if field == "properties":
        return json.dumps(_without_empty_lists(value if value not in (None, []) else {}), sort_keys=True)
    if field in ("triggerInterval", "order"):
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return value
    return None if value in ("", None) else value


def verify_duplicate(
    source: dict[str, Any],
    source_events: list[dict[str, Any]],
    created: dict[str, Any],
    created_events: list[dict[str, Any]],
    source_to_new: dict[str, str],
) -> list[str]:
    """Where the copy read back from Mautic differs from the source (empty when faithful)."""
    problems = []
    if created.get("isPublished"):
        problems.append("the copy is published")
    if str(created.get("name") or "") != duplicate_name(source.get("name")):
        problems.append("the copy's name is not the expected one")
    for field in ("lists", "forms"):
        if _source_ids(created.get(field)) != _source_ids(source.get(field)):
            problems.append(f"the copy's {field} differ from the source")
    if bool(created.get("allowRestart")) != bool(source.get("allowRestart")):
        problems.append("the copy's restart setting differs")

    new_by_id = {str(event.get("id")): event for event in created_events}
    source_ids = {str(event.get("id")) for event in source_events}
    if len(created_events) != len(source_events):
        problems.append(f"the copy has {len(created_events)} events, the source {len(source_events)}")
    if set(new_by_id) & source_ids:
        problems.append("the copy shares event IDs with the source")

    for event in source_events:
        old_id = str(event.get("id"))
        new_event = new_by_id.get(source_to_new.get(old_id, ""))
        if new_event is None:
            problems.append(f"source event {old_id} has no counterpart in the copy")
            continue
        for field in (*COPIED_EVENT_FIELDS, "decisionPath"):
            if _normalized(event, field) != _normalized(new_event, field):
                problems.append(f"event {old_id} -> {new_event.get('id')}: {field} differs")
        old_parent = _event_parent(event)
        expected = source_to_new.get(old_parent) if old_parent else None
        if _event_parent(new_event) != expected:
            problems.append(f"event {old_id} -> {new_event.get('id')}: parent is not the copied parent")

    if not audit_campaign({**created, "events": created_events}).classification.startswith("HEALTHY"):
        problems.append("the copy's stored canvas is not healthy")
    return problems
