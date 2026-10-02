"""Read-only audit of the canvas Mautic stores for each campaign.

Earlier versions of the ECP Campaign Builder sent their own canvas nodes and
edges (ids like ``node-1790…``, with a ``nodeType``) alongside Mautic's, and they
were stored as they came. The builder's trigger node is never the target of a
connection, which Mautic 7 treats as an orphaned event: ``Campaign::hasOrphanEvents``
runs as a form constraint against the *stored* canvas before an API update can
replace it, so every PATCH to such a campaign is refused (HTTP 400) and the
campaign is frozen for API clients, ECP included. The campaign itself still runs.

This module only classifies what it is given — a campaign as Mautic's REST API
returns it — and proposes what a repair would change. It performs no I/O.

A campaign is reported repairable only when removing the builder's own nodes
(and the connections touching them) leaves Mautic's own graph intact: no orphan
left, and every event reached by exactly one connection that agrees with the
event's own parent and YES/NO path. Anything else is reported for review.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

HEALTHY_NATIVE = "HEALTHY_NATIVE"
HEALTHY_CURRENT_ECP = "HEALTHY_CURRENT_ECP"
HEALTHY_NO_CANVAS = "HEALTHY_NO_CANVAS"
LEGACY_ORPHAN_CANVAS = "LEGACY_ORPHAN_CANVAS"
UNSUPPORTED_OTHER_STRUCTURE = "UNSUPPORTED_OTHER_STRUCTURE"
UNKNOWN = "UNKNOWN"

# Mautic's campaign source nodes; Campaign::hasOrphanEvents never counts them.
SOURCE_NODE_IDS = ("lists", "forms")
BRANCH_PATHS = ("yes", "no")
BRANCHING_EVENT_TYPES = ("condition", "decision")

NATIVE_RESAVE_REPAIR = (
    "Native Mautic re-save: open the campaign in Mautic, Launch Campaign Builder, "
    "Close Builder, then Save & Close."
)


@dataclass
class CanvasAudit:
    campaign_id: str
    name: str
    published: bool
    event_count: int
    classification: str
    reasons: list[str] = field(default_factory=list)
    orphan_nodes: list[str] = field(default_factory=list)
    legacy_builder_nodes: list[str] = field(default_factory=list)
    # The same rule ECP's builder and Mautic's form constraint apply.
    blocks_ecp_save: bool = False
    mautic_patch_fails: bool = False
    repairable: bool = False
    proposed_repair: str = ""
    would_change: dict[str, Any] = field(default_factory=dict)
    proposed_canvas: dict[str, Any] | None = None
    fingerprint: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, dict):
        return list(value.values())
    return list(value) if isinstance(value, list) else []


def _event_parent(event: dict[str, Any]) -> str | None:
    parent = event.get("parent")
    if isinstance(parent, dict):
        parent = parent.get("id")
    return None if parent in (None, "") else str(parent)


def _source_anchor(connection: dict[str, Any]) -> str:
    """The outlet a connection leaves its source by (yes / no / bottom / leadsource)."""
    anchors = connection.get("anchors")
    if isinstance(anchors, dict):
        return str(anchors.get("source") or "")
    # Mautic's builder posts [{endpoint, eventId}, …]; the source's entry names it.
    if isinstance(anchors, list):
        source = str(connection.get("sourceId") or "")
        for anchor in anchors:
            if isinstance(anchor, dict) and str(anchor.get("eventId") or "") == source:
                return str(anchor.get("endpoint") or "")
        if anchors and isinstance(anchors[0], dict):
            return str(anchors[0].get("endpoint") or "")
    return ""


def _is_legacy_builder_node(node: dict[str, Any], event_ids: set[str]) -> bool:
    node_id = str(node.get("id"))
    if node_id in SOURCE_NODE_IDS or node_id in event_ids:
        return False
    return "nodeType" in node or node_id.startswith("node-")


def _orphans(nodes: list[dict[str, Any]], connections: list[dict[str, Any]]) -> list[str]:
    """Campaign::hasOrphanEvents: every non-source node must be some connection's target."""
    if not nodes:
        return []
    targets = {str(connection.get("targetId")) for connection in connections}
    return sorted(
        {str(node.get("id")) for node in nodes}
        - set(SOURCE_NODE_IDS)
        - targets
    )


def _graph_problems(
    events: list[dict[str, Any]],
    nodes: list[dict[str, Any]],
    connections: list[dict[str, Any]],
) -> list[str]:
    """Where the canvas disagrees with the events' own parents and YES/NO paths."""
    node_ids = {str(node.get("id")) for node in nodes}
    types = {str(event.get("id")): str(event.get("eventType") or "") for event in events}
    problems = []
    for event in events:
        event_id = str(event.get("id"))
        if event_id not in node_ids:
            problems.append(f"event {event_id} is not on the canvas")
            continue
        incoming = [c for c in connections if str(c.get("targetId")) == event_id]
        if len(incoming) != 1:
            problems.append(f"event {event_id} has {len(incoming)} incoming connections")
            continue
        source = str(incoming[0].get("sourceId"))
        anchor = _source_anchor(incoming[0])
        parent = _event_parent(event)
        path = event.get("decisionPath")
        if parent is None:
            if source not in SOURCE_NODE_IDS:
                problems.append(f"event {event_id} has no parent but is drawn from {source}")
            continue
        if source != parent:
            problems.append(f"event {event_id} follows {parent} but is drawn from {source}")
        elif path in BRANCH_PATHS:
            if anchor != path:
                problems.append(f"event {event_id} is on the {path} path but drawn from {anchor or 'no outlet'}")
        elif types.get(parent) in BRANCHING_EVENT_TYPES:
            problems.append(f"event {event_id} follows {types[parent]} {parent} without a YES/NO path")
        elif anchor in BRANCH_PATHS:
            problems.append(f"event {event_id} has no path but is drawn from a {anchor} outlet")
    return problems


# Exactly the keys Mautic 7.1.3's campaign API returns for what a repair must
# preserve. Audit metadata (dateAdded/dateModified, created/modified by) and
# derived data (event ``children``, a source's own name/counts) are left out:
# they say nothing about whether the audited structure still holds.
FINGERPRINT_CAMPAIGN_KEYS = (
    "id",
    "name",
    "description",
    "isPublished",
    "publishUp",
    "publishDown",
    "allowRestart",
    "republishBehavior",
)
FINGERPRINT_EVENT_KEYS = (
    "id",
    "name",
    "description",
    "type",
    "eventType",
    "order",
    "properties",
    "decisionPath",
    "channel",
    "channelId",
    "triggerMode",
    "triggerInterval",
    "triggerIntervalUnit",
    "triggerDate",
    "triggerHour",
    "triggerRestrictedStartHour",
    "triggerRestrictedStopHour",
    "triggerRestrictedDaysOfWeek",
)


def _entity_id(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("id")
    return None if value in (None, "") else str(value)


def _source_ids(value: Any) -> list[str]:
    """A campaign's lists/forms come back as full objects; only which ones counts."""
    return sorted({sid for sid in (_entity_id(item) for item in _as_list(value)) if sid}, key=lambda s: (len(s), s))


def _fingerprint_event(event: dict[str, Any]) -> dict[str, Any]:
    item = {key: event.get(key) for key in FINGERPRINT_EVENT_KEYS}
    item["id"] = _entity_id(event.get("id"))
    item["parent"] = _event_parent(event)
    # A set of weekdays: the order Mautic lists them in carries no meaning.
    item["triggerRestrictedDaysOfWeek"] = sorted(str(day) for day in _as_list(event.get("triggerRestrictedDaysOfWeek")))
    return item


def _fingerprint_canvas(canvas: Any) -> Any:
    """Node and connection order is not semantic; their content is."""
    if not isinstance(canvas, dict):
        return canvas
    nodes = sorted(_as_list(canvas.get("nodes")), key=lambda n: json.dumps(n, sort_keys=True, default=str))
    connections = sorted(_as_list(canvas.get("connections")), key=lambda c: json.dumps(c, sort_keys=True, default=str))
    return {"nodes": nodes, "connections": connections}


def campaign_fingerprint(campaign: dict[str, Any]) -> str:
    """Stale-audit check: changes whenever anything the repair must preserve changes.

    Covers the campaign's own settings, its sources, every event's graph,
    configuration and timing (hidden timing restrictions included), and the
    stored canvas. Contacts are never part of a campaign payload.
    """
    events = sorted(
        (_fingerprint_event(event) for event in _as_list(campaign.get("events")) if isinstance(event, dict)),
        key=lambda item: (len(item["id"] or ""), item["id"] or ""),
    )
    payload = json.dumps(
        {
            "campaign": {key: campaign.get(key) for key in FINGERPRINT_CAMPAIGN_KEYS}
            | {"id": _entity_id(campaign.get("id")), "category": _entity_id(campaign.get("category"))},
            "sources": {"lists": _source_ids(campaign.get("lists")), "forms": _source_ids(campaign.get("forms"))},
            "events": events,
            "canvas": _fingerprint_canvas(campaign.get("canvasSettings")),
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def audit_campaign(campaign: dict[str, Any]) -> CanvasAudit:
    events = [event for event in _as_list(campaign.get("events")) if isinstance(event, dict)]
    audit = CanvasAudit(
        campaign_id=str(campaign.get("id")),
        name=str(campaign.get("name") or ""),
        published=bool(campaign.get("isPublished")),
        event_count=len(events),
        classification=UNKNOWN,
        fingerprint=campaign_fingerprint(campaign),
    )

    canvas = campaign.get("canvasSettings")
    if canvas in (None, [], {}):
        canvas = {}
    if not isinstance(canvas, dict):
        audit.reasons.append("stored canvas is not readable")
        return audit
    nodes = [node for node in _as_list(canvas.get("nodes")) if isinstance(node, dict)]
    connections = [c for c in _as_list(canvas.get("connections")) if isinstance(c, dict)]
    if any(node.get("id") in (None, "") for node in nodes):
        audit.reasons.append("a canvas node has no id")
        return audit

    event_ids = {str(event.get("id")) for event in events}
    audit.orphan_nodes = _orphans(nodes, connections)
    audit.blocks_ecp_save = audit.mautic_patch_fails = bool(audit.orphan_nodes)
    audit.legacy_builder_nodes = sorted(
        str(node["id"]) for node in nodes if _is_legacy_builder_node(node, event_ids)
    )

    if not nodes:
        audit.classification = HEALTHY_NO_CANVAS
        return audit

    if not audit.orphan_nodes:
        # Saved last by Mautic's own builder: it writes positions as numbers;
        # the REST API (current ECP included) stores what it is sent, strings.
        native = all(
            isinstance(node.get("positionX"), int) and isinstance(node.get("positionY"), int)
            for node in nodes
        )
        audit.classification = HEALTHY_NATIVE if native else HEALTHY_CURRENT_ECP
        if audit.legacy_builder_nodes:
            audit.reasons.append("contains old ECP builder nodes, but none is orphaned")
        return audit

    foreign = sorted(
        str(node["id"])
        for node in nodes
        if str(node["id"]) not in SOURCE_NODE_IDS
        and str(node["id"]) not in event_ids
        and str(node["id"]) not in audit.legacy_builder_nodes
    )
    if foreign:
        audit.reasons.append(f"canvas node(s) {', '.join(foreign)} match no event and no known builder shape")
        return audit

    orphaned_events = [node_id for node_id in audit.orphan_nodes if node_id in event_ids]
    if orphaned_events:
        audit.classification = UNSUPPORTED_OTHER_STRUCTURE
        audit.reasons.append(f"event(s) {', '.join(orphaned_events)} are not connected to anything")
        return audit

    legacy = set(audit.legacy_builder_nodes)
    kept_nodes = [node for node in nodes if str(node["id"]) not in legacy]
    kept_connections = [
        c for c in connections
        if str(c.get("sourceId")) not in legacy and str(c.get("targetId")) not in legacy
    ]
    problems = []
    remaining = _orphans(kept_nodes, kept_connections)
    if remaining:
        problems.append(f"node(s) {', '.join(remaining)} stay orphaned without the builder nodes")
    problems += _graph_problems(events, kept_nodes, kept_connections)
    if not events:
        problems.append("the campaign has no events")
    if problems:
        audit.classification = UNSUPPORTED_OTHER_STRUCTURE
        audit.reasons.append("old ECP builder nodes are orphaned, and Mautic's own graph does not match the events:")
        audit.reasons.extend(problems)
        return audit

    audit.classification = LEGACY_ORPHAN_CANVAS
    audit.repairable = True
    audit.reasons.append("only the old ECP builder's own canvas nodes are orphaned; Mautic's graph matches every event")
    audit.proposed_repair = NATIVE_RESAVE_REPAIR
    audit.proposed_canvas = {"nodes": kept_nodes, "connections": kept_connections}
    audit.would_change = {
        "canvasSettings.nodes.removed": audit.legacy_builder_nodes,
        "canvasSettings.connections.removed": len(connections) - len(kept_connections),
        "events": "unchanged",
    }
    return audit
