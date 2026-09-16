from __future__ import annotations

import math
from typing import Any

from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.exceptions import MauticBridgeRejectedError, MauticIdentityError
from .mautic.identity import MauticExecutionContext, get_mautic_client
from .mautic_reference_choices import (
    REFERENCE_CHOICE_SOURCES,
    normalize_choice_rows,
    reference_choice_page,
)


_CAMPAIGN_FIELDS = {
    "name",
    "description",
    "isPublished",
    "sources",
    "lists",
    "forms",
    "events",
    "canvasSettings",
}

_EVENT_TYPES = {"action", "condition", "decision"}


def _provider_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    return bool(value)


def _parse_bool(value, *, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{field_name} must be a boolean.")


def _collection_items(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        rows = list(value.values())
    elif isinstance(value, list):
        rows = list(value)
    else:
        return []
    return [row for row in rows if isinstance(row, dict)]


def _normalize_relation_id(value):
    if isinstance(value, dict):
        value = value.get("id")
    if value in (None, ""):
        return None
    return str(value)


def _normalize_campaign(campaign: dict[str, Any]) -> dict[str, Any]:
    campaign_id = campaign.get("id")
    lists = _collection_items(campaign.get("lists"))
    forms = _collection_items(campaign.get("forms"))
    events = _collection_items(campaign.get("events"))

    normalized_events = []
    for event in events:
        event_id = event.get("id")
        children = event.get("children")
        if isinstance(children, dict):
            child_values = list(children.values())
        elif isinstance(children, list):
            child_values = children
        else:
            child_values = []

        properties = event.get("properties")
        if isinstance(properties, list):
            properties = {}
        elif not isinstance(properties, dict):
            properties = {}

        normalized_events.append(
            {
                "id": str(event_id) if event_id is not None else None,
                "name": str(event.get("name") or ""),
                "description": str(event.get("description") or ""),
                "type": str(event.get("type") or ""),
                "eventType": str(event.get("eventType") or ""),
                "order": event.get("order"),
                "properties": properties,
                "triggerInterval": event.get("triggerInterval"),
                "triggerIntervalUnit": event.get("triggerIntervalUnit"),
                "triggerMode": event.get("triggerMode"),
                "triggerDate": event.get("triggerDate"),
                "parent": _normalize_relation_id(event.get("parent")),
                "decisionPath": event.get("decisionPath"),
                "children": [
                    child_id
                    for child_id in (
                        _normalize_relation_id(child)
                        for child in child_values
                    )
                    if child_id is not None
                ],
            }
        )

    return {
        "id": str(campaign_id) if campaign_id is not None else None,
        "name": str(campaign.get("name") or "").strip(),
        "description": str(campaign.get("description") or ""),
        "isPublished": _provider_bool(campaign.get("isPublished", False)),
        "dateAdded": campaign.get("dateAdded"),
        "dateModified": campaign.get("dateModified"),
        "contactCount": campaign.get("contactCount"),
        "lists": [
            {
                "id": str(row.get("id")) if row.get("id") is not None else None,
                "name": str(row.get("name") or ""),
                "alias": str(row.get("alias") or ""),
            }
            for row in lists
        ],
        "forms": [
            {
                "id": str(row.get("id")) if row.get("id") is not None else None,
                "name": str(row.get("name") or ""),
            }
            for row in forms
        ],
        "events": normalized_events,
        "canvasSettings": (
            campaign.get("canvasSettings")
            if isinstance(campaign.get("canvasSettings"), dict)
            else {}
        ),
    }


def _normalize_source_rows(value) -> list[dict[str, Any]]:
    return [
        {
            "id": str(row.get("id")) if row.get("id") is not None else None,
            "name": str(row.get("name") or ""),
            "alias": str(row.get("alias") or ""),
            "isPublished": _provider_bool(row.get("isPublished", False)),
        }
        for row in _collection_items(value)
    ]


def _parse_source_ids(value, *, field_name: str) -> list[dict[str, int]]:
    if not isinstance(value, list):
        raise ValueError(f"Native Mautic Campaign {field_name} must be a list.")

    result = []
    seen = set()
    for item in value:
        raw_id = item.get("id") if isinstance(item, dict) else item
        if isinstance(raw_id, bool):
            raise ValueError(
                f"Native Mautic Campaign {field_name} IDs must be positive integers."
            )
        try:
            source_id = int(raw_id)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Native Mautic Campaign {field_name} IDs must be positive integers."
            ) from exc
        if source_id <= 0:
            raise ValueError(
                f"Native Mautic Campaign {field_name} IDs must be positive integers."
            )
        if source_id not in seen:
            result.append({"id": source_id})
            seen.add(source_id)
    return result


def _parse_sources(value) -> dict[str, list[dict[str, int]]]:
    if not isinstance(value, dict):
        raise ValueError("Native Mautic Campaign sources must be an object.")

    unsupported = sorted(set(value.keys()) - {"segments", "lists", "forms"})
    if unsupported:
        raise ValueError(
            "Unsupported Native Mautic Campaign source field(s): "
            + ", ".join(unsupported)
        )

    parsed = {}
    if "segments" in value or "lists" in value:
        parsed["lists"] = _parse_source_ids(
            value.get("segments", value.get("lists", [])),
            field_name="sources.segments",
        )
    if "forms" in value:
        parsed["forms"] = _parse_source_ids(
            value.get("forms", []),
            field_name="sources.forms",
        )
    return parsed


def _is_builder_event(item: Any) -> bool:
    return isinstance(item, dict) and (
        "key" in item or "metadata" in item or "type" not in item
    )


def _uses_builder_events(value) -> bool:
    return isinstance(value, list) and any(_is_builder_event(item) for item in value)


def _request_uses_builder_events(data) -> bool:
    return hasattr(data, "get") and _uses_builder_events(data.get("events"))


def _event_capability_rows(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for field, event_type in (
        ("actions", "action"),
        ("conditions", "condition"),
        ("decisions", "decision"),
    ):
        for event in capabilities.get(field, []):
            if isinstance(event, dict):
                normalized = dict(event)
                normalized.setdefault("eventType", event_type)
                rows.append(normalized)
    return rows


def _event_key(event: dict[str, Any]) -> str:
    return str(event.get("key") or event.get("type") or "").strip()


def _json_safe(value: Any) -> bool:
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, list):
        return all(_json_safe(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _json_safe(child) for key, child in value.items())
    return False


def _option_value(option: Any) -> Any:
    if isinstance(option, dict):
        for field in ("value", "id", "key", "label", "name"):
            if field in option:
                return option.get(field)
        return None
    return option


def _choice_values(value: Any) -> list[Any]:
    if isinstance(value, list):
        return [_option_value(option) for option in value]
    if isinstance(value, dict):
        choices = value.get("choices")
        if isinstance(choices, dict):
            return list(choices.keys())
        if isinstance(choices, list):
            return [_option_value(option) for option in choices]
        options = value.get("options")
        if isinstance(options, list):
            return [_option_value(option) for option in options]
    return []


def _schema_choice_values(choices: Any) -> list[Any]:
    values: list[Any] = []
    choice_rows = choices if isinstance(choices, list) else []
    for choice in choice_rows:
        if isinstance(choice, dict) and isinstance(choice.get("choices"), list):
            values.extend(_schema_choice_values(choice.get("choices")))
        else:
            values.append(_option_value(choice))
    return values


def _get_property(properties: dict[str, Any], path: list[str]) -> tuple[bool, Any]:
    current: Any = properties
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _iter_form_metadata_fields(value: Any, path: list[str] | None = None):
    path = path or []
    if not isinstance(value, dict):
        return

    for key, child in value.items():
        child_path = [*path, str(key)]
        if isinstance(child, dict):
            has_field_hint = (
                child.get("required") is True
                or bool(_choice_values(child))
                or child.get("type") in {"choice", "select", "boolean", "checkbox"}
            )
            if has_field_hint:
                yield child_path, child
            yield from _iter_form_metadata_fields(child, child_path)
        elif isinstance(child, list):
            yield child_path, child


_NON_DATA_CONTROL_TYPES = {"action", "hidden", "internal"}
_NON_DATA_BLOCK_PREFIXES = {"button", "submit", "reset", "hidden"}


def _is_configurable_schema_field(field: Any) -> bool:
    """Event data, as opposed to a provider UI control.

    Buttons, submit/reset controls, hidden inputs and anything the provider form
    does not map onto the event's properties are not configuration: an event made
    only of those needs nothing filled in.
    """
    if not isinstance(field, dict) or not str(field.get("name") or "").strip():
        return False
    if field.get("renderable") is False or field.get("mapped") is False:
        return False
    if str(field.get("controlType") or "").lower() in _NON_DATA_CONTROL_TYPES:
        return False

    prefixes = field.get("blockPrefixes")
    if isinstance(prefixes, list) and any(
        str(prefix).lower() in _NON_DATA_BLOCK_PREFIXES for prefix in prefixes
    ):
        return False

    return True


def _iter_schema_fields(fields: Any, path: list[str] | None = None):
    path = path or []
    if not isinstance(fields, list):
        return

    for field in fields:
        if not _is_configurable_schema_field(field):
            continue
        name = str(field.get("name") or "").strip()
        child_path = [*path, name]
        children = field.get("children")
        choices = field.get("choices")
        if isinstance(children, list) and not choices:
            yield from _iter_schema_fields(children, child_path)
            continue
        yield child_path, field


_NUMERIC_FIELD_MARKERS = ("number", "integer", "percent")


def _is_numeric_schema_field(metadata: Any) -> bool:
    """A provider field Mautic renders as a number input."""
    if not isinstance(metadata, dict):
        return False

    prefixes = metadata.get("blockPrefixes")
    if isinstance(prefixes, list) and any(
        str(prefix).lower() in _NUMERIC_FIELD_MARKERS for prefix in prefixes
    ):
        return True

    field_type = str(metadata.get("type") or "").lower()
    return any(marker in field_type for marker in ("numbertype", "integertype"))


def _is_blank_property(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _is_entity_identifier(data: Any) -> bool:
    if isinstance(data, dict):
        return data.get("id") not in (None, "")
    if isinstance(data, bool):
        return False
    if isinstance(data, (int, float)):
        return True
    if isinstance(data, str):
        try:
            float(data.strip())
        except (TypeError, ValueError):
            return False
        return data.strip() != ""
    return False


def _is_selectable_entity_choice(choice: Any) -> bool:
    """Whether a choice in a provider entity selector identifies a stored entity.

    Mautic's EntityLookupChoiceLoader prepends a "Create new…" => "new" choice to
    every entity field that has a creation modal. It is a UI command that opens
    that modal, never a selection, and unlike a real choice it carries no entity
    identifier in `data`.
    """
    if not isinstance(choice, dict):
        return True
    data = choice.get("data")
    if data is None:
        data = choice.get("value")
    return _is_entity_identifier(data)


def _is_provider_command_value(metadata: Any, value: Any) -> bool:
    if not isinstance(metadata, dict) or metadata.get("choiceKind") != "entity":
        return False

    for choice in _flat_schema_choices(metadata.get("choices")):
        if str(_option_value(choice)) == str(value):
            return not _is_selectable_entity_choice(choice)

    return False


def _flat_schema_choices(choices: Any) -> list[Any]:
    flattened: list[Any] = []
    for choice in choices if isinstance(choices, list) else []:
        if isinstance(choice, dict) and isinstance(choice.get("choices"), list):
            flattened.extend(_flat_schema_choices(choice["choices"]))
            continue
        flattened.append(choice)
    return flattened


def _is_configured_property(metadata: Any, exists: bool, value: Any) -> bool:
    """A value counts as configuration unless it is blank or a UI command."""
    if not exists or _is_blank_property(value):
        return False

    selected = value if isinstance(value, list) else [value]
    return any(
        not _is_blank_property(item) and not _is_provider_command_value(metadata, item)
        for item in selected
    )


def _schema_field_label(path: list[str], metadata: Any) -> str:
    if isinstance(metadata, dict):
        label = metadata.get("label")
        if isinstance(label, str) and label.strip():
            return label.strip()
    return ".".join(path)


def _validate_builder_properties(
    *,
    event_index: int,
    properties: Any,
    capability: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(properties, dict):
        raise ValueError(
            f"Native Mautic Campaign event #{event_index} properties must be an object."
        )
    if not _json_safe(properties):
        raise ValueError(
            f"Native Mautic Campaign event #{event_index} properties must be JSON serializable."
        )

    schema = capability.get("formSchema")
    schema_fields = (
        list(_iter_schema_fields(schema.get("fields")))
        if isinstance(schema, dict) and schema.get("available") is True
        else []
    )
    metadata_fields = (
        []
        if schema_fields
        else list(_iter_form_metadata_fields(capability.get("formTypeOptions")))
    )

    all_fields = [*schema_fields, *metadata_fields]
    required_fields = [
        path
        for path, metadata in all_fields
        if isinstance(metadata, dict) and metadata.get("required") is True
    ]
    configured_fields = [
        path
        for path, metadata in all_fields
        if _is_configured_property(metadata, *_get_property(properties, path))
    ]

    # An event whose provider form has no required field still has to be told what
    # to do — an "add or remove tags" action with neither set, for instance, would
    # be saved as a step that does nothing.
    if all_fields and not required_fields and not configured_fields:
        options = ", ".join(
            _schema_field_label(path, metadata) for path, metadata in all_fields
        )
        raise ValueError(
            f"Native Mautic Campaign event #{event_index} needs at least one of: "
            f"{options}."
        )

    for path, metadata in all_fields:
        exists, value = _get_property(properties, path)
        label = ".".join(path)
        if isinstance(metadata, dict) and metadata.get("required") is True:
            if not _is_configured_property(metadata, exists, value):
                raise ValueError(
                    f"Native Mautic Campaign event #{event_index} missing required "
                    f"property {label}."
                )

        if exists and not _is_blank_property(value) and _is_numeric_schema_field(metadata):
            if isinstance(value, bool) or isinstance(value, (list, dict)):
                raise ValueError(
                    f"Native Mautic Campaign event #{event_index} property {label} "
                    "must be a number."
                )
            try:
                float(value)
            except (TypeError, ValueError):
                raise ValueError(
                    f"Native Mautic Campaign event #{event_index} property {label} "
                    "must be a number."
                ) from None

        choices = (
            _schema_choice_values(metadata.get("choices"))
            if isinstance(metadata, dict) and isinstance(metadata.get("choices"), list)
            else _choice_values(metadata)
        )
        if exists and choices:
            values = value if isinstance(value, list) else [value]
            allowed = {str(choice) for choice in choices if choice is not None}
            invalid = [
                choice
                for choice in values
                if choice not in (None, "") and str(choice) not in allowed
            ]
            if invalid:
                raise ValueError(
                    f"Native Mautic Campaign event #{event_index} has invalid "
                    f"value for property {label}."
                )

    return properties


def _parse_builder_events(
    value,
    *,
    capabilities: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if not isinstance(capabilities, dict):
        raise ValueError(
            "Native Mautic Campaign runtime builder capabilities are required."
        )

    capability_index: dict[tuple[str, str], dict[str, Any]] = {}
    for capability in _event_capability_rows(capabilities):
        key = _event_key(capability)
        event_type = str(capability.get("eventType") or "").strip()
        if key and event_type:
            capability_index[(event_type, key)] = capability

    parsed = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            raise ValueError(
                f"Native Mautic Campaign event #{index} must be an object."
            )

        key = str(item.get("key") or item.get("type") or "").strip()
        event_type = str(item.get("eventType") or "").strip()
        if not key:
            raise ValueError(f"Native Mautic Campaign event #{index} key is required.")
        if event_type not in _EVENT_TYPES:
            raise ValueError(
                f"Native Mautic Campaign event #{index} eventType must be "
                "action, condition, or decision."
            )

        capability = capability_index.get((event_type, key))
        if not capability:
            raise ValueError(
                f"Native Mautic Campaign event #{index} is not available in "
                "runtime Mautic Campaign Builder capabilities."
            )

        properties = _validate_builder_properties(
            event_index=index,
            properties=item.get("properties", {}),
            capability=capability,
        )
        event_id = str(item.get("id") or f"new_{index}").strip()
        if not event_id or event_id.startswith("event-"):
            event_id = f"new_{index}"

        event = {
            "id": event_id,
            "name": str(item.get("name") or capability.get("label") or key).strip(),
            "type": key,
            "eventType": event_type,
            "properties": properties,
            "children": [],
            "order": item.get("order", index),
        }

        for field in (
            "description",
            "triggerInterval",
            "triggerIntervalUnit",
            "triggerMode",
            "triggerDate",
            "parent",
            "decisionPath",
        ):
            if field in item:
                event[field] = item.get(field)

        parsed.append(event)

    return parsed


def _parse_events(
    value,
    *,
    capabilities: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("Native Mautic Campaign events must be a list.")
    if _uses_builder_events(value):
        return _parse_builder_events(value, capabilities=capabilities)

    parsed = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} must be an object."
            )

        event_id = str(item.get("id") or "").strip()
        name = str(item.get("name") or "").strip()
        provider_type = str(item.get("type") or "").strip()
        event_type = str(item.get("eventType") or "").strip()

        if not event_id:
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} id is required."
            )
        if not name:
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} name is required."
            )
        if not provider_type:
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} type is required."
            )
        if event_type not in _EVENT_TYPES:
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} eventType must be "
                "action, condition, or decision."
            )

        properties = item.get("properties", {})
        if not isinstance(properties, (dict, list)):
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} properties "
                "must be an object or list."
            )

        children = item.get("children", [])
        if not isinstance(children, list):
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} children must be a list."
            )

        event = {
            "id": event_id,
            "name": name,
            "type": provider_type,
            "eventType": event_type,
            "properties": properties,
            "children": [str(child) for child in children],
        }

        optional_fields = (
            "description",
            "order",
            "triggerInterval",
            "triggerIntervalUnit",
            "triggerMode",
            "triggerDate",
            "parent",
            "decisionPath",
        )
        for field in optional_fields:
            if field in item:
                event[field] = item.get(field)

        parsed.append(event)

    return parsed


def _parse_canvas(value) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Native Mautic Campaign canvasSettings must be an object.")

    nodes = value.get("nodes", [])
    connections = value.get("connections", [])
    if not isinstance(nodes, list) or not isinstance(connections, list):
        raise ValueError(
            "Native Mautic Campaign canvasSettings nodes and connections must be lists."
        )
    if any(not isinstance(node, dict) for node in nodes):
        raise ValueError("Native Mautic Campaign canvas nodes must be objects.")
    if any(not isinstance(connection, dict) for connection in connections):
        raise ValueError("Native Mautic Campaign canvas connections must be objects.")

    return {
        "nodes": nodes,
        "connections": connections,
    }


def _validate_event_graph(
    events: list[dict[str, Any]],
    client_canvas: dict[str, Any] | None,
) -> None:
    """Reject a workflow whose graph points at things that are not there."""
    event_ids = {str(event.get("id")) for event in events if event.get("id") is not None}

    for index, event in enumerate(events, start=1):
        parent = event.get("parent")
        if parent in (None, ""):
            continue
        parent = str(parent)
        if parent == str(event.get("id")):
            raise ValueError(
                f"Native Mautic Campaign event #{index} cannot follow itself."
            )
        if parent not in event_ids:
            raise ValueError(
                f"Native Mautic Campaign event #{index} follows an event that is "
                "not part of this campaign."
            )

    if not isinstance(client_canvas, dict):
        return

    node_ids = {
        str(node.get("id"))
        for node in (client_canvas.get("nodes") or [])
        if isinstance(node, dict) and node.get("id") not in (None, "")
    }
    # The caller's own canvas is self-contained: its connections may only join its
    # own nodes, the campaign sources, or events in this payload.
    known = node_ids | event_ids | {"lists", "forms"}

    for connection in client_canvas.get("connections") or []:
        if not isinstance(connection, dict):
            continue
        source = connection.get("sourceId") or connection.get("source")
        target = connection.get("targetId") or connection.get("target")
        for endpoint in (source, target):
            if endpoint in (None, ""):
                raise ValueError(
                    "Native Mautic Campaign canvas connections must name a source "
                    "and a target."
                )
            if str(endpoint) not in known:
                raise ValueError(
                    "Native Mautic Campaign canvas connects to unknown node "
                    f'"{endpoint}".'
                )


def _canvas_node(node_id: Any, column: int, depth: int) -> dict[str, Any]:
    return {
        "id": str(node_id),
        "positionX": str(380 + column * 240),
        "positionY": str(100 + depth * 160),
    }


def _canvas_connection(source: Any, target: Any, source_anchor: str) -> dict[str, Any]:
    return {
        "sourceId": str(source),
        "targetId": str(target),
        "anchors": {"source": source_anchor, "target": "top"},
    }


def _normalized_canvas_node(node: Any, fallback_column: int) -> dict[str, Any] | None:
    """Mautic dereferences ``id`` on every canvas node, so drop unusable ones."""
    if not isinstance(node, dict):
        return None
    node_id = node.get("id")
    if node_id in (None, ""):
        return None

    normalized = dict(node)
    normalized["id"] = str(node_id)
    normalized.setdefault("positionX", str(380 + fallback_column * 240))
    normalized.setdefault("positionY", "100")
    return normalized


def _normalized_canvas_connection(connection: Any) -> dict[str, Any] | None:
    """Mautic dereferences ``sourceId``/``targetId``/``anchors`` on every connection."""
    if not isinstance(connection, dict):
        return None
    source = connection.get("sourceId") or connection.get("source")
    target = connection.get("targetId") or connection.get("target")
    if source in (None, "") or target in (None, ""):
        return None

    normalized = dict(connection)
    normalized["sourceId"] = str(source)
    normalized["targetId"] = str(target)
    anchors = normalized.get("anchors")
    if not isinstance(anchors, dict) or not anchors.get("source"):
        normalized["anchors"] = {"source": "bottom", "target": "top"}
    return normalized


def _event_depths(events: list[dict[str, Any]]) -> dict[str, int]:
    parents = {
        str(event.get("id")): str(event["parent"])
        for event in events
        if event.get("parent") not in (None, "")
    }
    known = {str(event.get("id")) for event in events}
    depths: dict[str, int] = {}

    for event_id in known:
        depth = 0
        seen = {event_id}
        cursor = event_id
        while cursor in parents and parents[cursor] in known:
            cursor = parents[cursor]
            if cursor in seen:  # defensive: never spin on a cyclic payload
                break
            seen.add(cursor)
            depth += 1
        depths[event_id] = depth

    return depths


def _provider_canvas_graph(
    events: list[dict[str, Any]],
    *,
    source_node_id: str | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Describe the event graph the way Mautic's own Campaign Builder does.

    Mautic only applies campaign events when ``canvasSettings`` is present, and it
    reads parent/child relationships from canvas connections rather than from each
    event's ``parent`` field, so the graph has to be expressed here.
    """
    known = {str(event.get("id")) for event in events if event.get("id") not in (None, "")}
    depths = _event_depths(events)

    nodes: list[dict[str, Any]] = []
    connections: list[dict[str, Any]] = []
    columns: dict[int, int] = {}

    if source_node_id:
        nodes.append(_canvas_node(source_node_id, 0, 0))

    for event in events:
        event_id = str(event.get("id") or "")
        if not event_id:
            continue

        depth = depths.get(event_id, 0) + 1
        column = columns.get(depth, 0)
        columns[depth] = column + 1
        nodes.append(_canvas_node(event_id, column, depth))

        parent_id = event.get("parent")
        parent_id = str(parent_id) if parent_id not in (None, "") else ""
        if parent_id and parent_id in known:
            decision_path = str(event.get("decisionPath") or "")
            anchor = decision_path if decision_path in ("yes", "no") else "bottom"
            connections.append(_canvas_connection(parent_id, event_id, anchor))
        elif source_node_id:
            connections.append(
                _canvas_connection(source_node_id, event_id, "leadsource")
            )

    return nodes, connections


def _build_campaign_canvas_settings(
    events: list[dict[str, Any]],
    client_canvas: dict[str, Any] | None,
    *,
    lists: Any,
    forms: Any,
) -> dict[str, Any]:
    """Merge the caller's own canvas with the provider-native event graph."""
    source_node_id = "lists"
    if isinstance(lists, list) and isinstance(forms, list):
        if not lists and forms:
            source_node_id = "forms"
        elif not lists and not forms:
            source_node_id = None

    provider_nodes, provider_connections = _provider_canvas_graph(
        events,
        source_node_id=source_node_id,
    )

    client_nodes = [
        node
        for node in (
            _normalized_canvas_node(node, index)
            for index, node in enumerate(
                (client_canvas or {}).get("nodes") or []
            )
        )
        if node is not None
    ]
    # A caller that already placed a node for an event keeps its own position.
    client_nodes_by_id = {node["id"]: node for node in client_nodes}
    merged_provider_nodes = [
        {**node, **client_nodes_by_id.get(node["id"], {})} for node in provider_nodes
    ]
    provider_ids = {node["id"] for node in provider_nodes}

    provider_edges = {
        (connection["sourceId"], connection["targetId"])
        for connection in provider_connections
    }
    client_connections = [
        connection
        for connection in (
            _normalized_canvas_connection(connection)
            for connection in ((client_canvas or {}).get("connections") or [])
        )
        if connection is not None
        and (connection["sourceId"], connection["targetId"]) not in provider_edges
    ]

    return {
        "nodes": [node for node in client_nodes if node["id"] not in provider_ids]
        + merged_provider_nodes,
        "connections": client_connections + provider_connections,
    }


def _parse_campaign_payload(
    data,
    *,
    partial: bool = False,
    capabilities: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not hasattr(data, "keys"):
        raise ValueError("Native Mautic Campaign payload must be an object.")

    unsupported = sorted(set(data.keys()) - _CAMPAIGN_FIELDS)
    if unsupported:
        raise ValueError(
            "Unsupported Native Mautic Campaign field(s): " + ", ".join(unsupported)
        )

    payload: dict[str, Any] = {}

    if "sources" in data:
        payload.update(_parse_sources(data.get("sources")))

    if not partial or "name" in data:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("Native Mautic Campaign name is required.")
        if len(name) > 190:
            raise ValueError(
                "Native Mautic Campaign name cannot exceed 190 characters."
            )
        payload["name"] = name

    if "description" in data:
        payload["description"] = str(data.get("description") or "")

    if "isPublished" in data:
        payload["isPublished"] = _parse_bool(
            data.get("isPublished"),
            field_name="Native Mautic Campaign isPublished",
        )
    elif not partial:
        payload["isPublished"] = False

    for field in ("lists", "forms"):
        if field in data:
            payload[field] = _parse_source_ids(
                data.get(field),
                field_name=field,
            )

    if "events" in data:
        payload["events"] = _parse_events(
            data.get("events"),
            capabilities=capabilities,
        )

    if "canvasSettings" in data:
        payload["canvasSettings"] = _parse_canvas(data.get("canvasSettings"))

    if not partial:
        if not payload.get("lists") and not payload.get("forms"):
            raise ValueError(
                "Native Mautic Campaign requires at least one Segment or Form source."
            )
        if not payload.get("events"):
            raise ValueError(
                "Native Mautic Campaign requires at least one workflow event."
            )
        payload.setdefault("lists", [])
        payload.setdefault("forms", [])

    # Mautic ignores the whole `events` array unless `canvasSettings` describes the
    # graph as well, so every request that carries events must carry a canvas.
    if "events" in payload:
        _validate_event_graph(payload["events"], payload.get("canvasSettings"))
        payload["canvasSettings"] = _build_campaign_canvas_settings(
            payload["events"],
            payload.get("canvasSettings"),
            lists=payload.get("lists"),
            forms=payload.get("forms"),
        )
    elif not partial:
        payload.setdefault("canvasSettings", {"nodes": [], "connections": []})

    if partial and not payload:
        raise ValueError("At least one Native Mautic Campaign field is required.")

    return payload


def _active_events_only(events: Any, active_event_ids: Any) -> list[dict[str, Any]]:
    """Keep the events the provider still counts as part of the workflow."""
    rows = events if isinstance(events, list) else []
    if not isinstance(active_event_ids, list):
        return rows

    active = {str(event_id) for event_id in active_event_ids}
    return [
        event
        for event in rows
        if not isinstance(event, dict)
        or event.get("id") is None
        or str(event.get("id")) in active
    ]


def _format_campaign_for_builder(campaign: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": campaign.get("id"),
        "name": campaign.get("name"),
        "description": campaign.get("description"),
        "isPublished": campaign.get("isPublished", False),
        "sources": {
            "segments": campaign.get("lists", []),
            "forms": campaign.get("forms", []),
        },
        "events": [
            {
                "id": event.get("id"),
                "key": event.get("type"),
                "eventType": event.get("eventType"),
                "properties": event.get("properties", {}),
                "metadata": event,
            }
            for event in campaign.get("events", [])
        ],
        "canvasSettings": campaign.get("canvasSettings", {}),
    }


def _identity_error_response(exc):
    """Identity/bridge failures on the migrated per-user campaign paths.

    Never exposes keys, assertions, or provider internals.
    """
    if isinstance(exc, MauticBridgeRejectedError):
        return Response(
            {"detail": "Your Mautic user is not allowed to perform this campaign operation."},
            status=status.HTTP_403_FORBIDDEN,
        )
    return Response(
        {"detail": "Mautic identity bridge is unavailable."},
        status=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def _interactive_campaign_client(request):
    """Client for manual staff campaign create/update.

    Authenticates with the service account and, when per-user execution is
    enabled and the actor has an active mapping, carries a signed assertion so
    Mautic executes as the mapped user.
    """
    return get_mautic_client(
        actor=request.user,
        purpose=MauticExecutionContext.INTERACTIVE,
        # Construct through this module's MauticClient so the service-account
        # path is unchanged from Phase 1.
        client_factory=MauticClient,
    )


def _provider_error_response(exc):
    message = str(exc)
    if isinstance(exc, PermanentMauticError):
        if "HTTP 404" in message:
            raise Http404
        if any(f"HTTP {code}" in message for code in (400, 409, 422)):
            return Response(
                {"detail": message},
                status=status.HTTP_400_BAD_REQUEST,
            )
    return Response(
        {"detail": message or "Native Mautic Campaign operation failed."},
        status=status.HTTP_502_BAD_GATEWAY,
    )


class NewsletterAdminMauticCampaignListCreateView(APIView):
    """Staff-only native Mautic Campaign list and create API."""

    permission_classes = [IsStaffOrSuperuser]
    default_page_size = 25
    max_page_size = 100

    def get(self, request):
        try:
            page = max(1, int(request.query_params.get("page", 1)))
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(
                request.query_params.get("page_size", self.default_page_size)
            )
        except (TypeError, ValueError):
            page_size = self.default_page_size
        page_size = max(1, min(page_size, self.max_page_size))

        search = str(request.query_params.get("search", "") or "").strip()

        params = {
            "start": (page - 1) * page_size,
            "limit": page_size,
            "withContactCounts": "true",
        }
        if search:
            params["search"] = search

        try:
            data = MauticClient().list_campaigns(**params)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        rows = _collection_items(data.get("campaigns"))
        try:
            total = max(0, int(data.get("total", len(rows))))
        except (TypeError, ValueError):
            total = len(rows)

        return Response(
            {
                "count": total,
                "page": page,
                "page_size": page_size,
                "num_pages": math.ceil(total / page_size) if total else 0,
                "results": [
                    _normalize_campaign(campaign)
                    for campaign in rows
                ],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        try:
            client = _interactive_campaign_client(request)
            capabilities = (
                client.get_campaign_builder_capabilities()
                if _request_uses_builder_events(request.data)
                else None
            )
        except MauticIdentityError as exc:
            return _identity_error_response(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        try:
            payload = _parse_campaign_payload(
                request.data,
                capabilities=capabilities,
            )
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            campaign = client.create_campaign(payload)
        except (MauticBridgeRejectedError, MauticIdentityError) as exc:
            return _identity_error_response(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_campaign(campaign),
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminMauticCampaignCapabilitiesView(APIView):
    """Staff-only native Mautic Campaign Builder capability discovery API."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            client = MauticClient()
            capabilities = client.get_campaign_builder_capabilities()
            segments = client.list_segments(limit=200)
            forms = client.list_forms(limit=200)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            {
                "actions": capabilities.get("actions", []),
                "conditions": capabilities.get("conditions", []),
                "decisions": capabilities.get("decisions", []),
                "connection_restrictions": capabilities.get(
                    "connectionRestrictions",
                    {},
                ),
                "builder_metadata": {
                    "available": True,
                    "source": "runtime-mautic-eventcollector-plugin-bridge",
                },
                "form_schema": capabilities.get("formSchema"),
                "sources": {
                    "segments": _normalize_source_rows(
                        segments.get("lists", segments.get("segments"))
                    ),
                    "forms": _normalize_source_rows(forms.get("forms")),
                },
            },
            status=status.HTTP_200_OK,
        )


_REFERENCE_CHOICE_SOURCES = REFERENCE_CHOICE_SOURCES
_EVENT_FIELD_CHOICE_SOURCE = "event_field"


class NewsletterAdminMauticCampaignChoicesView(APIView):
    """Staff-only lookup for campaign event choices that are not inlined.

    Reference catalogs (country/region/timezone/locale) come from the field metadata
    bridge that already publishes them; everything else is resolved by the campaign
    event's own provider form. Django only routes and normalizes.
    """

    permission_classes = [IsStaffOrSuperuser]
    default_page_size = 50
    max_page_size = 200

    def get(self, request):
        source = str(request.query_params.get("source", "") or "").strip().lower()
        search = str(request.query_params.get("search", "") or "").strip()
        # Accept both `values=a&values=b` and the bracket form some HTTP clients
        # emit, so a value lookup can never silently fall through to a full page.
        values = [
            str(value)
            for value in (
                request.query_params.getlist("values")
                or request.query_params.getlist("values[]")
            )
            if str(value) != ""
        ]

        try:
            start = max(0, int(request.query_params.get("start", 0)))
        except (TypeError, ValueError):
            start = 0
        try:
            limit = int(request.query_params.get("limit", self.default_page_size))
        except (TypeError, ValueError):
            limit = self.default_page_size
        limit = max(1, min(limit, self.max_page_size))

        if source in _REFERENCE_CHOICE_SOURCES:
            return self._reference_choices(
                source,
                search=search,
                values=values,
                start=start,
                limit=limit,
            )

        if source == _EVENT_FIELD_CHOICE_SOURCE:
            return self._event_field_choices(
                request,
                search=search,
                values=values,
                start=start,
                limit=limit,
            )

        return Response(
            {"detail": f'Unsupported campaign choice source "{source}".'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    def _reference_choices(self, source, *, search, values, start, limit):
        try:
            data = MauticClient().get_field_type_choices(source)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        page = reference_choice_page(
            data.get("choices"),
            search=search,
            values=values,
            start=start,
            limit=limit,
        )

        return Response({"source": source, **page}, status=status.HTTP_200_OK)

    def _event_field_choices(self, request, *, search, values, start, limit):
        event_type = str(request.query_params.get("eventType", "") or "").strip()
        key = str(request.query_params.get("key", "") or "").strip()
        field = str(request.query_params.get("field", "") or "").strip()

        if not event_type or not key or not field:
            return Response(
                {
                    "detail": (
                        "Campaign event field choices require eventType, key and field."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            data = MauticClient().get_campaign_builder_event_field_choices(
                event_type=event_type,
                key=key,
                field=field,
                search=search,
                start=start,
                limit=limit,
                values=values,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            {
                "source": _EVENT_FIELD_CHOICE_SOURCE,
                "results": normalize_choice_rows(data.get("choices")),
                "total": data.get("total", 0),
                "start": data.get("start", start),
                "limit": data.get("limit", limit),
                "hasMore": bool(data.get("hasMore")),
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminMauticCampaignDetailView(APIView):
    """Staff-only native Mautic Campaign detail, update and delete API."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, campaign_id):
        try:
            campaign = MauticClient().get_campaign(campaign_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_campaign(campaign),
            status=status.HTTP_200_OK,
        )

    def patch(self, request, campaign_id):
        try:
            client = _interactive_campaign_client(request)
            capabilities = (
                client.get_campaign_builder_capabilities()
                if _request_uses_builder_events(request.data)
                else None
            )
        except MauticIdentityError as exc:
            return _identity_error_response(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        try:
            payload = _parse_campaign_payload(
                request.data,
                partial=True,
                capabilities=capabilities,
            )
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            campaign = client.update_campaign(
                campaign_id,
                payload,
            )
        except (MauticBridgeRejectedError, MauticIdentityError) as exc:
            return _identity_error_response(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_campaign(campaign),
            status=status.HTTP_200_OK,
        )

    def delete(self, request, campaign_id):
        try:
            MauticClient().delete_campaign(campaign_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminMauticCampaignEventView(APIView):
    """Staff-only deletion of a single provider campaign workflow event.

    Deletion is the one campaign builder operation official Mautic REST cannot
    perform, so it is routed to the campaign builder bridge, which runs Mautic's
    own campaign event deletion. Django validates and normalizes only.
    """

    permission_classes = [IsStaffOrSuperuser]

    def delete(self, request, campaign_id, event_id):
        campaign_id = str(campaign_id or "").strip()
        event_id = str(event_id or "").strip()
        if not campaign_id.isdigit() or not event_id.isdigit():
            return Response(
                {
                    "detail": (
                        "Native Mautic Campaign and event IDs must be provider IDs."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            result = MauticClient().delete_campaign_event(campaign_id, event_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            if isinstance(exc, PermanentMauticError) and "HTTP 403" in str(exc):
                return Response(
                    {"detail": str(exc)},
                    status=status.HTTP_403_FORBIDDEN,
                )
            return _provider_error_response(exc)

        deleted = result.get("deleted")
        return Response(
            {
                "deleted": deleted if isinstance(deleted, dict) else {"id": event_id},
                "detachedChildren": [
                    str(child)
                    for child in (result.get("detachedChildren") or [])
                    if child not in (None, "")
                ],
                "remainingEventIds": [
                    str(remaining)
                    for remaining in (result.get("remainingEventIds") or [])
                    if remaining not in (None, "")
                ],
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminMauticCampaignBuilderView(APIView):
    """Staff-only native Mautic Campaign builder data API."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, campaign_id):
        try:
            client = MauticClient()
            campaign = client.get_campaign(campaign_id)
            # Mautic deletes campaign events by stamping them `deleted`, and the
            # campaign endpoint keeps returning them without that field, so the
            # provider has to say which events are still part of the workflow.
            states = client.get_campaign_event_states(campaign_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        normalized = _normalize_campaign(campaign)
        normalized["events"] = _active_events_only(
            normalized.get("events"),
            states.get("activeEventIds"),
        )
        return Response(
            _format_campaign_for_builder(normalized),
            status=status.HTTP_200_OK,
        )
