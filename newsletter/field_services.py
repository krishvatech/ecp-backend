"""Native Mautic custom-field administration.

Mautic owns every field definition exposed here. This module only translates between
the ECP admin representation and the official Mautic REST field API
(``/api/fields/{contact|company}``), plus the bridge capability endpoint that publishes
the field-type registry Mautic core owns but does not expose over REST.

No field definition is mirrored in Django.
"""

from __future__ import annotations

from typing import Any

from .mautic import MauticClient


FIELD_OBJECTS = ("contact", "company")

# Mautic locks these on an existing field: LeadBundle FieldType disables `alias` and
# `type` whenever the field is not new, so ECP must not offer to change them on edit.
IMMUTABLE_FIELD_KEYS = ("alias", "type", "object")

# Accepted on create. `properties` is derived from `options`/`properties` separately.
_CREATE_KEYS = (
    "label",
    "alias",
    "type",
    "group",
    "is_published",
    "is_required",
    "default_value",
    "order",
)
_UPDATE_KEYS = (
    "label",
    "group",
    "is_published",
    "is_required",
    "default_value",
    "order",
)

_PAYLOAD_TO_MAUTIC = {
    "label": "label",
    "alias": "alias",
    "type": "type",
    "group": "group",
    "is_published": "isPublished",
    "is_required": "isRequired",
    "default_value": "defaultValue",
    "order": "order",
}


class ProtectedMauticFieldError(Exception):
    """Raised when a mutation is refused because Mautic itself protects the field."""


def normalize_field_object(field_object) -> str:
    normalized = str(field_object or "contact").strip().lower()
    if normalized == "lead":
        normalized = "contact"
    if normalized not in FIELD_OBJECTS:
        raise ValueError("object must be either 'contact' or 'company'.")
    return normalized


def _values(source) -> list[dict[str, Any]]:
    if isinstance(source, dict):
        return [item for item in source.values() if isinstance(item, dict)]
    if isinstance(source, list):
        return [item for item in source if isinstance(item, dict)]
    return []


def _normalize_options(properties: dict[str, Any]) -> list[dict[str, Any]]:
    """Return option-list entries as ordered {label, value} pairs.

    Mautic stores option lists either as a flat list of strings (core lookup fields) or
    as a list of {label, value} objects (fields built in the UI). Ordering is meaningful
    and is preserved exactly as Mautic returned it.
    """
    raw = properties.get("list")
    if raw is None:
        return []

    if isinstance(raw, dict):
        return [
            {"label": str(label), "value": str(value)}
            for value, label in raw.items()
        ]

    if not isinstance(raw, list):
        return []

    options = []
    for entry in raw:
        if isinstance(entry, dict):
            value = entry.get("value", entry.get("label"))
            label = entry.get("label", entry.get("value"))
        else:
            value = label = entry
        if value is None and label is None:
            continue
        options.append({"label": str(label), "value": str(value)})
    return options


def normalize_admin_field(field: dict[str, Any]) -> dict[str, Any]:
    properties = field.get("properties")
    properties = properties if isinstance(properties, dict) else {}

    object_name = str(field.get("object") or "").strip().lower()
    if object_name == "lead":
        object_name = "contact"

    # `isFixed` is Mautic's own protection flag for built-in fields; it is never
    # inferred from the alias or the group name.
    is_system = bool(field.get("isFixed", False))

    return {
        "id": str(field.get("id") or ""),
        "label": str(field.get("label") or "").strip(),
        "alias": str(field.get("alias") or "").strip(),
        "type": str(field.get("type") or "").strip(),
        "group": str(field.get("group") or "").strip(),
        "object": object_name,
        "order": field.get("order"),
        "is_published": bool(field.get("isPublished", True)),
        "is_required": bool(field.get("isRequired", False)),
        "is_system": is_system,
        "is_unique_identifier": bool(field.get("isUniqueIdentifier", False)),
        "default_value": field.get("defaultValue"),
        "options": _normalize_options(properties),
        "properties": properties,
        "char_length_limit": field.get("charLengthLimit"),
        # Surfaced so the UI can disable controls for exactly what Mautic refuses.
        "can_delete": not is_system,
        "can_edit_group": not is_system,
        "immutable_keys": list(IMMUTABLE_FIELD_KEYS),
    }


def list_admin_fields(
    field_object: str = "contact",
    *,
    search: str = "",
    published_only: bool = False,
    limit: int = 200,
) -> dict[str, Any]:
    field_object = normalize_field_object(field_object)
    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit = 200

    params: dict[str, Any] = {"limit": limit}
    search = str(search or "").strip()
    if search:
        params["search"] = search

    data = MauticClient().list_fields(field_object, **params)
    fields = [normalize_admin_field(field) for field in _values(data.get("fields"))]
    fields = [field for field in fields if field["alias"]]
    if published_only:
        fields = [field for field in fields if field["is_published"]]

    fields.sort(key=lambda field: (_order_key(field["order"]), field["label"].lower()))
    return {"object": field_object, "count": len(fields), "results": fields}


def _order_key(order) -> int:
    try:
        return int(order)
    except (TypeError, ValueError):
        return 10**6


def get_admin_field(field_object: str, field_id) -> dict[str, Any]:
    field_object = normalize_field_object(field_object)
    field_id = str(field_id or "").strip()
    if not field_id:
        raise ValueError("Mautic field ID is required.")
    return normalize_admin_field(MauticClient().get_field(field_object, field_id))


def _options_to_properties(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Build the Mautic `properties` payload, or None when the caller did not touch it.

    Returning None matters: Mautic only rewrites a field's properties when `properties`
    is present in the request, so omitting it preserves the existing option list.
    """
    if "properties" in payload:
        properties = payload.get("properties")
        if properties in (None, ""):
            return None
        if not isinstance(properties, dict):
            raise ValueError("properties must be an object.")
        return properties

    if "options" not in payload:
        return None

    options = payload.get("options")
    if options in (None, ""):
        options = []
    if not isinstance(options, list):
        raise ValueError("options must be a list.")

    entries = []
    for option in options:
        if isinstance(option, dict):
            value = option.get("value", option.get("label"))
            label = option.get("label", option.get("value"))
        else:
            value = label = option
        value = str(value if value is not None else "").strip()
        label = str(label if label is not None else "").strip()
        if not value:
            raise ValueError("Each option requires a value.")
        entries.append({"label": label or value, "value": value})

    return {"list": entries}


def _normalize_field_payload(
    payload: dict[str, Any],
    *,
    partial: bool,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Field payload must be an object.")

    allowed = set(_UPDATE_KEYS if partial else _CREATE_KEYS) | {"options", "properties"}
    unsupported = sorted(set(payload.keys()) - allowed)
    if unsupported:
        locked = [key for key in unsupported if key in IMMUTABLE_FIELD_KEYS]
        if partial and locked:
            raise ValueError(
                "Mautic does not allow changing "
                + ", ".join(locked)
                + " on an existing field."
            )
        raise ValueError("Unsupported field(s): " + ", ".join(unsupported))

    data: dict[str, Any] = {}
    for key in _UPDATE_KEYS if partial else _CREATE_KEYS:
        if key not in payload:
            continue
        mautic_key = _PAYLOAD_TO_MAUTIC[key]
        value = payload.get(key)
        if key in {"is_published", "is_required"}:
            data[mautic_key] = 1 if _as_bool(value, field_name=key) else 0
        elif key == "order":
            if value in (None, ""):
                continue
            try:
                data[mautic_key] = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError("order must be an integer.") from exc
        elif key == "default_value":
            data[mautic_key] = value
        else:
            data[mautic_key] = str(value or "").strip()

    if not partial:
        if not data.get("label"):
            raise ValueError("label is required.")
        if not data.get("type"):
            data["type"] = "text"

    properties = _options_to_properties(payload)
    if properties is not None:
        data["properties"] = properties

    if partial and not data:
        raise ValueError("At least one field attribute is required.")
    return data


def _as_bool(value, *, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    raise ValueError(f"{field_name} must be a boolean.")


def _assert_type_is_supported(client: MauticClient, field_type: str) -> None:
    """Reject a field type Mautic would not accept, using Mautic's own registry."""
    field_type = str(field_type or "").strip()
    if not field_type:
        return
    supported = {
        str(entry.get("type") or "")
        for entry in client.get_field_type_capabilities().get("types", [])
        if isinstance(entry, dict)
    }
    if supported and field_type not in supported:
        raise ValueError(
            f"Unsupported Mautic field type '{field_type}'. Supported types: "
            + ", ".join(sorted(supported))
        )


def create_admin_field(field_object: str, payload: dict[str, Any]) -> dict[str, Any]:
    field_object = normalize_field_object(field_object)
    data = _normalize_field_payload(payload, partial=False)
    client = MauticClient()
    _assert_type_is_supported(client, data.get("type"))
    field = client.create_field(field_object, data)
    return normalize_admin_field(field)


def update_admin_field(
    field_object: str,
    field_id,
    payload: dict[str, Any],
) -> dict[str, Any]:
    field_object = normalize_field_object(field_object)
    field_id = str(field_id or "").strip()
    if not field_id:
        raise ValueError("Mautic field ID is required.")

    data = _normalize_field_payload(payload, partial=True)
    client = MauticClient()
    existing = normalize_admin_field(client.get_field(field_object, field_id))

    # Mautic's native field form disables the group selector on a fixed field.
    if existing["is_system"] and "group" in data and data["group"] != existing["group"]:
        raise ProtectedMauticFieldError(
            f"'{existing['label']}' is a built-in Mautic field; its group cannot be changed."
        )

    return normalize_admin_field(client.update_field(field_object, field_id, data))


def delete_admin_field(field_object: str, field_id) -> dict[str, Any]:
    field_object = normalize_field_object(field_object)
    field_id = str(field_id or "").strip()
    if not field_id:
        raise ValueError("Mautic field ID is required.")

    client = MauticClient()
    existing = normalize_admin_field(client.get_field(field_object, field_id))
    # Mautic core refuses this outright (LeadBundle FieldController::deleteAction), so
    # ECP refuses it before the call rather than surfacing an opaque provider error.
    if existing["is_system"]:
        raise ProtectedMauticFieldError(
            f"'{existing['label']}' is a built-in Mautic field and cannot be deleted."
        )

    client.delete_field(field_object, field_id)
    return {"deleted": True, "id": existing["id"], "object": field_object}


REFERENCE_CHOICE_TYPES = ("country", "region", "timezone", "locale")


def list_admin_field_choices(field_type: str) -> dict[str, Any]:
    """Return the Mautic reference option list backing a country/region/timezone/locale field."""
    normalized = str(field_type or "").strip().lower()
    if normalized not in REFERENCE_CHOICE_TYPES:
        raise ValueError(
            "Reference choices are only available for: "
            + ", ".join(REFERENCE_CHOICE_TYPES)
        )

    data = MauticClient().get_field_type_choices(normalized)
    choices = []
    for entry in data.get("choices", []):
        if not isinstance(entry, dict):
            continue
        value = str(entry.get("value") or "").strip()
        if not value:
            continue
        choice = {"label": str(entry.get("label") or value), "value": value}
        if entry.get("group"):
            choice["group"] = str(entry.get("group"))
        choices.append(choice)

    return {"type": normalized, "count": len(choices), "results": choices}


def list_admin_field_types() -> dict[str, Any]:
    """Publish the Mautic-owned field-type registry for the ECP field builder."""
    data = MauticClient().get_field_type_capabilities()
    types = []
    for entry in data.get("types", []):
        if not isinstance(entry, dict):
            continue
        field_type = str(entry.get("type") or "").strip()
        if not field_type:
            continue
        types.append(
            {
                "type": field_type,
                "label": str(entry.get("label") or field_type),
                "has_option_list": bool(entry.get("hasOptionList", False)),
                "required_properties": [
                    str(key)
                    for key in entry.get("requiredProperties", [])
                    if isinstance(key, (str, int))
                ],
            }
        )
    types.sort(key=lambda entry: entry["label"].lower())
    return {
        "count": len(types),
        "results": types,
        "objects": list(FIELD_OBJECTS),
    }
