"""Form Field Builder rules: which native Mautic Form fields ECP manages and how.

Mautic owns the fields. ECP validates a field change, sends it through the
bridge (which re-checks the same allowlist), then reads the Form back and
confirms that only the intended change happened.

Native Mautic 7.1.3 facts these rules rely on (verified against local Mautic):

* Fields are written through the Form PATCH. It renumbers ``order`` over the
  fields it is sent and stores ``properties`` exactly as sent, so the bridge
  re-sends every field (id-only stubs) and merges properties.
* Mautic accepts duplicate Contact mappings and several submit buttons over the
  API; ECP refuses both.
* A field's alias names its results column, so type and alias never change.
* Forms with conditional fields are re-ordered wrongly by a PATCH; their fields
  are left to Mautic.
* Field deletion is not offered: the native field-delete endpoint did not delete
  over the API in testing, and deleting would also orphan submission data.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email

LABEL_MAX_LENGTH = 255
TEXT_MAX_LENGTH = 255
MAX_OPTIONS = 100
ALIAS_MAX_LENGTH = 25

# Native type identifiers, in the order the builder offers them.
FIELD_TYPES = {
    "text": "Text",
    "email": "Email",
    "tel": "Telephone",
    "textarea": "Text area",
    "number": "Number",
    "select": "Dropdown",
    "radiogrp": "Radio group",
    "checkboxgrp": "Checkbox group",
    "date": "Date",
    "country": "Country",
    "hidden": "Hidden",
    "button": "Submit button",
}
OPTION_TYPES = {"select": "list", "radiogrp": "optionlist", "checkboxgrp": "optionlist"}
PLACEHOLDER_TYPES = {"text", "email", "tel", "date", "number", "select", "country"}
NO_REQUIRED = {"button", "hidden"}
NO_HELP = {"button", "hidden"}
NO_DEFAULT = {"button", "checkboxgrp", "country"}
NO_MAPPING = {"button"}

# Which native Contact field types each Form field type may fill.
COMPATIBLE_CONTACT_TYPES = {
    "text": {"text", "lookup", "url", "region"},
    "email": {"email"},
    "tel": {"tel"},
    "textarea": {"text", "textarea"},
    "number": {"number"},
    "select": {"text", "lookup", "select", "multiselect", "boolean", "region", "locale", "timezone"},
    "radiogrp": {"text", "lookup", "select", "boolean"},
    "checkboxgrp": {"text", "multiselect"},
    "date": {"date", "datetime"},
    "country": {"country"},
    "hidden": {"text", "lookup", "url", "number", "select"},
}

# Contact fields a Form may never fill: ECP consent records and system values.
# Consent is only ever recorded by ECP's own workflows, never by a submission.
PROTECTED_CONTACT_FIELDS = {"points", "last_active", "attribution", "attribution_date"}
PROTECTED_CONTACT_FIELD_PREFIX = "ecp_"
# Input names Mautic's rendered Forms already use.
RESERVED_ALIASES = {"formid", "formname", "return", "messenger"}

# Properties the native Mautic builder stores for a new field of each type.
# Option fields need `syncList`: Mautic's group template only renders choices
# when it is present ("0" = use the field's own options).
NATIVE_PROPERTY_DEFAULTS = {
    "text": {"placeholder": ""},
    "email": {"placeholder": ""},
    "tel": {"placeholder": ""},
    "date": {"placeholder": ""},
    "number": {"placeholder": "", "precision": "0"},
    "select": {"placeholder": "", "multiple": "0", "syncList": "0"},
    "country": {"placeholder": "", "multiple": "0"},
    "radiogrp": {"syncList": "0"},
    "checkboxgrp": {"syncList": "0"},
}

EDITABLE_KEYS = {
    "label", "isRequired", "helpMessage", "validationMessage", "defaultValue",
    "mappedField", "placeholder", "precision", "multiple", "options",
}
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class FieldPolicyError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid_form_field", field: str = ""):
        super().__init__(message)
        self.code = code
        self.field = field


# Reading native fields --------------------------------------------------------


def _bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def native_options(field: dict[str, Any]) -> list[dict[str, str]]:
    properties = field.get("properties") if isinstance(field.get("properties"), dict) else {}
    key = OPTION_TYPES.get(str(field.get("type") or ""))
    holder = properties.get(key) if key else None
    if holder is None and key == "optionlist":
        holder = {"list": properties.get("list")}  # pre-optionlist storage
    rows = holder.get("list") if isinstance(holder, dict) else None
    if isinstance(rows, dict):
        rows = list(rows.values())
    return [
        {"label": str(row.get("label") or ""), "value": str(row.get("value") or "")}
        for row in rows or []
        if isinstance(row, dict)
    ]


def fields_lock_reason(form: dict[str, Any]) -> str:
    for field in form.get("fields") or []:
        if isinstance(field, dict) and field.get("parent"):
            return "This Form has conditional fields, so its fields are managed in Mautic."
    return ""


def normalize_field(field: dict[str, Any], *, locked: str = "") -> dict[str, Any]:
    field_type = str(field.get("type") or "")
    properties = field.get("properties") if isinstance(field.get("properties"), dict) else {}
    lock = locked or ("" if field_type in FIELD_TYPES else "This field type is managed in Mautic.")
    return {
        "id": str(field.get("id") or ""),
        "label": str(field.get("label") or ""),
        "alias": str(field.get("alias") or ""),
        "type": field_type,
        "typeLabel": FIELD_TYPES.get(field_type, field_type),
        "isRequired": _bool(field.get("isRequired", False)),
        "order": field.get("order"),
        "helpMessage": str(field.get("helpMessage") or ""),
        "validationMessage": str(field.get("validationMessage") or ""),
        "defaultValue": str(field.get("defaultValue") or ""),
        "mappedObject": str(field.get("mappedObject") or ""),
        "mappedField": str(field.get("mappedField") or field.get("leadField") or ""),
        "placeholder": str(properties.get("placeholder") or ""),
        "precision": str(properties.get("precision") if properties.get("precision") is not None else ""),
        "multiple": _bool(properties.get("multiple", False)),
        "options": native_options(field),
        "editable": not lock,
        "lockReason": lock,
    }


def contact_field_choices(rows) -> list[dict[str, Any]]:
    """Published native Contact fields a Form may fill, with the Form field
    types each one accepts."""
    if isinstance(rows, dict):
        rows = list(rows.values())
    choices = []
    for row in rows or []:
        if not isinstance(row, dict) or not _bool(row.get("isPublished", True)):
            continue
        alias = str(row.get("alias") or "")
        if not alias or is_protected_contact_field(alias):
            continue
        contact_type = str(row.get("type") or "")
        accepts = sorted(t for t, types in COMPATIBLE_CONTACT_TYPES.items() if contact_type in types)
        if accepts:
            choices.append({
                "alias": alias,
                "label": str(row.get("label") or alias),
                "type": contact_type,
                "group": str(row.get("group") or ""),
                "fieldTypes": accepts,
            })
    return sorted(choices, key=lambda item: item["label"].lower())


def is_protected_contact_field(alias: str) -> bool:
    return alias in PROTECTED_CONTACT_FIELDS or alias.startswith(PROTECTED_CONTACT_FIELD_PREFIX)


def field_type_catalogue() -> list[dict[str, Any]]:
    return [
        {
            "type": field_type,
            "label": label,
            "options": field_type in OPTION_TYPES,
            "placeholder": field_type in PLACEHOLDER_TYPES,
            "required": field_type not in NO_REQUIRED,
            "helpMessage": field_type not in NO_HELP,
            "defaultValue": field_type not in NO_DEFAULT,
            "mapping": field_type not in NO_MAPPING,
            "precision": field_type == "number",
            "multiple": field_type == "select",
        }
        for field_type, label in FIELD_TYPES.items()
    ]


# Validation -------------------------------------------------------------------


def _text(data: dict, key: str, label: str, *, required: bool = False, max_length: int = TEXT_MAX_LENGTH) -> str:
    value = data.get(key)
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise FieldPolicyError(f"{label} must be text.", field=key)
    value = value.strip()
    if _CONTROL_CHARS.search(value):
        raise FieldPolicyError(f"{label} contains unsupported characters.", field=key)
    if len(value) > max_length:
        raise FieldPolicyError(f"{label} must be {max_length} characters or fewer.", field=key)
    if required and not value:
        raise FieldPolicyError(f"{label} is required.", field=key)
    return value


def _flag(data: dict, key: str, label: str) -> bool:
    value = data.get(key)
    if isinstance(value, bool):
        return value
    if value in (0, 1, "0", "1", "true", "false"):
        return str(value) in {"1", "true"}
    raise FieldPolicyError(f"{label} must be true or false.", field=key)


def suggest_alias(label: str, taken: set[str]) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")[:ALIAS_MAX_LENGTH] or "field"
    if not base[0].isalpha():
        base = f"f_{base}"[:ALIAS_MAX_LENGTH]
    if base in RESERVED_ALIASES:
        base = f"f_{base}"
    alias, counter = base, 2
    while alias in taken:
        suffix = f"_{counter}"
        alias = base[: ALIAS_MAX_LENGTH - len(suffix)] + suffix
        counter += 1
    return alias


def _options(value) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise FieldPolicyError("Add at least one option.", field="options")
    if len(value) > MAX_OPTIONS:
        raise FieldPolicyError(f"Use {MAX_OPTIONS} options or fewer.", field="options")
    options, seen = [], set()
    for index, row in enumerate(value, start=1):
        if not isinstance(row, dict) or set(row) - {"label", "value"}:
            raise FieldPolicyError("Each option needs only a label and a value.", field="options")
        label = _text(row, "label", f"Option {index} label", required=True)
        stored = _text(row, "value", f"Option {index} value", required=True)
        if stored in seen:
            raise FieldPolicyError(f'Option value "{stored}" is used more than once.', field="options")
        seen.add(stored)
        options.append({"label": label, "value": stored})
    return options


def _check_default(field_type: str, default: str, options: list[dict[str, str]]) -> None:
    if not default:
        return
    if field_type in OPTION_TYPES and default not in {option["value"] for option in options}:
        raise FieldPolicyError("The default must be one of the option values.", field="defaultValue")
    if field_type == "email":
        try:
            validate_email(default)
        except DjangoValidationError:
            raise FieldPolicyError("The default must be a valid email address.", field="defaultValue") from None
    if field_type == "number":
        try:
            float(default)
        except ValueError:
            raise FieldPolicyError("The default must be a number.", field="defaultValue") from None
    if field_type == "date":
        try:
            date.fromisoformat(default)
        except ValueError:
            raise FieldPolicyError("The default must be a date (YYYY-MM-DD).", field="defaultValue") from None


def _check_mapping(field_type: str, target: str, contact_fields: dict[str, str], others: list[dict[str, Any]]) -> None:
    if not target:
        return
    if is_protected_contact_field(target):
        raise FieldPolicyError(
            f'The "{target}" Contact field records consent or system data and cannot be filled by a Form.',
            code="form_field_protected_mapping", field="mappedField",
        )
    contact_type = contact_fields.get(target)
    if contact_type is None:
        raise FieldPolicyError(f'"{target}" is not a published Contact field.', code="form_field_invalid_mapping", field="mappedField")
    if contact_type not in COMPATIBLE_CONTACT_TYPES.get(field_type, set()):
        raise FieldPolicyError(
            f'A {FIELD_TYPES[field_type]} field cannot fill the "{target}" Contact field ({contact_type}).',
            code="form_field_invalid_mapping", field="mappedField",
        )
    for other in others:
        if str(other.get("mappedObject") or "contact") == "contact" and str(other.get("mappedField") or "") == target:
            raise FieldPolicyError(
                f'Field "{other.get("label") or other.get("alias")}" is already mapped to "{target}".',
                code="form_field_duplicate_mapping", field="mappedField",
            )


def _state(field_type: str, data: dict, current: dict[str, Any] | None) -> dict[str, Any]:
    """The field's full ECP-managed state after applying ``data``."""
    base = normalize_field(current) if current else {
        "label": "", "isRequired": False, "helpMessage": "", "validationMessage": "", "defaultValue": "",
        "mappedField": "", "placeholder": "", "precision": "", "multiple": False, "options": [],
    }
    state = {key: base[key] for key in ("label", "isRequired", "helpMessage", "validationMessage", "defaultValue",
                                         "mappedField", "placeholder", "precision", "multiple", "options")}
    if "label" in data or current is None:
        state["label"] = _text(data, "label", "Field label", required=True, max_length=LABEL_MAX_LENGTH)
    for key, label in (("helpMessage", "Help text"), ("validationMessage", "Validation message"),
                       ("defaultValue", "Default value"), ("placeholder", "Placeholder")):
        if key in data:
            state[key] = _text(data, key, label)
    if "mappedField" in data:
        state["mappedField"] = _text(data, "mappedField", "Contact field", max_length=191)
    if "isRequired" in data:
        state["isRequired"] = _flag(data, "isRequired", "Required")
    if "multiple" in data:
        state["multiple"] = _flag(data, "multiple", "Allow several choices")
    if "precision" in data:
        precision = str(data.get("precision") if data.get("precision") is not None else "").strip()
        if precision and (not precision.isdigit() or int(precision) > 10):
            raise FieldPolicyError("Decimal places must be a whole number from 0 to 10.", field="precision")
        state["precision"] = precision
    if "options" in data:
        state["options"] = _options(data.get("options"))
    elif field_type in OPTION_TYPES and current is None:
        raise FieldPolicyError("Add at least one option.", field="options")
    return state


def _reject_unsupported(field_type: str, data: dict) -> None:
    unsupported = sorted(set(data) - EDITABLE_KEYS - {"type", "alias", "position"})
    if unsupported:
        raise FieldPolicyError("Unsupported field setting(s): " + ", ".join(unsupported) + ".", code="unsupported_form_field_settings")
    not_for_type = []
    for key in data:
        if (key == "isRequired" and field_type in NO_REQUIRED and _bool(data[key])) \
                or (key == "helpMessage" and field_type in NO_HELP and data[key]) \
                or (key == "defaultValue" and field_type in NO_DEFAULT and data[key]) \
                or (key == "mappedField" and field_type in NO_MAPPING and data[key]) \
                or (key == "placeholder" and field_type not in PLACEHOLDER_TYPES and data[key]) \
                or (key == "precision" and field_type != "number" and data[key] not in (None, "")) \
                or (key == "multiple" and field_type != "select" and _bool(data[key])) \
                or (key == "options" and field_type not in OPTION_TYPES):
            not_for_type.append(key)
    if not_for_type:
        raise FieldPolicyError(
            f"Not available for a {FIELD_TYPES[field_type]} field: {', '.join(sorted(not_for_type))}.",
            code="unsupported_form_field_settings",
        )


def _native(field_type: str, state: dict[str, Any], keys: set[str]) -> dict[str, Any]:
    """Native Mautic field settings for the given state keys."""
    native: dict[str, Any] = {}
    for key in ("label", "helpMessage", "validationMessage", "defaultValue"):
        if key in keys:
            native[key] = state[key]
    if "isRequired" in keys and field_type not in NO_REQUIRED:
        native["isRequired"] = bool(state["isRequired"])
    if "mappedField" in keys and field_type not in NO_MAPPING:
        native["mappedObject"] = "contact" if state["mappedField"] else ""
        native["mappedField"] = state["mappedField"]
    properties: dict[str, Any] = {}
    if "placeholder" in keys and field_type in PLACEHOLDER_TYPES:
        properties["placeholder"] = state["placeholder"]
    if "precision" in keys and field_type == "number":
        properties["precision"] = state["precision"] or "0"
    if "multiple" in keys and field_type == "select":
        properties["multiple"] = "1" if state["multiple"] else "0"
    if "options" in keys and field_type in OPTION_TYPES:
        properties[OPTION_TYPES[field_type]] = {"list": state["options"]}
    if properties:
        native["properties"] = properties
    return native


def plan_new_field(data, form: dict[str, Any], contact_fields: dict[str, str]) -> tuple[dict[str, Any], int | None]:
    """Validate a new field; return its native settings and position."""
    if not isinstance(data, dict):
        raise FieldPolicyError("Send the field as a JSON object.")
    field_type = data.get("type")
    if field_type not in FIELD_TYPES:
        raise FieldPolicyError(
            "Choose a supported field type: " + ", ".join(FIELD_TYPES.values()) + ".",
            code="unsupported_form_field_type", field="type",
        )
    _reject_unsupported(field_type, data)
    fields = [f for f in form.get("fields") or [] if isinstance(f, dict)]
    if field_type == "button" and any(str(f.get("type")) == "button" for f in fields):
        raise FieldPolicyError("The Form already has a submit button.", code="form_field_duplicate_button", field="type")
    state = _state(field_type, data, None)

    taken = {str(f.get("alias") or "") for f in fields}
    alias = data.get("alias")
    if alias in (None, ""):
        alias = suggest_alias(state["label"], taken)
    elif not isinstance(alias, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,24}", alias):
        raise FieldPolicyError("Alias must be 1-25 lowercase letters, digits or underscores, starting with a letter.", field="alias")
    elif alias in RESERVED_ALIASES:
        raise FieldPolicyError("This alias is reserved by Mautic.", field="alias")
    elif alias in taken:
        raise FieldPolicyError("Another field already uses this alias.", field="alias")

    _check_default(field_type, state["defaultValue"], state["options"])
    _check_mapping(field_type, state["mappedField"], contact_fields, fields)

    position = data.get("position")
    if position is not None:
        if not isinstance(position, int) or isinstance(position, bool) or not 0 <= position <= len(fields):
            raise FieldPolicyError("Position must be a field index within the Form.", field="position")

    keys = {key for key in state if key in data} | {"label"}
    native = {"type": field_type, "alias": alias, **_native(field_type, state, keys)}
    defaults = NATIVE_PROPERTY_DEFAULTS.get(field_type)
    if defaults:
        native["properties"] = {**defaults, **native.get("properties", {})}
    return native, position


def plan_field_update(data, field: dict[str, Any], form: dict[str, Any], contact_fields: dict[str, str]) -> dict[str, Any]:
    """Validate a change to one existing field; return only the native settings
    that change."""
    if not isinstance(data, dict) or not data:
        raise FieldPolicyError("Send the field changes as a JSON object.")
    if {"type", "alias"} & set(data):
        raise FieldPolicyError(
            "A field's type and alias cannot change after it is created. Add a new field instead.",
            code="form_field_immutable",
        )
    field_type = str(field.get("type") or "")
    if field_type not in FIELD_TYPES:
        raise FieldPolicyError("This field type is managed in Mautic.", code="form_field_managed_in_mautic")
    _reject_unsupported(field_type, data)
    current = normalize_field(field)
    state = _state(field_type, data, field)
    _check_default(field_type, state["defaultValue"], state["options"])
    if state["mappedField"] != current["mappedField"]:
        others = [f for f in form.get("fields") or [] if isinstance(f, dict) and str(f.get("id")) != str(field.get("id"))]
        _check_mapping(field_type, state["mappedField"], contact_fields, others)
    changed = {key for key in state if key in data and state[key] != current[key]}
    return _native(field_type, state, changed)


def parse_order(data, form: dict[str, Any]) -> list[str]:
    order = data.get("order") if isinstance(data, dict) else None
    current = [str(f.get("id")) for f in form.get("fields") or [] if isinstance(f, dict)]
    if not isinstance(order, list) or sorted(map(str, order)) != sorted(current) or len(set(map(str, order))) != len(order):
        raise FieldPolicyError("Send the new order as every field ID of the Form, each once.", field="order")
    return [str(item) for item in order]


# Read-back verification ---------------------------------------------------------


def ordered_fields(form: dict[str, Any]) -> list[dict[str, Any]]:
    fields = [f for f in form.get("fields") or [] if isinstance(f, dict)]
    return sorted(fields, key=lambda f: (int(f.get("order") or 0), int(f.get("id") or 0)))


def _comparable(field: dict[str, Any]) -> dict[str, Any]:
    snapshot = {key: value for key, value in field.items() if key != "order"}
    for key in ("mappedObject", "mappedField", "helpMessage", "validationMessage", "defaultValue"):
        snapshot[key] = snapshot.get(key) or ""
    return snapshot


def unexpected_changes(
    before: dict[str, Any], after: dict[str, Any], *, target_id: str | None = None,
    expected_order: list[str] | None = None,
) -> list[str]:
    """What changed in ``after`` beyond the one intended field write: other
    fields, their order, submit actions, after-submit settings, publication
    and Form type. Empty when only the intended change happened."""
    problems = []
    old = {str(f.get("id")): f for f in ordered_fields(before)}
    new = {str(f.get("id")): f for f in ordered_fields(after)}
    for field_id, field in old.items():
        if field_id not in new:
            problems.append(f"field {field_id} is missing")
        elif field_id != target_id and _comparable(field) != _comparable(new[field_id]):
            problems.append(f"field {field_id} changed")
    added = set(new) - set(old)
    if target_id is None and len(added) > 1:
        problems.append("more than one field was added")
    if target_id is not None and added:
        problems.append("a field was added")
    if expected_order is not None and [str(f.get("id")) for f in ordered_fields(after)] != expected_order:
        problems.append("the field order is not the requested one")
    if [a.get("id") for a in before.get("actions") or []] != [a.get("id") for a in after.get("actions") or []]:
        problems.append("submit actions changed")
    for key in ("postAction", "postActionProperty", "isPublished", "formType", "name"):
        if before.get(key) != after.get(key):
            problems.append(f"{key} changed")
    return problems


def field_matches(field: dict[str, Any], native: dict[str, Any]) -> bool:
    """True when the stored field carries every native setting that was sent."""
    for key, value in native.items():
        if key == "properties":
            stored = field.get("properties") if isinstance(field.get("properties"), dict) else {}
            if any(stored.get(k) != v for k, v in value.items()):
                return False
        elif key == "isRequired":
            if _bool(field.get(key)) != bool(value):
                return False
        elif str(field.get(key) or "") != str(value or ""):
            return False
    return True
