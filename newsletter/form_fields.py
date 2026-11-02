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
* Deleting a field drops its column from the Form's results table, so the
  stored values of every submission are lost with it. Removal therefore needs an
  explicit confirmation when submissions exist, and is refused while a Campaign
  condition checks the field. The bridge clears the Form's cached HTML, which
  the native delete leaves showing the removed field.
* Free text and free HTML content is rendered raw (scripts included) on the
  public Form, which IMAA sites embed, so active content is refused.
* Uploads stay private (only Mautic users may download them), accept documents
  and images only, and never set the contact's profile image.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import URLValidator, validate_email

from .page_html_policy import find_active_content

LABEL_MAX_LENGTH = 255
TEXT_MAX_LENGTH = 255
MAX_OPTIONS = 100
ALIAS_MAX_LENGTH = 25

# Native type identifiers, in the order the builder offers them.
FIELD_TYPES = {
    "text": "Text",
    "email": "Email",
    "tel": "Telephone",
    "url": "Website (URL)",
    "textarea": "Text area",
    "number": "Number",
    "slider": "Slider",
    "select": "Dropdown",
    "radiogrp": "Radio group",
    "checkboxgrp": "Checkbox group",
    "date": "Date",
    "datetime": "Date and time",
    "country": "Country",
    "file": "File upload",
    "hidden": "Hidden",
    "captcha": "CAPTCHA",
    "freetext": "Text block",
    "freehtml": "HTML block",
    "pagebreak": "Page break",
    "button": "Submit button",
}
OPTION_TYPES = {"select": "list", "radiogrp": "optionlist", "checkboxgrp": "optionlist"}
PLACEHOLDER_TYPES = {"text", "email", "tel", "url", "date", "datetime", "number", "select", "country", "captcha"}
NO_REQUIRED = {"button", "hidden", "captcha", "freetext", "freehtml", "pagebreak"}
NO_HELP = {"button", "hidden", "freetext", "freehtml", "pagebreak"}
NO_DEFAULT = {"button", "checkboxgrp", "country", "slider", "datetime", "file", "captcha", "freetext", "freehtml", "pagebreak"}
NO_MAPPING = {"button", "file", "captcha", "freetext", "freehtml", "pagebreak"}
# Fields that hold no visitor value (as the bridge counts them for publication).
NON_INPUT_TYPES = {"button", "freetext", "freehtml", "pagebreak", "captcha", "hidden"}
# Removing these never loses submitted values.
NO_VALUE_TYPES = {"button", "freetext", "freehtml", "pagebreak"}

FILE_EXTENSIONS = ("pdf", "doc", "docx", "odt", "rtf", "txt", "csv", "xls", "xlsx", "ods", "ppt", "pptx", "odp",
                   "jpg", "jpeg", "png", "gif", "webp")
DEFAULT_FILE_EXTENSIONS = ["pdf", "doc", "docx", "jpg", "jpeg", "png"]
MAX_FILE_SIZE_MB = 10
CONTENT_MAX_LENGTH = 20000
SLIDER_LIMIT = 1000000

# Type-specific settings: ECP key -> (native property, label, kind, default).
EXTRA_SETTINGS = {
    "slider": [
        ("minValue", "min", "Minimum", "integer", "0"),
        ("maxValue", "max", "Maximum", "integer", "100"),
        ("step", "step", "Step", "integer", "1"),
    ],
    "file": [
        ("allowedExtensions", "allowed_file_extensions", "Allowed file types", "extensions", DEFAULT_FILE_EXTENSIONS),
        ("maxFileSize", "allowed_file_size", "Maximum size (MB)", "integer", "5"),
    ],
    "captcha": [
        ("captchaAnswer", "captcha", "Answer (leave empty for a hidden spam trap)", "text", ""),
        ("errorMessage", "errorMessage", "Wrong-answer message", "text", ""),
    ],
    "freetext": [("content", "text", "Text", "html", "")],
    "freehtml": [("content", "text", "HTML", "html", "")],
    "pagebreak": [
        ("nextLabel", "next_page_label", "Next button label", "text", "Continue"),
        ("prevLabel", "prev_page_label", "Back button label", "text", "Back"),
    ],
}
EXTRA_KEYS = {entry[0] for entries in EXTRA_SETTINGS.values() for entry in entries}

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
    "datetime": {"datetime", "date"},
    "url": {"url", "text"},
    "slider": {"number"},
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
    "url": {"placeholder": ""},
    "datetime": {"placeholder": ""},
    "captcha": {"placeholder": ""},
    # Uploads are private and never become the contact's profile image.
    "file": {"public": "0", "profile_image": "0"},
}

EDITABLE_KEYS = {
    "label", "isRequired", "helpMessage", "validationMessage", "defaultValue",
    "mappedField", "placeholder", "precision", "multiple", "options",
} | EXTRA_KEYS
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
        **_extra_values(field_type, properties),
        "editable": not lock,
        "lockReason": lock,
    }


def _extra_values(field_type: str, properties: dict[str, Any]) -> dict[str, Any]:
    values = {}
    for key, native, _label, kind, _default in EXTRA_SETTINGS.get(field_type, []):
        raw = properties.get(native)
        if kind == "extensions":
            values[key] = [str(item) for item in raw] if isinstance(raw, list) else []
        else:
            values[key] = "" if raw is None else str(raw)
    return values


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
            "input": field_type not in NON_INPUT_TYPES,
            "settings": [
                {"key": key, "label": setting_label, "kind": kind, "default": default,
                 **({"choices": list(FILE_EXTENSIONS)} if kind == "extensions" else {}),
                 **({"min": 1, "max": MAX_FILE_SIZE_MB} if key == "maxFileSize" else {}),
                 **({"maxLength": CONTENT_MAX_LENGTH} if kind == "html" else {})}
                for key, _native, setting_label, kind, default in EXTRA_SETTINGS.get(field_type, [])
            ],
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
    if field_type == "url":
        try:
            URLValidator(schemes=["http", "https"])(default)
        except DjangoValidationError:
            raise FieldPolicyError("The default must be a web address (https://…).", field="defaultValue") from None


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
    state.update(_extras(field_type, data, base if current else None))
    return state


def _integer(data: dict, key: str, label: str, *, low: int, high: int) -> str:
    raw = data.get(key)
    text = str(raw).strip() if raw is not None and not isinstance(raw, bool) else ""
    if not re.fullmatch(r"-?\d{1,7}", text) or not low <= int(text) <= high:
        raise FieldPolicyError(f"{label} must be a whole number from {low} to {high}.", field=key)
    return str(int(text))


def _extras(field_type: str, data: dict, current: dict[str, Any] | None) -> dict[str, Any]:
    """Type-specific settings after applying ``data``, checked as a whole."""
    state = {}
    for key, _native, label, kind, default in EXTRA_SETTINGS.get(field_type, []):
        if key not in data:
            state[key] = current[key] if current is not None else default
            continue
        if kind == "integer":
            low, high = (1, MAX_FILE_SIZE_MB) if key == "maxFileSize" else (-SLIDER_LIMIT, SLIDER_LIMIT)
            state[key] = _integer(data, key, label, low=low, high=high)
        elif kind == "extensions":
            value = data.get(key)
            if not isinstance(value, list) or not value:
                raise FieldPolicyError("Choose at least one allowed file type.", field=key)
            chosen = []
            for item in value:
                text = str(item).strip().lower().lstrip(".")
                if isinstance(item, bool) or text not in FILE_EXTENSIONS:
                    raise FieldPolicyError("Allowed file types: " + ", ".join(FILE_EXTENSIONS) + ".", field=key)
                if text not in chosen:
                    chosen.append(text)
            state[key] = chosen
        elif kind == "html":
            value = data.get(key)
            if not isinstance(value, str):
                raise FieldPolicyError(f"{label} must be text.", field=key)
            if len(value) > CONTENT_MAX_LENGTH:
                raise FieldPolicyError(f"{label} must be {CONTENT_MAX_LENGTH} characters or fewer.", field=key)
            findings = find_active_content(value)
            if findings:
                raise FieldPolicyError(
                    f"{label} contains {findings[0]}. Forms are embedded on other sites, so code is not allowed.",
                    code="form_field_active_content", field=key,
                )
            state[key] = value.strip()
        else:
            state[key] = _text(data, key, label)
    if field_type == "slider":
        low, high, step = int(state["minValue"]), int(state["maxValue"]), int(state["step"])
        if low >= high:
            raise FieldPolicyError("The maximum must be greater than the minimum.", field="maxValue")
        if not 1 <= step <= high - low:
            raise FieldPolicyError("The step must be at least 1 and fit within the range.", field="step")
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
                or (key == "options" and field_type not in OPTION_TYPES) \
                or (key in EXTRA_KEYS and key not in {entry[0] for entry in EXTRA_SETTINGS.get(field_type, [])}):
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
    for key, native_key, _label, _kind, _default in EXTRA_SETTINGS.get(field_type, []):
        if key in keys:
            properties[native_key] = state[key]
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

    # A new field stores every type-specific setting (defaults included).
    keys = {key for key in state if key in data} | {"label"} | {entry[0] for entry in EXTRA_SETTINGS.get(field_type, [])}
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


# Removal --------------------------------------------------------------------------


def plan_field_removal(field: dict[str, Any], form: dict[str, Any], *, submissions: int, confirmed: bool) -> None:
    """Refuse a removal that would break a published Form, or lose stored
    submission values without an explicit confirmation. (Campaign conditions
    that check the field are refused by the bridge, which can read them.)"""
    remaining = [str(f.get("type") or "") for f in ordered_fields(form) if str(f.get("id")) != str(field.get("id"))]
    if _bool(form.get("isPublished")):
        if "button" not in remaining:
            raise FieldPolicyError("A published Form needs its submit button. Unpublish the Form first.",
                                   code="form_field_removal_blocked")
        if not any(field_type not in NON_INPUT_TYPES for field_type in remaining):
            raise FieldPolicyError("A published Form needs at least one field visitors can fill in. Unpublish the Form first.",
                                   code="form_field_removal_blocked")
    if submissions > 0 and not confirmed and str(field.get("type") or "") not in NO_VALUE_TYPES:
        raise FieldPolicyError(
            f"The Form has {submissions} stored submission(s). Removing this field permanently deletes its value "
            "from every one of them. Confirm the removal to continue.",
            code="form_field_removal_unconfirmed",
        )


def removal_problems(before: dict[str, Any], after: dict[str, Any], field_id: str) -> list[str]:
    """What is wrong with ``after`` beyond the one field being gone."""
    problems = []
    after_fields = {str(f.get("id")): f for f in ordered_fields(after)}
    if str(field_id) in after_fields:
        problems.append("the field is still on the Form")
    kept = [f for f in ordered_fields(before) if str(f.get("id")) != str(field_id)]
    for field in kept:
        stored = after_fields.get(str(field.get("id")))
        if stored is None:
            problems.append(f"field {field.get('id')} is missing")
        elif _comparable(field) != _comparable(stored):
            problems.append(f"field {field.get('id')} changed")
    if [str(f.get("id")) for f in ordered_fields(after)] != [str(f.get("id")) for f in kept if str(f.get("id")) in after_fields]:
        problems.append("the field order changed")
    if set(after_fields) - {str(f.get("id")) for f in kept}:
        problems.append("a field was added")
    if [a.get("id") for a in before.get("actions") or []] != [a.get("id") for a in after.get("actions") or []]:
        problems.append("submit actions changed")
    for key in ("postAction", "postActionProperty", "isPublished", "formType", "name"):
        if before.get(key) != after.get(key):
            problems.append(f"{key} changed")
    return problems
