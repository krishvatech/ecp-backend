"""Form submit-action rules: which native Mautic Form actions ECP manages.

Mautic owns the actions; ECP validates a change, sends it through the bridge
(which re-checks the same allowlist) and reads the Form back to confirm only
the intended change happened.

Managed (annotate the submitting contact only):

* ``lead.changetags``  add/remove tags. Mautic takes tag IDs and stores tag
  names; ECP edits by ID and maps stored names back to IDs. If any stored name
  no longer matches a tag, the tag lists are locked rather than silently
  changing the association.
* ``lead.pointschange`` add or subtract points (no multiply/divide).

Never managed: ``lead.remove_do_not_contact`` and ``email.send.lead``
(prohibited by name), ``lead.changelist`` (segment membership is a marketing
audience and ECP Subscription List segments must never be targeted; deferred
until a consent-safe design is approved) and every other native type (email,
repost, CRM push, contact updates, assets). Existing actions of any type are
kept exactly as they are and shown read-only.

Native facts (Mautic 7.1.3, verified): a Form PATCH renumbers ``order`` over
the actions it is sent; id-only stubs keep an action's stored properties; one
invalid action fails the whole PATCH; a points action without points is
accepted natively, so ECP requires them.
"""

from __future__ import annotations

import re
from typing import Any

TAGS = "lead.changetags"
POINTS = "lead.pointschange"
SEGMENTS = "lead.changelist"

ACTION_TYPES = {TAGS: "Modify tags", POINTS: "Adjust points"}
PROHIBITED_TYPES = {
    "lead.remove_do_not_contact": "Remove Do Not Contact",
    "email.send.lead": "Send email to contact",
}
DEFERRED_REASONS = {
    SEGMENTS: "Segment membership is a marketing audience; Form segment actions are not offered yet.",
}
POINT_OPERATORS = {"plus": "Add", "minus": "Subtract"}
NATIVE_POINT_OPERATORS = {"plus": "+", "minus": "-", "times": "×", "divide": "÷"}
MAX_POINTS = 10000
MAX_TAGS = 50
NAME_MAX_LENGTH = 191
DESCRIPTION_MAX_LENGTH = 2000
EDITABLE_KEYS = {"name", "description", "addTags", "removeTags", "operator", "points"}

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ActionPolicyError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid_form_action", field: str = ""):
        super().__init__(message)
        self.code = code
        self.field = field


def _collection(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = list(value.values())
    return [item for item in value or [] if isinstance(item, dict)] if isinstance(value, list) else []


def ordered_actions(form: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(_collection(form.get("actions")), key=lambda a: (int(a.get("order") or 0), int(a.get("id") or 0)))


def tag_catalogue(rows) -> dict[str, str]:
    """``{tag_id: tag_name}`` from a native tag list response."""
    out = {}
    for row in _collection(rows):
        if row.get("id") is not None and row.get("tag") is not None:
            out[str(row["id"])] = str(row["tag"])
    return out


def _tag_refs(names, by_name: dict[str, str]) -> list[dict[str, Any]]:
    refs = []
    for name in names if isinstance(names, list) else []:
        text = str(name)
        refs.append({"name": text, "id": by_name.get(text.lower())})
    return refs


def normalize_action(action: dict[str, Any], catalogue: dict[str, str], *, policy: str = "allowed", policy_reason: str = "") -> dict[str, Any]:
    action_type = str(action.get("type") or "")
    properties = action.get("properties") if isinstance(action.get("properties"), dict) else {}
    by_name = {name.lower(): tag_id for tag_id, name in catalogue.items()}
    lock = ""
    if policy != "allowed":
        lock = policy_reason
    elif action_type not in ACTION_TYPES:
        lock = DEFERRED_REASONS.get(action_type, "This submit action type is managed in Mautic.")
    body = {
        "id": str(action.get("id") or ""),
        "name": str(action.get("name") or ""),
        "description": str(action.get("description") or ""),
        "type": action_type,
        "typeLabel": ACTION_TYPES.get(action_type) or PROHIBITED_TYPES.get(action_type) or action_type,
        "order": action.get("order"),
        "policy": policy,
        "policyReason": policy_reason,
        "editable": not lock,
        "lockReason": lock,
        "settingsLocked": "",
    }
    if action_type == TAGS:
        body["addTags"] = _tag_refs(properties.get("add_tags"), by_name)
        body["removeTags"] = _tag_refs(properties.get("remove_tags"), by_name)
        if any(ref["id"] is None for ref in body["addTags"] + body["removeTags"]):
            body["settingsLocked"] = "A stored tag no longer exists in Mautic, so the tag lists are managed in Mautic."
    if action_type == POINTS:
        operator = str(properties.get("operator") or "")
        body["operator"] = operator
        body["points"] = properties.get("points")
        body["pointGroup"] = properties.get("group")
        if operator not in POINT_OPERATORS:
            body["settingsLocked"] = f"Points are changed with “{NATIVE_POINT_OPERATORS.get(operator, operator)}”, which is managed in Mautic."
    return body


def action_type_catalogue() -> list[dict[str, Any]]:
    return [
        {"type": TAGS, "label": ACTION_TYPES[TAGS], "description": "Add or remove tags on the submitting contact."},
        {"type": POINTS, "label": ACTION_TYPES[POINTS], "description": "Add or subtract points for the submitting contact.",
         "operators": [{"value": key, "label": label} for key, label in POINT_OPERATORS.items()], "maxPoints": MAX_POINTS},
    ]


# Validation ---------------------------------------------------------------------


def _text(data: dict, key: str, label: str, *, required: bool, max_length: int) -> str:
    value = data.get(key)
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ActionPolicyError(f"{label} must be text.", field=key)
    value = value.strip()
    if _CONTROL_CHARS.search(value):
        raise ActionPolicyError(f"{label} contains unsupported characters.", field=key)
    if len(value) > max_length:
        raise ActionPolicyError(f"{label} must be {max_length} characters or fewer.", field=key)
    if required and not value:
        raise ActionPolicyError(f"{label} is required.", field=key)
    return value


def _tag_ids(data: dict, key: str, catalogue: dict[str, str]) -> list[str]:
    value = data.get(key, [])
    if not isinstance(value, list) or len(value) > MAX_TAGS:
        raise ActionPolicyError(f"Choose up to {MAX_TAGS} tags.", field=key)
    ids = []
    for item in value:
        text = str(item).strip()
        if isinstance(item, bool) or not text.isdigit():
            raise ActionPolicyError("Tags must be chosen from Mautic's tag list.", field=key)
        if text not in catalogue:
            raise ActionPolicyError(f"Tag {text} does not exist in Mautic.", field=key)
        if text not in ids:
            ids.append(text)
    return ids


def _points(data: dict) -> tuple[str, int]:
    operator = data.get("operator")
    if operator not in POINT_OPERATORS:
        raise ActionPolicyError("Choose whether to add or subtract points.", field="operator")
    points = data.get("points")
    try:
        value = int(str(points).strip())
    except (TypeError, ValueError):
        value = None
    if isinstance(points, bool) or value is None or str(points).strip().lstrip("+") != str(value) or not 1 <= value <= MAX_POINTS:
        raise ActionPolicyError(f"Points must be a whole number from 1 to {MAX_POINTS}.", field="points")
    return operator, value


def _reject_type(action_type) -> None:
    if action_type in PROHIBITED_TYPES:
        raise ActionPolicyError(f"{PROHIBITED_TYPES[action_type]} is not allowed by ECP policy.", code="form_action_prohibited", field="type")
    if action_type in DEFERRED_REASONS:
        raise ActionPolicyError(DEFERRED_REASONS[action_type], code="form_action_deferred", field="type")
    if action_type not in ACTION_TYPES:
        raise ActionPolicyError("Choose a supported submit action: " + ", ".join(ACTION_TYPES.values()) + ".",
                                code="unsupported_form_action_type", field="type")


def _reject_unknown(data: dict, allowed: set[str]) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ActionPolicyError("Unsupported submit action setting(s): " + ", ".join(unknown) + ".", code="unsupported_form_action_settings")


def _tag_properties(data: dict, catalogue: dict[str, str]) -> dict[str, list[str]]:
    add = _tag_ids(data, "addTags", catalogue)
    remove = _tag_ids(data, "removeTags", catalogue)
    if not add and not remove:
        raise ActionPolicyError("Choose at least one tag to add or remove.", field="addTags")
    if set(add) & set(remove):
        raise ActionPolicyError("A tag cannot be both added and removed.", field="removeTags")
    return {"add_tags": add, "remove_tags": remove}


def plan_new_action(data, form: dict[str, Any], catalogue: dict[str, str]) -> tuple[dict[str, Any], int | None]:
    if not isinstance(data, dict):
        raise ActionPolicyError("Send the submit action as a JSON object.")
    action_type = data.get("type")
    _reject_type(action_type)
    allowed = {"type", "name", "description", "position"} | ({"addTags", "removeTags"} if action_type == TAGS else {"operator", "points"})
    _reject_unknown(data, allowed)
    native: dict[str, Any] = {
        "type": action_type,
        "name": _text(data, "name", "Action name", required=True, max_length=NAME_MAX_LENGTH),
        "description": _text(data, "description", "Description", required=False, max_length=DESCRIPTION_MAX_LENGTH),
    }
    if action_type == TAGS:
        native["properties"] = _tag_properties(data, catalogue)
    else:
        operator, points = _points(data)
        native["properties"] = {"operator": operator, "points": points}
    position = data.get("position")
    if position is not None and (not isinstance(position, int) or isinstance(position, bool)
                                 or not 0 <= position <= len(ordered_actions(form))):
        raise ActionPolicyError("Position must be an action index within the Form.", field="position")
    return native, position


def plan_action_update(data, action: dict[str, Any], catalogue: dict[str, str]) -> dict[str, Any]:
    """Only the native settings that change; never the type."""
    if not isinstance(data, dict) or not data:
        raise ActionPolicyError("Send the submit action changes as a JSON object.")
    action_type = str(action.get("type") or "")
    if "type" in data:
        raise ActionPolicyError("A submit action's type cannot change. Add a new action instead.", code="form_action_immutable", field="type")
    _reject_type(action_type)
    current = normalize_action(action, catalogue)
    allowed = {"name", "description"} | ({"addTags", "removeTags"} if action_type == TAGS else {"operator", "points"})
    _reject_unknown(data, allowed)

    native: dict[str, Any] = {}
    if "name" in data:
        name = _text(data, "name", "Action name", required=True, max_length=NAME_MAX_LENGTH)
        if name != current["name"]:
            native["name"] = name
    if "description" in data:
        description = _text(data, "description", "Description", required=False, max_length=DESCRIPTION_MAX_LENGTH)
        if description != current["description"]:
            native["description"] = description
    settings_keys = {"addTags", "removeTags"} if action_type == TAGS else {"operator", "points"}
    if settings_keys & set(data):
        if current["settingsLocked"]:
            raise ActionPolicyError(current["settingsLocked"], code="form_action_settings_locked")
        if action_type == TAGS:
            properties = _tag_properties({"addTags": data.get("addTags", [r["id"] for r in current["addTags"]]),
                                          "removeTags": data.get("removeTags", [r["id"] for r in current["removeTags"]])}, catalogue)
            before = {"add_tags": [r["id"] for r in current["addTags"]], "remove_tags": [r["id"] for r in current["removeTags"]]}
            if properties != before:
                native["properties"] = properties
        else:
            operator, points = _points({"operator": data.get("operator", current["operator"]),
                                        "points": data.get("points", current["points"])})
            if (operator, points) != (current["operator"], int(current["points"] or 0)):
                native["properties"] = {"operator": operator, "points": points}
    return native


def parse_action_order(data, form: dict[str, Any]) -> list[str]:
    order = data.get("order") if isinstance(data, dict) else None
    current = [str(a.get("id")) for a in ordered_actions(form)]
    if not isinstance(order, list) or sorted(map(str, order)) != sorted(current) or len(set(map(str, order))) != len(order):
        raise ActionPolicyError("Send the new order as every submit action ID of the Form, each once.", field="order")
    return [str(item) for item in order]


# Read-back verification ----------------------------------------------------------


def _comparable(item: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in item.items() if key != "order"}


def unexpected_changes(before: dict[str, Any], after: dict[str, Any], *, target_id: str | None,
                       expected_order: list[str] | None) -> list[str]:
    """What changed beyond the one intended action write: other actions, any
    field, the action order, after-submit settings, publication, type, name."""
    problems = []
    old = {str(a.get("id")): a for a in ordered_actions(before)}
    new = {str(a.get("id")): a for a in ordered_actions(after)}
    for action_id, action in old.items():
        if action_id not in new:
            problems.append(f"action {action_id} is missing")
        elif action_id != target_id and _comparable(action) != _comparable(new[action_id]):
            problems.append(f"action {action_id} changed")
    added = set(new) - set(old)
    if target_id is None and len(added) != 1:
        problems.append("the new action was not saved exactly once")
    if target_id is not None and added:
        problems.append("an action was added")
    if expected_order is not None and [str(a.get("id")) for a in ordered_actions(after)] != expected_order:
        problems.append("the action order is not the requested one")
    fields_before = {str(f.get("id")): _comparable(f) for f in _collection(before.get("fields"))}
    fields_after = {str(f.get("id")): _comparable(f) for f in _collection(after.get("fields"))}
    if fields_before != fields_after:
        problems.append("form fields changed")
    for key in ("postAction", "postActionProperty", "isPublished", "formType", "name"):
        if before.get(key) != after.get(key):
            problems.append(f"{key} changed")
    return problems


def action_matches(stored: dict[str, Any], native: dict[str, Any], catalogue: dict[str, str]) -> bool:
    for key in ("name", "description", "type"):
        if key in native and str(stored.get(key) or "") != str(native[key] or ""):
            return False
    if "properties" not in native:
        return True
    properties = stored.get("properties") if isinstance(stored.get("properties"), dict) else {}
    if str(native.get("type") or stored.get("type")) == TAGS:
        for key in ("add_tags", "remove_tags"):
            expected = sorted(catalogue.get(tag_id, "").lower() for tag_id in native["properties"][key])
            if sorted(str(name).lower() for name in properties.get(key) or []) != expected:
                return False
        return True
    return (str(properties.get("operator")), str(properties.get("points"))) == (
        str(native["properties"]["operator"]), str(native["properties"]["points"]))
