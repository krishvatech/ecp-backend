"""Form submit-action rules: which native Mautic Form actions ECP manages.

Mautic owns the actions; ECP validates a change, sends it through the bridge
(which re-checks the same allowlist) and reads the Form back to confirm only
the intended change happened.

Managed (annotate the submitting contact, or notify the team):

* ``lead.changetags``  add/remove tags. Mautic takes tag IDs and stores tag
  names; ECP edits by ID and maps stored names back to IDs. If any stored name
  no longer matches a tag, the tag lists are locked rather than silently
  changing the association.
* ``lead.pointschange`` add or subtract points (no multiply/divide).
* ``lead.scorecontactscompanies`` change the contact's company score.
* ``lead.updatelead`` set contact fields to fixed values (never the email,
  consent or system fields).
* ``lead.addutmtags`` record the visit's UTM tags.
* ``asset.download`` offer one asset for download after submitting.
* ``form.email`` email the results to listed addresses and/or the contact's
  owner. Never a copy to the contact: that is an email to the contact.
* ``email.send.user`` email a template to Mautic users. At least one user is
  required: with none, Mautic sends the email to the CONTACT with Do Not
  Contact ignored.
* ``form.repost`` post the results to a public https:// address. Its
  authorization header is write-only (never returned).

Never managed: ``lead.remove_do_not_contact`` and ``email.send.lead``
(prohibited by name), ``lead.changelist`` (segment membership is a marketing
audience and ECP Subscription List segments must never be targeted; deferred
until a consent-safe design is approved) and other native types (CRM push).
Existing actions of any type are kept exactly as they are and shown read-only;
any action may be removed.

Native facts (Mautic 7.1.3, verified): a Form PATCH renumbers ``order`` over
the actions it is sent; id-only stubs keep an action's stored properties; one
invalid action fails the whole PATCH; a points action without points is
accepted natively, so ECP requires them.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email

from .page_html_policy import find_active_content

TAGS = "lead.changetags"
POINTS = "lead.pointschange"
SEGMENTS = "lead.changelist"
COMPANY_SCORE = "lead.scorecontactscompanies"
UPDATE_CONTACT = "lead.updatelead"
UTM_TAGS = "lead.addutmtags"
ASSET = "asset.download"
RESULTS_EMAIL = "form.email"
USER_EMAIL = "email.send.user"
REPOST = "form.repost"

ACTION_TYPES = {
    TAGS: "Modify tags",
    POINTS: "Adjust points",
    COMPANY_SCORE: "Change company score",
    UPDATE_CONTACT: "Update contact fields",
    UTM_TAGS: "Record UTM tags",
    ASSET: "Download an asset",
    RESULTS_EMAIL: "Send form results by email",
    USER_EMAIL: "Send an email to users",
    REPOST: "Post results to another URL",
}
# ECP request keys holding each type's settings.
SETTINGS_KEYS = {
    TAGS: {"addTags", "removeTags"},
    POINTS: {"operator", "points"},
    COMPANY_SCORE: {"score"},
    UPDATE_CONTACT: {"fieldValues"},
    UTM_TAGS: set(),
    ASSET: {"assetId"},
    RESULTS_EMAIL: {"subject", "message", "to", "cc", "bcc", "emailToOwner", "replyToSubmitter"},
    USER_EMAIL: {"emailId", "userIds"},
    REPOST: {"postUrl", "failureEmail", "authorizationHeader"},
}
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
MAX_SCORE = 10000
MAX_RECIPIENTS = 20
MAX_USERS = 20
MAX_CONTACT_FIELDS = 30
MESSAGE_MAX_LENGTH = 20000
NAME_MAX_LENGTH = 191
DESCRIPTION_MAX_LENGTH = 2000
# Contact fields an "update contact" action never sets: identity, consent, system.
PROTECTED_UPDATE_FIELDS = {"email", "points", "last_active", "attribution", "attribution_date"}
EDITABLE_KEYS = {"name", "description"} | set().union(*SETTINGS_KEYS.values())

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


def _flag(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _address_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


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
        # Any action may be removed: removing never emails, lifts DNC or adds to an audience.
        "removable": True,
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
    if action_type == COMPANY_SCORE:
        body["score"] = str(properties.get("score") if properties.get("score") is not None else "")
    if action_type == UPDATE_CONTACT:
        body["fieldValues"] = {str(key): "" if value is None else str(value) for key, value in properties.items()}
        if any(_protected_update_field(key) for key in body["fieldValues"]):
            body["settingsLocked"] = "This action sets a protected contact field, so it is managed in Mautic."
    if action_type == ASSET:
        body["assetId"] = str(properties.get("asset") or "")
        if str(properties.get("category") or "") not in ("", "0"):
            body["settingsLocked"] = "This action offers a whole asset category, which is managed in Mautic."
    if action_type == RESULTS_EMAIL:
        body.update({
            "subject": str(properties.get("subject") or ""),
            "message": str(properties.get("message") or ""),
            "to": _address_list(properties.get("to")),
            "cc": _address_list(properties.get("cc")),
            "bcc": _address_list(properties.get("bcc")),
            "emailToOwner": _flag(properties.get("email_to_owner")),
            # Native default when unset: reply to the submitter.
            "replyToSubmitter": _flag(properties.get("set_replyto", True)),
        })
        if _flag(properties.get("copy_lead")) or str(properties.get("templates") or "") not in ("", "0"):
            body["settingsLocked"] = "This action sends a copy to the contact or uses an email template, so it is managed in Mautic."
    if action_type == USER_EMAIL:
        useremail = properties.get("useremail") if isinstance(properties.get("useremail"), dict) else {}
        body["emailId"] = str(useremail.get("email") or "")
        users = properties.get("user_id")
        body["userIds"] = [str(item) for item in users] if isinstance(users, list) else []
        if not body["userIds"]:
            body["settingsLocked"] = "With no users chosen Mautic emails the contact itself, so this action is managed in Mautic."
    if action_type == REPOST:
        body["postUrl"] = str(properties.get("post_url") or "")
        body["failureEmail"] = str(properties.get("failure_email") or "")
        # Write-only: the header is a credential and is never sent back.
        body["hasAuthorizationHeader"] = bool(str(properties.get("authorization_header") or "").strip())
    return body


def _protected_update_field(alias: str) -> bool:
    return alias in PROTECTED_UPDATE_FIELDS or alias.startswith("ecp_")


def action_type_catalogue() -> list[dict[str, Any]]:
    return [
        {"type": TAGS, "label": ACTION_TYPES[TAGS], "description": "Add or remove tags on the submitting contact."},
        {"type": POINTS, "label": ACTION_TYPES[POINTS], "description": "Add or subtract points for the submitting contact.",
         "operators": [{"value": key, "label": label} for key, label in POINT_OPERATORS.items()], "maxPoints": MAX_POINTS},
        {"type": COMPANY_SCORE, "label": ACTION_TYPES[COMPANY_SCORE],
         "description": "Add to (or subtract from) the score of the contact's company.", "maxScore": MAX_SCORE},
        {"type": UPDATE_CONTACT, "label": ACTION_TYPES[UPDATE_CONTACT],
         "description": "Set contact fields to fixed values. Email, consent and system fields are never set.",
         "maxFields": MAX_CONTACT_FIELDS},
        {"type": UTM_TAGS, "label": ACTION_TYPES[UTM_TAGS], "description": "Store the visit's UTM tags on the contact."},
        {"type": ASSET, "label": ACTION_TYPES[ASSET], "description": "Start a download of one asset after the visitor submits."},
        {"type": RESULTS_EMAIL, "label": ACTION_TYPES[RESULTS_EMAIL],
         "description": "Email the submitted values to your team or the contact's owner. A copy is never sent to the contact.",
         "maxRecipients": MAX_RECIPIENTS},
        {"type": USER_EMAIL, "label": ACTION_TYPES[USER_EMAIL],
         "description": "Send a published email to Mautic users (for example a new-lead alert).", "maxUsers": MAX_USERS},
        {"type": REPOST, "label": ACTION_TYPES[REPOST],
         "description": "Post the submitted values to a public https:// address, such as a CRM webhook."},
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


def _reference(value, key: str, label: str, known: dict[str, str] | None) -> str:
    """A numeric Mautic ID; checked against ``known`` when it could be loaded."""
    text = str(value if value is not None else "").strip()
    if isinstance(value, bool) or not text.isdigit() or text == "0":
        raise ActionPolicyError(f"Choose {label}.", field=key)
    if known is not None and text not in known:
        raise ActionPolicyError(f"The chosen {label.split(' ', 1)[-1]} does not exist in Mautic.", field=key)
    return text


def _addresses(data: dict, key: str, label: str) -> list[str]:
    value = data.get(key, [])
    items = _address_list(value) if isinstance(value, (list, str)) else None
    if items is None:
        raise ActionPolicyError(f"{label} must be a list of email addresses.", field=key)
    if len(items) > MAX_RECIPIENTS:
        raise ActionPolicyError(f"{label}: use {MAX_RECIPIENTS} addresses or fewer.", field=key)
    for item in items:
        if "{" in item or _CONTROL_CHARS.search(item):
            raise ActionPolicyError(f"{label} must list plain email addresses (no tokens).", field=key)
        try:
            validate_email(item)
        except DjangoValidationError:
            raise ActionPolicyError(f'"{item}" is not a valid email address.', field=key) from None
    return items


def _bool_setting(data: dict, key: str, label: str) -> bool:
    value = data.get(key)
    if isinstance(value, bool):
        return value
    if value in (0, 1, "0", "1", "true", "false"):
        return str(value) in {"1", "true"}
    raise ActionPolicyError(f"{label} must be true or false.", field=key)


def _whole(data: dict, key: str, label: str, *, low: int, high: int, nonzero: bool = False) -> int:
    raw = data.get(key)
    text = str(raw).strip() if raw is not None and not isinstance(raw, bool) else ""
    if not re.fullmatch(r"[+-]?\d{1,6}", text) or not low <= int(text) <= high or (nonzero and int(text) == 0):
        extra = ", not 0" if nonzero else ""
        raise ActionPolicyError(f"{label} must be a whole number from {low} to {high}{extra}.", field=key)
    return int(text)


RESOLVE_TIMEOUT_SECONDS = 4.0


def resolve_host(host: str, *, timeout: float = RESOLVE_TIMEOUT_SECONDS) -> list[str] | None:
    """The host's IPv4 and IPv6 addresses; [] when it does not exist, None when
    the lookup did not finish in time (a slow resolver must not hold a request)."""
    import concurrent.futures
    import socket

    def lookup():
        try:
            return sorted({info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
        except socket.gaierror as exc:
            # Only a definite answer means the host does not exist; a resolver
            # failure (EAI_AGAIN and the like) means it could not be checked.
            definite = {getattr(socket, name) for name in ("EAI_NONAME", "EAI_NODATA") if hasattr(socket, name)}
            return [] if exc.errno in definite else None

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        return executor.submit(lookup).result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        return None
    finally:
        executor.shutdown(wait=False)


def validate_repost_url(value, *, resolve=None) -> str:
    """A public https:// address on the standard port, without credentials.
    With ``resolve`` the host must also resolve to public addresses only (the
    bridge checks again before Mautic stores it)."""
    if not isinstance(value, str) or not value.strip() or len(value) > 2048 or _CONTROL_CHARS.search(value) or " " in value.strip():
        raise ActionPolicyError("Enter the https:// address to post results to.", field="postUrl")
    url = value.strip()
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = -1
    if parts.scheme != "https" or not host or parts.username or parts.password or port not in (None, 443):
        raise ActionPolicyError("Results can only be posted to an https:// address on the standard port, without a user name or password.",
                                field="postUrl")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ActionPolicyError("Results can only be posted to a public website.", field="postUrl")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ActionPolicyError("Results can only be posted to a public website.", field="postUrl")
    if resolve is not None and address is None:
        addresses = resolve(host)
        if addresses is None:
            raise ActionPolicyError("The address could not be checked in time. Try again.", code="form_action_host_unchecked", field="postUrl")
        if not addresses:
            raise ActionPolicyError("The website in this address could not be found.", field="postUrl")
        if any(not ipaddress.ip_address(item.split("%")[0]).is_global for item in addresses):
            raise ActionPolicyError("Results can only be posted to a public website.", field="postUrl")
    return url


def _settings(action_type: str, data: dict, refs: dict[str, Any]) -> dict[str, Any]:
    """Native properties for a type's complete settings in ``data``."""
    if action_type == TAGS:
        return _tag_properties(data, refs.get("tags") or {})
    if action_type == POINTS:
        operator, points = _points(data)
        return {"operator": operator, "points": points}
    if action_type == COMPANY_SCORE:
        return {"score": _whole(data, "score", "The company score change", low=-MAX_SCORE, high=MAX_SCORE, nonzero=True)}
    if action_type == UPDATE_CONTACT:
        values = data.get("fieldValues")
        if not isinstance(values, dict) or not values or len(values) > MAX_CONTACT_FIELDS:
            raise ActionPolicyError(f"Choose 1-{MAX_CONTACT_FIELDS} contact fields to set.", field="fieldValues")
        known = refs.get("contactFields")
        properties = {}
        for alias, value in values.items():
            alias = str(alias)
            if _protected_update_field(alias):
                raise ActionPolicyError(f'The "{alias}" contact field records identity, consent or system data and cannot be set by a Form.',
                                        code="form_action_protected_field", field="fieldValues")
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,190}", alias) or (known is not None and alias not in known):
                raise ActionPolicyError(f'"{alias}" is not a published contact field.', field="fieldValues")
            properties[alias] = _text({"v": "" if value is None else value}, "v", f'The value for "{alias}"', required=False, max_length=255)
        return properties
    if action_type == UTM_TAGS:
        return {}
    if action_type == ASSET:
        return {"asset": _reference(data.get("assetId"), "assetId", "an asset", refs.get("assets")), "category": ""}
    if action_type == RESULTS_EMAIL:
        subject = _text(data, "subject", "Subject", required=True, max_length=255)
        message = data.get("message", "")
        if not isinstance(message, str) or len(message) > MESSAGE_MAX_LENGTH:
            raise ActionPolicyError(f"The message must be text of up to {MESSAGE_MAX_LENGTH} characters.", field="message")
        findings = find_active_content(message)
        if findings:
            raise ActionPolicyError(f"The message contains {findings[0]}, which is not allowed.", code="form_action_active_content", field="message")
        to, cc, bcc = _addresses(data, "to", "To"), _addresses(data, "cc", "Cc"), _addresses(data, "bcc", "Bcc")
        owner = _bool_setting({"v": data.get("emailToOwner", False)}, "v", "Email the contact owner")
        reply = _bool_setting({"v": data.get("replyToSubmitter", True)}, "v", "Reply to the submitter")
        if not (to or cc or bcc or owner):
            raise ActionPolicyError("Send the results to at least one address or to the contact owner.", field="to")
        return {
            "subject": subject, "message": message.strip(), "to": ", ".join(to), "cc": ", ".join(cc), "bcc": ", ".join(bcc),
            "email_to_owner": "1" if owner else "0", "set_replyto": "1" if reply else "0",
            # Never a copy to the submitting contact (an email to the contact).
            "copy_lead": "0",
        }
    if action_type == USER_EMAIL:
        email = _reference(data.get("emailId"), "emailId", "an email to send", refs.get("emails"))
        users = data.get("userIds")
        if not isinstance(users, list) or not users or len(users) > MAX_USERS:
            # Mautic emails the CONTACT (ignoring Do Not Contact) when no user is set.
            raise ActionPolicyError(f"Choose 1-{MAX_USERS} Mautic users to email.", field="userIds")
        ids = []
        for user in users:
            user_id = _reference(user, "userIds", "a Mautic user", refs.get("users"))
            if user_id not in ids:
                ids.append(user_id)
        return {"useremail": {"email": email}, "user_id": ids}
    if action_type == REPOST:
        properties = {"post_url": validate_repost_url(data.get("postUrl"), resolve=refs.get("resolveHost")),
                      "failure_email": ""}
        failure = _text(data, "failureEmail", "Failure notice address", required=False, max_length=191)
        if failure:
            properties["failure_email"] = _addresses({"v": failure}, "v", "Failure notice address")[0]
        if "authorizationHeader" in data:
            header = data.get("authorizationHeader")
            if not isinstance(header, str) or len(header) > 1000 or _CONTROL_CHARS.search(header) or "\n" in header or "\r" in header:
                raise ActionPolicyError("The authorization header must be one line of up to 1000 characters.", field="authorizationHeader")
            properties["authorization_header"] = header.strip()
        return properties
    raise ActionPolicyError("This submit action type is not supported here.", code="unsupported_form_action_type")


def _current_settings(action_type: str, current: dict[str, Any]) -> dict[str, Any]:
    """The ECP settings of a stored action, as a complete request would send them."""
    if action_type == TAGS:
        return {"addTags": [r["id"] for r in current["addTags"]], "removeTags": [r["id"] for r in current["removeTags"]]}
    return {key: current[key] for key in SETTINGS_KEYS[action_type] if key in current}


def plan_new_action(data, form: dict[str, Any], catalogue: dict[str, str], refs: dict[str, Any] | None = None) -> tuple[dict[str, Any], int | None]:
    if not isinstance(data, dict):
        raise ActionPolicyError("Send the submit action as a JSON object.")
    action_type = data.get("type")
    _reject_type(action_type)
    allowed = {"type", "name", "description", "position"} | SETTINGS_KEYS[action_type]
    _reject_unknown(data, allowed)
    native: dict[str, Any] = {
        "type": action_type,
        "name": _text(data, "name", "Action name", required=True, max_length=NAME_MAX_LENGTH),
        "description": _text(data, "description", "Description", required=False, max_length=DESCRIPTION_MAX_LENGTH),
        "properties": _settings(action_type, data, {**(refs or {}), "tags": catalogue}),
    }
    position = data.get("position")
    if position is not None and (not isinstance(position, int) or isinstance(position, bool)
                                 or not 0 <= position <= len(ordered_actions(form))):
        raise ActionPolicyError("Position must be an action index within the Form.", field="position")
    return native, position


def plan_action_update(data, action: dict[str, Any], catalogue: dict[str, str], refs: dict[str, Any] | None = None) -> dict[str, Any]:
    """Only the native settings that change; never the type."""
    if not isinstance(data, dict) or not data:
        raise ActionPolicyError("Send the submit action changes as a JSON object.")
    action_type = str(action.get("type") or "")
    if "type" in data:
        raise ActionPolicyError("A submit action's type cannot change. Add a new action instead.", code="form_action_immutable", field="type")
    _reject_type(action_type)
    current = normalize_action(action, catalogue)
    allowed = {"name", "description"} | SETTINGS_KEYS[action_type]
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
    if SETTINGS_KEYS[action_type] & set(data):
        if current["settingsLocked"]:
            raise ActionPolicyError(current["settingsLocked"], code="form_action_settings_locked")
        before_settings = _current_settings(action_type, current)
        merged = {**before_settings, **{key: data[key] for key in SETTINGS_KEYS[action_type] if key in data}}
        refs = {**(refs or {}), "tags": catalogue}
        properties = _settings(action_type, merged, refs)
        if action_type == TAGS:
            before = {"add_tags": before_settings["addTags"], "remove_tags": before_settings["removeTags"]}
            if properties != before:
                native["properties"] = properties
        elif action_type == POINTS:
            if (properties["operator"], properties["points"]) != (current["operator"], int(current["points"] or 0)):
                native["properties"] = properties
        else:
            stored = action.get("properties") if isinstance(action.get("properties"), dict) else {}
            if not _same(stored, properties) or (action_type == REPOST and "authorization_header" in properties):
                native["properties"] = properties
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


def _same(stored, sent) -> bool:
    """True when ``stored`` carries every value that was sent (lists and
    nested objects compared as text, as Mautic stores them)."""
    if isinstance(sent, dict):
        return isinstance(stored, dict) and all(_same(stored.get(key), value) for key, value in sent.items())
    if isinstance(sent, list):
        return isinstance(stored, list) and [str(item) for item in stored] == [str(item) for item in sent]
    return str("" if stored is None else stored) == str(sent)


def action_matches(stored: dict[str, Any], native: dict[str, Any], catalogue: dict[str, str]) -> bool:
    for key in ("name", "description", "type"):
        if key in native and str(stored.get(key) or "") != str(native[key] or ""):
            return False
    if "properties" not in native:
        return True
    properties = stored.get("properties") if isinstance(stored.get("properties"), dict) else {}
    action_type = str(native.get("type") or stored.get("type"))
    if action_type == TAGS:
        for key in ("add_tags", "remove_tags"):
            expected = sorted(catalogue.get(tag_id, "").lower() for tag_id in native["properties"][key])
            if sorted(str(name).lower() for name in properties.get(key) or []) != expected:
                return False
        return True
    if action_type == POINTS:
        return (str(properties.get("operator")), str(properties.get("points"))) == (
            str(native["properties"]["operator"]), str(native["properties"]["points"]))
    return _same(properties, native["properties"])
