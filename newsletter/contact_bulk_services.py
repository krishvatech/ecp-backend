"""Bulk actions on ticked Marketing Hub contacts (native Mautic parity).

Matches the Contacts list batch menu of native Mautic 7.1: change segments,
change campaigns, change owner and Do Not Contact (add only; native has no
bulk remove either). Up to 100 contacts per request, the bulk-stage limit.

The target is checked once (segment rules, campaign, owner); each contact is
then changed on its own as the acting admin's Mautic user, with its own
single-use assertion and audit row, skipped when already in the requested
state, and read back so "updated" is only reported once Mautic shows it.

ECP Subscription List segments are never offered: their membership follows
newsletter consent, exactly as for single-contact segment changes.
"""

from __future__ import annotations

from typing import Any

from .contact_services import _contact_name, _contact_owner, _normalize_bulk_contact_ids, _normalize_owner_id
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.operations import (
    CAMPAIGN_CONTACT_ADD,
    CAMPAIGN_CONTACT_REMOVE,
    CONTACT_DNC_ADD,
    CONTACT_UPDATE,
    SEGMENT_CONTACT_ADD,
    SEGMENT_CONTACT_REMOVE,
)
from .category_segment_services import mapped_category_for_segment, segment_is_static

ACTIONS = ("segment_add", "segment_remove", "campaign_add", "campaign_remove", "owner_set", "dnc_add")
REASON_MAX_LENGTH = 255
# Mautic's DoNotContact::MANUAL.
DNC_MANUAL = 3


class BulkActionError(ValueError):
    def __init__(self, message: str, *, code: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class BulkActionAbort(Exception):
    """An identity/permission refusal: true for every contact, so it is the
    request's response rather than 100 identical per-contact failures."""

    def __init__(self, response):
        super().__init__("Bulk action was refused by the identity layer")
        self.response = response


def _positive_id(value, field: str) -> str:
    text = str(value if value is not None else "").strip()
    if isinstance(value, bool) or not text.isdigit() or int(text) <= 0:
        raise BulkActionError(f"{field} must be a positive integer.", code="invalid_target")
    return str(int(text))


def parse_bulk_request(data) -> dict[str, Any]:
    if not hasattr(data, "get"):
        raise BulkActionError("Send the bulk action as an object.", code="invalid_payload")
    action = str(data.get("action") or "").strip()
    if action not in ACTIONS:
        raise BulkActionError("action must be one of: " + ", ".join(ACTIONS) + ".", code="invalid_action")
    allowed = {"action", "contact_ids", {
        "segment_add": "segment_id", "segment_remove": "segment_id",
        "campaign_add": "campaign_id", "campaign_remove": "campaign_id",
        "owner_set": "owner_id", "dnc_add": "reason",
    }[action]}
    unsupported = sorted(set(data.keys()) - allowed)
    if unsupported:
        raise BulkActionError("Unsupported field(s) for this action: " + ", ".join(unsupported) + ".", code="invalid_payload")
    try:
        contact_ids = _normalize_bulk_contact_ids(data.get("contact_ids"))
    except ValueError as exc:
        raise BulkActionError(str(exc), code="invalid_contact_ids") from exc

    options: dict[str, Any] = {"action": action, "contact_ids": contact_ids}
    if action.startswith("segment_"):
        options["segment_id"] = _positive_id(data.get("segment_id"), "segment_id")
    elif action.startswith("campaign_"):
        options["campaign_id"] = _positive_id(data.get("campaign_id"), "campaign_id")
    elif action == "owner_set":
        try:
            options["owner_id"] = _normalize_owner_id(data.get("owner_id"))
        except ValueError as exc:
            raise BulkActionError(str(exc), code="invalid_target") from exc
    else:
        reason = str(data.get("reason") or "").strip()
        if len(reason) > REASON_MAX_LENGTH:
            raise BulkActionError(f"reason must be {REASON_MAX_LENGTH} characters or fewer.", code="invalid_target")
        options["reason"] = reason
    return options


def _target(options: dict[str, Any], client: MauticClient) -> dict[str, Any]:
    """Checks the target once and describes it for the results."""
    action = options["action"]
    if action.startswith("segment_"):
        # Checked before reading Mautic: a Subscription List segment is refused
        # even when Mautic cannot be reached or no longer has it.
        if mapped_category_for_segment(options["segment_id"]) is not None:
            raise BulkActionError(
                "This segment is managed by Subscription Lists. Its membership follows newsletter consent.",
                code="subscription_list_segment", status_code=409,
            )
        segment = client.get_segment(options["segment_id"])
        if not segment_is_static(segment):
            raise BulkActionError(
                "Contacts can be added or removed by hand only for static segments (segments without filters).",
                code="segment_not_static",
            )
        return {"type": "segment", "id": options["segment_id"], "name": str(segment.get("name") or "")}
    if action.startswith("campaign_"):
        campaign = client.get_campaign(options["campaign_id"])
        return {"type": "campaign", "id": options["campaign_id"], "name": str(campaign.get("name") or "")}
    if action == "owner_set":
        if options["owner_id"] == "":
            return {"type": "owner", "id": None, "name": "No owner"}
        user = client.get_user(options["owner_id"])
        if user.get("isPublished") in (False, 0, "0"):
            raise BulkActionError("That Mautic user is inactive and cannot own contacts.", code="owner_inactive")
        name = " ".join(str(user.get(k) or "").strip() for k in ("firstName", "lastName")).strip()
        return {"type": "owner", "id": str(options["owner_id"]), "name": name or str(user.get("username") or "")}
    return {"type": "dnc", "id": "email", "name": "Email Do Not Contact"}


def _has_email_dnc(contact: dict[str, Any]) -> bool:
    return any(
        isinstance(entry, dict) and str(entry.get("channel") or "email") == "email"
        for entry in contact.get("doNotContact") or []
    )


def run_bulk_action(options: dict[str, Any], *, run_mutation=None, client: MauticClient | None = None) -> dict[str, Any]:
    """Applies the action to each contact and reports updated/skipped/failed per contact.

    ``run_mutation(action, resource, resource_id, fn)`` runs one change as the
    acting admin and returns ``(result, identity_response)``.
    """
    client = client or MauticClient()
    action = options["action"]
    target = _target(options, client)

    def mutate(operation, resource, resource_id, fn):
        if run_mutation is None:
            return fn(client)
        result, identity_response = run_mutation(operation, resource, resource_id, fn)
        if identity_response is not None:
            raise BulkActionAbort(identity_response)
        return result

    results = []
    counts = {"updated": 0, "skipped": 0, "failed": 0}
    for contact_id in options["contact_ids"]:
        name = ""
        try:
            contact = client.get_contact(contact_id)
            name = _contact_name(contact)
            status, message = _apply(action, options, target, contact_id, contact, client, mutate)
        except (PermanentMauticError, TemporaryMauticError, ValueError) as exc:
            status, message = "failed", str(exc) or "Mautic did not complete the change."
        counts[status] += 1
        results.append({"mautic_contact_id": contact_id, "name": name, "status": status, "message": message})

    return {"action": action, "target": target, "requested": len(options["contact_ids"]), **counts, "results": results}


def _apply(action, options, target, contact_id, contact, client, mutate) -> tuple[str, str]:
    if action in ("segment_add", "segment_remove"):
        segment_id = options["segment_id"]
        member = segment_id in client.get_contact_segment_ids(contact_id)
        if member == (action == "segment_add"):
            return "skipped", "Already in the segment." if member else "Not in the segment."
        operation = SEGMENT_CONTACT_ADD if action == "segment_add" else SEGMENT_CONTACT_REMOVE
        mutate(operation, "segment_contact", f"{segment_id}:{contact_id}",
               lambda c: (c.add_contact_to_segment if action == "segment_add" else c.remove_contact_from_segment)(segment_id, contact_id))
        if (segment_id in client.get_contact_segment_ids(contact_id)) != (action == "segment_add"):
            raise TemporaryMauticError("Mautic did not confirm the segment change.")
        return "updated", ""

    if action in ("campaign_add", "campaign_remove"):
        campaign_id = options["campaign_id"]
        member = campaign_id in client.get_contact_campaign_ids(contact_id)
        if member == (action == "campaign_add"):
            return "skipped", "Already in the campaign." if member else "Not in the campaign."
        operation = CAMPAIGN_CONTACT_ADD if action == "campaign_add" else CAMPAIGN_CONTACT_REMOVE
        mutate(operation, "campaign_contact", f"{campaign_id}:{contact_id}",
               lambda c: (c.add_contact_to_campaign if action == "campaign_add" else c.remove_contact_from_campaign)(campaign_id, contact_id))
        if (campaign_id in client.get_contact_campaign_ids(contact_id)) != (action == "campaign_add"):
            raise TemporaryMauticError("Mautic did not confirm the campaign change.")
        return "updated", ""

    if action == "owner_set":
        wanted = target["id"]
        current = (_contact_owner(contact) or {}).get("id")
        if current == wanted:
            return "skipped", "Already has this owner." if wanted else "Already has no owner."
        mutate(CONTACT_UPDATE, "contact", contact_id, lambda c: c.update_contact(contact_id, {"owner": options["owner_id"]}))
        if (_contact_owner(client.get_contact(contact_id)) or {}).get("id") != wanted:
            raise TemporaryMauticError("Mautic did not confirm the owner change.")
        return "updated", ""

    # dnc_add
    if _has_email_dnc(contact):
        return "skipped", "Already Do Not Contact."
    comments = options["reason"] or "Marked Do Not Contact in bulk from the Marketing Hub."
    mutate(CONTACT_DNC_ADD, "contact_dnc", f"{contact_id}:email",
           lambda c: c.add_contact_dnc(contact_id, "email", reason=DNC_MANUAL, comments=comments))
    if not _has_email_dnc(client.get_contact(contact_id)):
        raise TemporaryMauticError("Mautic did not confirm the Do Not Contact change.")
    return "updated", ""


def list_owner_choices(client: MauticClient | None = None) -> list[dict[str, str]]:
    """Active Mautic users who can own contacts, by name."""
    client = client or MauticClient()
    data = client.list_users(limit=500, orderBy="lastName", orderByDir="ASC")
    rows = data.get("users")
    rows = rows.values() if isinstance(rows, dict) else rows or []
    owners = []
    for user in rows:
        if not isinstance(user, dict) or user.get("id") is None or user.get("isPublished") in (False, 0, "0"):
            continue
        name = " ".join(str(user.get(k) or "").strip() for k in ("firstName", "lastName")).strip()
        owners.append({"id": str(user["id"]), "name": name or str(user.get("username") or ""), "email": str(user.get("email") or "")})
    return sorted(owners, key=lambda owner: owner["name"].lower())
