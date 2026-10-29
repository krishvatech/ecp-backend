"""Manual contact merge from the Marketing Hub (native Mautic "Merge" button).

The contact being viewed is kept; the other one is merged into it and then
deleted by Mautic. Mautic decides the merged values: for each field the most
recently updated contact's value wins, points are added up, the kept
contact's owner stays (the other one's is used only if it has none), and
tags, segments, campaigns, notes and history all move across. Do Not Contact
records are kept by the ECP plugin's merge listener.

ECP adds blockers native Mautic does not have:
- a contact linked to an ECP account is never the one deleted, so the
  account's mapping never points at a retired contact;
- two contacts linked to two ECP accounts are never merged;
- Subscription List membership is consent, so a merge that would give the
  kept contact a Subscription List it is not already in is refused. The ECP
  plugin enforces the same rule in Mautic itself.

The preview reports the blockers so the admin sees them before confirming;
the merge checks them again first.
"""

from __future__ import annotations

from typing import Any

from .category_segment_services import mapped_category_for_segment
from .contact_services import _contact_field, _contact_name, _contact_owner
from .mautic import MauticClient
from .models import MauticContactMapping


class MergeError(ValueError):
    def __init__(self, message: str, *, code: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def _contact_id(value, *, field: str) -> str:
    text = str(value if value is not None else "").strip()
    if not text.isdigit() or int(text) < 1:
        raise MergeError(f"{field} must be a Mautic contact id.", code="invalid_contact")
    return str(int(text))


def parse_merge_ids(contact_id, other_contact_id) -> tuple[str, str]:
    kept = _contact_id(contact_id, field="Contact")
    other = _contact_id(other_contact_id, field="other_contact_id")
    if kept == other:
        raise MergeError("A contact cannot be merged with itself.", code="same_contact")
    return kept, other


def _summary(contact: dict[str, Any], contact_id: str, mapping) -> dict[str, Any]:
    return {
        "mautic_contact_id": contact_id,
        "name": _contact_name(contact) or f"Contact #{contact_id}",
        "email": str(_contact_field(contact, "email") or ""),
        "points": contact.get("points") or 0,
        "owner": _contact_owner(contact),
        "date_modified": contact.get("dateModified") or contact.get("dateAdded"),
        "last_active_at": contact.get("lastActive"),
        "linked_ecp_user_id": mapping.user_id if mapping is not None else None,
    }


def _subscription_lists_only_on(client: MauticClient, other_id: str, kept_id: str) -> list[str]:
    extra = client.get_contact_segment_ids(other_id) - client.get_contact_segment_ids(kept_id)
    names = []
    for segment_id in sorted(extra, key=int):
        category = mapped_category_for_segment(segment_id)
        if category is not None:
            names.append(category.name)
    return names


def merge_preview(contact_id, other_contact_id, *, client: MauticClient | None = None) -> dict[str, Any]:
    """Both contacts side by side, plus every reason the merge cannot run."""
    kept_id, other_id = parse_merge_ids(contact_id, other_contact_id)
    client = client or MauticClient()
    kept = client.get_contact(kept_id)
    other = client.get_contact(other_id)
    # getEntity resolves a merged-away id to its survivor: never merge a contact into itself.
    if str(kept.get("id")) != kept_id or str(other.get("id")) != other_id:
        raise MergeError("One of these contacts was already merged into another contact.", code="already_merged", status_code=409)

    mappings = {
        row.mautic_contact_id: row for row in MauticContactMapping.objects.filter(mautic_contact_id__in=[kept_id, other_id])
    }
    kept_summary = _summary(kept, kept_id, mappings.get(kept_id))
    other_summary = _summary(other, other_id, mappings.get(other_id))

    blockers = []
    if other_id in mappings and kept_id in mappings:
        blockers.append({
            "code": "both_linked",
            "message": "Both contacts are linked to ECP accounts. Two ECP members cannot be merged.",
        })
    elif other_id in mappings:
        blockers.append({
            "code": "linked_contact_merged_away",
            "message": (
                f"{other_summary['name']} is linked to an ECP account, so it must be the contact you keep. "
                "Open that contact and merge this one into it."
            ),
        })
    lists = _subscription_lists_only_on(client, other_id, kept_id)
    if lists:
        blockers.append({
            "code": "subscription_list_conflict",
            "message": (
                f"{other_summary['name']} is subscribed to {', '.join(lists)}, which the kept contact is not. "
                "Subscriptions are consent and cannot move between contacts."
            ),
        })

    return {"kept": kept_summary, "merged_away": other_summary, "blockers": blockers, "can_merge": not blockers}


def run_merge(contact_id, other_contact_id, *, run_mutation, client: MauticClient | None = None) -> dict[str, Any]:
    """Re-check the blockers, then merge as the acting admin's Mautic user.

    ``run_mutation(client_call)`` runs ``client_call(client)`` with an asserted
    client and returns ``(result, identity_response)``.
    """
    preview = merge_preview(contact_id, other_contact_id, client=client)
    if preview["blockers"]:
        first = preview["blockers"][0]
        raise MergeError(first["message"], code=first["code"], status_code=409)
    kept_id = preview["kept"]["mautic_contact_id"]
    other_id = preview["merged_away"]["mautic_contact_id"]
    result, identity_response = run_mutation(lambda asserted: asserted.merge_contacts(kept_id, other_id))
    if identity_response is not None:
        return {"identity_response": identity_response}
    return {
        "mautic_contact_id": str(result.get("contactId") or kept_id),
        "merged_contact_id": str(result.get("mergedContactId") or other_id),
        "kept": preview["kept"],
        "merged_away": preview["merged_away"],
    }
