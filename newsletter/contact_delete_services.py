"""Bulk delete of Mautic contacts from the Marketing Hub.

Two steps, never one:

1. *Prepare* resolves the request (selected contact IDs, or a CSV of email
   addresses matched exactly) into a server-side deletion plan: an expiring
   cache entry owned by one administrator that lists the exact contact IDs.
   Nothing is deleted while preparing. The browser only ever gets the plan ID
   and a summary, so it cannot change the targets.
2. *Execute* deletes the plan in batches of BATCH_SIZE. Each batch re-checks
   every target against Mautic and ECP first, deletes the ones still eligible
   through Mautic's native batch delete (as the administrator's own Mautic user
   when per-user execution is on), then looks the IDs up again to count what
   was really deleted. A repeated or retried call can therefore only finish
   the same plan, never touch another contact.

Protected contacts are never put in a plan and are re-checked before deletion:

* linked to an ECP account (MauticContactMapping), or whose email belongs to
  an ECP user: ECP's newsletter sync owns those and would recreate them;
* with any Do Not Contact record: Mautic deletes DNC rows with the contact, so
  deleting would silently lift the suppression if the address came back;
* (CSV) an email matching more than one contact: ambiguous, nothing is chosen.

No ECP user, subscription or other ECP record is deleted. Nothing here logs
email addresses.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import time
from typing import Any

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db.models.functions import Lower

from .contact_import_services import ParsedCsv
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .models import MauticContactMapping

logger = logging.getLogger(__name__)

BATCH_SIZE = 100
LOOKUP_BATCH_SIZE = 5000
MAX_SELECTED = 5000
PLAN_TTL_SECONDS = 30 * 60
RESULT_TTL_SECONDS = 24 * 60 * 60
LOCK_SECONDS = 120
SAMPLE_SIZE = 25
FAILURE_LIMIT = 200
CACHE_PREFIX = "newsletter:contact-delete"
EMAIL_HEADER_KEYS = ("email", "emailaddress", "mail")

PROTECTED_REASONS = {
    "linked_ecp_account": "Linked to an ECP account",
    "ecp_account_email": "Email belongs to an ECP account",
    "do_not_contact": "Has a Do Not Contact record (deleting would remove the suppression)",
    "ambiguous_email": "Email matches more than one Mautic contact",
}
SKIP_REASONS = {
    **PROTECTED_REASONS,
    "email_changed": "Email changed since the deletion was prepared",
}

STATES_ACTIVE = ("ready", "running")


class ContactDeleteError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid", status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


def client_for_reads() -> MauticClient:
    return MauticClient()


# ---------------------------------------------------------------- storage --


def _plan_key(plan_id: str) -> str:
    return f"{CACHE_PREFIX}:plan:{plan_id}"


def _save(plan: dict[str, Any], ttl: int) -> None:
    plan["expires_at"] = int(time.time()) + ttl
    try:
        cache.set(_plan_key(plan["plan_id"]), json.dumps(plan), ttl)
    except Exception:
        raise ContactDeleteError(
            "Deletion plans cannot be stored right now. Nothing was deleted.",
            code="storage_unavailable",
            status=503,
        ) from None


def load_plan(user, plan_id: str) -> dict[str, Any]:
    """The plan, only for its owner. Unknown, expired and foreign plans all
    give the same 404."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", str(plan_id or "")):
        raise ContactDeleteError("Deletion plan not found.", code="not_found", status=404)
    try:
        raw = cache.get(_plan_key(plan_id))
    except Exception:
        raw = None
    plan = json.loads(raw) if raw else None
    if not plan or plan.get("owner") != user.pk:
        raise ContactDeleteError(
            "Deletion plan not found or expired. Prepare the deletion again.",
            code="not_found",
            status=404,
        )
    return plan


# -------------------------------------------------------------- protection --


def _chunks(items, size):
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _lookup_ids(client, ids: list[int]) -> dict[int, dict[str, Any]]:
    found: dict[int, dict[str, Any]] = {}
    for chunk in _chunks(ids, LOOKUP_BATCH_SIZE):
        for key, value in client.lookup_contacts_by_id(chunk).items():
            found[int(key)] = value
    return found


def _ecp_protection(ids: list[int], emails: set[str]) -> tuple[set[int], set[str]]:
    """IDs mapped to ECP users, and which of `emails` belong to ECP users."""
    mapped: set[int] = set()
    for chunk in _chunks([str(i) for i in ids], LOOKUP_BATCH_SIZE):
        mapped.update(
            int(value)
            for value in MauticContactMapping.objects.filter(mautic_contact_id__in=chunk).values_list(
                "mautic_contact_id", flat=True
            )
            if str(value).isdigit()
        )
    user_emails: set[str] = set()
    email_list = sorted(emails)
    for chunk in _chunks(email_list, LOOKUP_BATCH_SIZE):
        user_emails.update(
            get_user_model()
            .objects.annotate(email_lower=Lower("email"))
            .filter(email_lower__in=chunk)
            .values_list("email_lower", flat=True)
        )
    return mapped, user_emails


def _protection_reason(contact_id: int, contact: dict[str, Any], mapped: set[int], user_emails: set[str]) -> str:
    if contact_id in mapped:
        return "linked_ecp_account"
    if str(contact.get("email") or "").strip().lower() in user_emails:
        return "ecp_account_email"
    if contact.get("dnc"):
        return "do_not_contact"
    return ""


def _classify(client, ids: list[int]) -> tuple[list[dict], dict[int, str], list[int], dict[int, dict]]:
    """Split IDs into deletable targets, protected {id: reason} and not found."""
    found = _lookup_ids(client, ids)
    emails = {str(c.get("email") or "").strip().lower() for c in found.values()} - {""}
    mapped, user_emails = _ecp_protection(list(found), emails)
    targets, protected, missing = [], {}, []
    for contact_id in ids:
        contact = found.get(contact_id)
        if contact is None:
            missing.append(contact_id)
            continue
        reason = _protection_reason(contact_id, contact, mapped, user_emails)
        if reason:
            protected[contact_id] = reason
        else:
            targets.append(
                {
                    "id": contact_id,
                    "email": str(contact.get("email") or "").strip().lower(),
                    "campaigns": int(contact.get("campaigns") or 0),
                }
            )
    return targets, protected, missing, found


# ----------------------------------------------------------------- prepare --


def _normalize_ids(raw) -> list[int]:
    if not isinstance(raw, list) or not raw:
        raise ContactDeleteError("Select at least one contact.", code="no_contacts")
    ids: dict[int, None] = {}
    for value in raw:
        text = str(value).strip()
        if not text.isdigit() or int(text) <= 0:
            raise ContactDeleteError("Contact IDs must be positive integers.", code="invalid_ids")
        ids[int(text)] = None
    if len(ids) > MAX_SELECTED:
        raise ContactDeleteError(
            f"At most {MAX_SELECTED:,} contacts can be selected for one deletion. Use Bulk Delete by CSV for more.",
            code="too_many_contacts",
        )
    return list(ids)


def _new_plan(user, mode: str, summary: dict, targets: list[dict], samples: dict, file_name: str = "") -> dict:
    plan = {
        "v": 1,
        "plan_id": secrets.token_urlsafe(18),
        "owner": user.pk,
        "mode": mode,
        "file_name": file_name,
        "state": "ready" if targets else "empty",
        "created_at": int(time.time()),
        "targets": targets,
        # Bound to the exact IDs: confirmation must repeat their count, and the
        # digest shows the target list never changed.
        "targets_digest": hashlib.sha256(",".join(str(t["id"]) for t in targets).encode()).hexdigest(),
        "cursor": 0,
        "summary": summary,
        "samples": samples,
        "results": {"deleted": 0, "already_gone": 0, "failed": 0, "skipped": {}},
        "failures": [],
    }
    _save(plan, PLAN_TTL_SECONDS)
    return plan


def _samples(targets, excluded) -> dict:
    return {
        "deletable": [{"id": t["id"], "email": t["email"], "campaigns": t["campaigns"]} for t in targets[:SAMPLE_SIZE]],
        "excluded": excluded[: SAMPLE_SIZE * 2],
    }


def prepare_selected(user, contact_ids, *, client=None) -> dict:
    ids = _normalize_ids(contact_ids)
    client = client or client_for_reads()
    targets, protected, missing, found = _classify(client, ids)
    excluded = [
        {"id": i, "email": str(found[i].get("email") or ""), "reason": r, "label": PROTECTED_REASONS[r]}
        for i, r in protected.items()
    ] + [{"id": i, "email": "", "reason": "not_found", "label": "No longer exists in Mautic"} for i in missing]
    summary = {
        "requested": len(ids),
        "deletable": len(targets),
        "protected": _count_reasons(protected.values()),
        "not_found": len(missing),
        "in_campaigns": sum(1 for t in targets if t["campaigns"]),
    }
    return _new_plan(user, "selected", summary, targets, _samples(targets, excluded))


def _count_reasons(reasons) -> dict[str, int]:
    counts: dict[str, int] = {}
    for reason in reasons:
        counts[reason] = counts.get(reason, 0) + 1
    return counts


def _email_column(parsed: ParsedCsv, requested: str = "") -> str:
    if requested:
        if requested not in parsed.headers:
            raise ContactDeleteError(f"'{requested}' is not a column in the file.", code="unknown_column")
        return requested
    keys = {re.sub(r"[^a-z0-9]", "", header.lower()): header for header in parsed.headers}
    for key in EMAIL_HEADER_KEYS:
        if key in keys:
            return keys[key]
    raise ContactDeleteError(
        "No Email column was found. Deletion by CSV only matches email addresses.",
        code="email_column_required",
    )


def prepare_csv(user, parsed: ParsedCsv, *, email_column: str = "", client=None) -> dict:
    column = _email_column(parsed, email_column)
    index = parsed.headers.index(column)
    client = client or client_for_reads()

    invalid: list[dict] = []
    duplicate_rows = 0
    first_row: dict[str, int] = {}
    data_rows = 0
    for row_number, cells in parsed.rows:
        if not cells:
            continue
        data_rows += 1
        value = cells[index].strip() if index < len(cells) else ""
        if not value:
            invalid.append({"row": row_number, "reason": "missing_email", "label": "No email address"})
            continue
        try:
            validate_email(value)
        except ValidationError:
            invalid.append({"row": row_number, "reason": "invalid_email", "label": "Not a valid email address"})
            continue
        key = value.lower()
        if key in first_row:
            duplicate_rows += 1
            continue
        first_row[key] = row_number

    emails = list(first_row)
    matches: dict[str, dict] = {}
    for chunk in _chunks(emails, LOOKUP_BATCH_SIZE):
        for email, match in client.lookup_contact_emails(chunk).items():
            matches[str(email).lower()] = match

    ambiguous = [e for e in emails if len((matches.get(e) or {}).get("contact_ids") or []) > 1]
    unmatched = [e for e in emails if not (matches.get(e) or {}).get("contact_ids")]
    single = {int(matches[e]["contact_ids"][0]): e for e in emails if len((matches.get(e) or {}).get("contact_ids") or []) == 1}

    targets, protected, missing, found = _classify(client, list(single))
    # The contact must still carry the email that matched it.
    targets = [t for t in targets if t["email"] == single[t["id"]]]

    excluded = (
        [{"row": first_row[e], "email": e, "reason": "ambiguous_email", "label": PROTECTED_REASONS["ambiguous_email"]} for e in ambiguous]
        + [{"row": first_row[single[i]], "email": single[i], "reason": r, "label": PROTECTED_REASONS[r]} for i, r in protected.items()]
        + [{"row": first_row[e], "email": e, "reason": "unmatched", "label": "No Mautic contact with this email"} for e in unmatched[:SAMPLE_SIZE]]
        + invalid[:SAMPLE_SIZE]
    )
    protected_counts = _count_reasons(protected.values())
    if ambiguous:
        protected_counts["ambiguous_email"] = len(ambiguous)
    summary = {
        "requested": data_rows,
        "deletable": len(targets),
        "protected": protected_counts,
        "not_found": len(unmatched) + len(missing),
        "invalid": len(invalid),
        "duplicate": duplicate_rows,
        "in_campaigns": sum(1 for t in targets if t["campaigns"]),
        "email_column": column,
    }
    return _new_plan(user, "csv", summary, targets, _samples(targets, excluded), parsed.filename)


# ----------------------------------------------------------------- execute --


def _lock(plan_id: str) -> bool:
    try:
        return bool(cache.add(f"{CACHE_PREFIX}:lock:{plan_id}", 1, LOCK_SECONDS))
    except Exception:
        raise ContactDeleteError(
            "Deletion cannot run right now. Nothing was deleted.", code="storage_unavailable", status=503
        ) from None


def _unlock(plan_id: str) -> None:
    try:
        cache.delete(f"{CACHE_PREFIX}:lock:{plan_id}")
    except Exception:
        pass


def execute_next_batch(user, plan_id: str, confirm_count, *, run_delete, client=None) -> tuple[dict, Any]:
    """Delete the next batch of a confirmed plan.

    ``run_delete(ids)`` performs the provider delete (as the acting user) and
    returns ``(result, identity_response)``; a non-None identity response
    stops the batch unchanged.
    """
    if not _lock(plan_id):
        raise ContactDeleteError("This deletion is already running a batch.", code="busy", status=409)
    try:
        plan = load_plan(user, plan_id)
        if plan["state"] not in STATES_ACTIVE:
            return plan, None
        expected = plan["summary"]["deletable"]
        if str(confirm_count).strip() != str(expected):
            raise ContactDeleteError(
                f"Type the exact number of contacts to delete ({expected:,}) to confirm.",
                code="confirmation_required",
            )
        digest = hashlib.sha256(",".join(str(t["id"]) for t in plan["targets"]).encode()).hexdigest()
        if digest != plan["targets_digest"]:
            raise ContactDeleteError("The deletion plan was altered. Nothing was deleted.", code="plan_invalid", status=409)

        plan["state"] = "running"
        plan.setdefault("started_at", int(time.time()))
        batch = plan["targets"][plan["cursor"] : plan["cursor"] + BATCH_SIZE]
        client = client or client_for_reads()
        results = plan["results"]

        # Re-check every target right before deleting it.
        ids = [t["id"] for t in batch]
        current = _lookup_ids(client, ids)
        emails = {str(c.get("email") or "").strip().lower() for c in current.values()} - {""}
        mapped, user_emails = _ecp_protection(list(current), emails)
        to_delete = []
        for target in batch:
            contact = current.get(target["id"])
            if contact is None:
                results["already_gone"] += 1
                continue
            reason = _protection_reason(target["id"], contact, mapped, user_emails)
            if not reason and str(contact.get("email") or "").strip().lower() != target["email"]:
                reason = "email_changed"
            if reason:
                results["skipped"][reason] = results["skipped"].get(reason, 0) + 1
                continue
            to_delete.append(target["id"])

        if to_delete:
            outcome, identity_response = run_delete(to_delete)
            if identity_response is not None:
                _save(plan, RESULT_TTL_SECONDS)
                return plan, identity_response
            remaining = _lookup_ids(client, to_delete)
            for contact_id in to_delete:
                if contact_id in remaining:
                    results["failed"] += 1
                    if len(plan["failures"]) < FAILURE_LIMIT:
                        plan["failures"].append({"id": contact_id, "reason": "not_deleted", "label": "Mautic did not delete this contact"})
                else:
                    results["deleted"] += 1

        plan["cursor"] += len(batch)
        if plan["cursor"] >= len(plan["targets"]):
            plan["state"] = "completed_with_errors" if results["failed"] else "completed"
            plan["finished_at"] = int(time.time())
        _save(plan, RESULT_TTL_SECONDS)
        logger.info(
            "Contact bulk delete batch",
            extra={
                "ecp_user_id": user.pk,
                "plan": plan_id[:8],
                "batch": len(batch),
                "deleted_total": results["deleted"],
                "failed_total": results["failed"],
                "state": plan["state"],
            },
        )
        return plan, None
    finally:
        _unlock(plan_id)


def cancel(user, plan_id: str) -> dict:
    if not _lock(plan_id):
        raise ContactDeleteError("A batch is running; try again in a moment.", code="busy", status=409)
    try:
        plan = load_plan(user, plan_id)
        if plan["state"] in STATES_ACTIVE:
            plan["state"] = "cancelled"
            plan["finished_at"] = int(time.time())
            _save(plan, RESULT_TTL_SECONDS)
        return plan
    finally:
        _unlock(plan_id)


def plan_payload(plan: dict) -> dict:
    """What the browser sees: never the full target list."""
    results = plan["results"]
    total = len(plan["targets"])
    processed = min(plan["cursor"], total)
    return {
        "plan_id": plan["plan_id"],
        "mode": plan["mode"],
        "file_name": plan.get("file_name", ""),
        "state": plan["state"],
        "expires_at": plan.get("expires_at"),
        "summary": plan["summary"],
        "samples": plan["samples"],
        "progress": {
            "total": total,
            "processed": processed,
            "remaining": total - processed,
            "percentage": round(processed / total * 100, 1) if total else 100.0,
        },
        "results": {
            **results,
            "skipped_labels": {key: SKIP_REASONS.get(key, key) for key in results["skipped"]},
        },
        "failures": plan["failures"][:50],
    }
