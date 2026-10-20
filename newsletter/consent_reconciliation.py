"""Reconcile ECP's mirror of Mautic email suppression with live Mautic state.

``MauticEmailSuppression`` is a mirror of Mautic's global email Do Not Contact
state (see its model docstring): its only writers are the Mautic webhook and
the explicit re-subscribe flow, both of which copy Mautic. Webhooks can be
lost (``immediate_process``) or arrive out of order (``command_process``
retries), so the mirror can drift. This module re-reads Mautic and reports —
and on request corrects — that drift.

Consent rules (fail closed):

* Live Mautic is the authority for *delivery suppression* only. The member's
  per-list choices (``NewsletterSubscription``) are ECP consent and are never
  read for, or changed by, reconciliation; nothing here subscribes anyone.
* A correction that adds or strengthens a restriction is safe: create the
  mirror when Mautic has a DNC, escalate an opt-out to a bounce/manual block.
* Nothing is ever lifted here. Mautic reporting no DNC is not evidence of a
  resubscribe: Mautic's contact merge (a known contact submitting a Form
  without a tracking cookie) deleted the merged contact's DNC rows before the
  bridge plugin preserved them, and Mautic keeps no usable history of why a
  DNC disappeared. Legitimate resubscribes clear the mirror through their own
  evidenced paths (a timestamped "contactable" webhook newer than the
  suppression, or ECP's re-subscribe flow). A voluntary opt-out Mautic no
  longer reports is therefore manual review, like a bounce, manual or unknown
  mirror Mautic no longer reports, a reason "downgrade", a contact-id
  conflict, a missing contact and every provider error.
* A mapping whose Mautic contact was merged away still reads the survivor
  (Mautic resolves retired IDs); it is flagged so the identity reconciliation
  (``reconcile_mautic_contact_identities``) can re-point it.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from django.db import transaction
from django.utils import timezone

from .dnc_services import email_dnc_reasons, is_reversible_reason, record_email_suppression
from .mautic import MauticClient
from .mautic.exceptions import PermanentMauticError, TemporaryMauticError
from .mautic_identity_audit import record_identity_audit
from .models import MauticContactMapping, MauticEmailSuppression, MauticIdentityAuditLog

AUDIT_ACTION = "contact.dnc.reconcile"  # plain string, like contact.import.create

# Statuses
IN_SYNC = "in_sync"
MISSING_SUPPRESSION = "missing_suppression"
ESCALATION = "escalation"
STALE_OPT_OUT = "stale_opt_out"
STALE_RESTRICTION = "stale_restriction"
REASON_DOWNGRADE = "reason_downgrade"
REASON_DIFFERS = "reason_differs"
CONTACT_ID_CONFLICT = "contact_id_conflict"
CONTACT_NOT_FOUND = "contact_not_found"
UNMAPPED = "unmapped"
PROVIDER_ERROR = "provider_error"
PROVIDER_INCOMPLETE = "provider_incomplete"
NOT_CHECKED = "not_checked"

# Actions
NONE = "none"
CREATE = "create_suppression"
ESCALATE = "escalate_suppression"
MANUAL_REVIEW = "manual_review"
SKIP = "skip"

#: Only corrections that add or strengthen a restriction are ever applied.
SAFE_ACTIONS = {CREATE, ESCALATE}

#: Most to least restrictive, for picking the mirror reason from several DNCs.
RESTRICTIVE_ORDER = (
    MauticEmailSuppression.Reason.BOUNCED,
    MauticEmailSuppression.Reason.MANUAL,
    MauticEmailSuppression.Reason.UNKNOWN,
)

DEFAULT_LIMIT = 500
MAX_LIMIT = 5000
DEFAULT_BATCH_SIZE = 100
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_SECONDS = 300
DEFAULT_MAX_CONSECUTIVE_ERRORS = 3


class ProviderUnavailable(Exception):
    """Mautic could not give a complete answer; nothing may be concluded."""

    def __init__(self, status: str, detail: str = ""):
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass
class Finding:
    user_id: int
    contact_id: str
    status: str
    action: str
    ecp_reason: str | None = None
    mautic_reasons: list[str] = field(default_factory=list)
    target_reason: str | None = None
    outcome: str = ""
    detail: str = ""
    survivor_contact_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify(ecp_reason: str | None, mautic_reasons: list[str]) -> tuple[str, str, str | None]:
    """``(status, action, target_reason)`` for one linked member. Pure."""
    restrictive = [reason for reason in RESTRICTIVE_ORDER if reason in mautic_reasons]
    if not mautic_reasons:
        if ecp_reason is None:
            return IN_SYNC, NONE, None
        # No DNC is not proof of consent (see module docstring).
        if is_reversible_reason(ecp_reason):
            return STALE_OPT_OUT, MANUAL_REVIEW, None
        return STALE_RESTRICTION, MANUAL_REVIEW, None

    target = restrictive[0] if restrictive else MauticEmailSuppression.Reason.UNSUBSCRIBED
    if ecp_reason is None:
        return MISSING_SUPPRESSION, CREATE, target
    if ecp_reason in mautic_reasons:
        if is_reversible_reason(ecp_reason) and restrictive:
            return ESCALATION, ESCALATE, target
        return IN_SYNC, NONE, None
    if is_reversible_reason(ecp_reason):
        return ESCALATION, ESCALATE, target
    if not restrictive:
        return REASON_DOWNGRADE, MANUAL_REVIEW, None
    # Both block delivery, for different non-reversible reasons.
    return REASON_DIFFERS, MANUAL_REVIEW, None


class Reconciler:
    def __init__(
        self,
        *,
        client: MauticClient | None = None,
        apply: bool = False,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_seconds: float = DEFAULT_MAX_SECONDS,
        max_consecutive_errors: int = DEFAULT_MAX_CONSECUTIVE_ERRORS,
        pause_seconds: float = 0.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.client = client or MauticClient()
        self.apply = apply
        self.timeout = timeout
        self.deadline = clock() + max_seconds
        self.max_consecutive_errors = max_consecutive_errors
        self.pause_seconds = pause_seconds
        self.clock = clock
        self.sleep = sleep
        self.consecutive_errors = 0
        self.stopped_reason = ""
        self.findings: list[Finding] = []
        self.batches = 0
        self.batch_errors: list[dict[str, Any]] = []
        # contact_id -> the ID Mautic answered with (differs after a merge).
        self.answered_ids: dict[str, str] = {}

    # -- provider --------------------------------------------------------------
    def _provider_stopped(self) -> bool:
        if self.stopped_reason:
            return True
        if self.clock() > self.deadline:
            self.stopped_reason = "time budget exhausted"
        elif self.consecutive_errors >= self.max_consecutive_errors:
            self.stopped_reason = f"{self.consecutive_errors} consecutive provider errors"
        return bool(self.stopped_reason)

    def live_reasons(self, contact_id: str) -> list[str]:
        """Email DNC reasons Mautic reports now; ProviderUnavailable otherwise."""
        if self.pause_seconds:
            self.sleep(self.pause_seconds)
        try:
            contact = self.client.get_contact(contact_id, timeout=self.timeout)
        except PermanentMauticError as exc:
            self.consecutive_errors = 0
            if "HTTP 404" in str(exc):
                raise ProviderUnavailable(CONTACT_NOT_FOUND, "Mautic has no such contact") from exc
            raise ProviderUnavailable(PROVIDER_ERROR, f"permanent: {str(exc)[:120]}") from exc
        except TemporaryMauticError as exc:
            self.consecutive_errors += 1
            raise ProviderUnavailable(PROVIDER_ERROR, f"temporary: {str(exc)[:120]}") from exc
        self.consecutive_errors = 0
        if not isinstance(contact, dict) or not isinstance(contact.get("doNotContact"), list):
            raise ProviderUnavailable(PROVIDER_INCOMPLETE, "contact has no doNotContact list")
        self.answered_ids[str(contact_id)] = str(contact.get("id") or "")
        return sorted(set(email_dnc_reasons(contact)))

    # -- scope -----------------------------------------------------------------
    def run(self, *, limit: int = DEFAULT_LIMIT, batch_size: int = DEFAULT_BATCH_SIZE,
            after_id: int = 0, user_ids: list[int] | None = None) -> dict[str, Any]:
        limit = max(1, min(int(limit), MAX_LIMIT))
        batch_size = max(1, min(int(batch_size), 500))
        mappings = MauticContactMapping.objects.filter(pk__gt=after_id).order_by("pk")
        if user_ids:
            mappings = mappings.filter(user_id__in=user_ids)
        selected = list(mappings.values_list("pk", "user_id", "mautic_contact_id")[:limit])
        last_id = after_id
        for start in range(0, len(selected), batch_size):
            batch = selected[start:start + batch_size]
            self.batches += 1
            try:
                self._run_batch(batch)
            except Exception as exc:  # noqa: BLE001 - one bad batch must not stop the report
                self.batch_errors.append({"batch": self.batches, "error": type(exc).__name__})
            last_id = batch[-1][0]

        # Suppressions with no mapping: reported, never resolved by assumption.
        unmapped = MauticEmailSuppression.objects.filter(user__mautic_contact_mapping__isnull=True)
        if user_ids:
            unmapped = unmapped.filter(user_id__in=user_ids)
        for row in unmapped.order_by("user_id")[:limit]:
            self.findings.append(Finding(
                user_id=row.user_id, contact_id=str(row.mautic_contact_id or ""), status=UNMAPPED,
                action=MANUAL_REVIEW, ecp_reason=row.reason,
                detail="suppression without an ECP-Mautic mapping",
            ))
        return self.summary(next_after_id=last_id if len(selected) == limit else None)

    def _run_batch(self, batch):
        suppressions = {
            row.user_id: row
            for row in MauticEmailSuppression.objects.filter(user_id__in=[user_id for _, user_id, _ in batch])
        }
        for _, user_id, contact_id in batch:
            contact_id = str(contact_id or "").strip()
            row = suppressions.get(user_id)
            ecp_reason = row.reason if row else None
            if row and row.mautic_contact_id and str(row.mautic_contact_id) != contact_id:
                self.findings.append(Finding(user_id, contact_id, CONTACT_ID_CONFLICT, MANUAL_REVIEW, ecp_reason,
                                             detail="suppression and mapping name different Mautic contacts"))
                continue
            if self._provider_stopped():
                self.findings.append(Finding(user_id, contact_id, NOT_CHECKED, SKIP, ecp_reason,
                                             detail=self.stopped_reason))
                continue
            try:
                reasons = self.live_reasons(contact_id)
            except ProviderUnavailable as exc:
                action = MANUAL_REVIEW if exc.status == CONTACT_NOT_FOUND else SKIP
                self.findings.append(Finding(user_id, contact_id, exc.status, action, ecp_reason, detail=exc.detail))
                continue
            status, action, target = classify(ecp_reason, reasons)
            finding = Finding(user_id, contact_id, status, action, ecp_reason, reasons, target)
            survivor = self.answered_ids.get(contact_id, "")
            if survivor and survivor != contact_id:
                finding.survivor_contact_id = survivor
                finding.detail = ("Mautic merged this contact into another; its retired ID resolves to the "
                                  "survivor. Run reconcile_mautic_contact_identities.")
            if self.apply and action in SAFE_ACTIONS:
                self._apply(finding, row)
            self.findings.append(finding)

    # -- corrections -------------------------------------------------------------
    def _snapshot(self, row):
        return None if row is None else (row.reason, row.suppressed_at, row.updated_at)

    def _apply(self, finding: Finding, row) -> None:
        before = self._snapshot(row)
        try:
            if finding.action in (CREATE, ESCALATE):
                self._strengthen(finding, before)
        except Exception as exc:  # noqa: BLE001 - reported per record
            finding.outcome = "failed"
            finding.detail = type(exc).__name__
            self._audit(finding, MauticIdentityAuditLog.Status.FAILED)

    def _strengthen(self, finding: Finding, before) -> None:
        with transaction.atomic():
            current = MauticEmailSuppression.objects.select_for_update().filter(user_id=finding.user_id).first()
            if self._snapshot(current) != before:
                finding.outcome = "skipped_concurrent_change"
                return
            user = MauticContactMapping.objects.select_related("user").get(user_id=finding.user_id).user
            record_email_suppression(
                user,
                finding.target_reason,
                mautic_contact_id=finding.contact_id,
                comments="reconciled from live Mautic DNC",
                occurred_at=timezone.now(),
            )
        finding.outcome = "applied"
        self._audit(finding, MauticIdentityAuditLog.Status.SUCCEEDED)

    def _audit(self, finding: Finding, status, extra: str = "") -> None:
        detail = (f"{finding.action}: ecp={finding.ecp_reason or 'none'} "
                  f"mautic={','.join(finding.mautic_reasons) or 'none'} {extra}").strip()
        record_identity_audit(
            action=AUDIT_ACTION,
            status=status,
            actor=None,
            resource="email_suppression",
            resource_id=str(finding.user_id),
            auth_mode="service_account",
            detail=detail[:255],
        )

    # -- report ------------------------------------------------------------------
    def summary(self, *, next_after_id=None) -> dict[str, Any]:
        counts: dict[str, int] = {}
        actions: dict[str, int] = {}
        outcomes: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.status] = counts.get(finding.status, 0) + 1
            actions[finding.action] = actions.get(finding.action, 0) + 1
            if finding.outcome:
                outcomes[finding.outcome] = outcomes.get(finding.outcome, 0) + 1
        return {
            "mode": "apply" if self.apply else "read-only",
            "checked": len(self.findings),
            "batches": self.batches,
            "statuses": counts,
            "actions": actions,
            "outcomes": outcomes,
            "batch_errors": self.batch_errors,
            "provider_stopped": self.stopped_reason,
            "next_after_id": next_after_id,
        }
