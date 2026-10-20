"""Keep ECP's member -> Mautic contact links pointing at live Mautic contacts.

Mautic merges contacts (for example a known contact submitting a Form without
a tracking cookie is merged into the new anonymous contact). The merged-away
contact is deleted and its ID retired; Mautic records the merge
(``contact_merge_records``) and answers any later read of the retired ID with
the surviving contact. ECP's ``MauticContactMapping`` still names the retired
ID, so webhooks about the survivor (which carry the survivor's ID) no longer
match the member.

This module re-points such a link only on provider evidence: Mautic itself
answered the mapped ID with a different contact. Matching emails alone are
never treated as proof. A link is changed only when:

* Mautic resolves the mapped ID to a different contact (a recorded merge);
* that survivor carries the member's own email address;
* no other ECP member is linked to the survivor;
* a second read just before the change still resolves to the same survivor;
* the link did not change since it was read (compare-and-swap).

Everything else (contact gone, provider errors, email mismatch, a survivor
already linked to someone else) is reported for manual review and never
changed. Read-only unless ``apply``. Nothing here touches consent or
subscriptions; the member's suppression row only has its informational
contact ID re-pointed alongside the link.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from django.db import IntegrityError, transaction

from .mautic import MauticClient
from .mautic.exceptions import PermanentMauticError, TemporaryMauticError
from .mautic_identity_audit import record_identity_audit
from .models import MauticContactMapping, MauticEmailSuppression, MauticIdentityAuditLog

AUDIT_ACTION = "contact.mapping.remap"  # plain string, like contact.dnc.reconcile

CURRENT = "current"
MERGED = "merged"
EMAIL_MISMATCH = "email_mismatch"
SURVIVOR_LINKED_ELSEWHERE = "survivor_linked_elsewhere"
CONTACT_NOT_FOUND = "contact_not_found"
PROVIDER_ERROR = "provider_error"

NONE = "none"
REMAP = "remap"
MANUAL_REVIEW = "manual_review"
SKIP = "skip"

DEFAULT_LIMIT = 500
MAX_LIMIT = 5000


@dataclass
class IdentityFinding:
    user_id: int
    mapped_contact_id: str
    status: str
    action: str
    survivor_contact_id: str = ""
    outcome: str = ""
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalized(value) -> str:
    return str(value or "").strip().lower()


def contact_email(contact: dict[str, Any]) -> str:
    fields = contact.get("fields") if isinstance(contact.get("fields"), dict) else {}
    flat = fields.get("all") if isinstance(fields.get("all"), dict) else {}
    if flat.get("email"):
        return _normalized(flat["email"])
    core = fields.get("core") if isinstance(fields.get("core"), dict) else {}
    email = core.get("email")
    return _normalized(email.get("value") if isinstance(email, dict) else email)


class IdentityReconciler:
    def __init__(self, *, client: MauticClient | None = None, apply: bool = False, timeout: float = 10):
        self.client = client or MauticClient()
        self.apply = apply
        self.timeout = timeout
        self.findings: list[IdentityFinding] = []

    def _resolve(self, contact_id: str) -> tuple[str, dict[str, Any]]:
        contact = self.client.get_contact(contact_id, timeout=self.timeout)
        return str(contact.get("id") or ""), contact

    def check(self, mapping: MauticContactMapping) -> IdentityFinding:
        mapped = str(mapping.mautic_contact_id or "").strip()
        try:
            survivor, contact = self._resolve(mapped)
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                return IdentityFinding(mapping.user_id, mapped, CONTACT_NOT_FOUND, MANUAL_REVIEW,
                                       detail="Mautic has no contact for this ID and no merge record")
            return IdentityFinding(mapping.user_id, mapped, PROVIDER_ERROR, SKIP, detail=str(exc)[:120])
        except TemporaryMauticError as exc:
            return IdentityFinding(mapping.user_id, mapped, PROVIDER_ERROR, SKIP, detail=str(exc)[:120])

        if not survivor:
            return IdentityFinding(mapping.user_id, mapped, PROVIDER_ERROR, SKIP, detail="contact without an ID")
        if survivor == mapped:
            return IdentityFinding(mapping.user_id, mapped, CURRENT, NONE)

        finding = IdentityFinding(mapping.user_id, mapped, MERGED, REMAP, survivor_contact_id=survivor)
        member_email = _normalized(getattr(mapping.user, "email", ""))
        if not member_email or contact_email(contact) != member_email:
            finding.status, finding.action = EMAIL_MISMATCH, MANUAL_REVIEW
            finding.detail = "the surviving contact does not carry the member's email"
        elif MauticContactMapping.objects.filter(mautic_contact_id=survivor).exclude(pk=mapping.pk).exists():
            finding.status, finding.action = SURVIVOR_LINKED_ELSEWHERE, MANUAL_REVIEW
            finding.detail = "the surviving contact is already linked to another ECP member"
        return finding

    def run(self, *, limit: int = DEFAULT_LIMIT, user_ids: list[int] | None = None) -> dict[str, Any]:
        mappings = MauticContactMapping.objects.select_related("user").order_by("pk")
        if user_ids:
            mappings = mappings.filter(user_id__in=user_ids)
        for mapping in mappings[: max(1, min(int(limit), MAX_LIMIT))]:
            finding = self.check(mapping)
            if self.apply and finding.action == REMAP:
                self._remap(mapping, finding)
            self.findings.append(finding)
        return self.summary()

    def _remap(self, mapping: MauticContactMapping, finding: IdentityFinding) -> None:
        old, new = finding.mapped_contact_id, finding.survivor_contact_id
        try:
            # The provider must still say the same thing just before the change.
            again, _ = self._resolve(old)
        except (PermanentMauticError, TemporaryMauticError) as exc:
            finding.outcome, finding.detail = "skipped_provider_unavailable", str(exc)[:120]
            return
        if again != new:
            finding.outcome, finding.detail = "skipped_provider_changed", f"now resolves to {again}"
            return
        try:
            with transaction.atomic():
                current = MauticContactMapping.objects.select_for_update().filter(pk=mapping.pk).first()
                if current is None or str(current.mautic_contact_id) != old:
                    finding.outcome = "skipped_concurrent_change"
                    return
                if MauticContactMapping.objects.filter(mautic_contact_id=new).exclude(pk=mapping.pk).exists():
                    finding.status, finding.action = SURVIVOR_LINKED_ELSEWHERE, MANUAL_REVIEW
                    finding.outcome = "skipped_conflict"
                    return
                MauticContactMapping.objects.filter(pk=mapping.pk, mautic_contact_id=old).update(mautic_contact_id=new)
                MauticEmailSuppression.objects.filter(user_id=mapping.user_id, mautic_contact_id=old).update(
                    mautic_contact_id=new)
        except IntegrityError:
            finding.status, finding.action, finding.outcome = SURVIVOR_LINKED_ELSEWHERE, MANUAL_REVIEW, "skipped_conflict"
            return
        finding.outcome = "applied"
        record_identity_audit(
            action=AUDIT_ACTION,
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            actor=None,
            resource="contact_mapping",
            resource_id=f"{old}->{new}"[:64],
            auth_mode="service_account",
            detail=f"user {mapping.user_id}: Mautic merged contact {old} into {new}",
        )

    def summary(self) -> dict[str, Any]:
        statuses: dict[str, int] = {}
        outcomes: dict[str, int] = {}
        for finding in self.findings:
            statuses[finding.status] = statuses.get(finding.status, 0) + 1
            if finding.outcome:
                outcomes[finding.outcome] = outcomes.get(finding.outcome, 0) + 1
        return {
            "mode": "apply" if self.apply else "read-only",
            "checked": len(self.findings),
            "statuses": statuses,
            "outcomes": outcomes,
        }
