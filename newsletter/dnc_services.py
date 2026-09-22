"""Mautic email Do Not Contact classification and ECP reconciliation.

Mautic owns delivery suppression; ECP owns consent. This module is the single
place where the two are compared, so the safety rules live in one readable
spot rather than being re-derived at each call site.

Reason mapping follows Mautic\\LeadBundle\\Entity\\DoNotContact in the running
7.1.3 runtime:

    0 IS_CONTACTABLE   no suppression
    1 UNSUBSCRIBED     the member opted out themselves  -> reversible
    2 BOUNCED          delivery failed                  -> never auto-cleared
    3 MANUAL           staff/system suppression         -> never auto-cleared

Mautic 7.1.3 has no distinct complaint/abuse reason: a spam complaint arrives
as BOUNCED or MANUAL depending on how it was processed, and both are already
treated as non-reversible. Anything Mautic reports that is not one of the
constants above is classified UNKNOWN and treated as non-reversible, so a
future Mautic version that adds a reason fails closed rather than open.
"""

from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from .mautic import MauticClient, MauticError
from .models import MauticContactMapping, MauticEmailSuppression


logger = logging.getLogger(__name__)


EMAIL_CHANNEL = "email"

#: Mautic DoNotContact reason constants -> ECP canonical reason.
MAUTIC_DNC_REASON_BY_ID = {
    1: MauticEmailSuppression.Reason.UNSUBSCRIBED,
    2: MauticEmailSuppression.Reason.BOUNCED,
    3: MauticEmailSuppression.Reason.MANUAL,
}

#: Verbs Mautic emits on the channel-subscription webhook
#: (ChannelSubscriptionChange::getDncReasonVerb) plus the spellings the
#: existing ECP synthetic payloads use.
MAUTIC_DNC_REASON_BY_VERB = {
    "unsubscribed": MauticEmailSuppression.Reason.UNSUBSCRIBED,
    "unsubscribe": MauticEmailSuppression.Reason.UNSUBSCRIBED,
    "bounced": MauticEmailSuppression.Reason.BOUNCED,
    "bounce": MauticEmailSuppression.Reason.BOUNCED,
    "hard_bounce": MauticEmailSuppression.Reason.BOUNCED,
    "hard-bounce": MauticEmailSuppression.Reason.BOUNCED,
    "hard bounce": MauticEmailSuppression.Reason.BOUNCED,
    "soft_bounce": MauticEmailSuppression.Reason.BOUNCED,
    "soft-bounce": MauticEmailSuppression.Reason.BOUNCED,
    "soft bounce": MauticEmailSuppression.Reason.BOUNCED,
    "manual": MauticEmailSuppression.Reason.MANUAL,
}

#: The only reason an explicit ECP re-subscribe may clear.
REVERSIBLE_REASONS = frozenset({MauticEmailSuppression.Reason.UNSUBSCRIBED})

#: Verb Mautic uses when a contact is contactable again.
CONTACTABLE_VERB = "contactable"


def classify_dnc_reason(value) -> str:
    """Return the canonical ECP reason for one Mautic DNC reason value.

    Accepts Mautic's numeric constant or its verb. Anything unrecognised is
    UNKNOWN, which is deliberately non-reversible.
    """
    if isinstance(value, bool):
        return MauticEmailSuppression.Reason.UNKNOWN

    if isinstance(value, int):
        return MAUTIC_DNC_REASON_BY_ID.get(
            value,
            MauticEmailSuppression.Reason.UNKNOWN,
        )

    normalized = str(value or "").strip().lower()
    if not normalized:
        return MauticEmailSuppression.Reason.UNKNOWN

    if normalized.isdigit():
        return MAUTIC_DNC_REASON_BY_ID.get(
            int(normalized),
            MauticEmailSuppression.Reason.UNKNOWN,
        )

    return MAUTIC_DNC_REASON_BY_VERB.get(
        normalized,
        MauticEmailSuppression.Reason.UNKNOWN,
    )


def is_reversible_reason(reason: str) -> bool:
    return reason in REVERSIBLE_REASONS


def _dnc_entries(contact: dict) -> list[dict]:
    raw = (
        contact.get("doNotContact")
        or contact.get("do_not_contact")
        or contact.get("dnc")
        or []
    )
    if isinstance(raw, dict):
        candidates = raw.values()
    elif isinstance(raw, list):
        candidates = raw
    else:
        return []
    return [entry for entry in candidates if isinstance(entry, dict)]


def email_dnc_reasons(contact: dict) -> list[str]:
    """Return canonical reasons for every email-channel DNC record on a contact.

    A contact may legitimately carry several records at once — Mautic's own
    source notes that some integrations set both unsubscribed and bounced — so
    this returns all of them rather than a single verdict.
    """
    if not isinstance(contact, dict):
        return []

    reasons = []
    for entry in _dnc_entries(contact):
        channel = str(
            entry.get("channel") or entry.get("channelName") or ""
        ).strip().lower()
        if channel and channel != EMAIL_CHANNEL:
            continue
        if not channel:
            # A record with no channel cannot be proven to be email-only.
            continue
        reasons.append(classify_dnc_reason(entry.get("reason")))
    return reasons


def suppression_state(user) -> dict:
    """Public read model for one user's Mautic email suppression."""
    suppression = MauticEmailSuppression.objects.filter(user=user).first()
    if suppression is None:
        return {
            "suppressed": False,
            "reason": "",
            "reversible": False,
            "suppressed_at": None,
        }
    return {
        "suppressed": True,
        "reason": suppression.reason,
        "reversible": suppression.is_reversible,
        "suppressed_at": suppression.suppressed_at,
    }


def is_suppressed(user) -> bool:
    return MauticEmailSuppression.objects.filter(user=user).exists()


def record_email_suppression(
    user,
    reason: str,
    *,
    mautic_contact_id: str = "",
    comments: str = "",
    occurred_at=None,
) -> MauticEmailSuppression:
    """Upsert the single suppression row for a user.

    State-based rather than event-based, so replaying the same Mautic event any
    number of times converges on one row with the same values. A non-reversible
    reason is never downgraded to a reversible one by a later event: if Mautic
    reports both a bounce and an unsubscribe over time, the bounce wins.
    """
    occurred_at = occurred_at or timezone.now()
    reason = reason or MauticEmailSuppression.Reason.UNKNOWN

    with transaction.atomic():
        suppression = (
            MauticEmailSuppression.objects.select_for_update()
            .filter(user=user)
            .first()
        )
        if suppression is None:
            return MauticEmailSuppression.objects.create(
                user=user,
                reason=reason,
                mautic_contact_id=str(mautic_contact_id or "")[:64],
                comments=str(comments or "")[:255],
                suppressed_at=occurred_at,
            )

        update_fields = ["updated_at"]
        if suppression.is_reversible and not is_reversible_reason(reason):
            # Escalate: a bounce or manual block outranks a voluntary opt-out.
            suppression.reason = reason
            suppression.suppressed_at = occurred_at
            update_fields += ["reason", "suppressed_at"]
            if comments:
                suppression.comments = str(comments)[:255]
                update_fields.append("comments")

        if mautic_contact_id and not suppression.mautic_contact_id:
            suppression.mautic_contact_id = str(mautic_contact_id)[:64]
            update_fields.append("mautic_contact_id")

        suppression.save(update_fields=update_fields)
        return suppression


def clear_email_suppression(user) -> bool:
    """Drop the suppression row. Returns True when a row was removed."""
    deleted, _ = MauticEmailSuppression.objects.filter(user=user).delete()
    return bool(deleted)


class SuppressionReconciliation:
    """Outcome of comparing ECP consent with live Mautic DNC state.

    ``cleared``  the voluntary opt-out was removed in Mautic; delivery resumes.
    ``blocked``  a non-reversible suppression remains; delivery stays blocked.
    ``unknown``  Mautic could not be reached, so nothing may be claimed.
    """

    CLEARED = "cleared"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"
    NOT_SUPPRESSED = "not_suppressed"

    def __init__(self, status: str, *, reason: str = "", detail: str = ""):
        self.status = status
        self.reason = reason
        self.detail = detail

    @property
    def delivery_blocked(self) -> bool:
        """True whenever delivery cannot be asserted to work."""
        return self.status in {self.BLOCKED, self.UNKNOWN}

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "detail": self.detail,
        }


def reconcile_email_suppression_for_resubscribe(
    user,
    *,
    client: MauticClient | None = None,
) -> SuppressionReconciliation:
    """Try to clear a voluntary Mautic opt-out after an explicit ECP opt-in.

    Live Mautic state is re-read before anything is removed. Mautic's REST
    endpoint ``contacts/{id}/dnc/{channel}/remove`` takes no reason and drops
    the first matching record for the channel, so it is only safe to call when
    every email DNC record on the contact is a voluntary opt-out. If a bounce,
    manual block or unrecognised reason is present alongside it, nothing is
    removed at all — losing a bounce suppression would damage deliverability
    far more than leaving an opt-out in place.
    """
    suppression = MauticEmailSuppression.objects.filter(user=user).first()
    if suppression is None:
        return SuppressionReconciliation(SuppressionReconciliation.NOT_SUPPRESSED)

    if not suppression.is_reversible:
        return SuppressionReconciliation(
            SuppressionReconciliation.BLOCKED,
            reason=suppression.reason,
            detail=(
                "Mautic still blocks email for this member and the block is "
                "not a voluntary opt-out."
            ),
        )

    contact_id = str(suppression.mautic_contact_id or "").strip()
    if not contact_id:
        mapping = MauticContactMapping.objects.filter(user=user).first()
        contact_id = str(mapping.mautic_contact_id).strip() if mapping else ""

    if not contact_id:
        # No linked contact means nothing to clear in Mautic, and nothing to
        # suppress either once the member has opted back in locally.
        clear_email_suppression(user)
        return SuppressionReconciliation(
            SuppressionReconciliation.CLEARED,
            detail="No linked Mautic contact; local suppression cleared.",
        )

    provider = client or MauticClient()

    try:
        contact = provider.get_contact(contact_id)
        reasons = email_dnc_reasons(contact)

        if not reasons:
            # Already contactable in Mautic; ECP was simply stale.
            clear_email_suppression(user)
            return SuppressionReconciliation(
                SuppressionReconciliation.CLEARED,
                detail="Mautic no longer suppresses email for this contact.",
            )

        unsafe = [reason for reason in reasons if not is_reversible_reason(reason)]
        if unsafe:
            record_email_suppression(
                user,
                unsafe[0],
                mautic_contact_id=contact_id,
            )
            return SuppressionReconciliation(
                SuppressionReconciliation.BLOCKED,
                reason=unsafe[0],
                detail=(
                    "Mautic blocks email for this member for a reason that "
                    "cannot be cleared automatically."
                ),
            )

        provider.remove_contact_dnc(contact_id, EMAIL_CHANNEL)
    except MauticError as exc:
        logger.warning(
            "Could not reconcile Mautic email suppression for user_id=%s: %s",
            getattr(user, "pk", None),
            exc,
        )
        return SuppressionReconciliation(
            SuppressionReconciliation.UNKNOWN,
            reason=suppression.reason,
            detail=(
                "Mautic could not be reached, so email delivery remains "
                "suppressed for now."
            ),
        )

    clear_email_suppression(user)
    return SuppressionReconciliation(
        SuppressionReconciliation.CLEARED,
        detail="Voluntary Mautic opt-out cleared.",
    )
