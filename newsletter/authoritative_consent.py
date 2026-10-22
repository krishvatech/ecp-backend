"""Authoritative marketing-consent decisions for protected Mautic emails.

Answers, from ECP's own records, whether each Mautic contact may be sent one
Form-sourced Campaign "Send email" step now. Read-only: nothing is subscribed,
unsubscribed, re-linked or cached.

Only data ECP trusts decides:

* the Campaign step is read from Mautic with ECP's own credentials (never the
  caller's description of it) and must still be a protected step: a marketing
  email directly on the YES path of a "Contact segments" condition whose
  segments are all active ECP Subscription Lists (form_campaign_consent);
* the email's own scope: its Mautic category must be ``ecp-list-<list id>``
  (the immutable NewsletterCategory id) for one of those lists. A list the
  member chose authorises only email declared for that list;
* the contact's ECP member comes from MauticContactMapping. A contact Mautic
  merged into a new id is accepted only when Mautic itself resolves the old,
  mapped id to the current one (``merged_ids`` are claims to check, not facts);
  no email address is ever matched;
* consent is the member's current NewsletterSubscription to that list.

ALLOW is the only positive outcome. Anything Mautic cannot tell ECP right now
raises ConsentLookupUnavailable, so the caller treats the whole batch as
UNAVAILABLE and sends nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .form_campaign_consent import DELAYED, form_source_ids, unsafe_email_steps
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic_campaign_duplicate import DuplicateBlocked, active_events
from .models import MauticContactMapping, MauticEmailSuppression, NewsletterCategory, NewsletterSubscription

ALLOW, DENY, UNKNOWN = "ALLOW", "DENY", "UNKNOWN"
EMAIL_SCOPE_PREFIX = "ecp-list-"
MAX_CONTACTS = 100
MAX_MERGED_IDS = 20


class ConsentLookupUnavailable(Exception):
    """Mautic could not be read reliably; no decision can be made now."""


@dataclass(frozen=True)
class StepScope:
    category: NewsletterCategory | None
    reason: str | None  # a DENY reason that applies to every contact


def email_scope_alias(category: NewsletterCategory) -> str:
    return f"{EMAIL_SCOPE_PREFIX}{category.pk}"


def _category_alias(email: dict[str, Any]) -> str:
    category = email.get("category")
    return str(category.get("alias") or "") if isinstance(category, dict) else ""


def protected_step_scope(client, campaign_id: int, event_id: int) -> StepScope:
    """The Subscription List that authorises this step's email, or a DENY reason."""
    try:
        campaign = client.get_campaign(campaign_id)
        states = client.get_campaign_event_states(campaign_id)
    except PermanentMauticError as exc:
        if "HTTP 404" in str(exc):
            return StepScope(None, "step_not_found")
        raise ConsentLookupUnavailable("campaign_read_failed") from exc
    except TemporaryMauticError as exc:
        raise ConsentLookupUnavailable("campaign_read_failed") from exc
    if not form_source_ids(campaign.get("forms")):
        return StepScope(None, "not_form_sourced")
    try:
        events = active_events(campaign, states.get("activeEventIds") if isinstance(states, dict) else None)
    except DuplicateBlocked as exc:
        raise ConsentLookupUnavailable("campaign_read_failed") from exc
    by_id = {str(event.get("id")): event for event in events}
    step = by_id.get(str(event_id))
    if step is None or str(step.get("type") or "") != "email.send":
        return StepScope(None, "step_not_found")

    lists = {
        category.mautic_segment_id: category
        for category in NewsletterCategory.objects.filter(is_active=True, deletion_state="").exclude(mautic_segment_id="")
    }
    # The same structural rule ECP enforces when publishing. The delay rule is a
    # publish-time precaution only: consent is re-checked here when it is sent.
    problems = [p for p in unsafe_email_steps(events, set(lists)) if p["id"] == str(event_id) and p["reason"] != DELAYED]
    if problems:
        return StepScope(None, problems[0]["reason"])

    parent = by_id.get(str((step.get("parent") or {}).get("id") if isinstance(step.get("parent"), dict) else step.get("parent")))
    gate_lists = [lists[str(s)] for s in ((parent or {}).get("properties") or {}).get("segments") or [] if str(s) in lists]

    email_id = (step.get("properties") or {}).get("email")
    try:
        email = client.get_email(email_id)
    except PermanentMauticError as exc:
        if "HTTP 404" in str(exc):
            return StepScope(None, "email_not_found")
        raise ConsentLookupUnavailable("email_read_failed") from exc
    except TemporaryMauticError as exc:
        raise ConsentLookupUnavailable("email_read_failed") from exc
    alias = _category_alias(email)
    if not alias.startswith(EMAIL_SCOPE_PREFIX):
        return StepScope(None, "email_scope_missing")
    scoped = [category for category in gate_lists if email_scope_alias(category) == alias]
    if not scoped:
        return StepScope(None, "email_scope_mismatch")
    return StepScope(scoped[0], None)


def _resolve_member(client, contact_id: int, merged_ids: list[int]) -> tuple[int | None, str | None]:
    """(user id, None) or (None, UNKNOWN reason). Never matches email addresses
    and never re-links a mapping."""
    users = set()
    direct = MauticContactMapping.objects.filter(mautic_contact_id=str(contact_id)).values_list("user_id", flat=True).first()
    if direct is not None:
        users.add(direct)
    claimed = dict(MauticContactMapping.objects.filter(
        mautic_contact_id__in=[str(m) for m in merged_ids]
    ).values_list("mautic_contact_id", "user_id"))
    unverified = False
    for merged_id, user_id in claimed.items():
        try:
            survivor = client.get_contact(merged_id)
        except PermanentMauticError:
            unverified = True  # Mautic does not resolve it: the claim is not proven
            continue
        except TemporaryMauticError as exc:
            raise ConsentLookupUnavailable("contact_read_failed") from exc
        if str((survivor or {}).get("id")) == str(contact_id):
            users.add(user_id)
        else:
            unverified = True
    if len(users) > 1:
        return None, "identity_conflict"
    if not users:
        return None, "merge_unverified" if claimed or unverified else "identity_unknown"
    return users.pop(), None


def decide(campaign_id: int, event_id: int, contacts: list[dict[str, Any]], client=None) -> list[dict[str, str]]:
    """One decision per requested contact, in request order."""
    client = client or MauticClient()
    scope = protected_step_scope(client, campaign_id, event_id)
    if scope.reason:
        return [{"id": c["id"], "decision": DENY, "reason": scope.reason} for c in contacts]

    decisions = []
    for contact in contacts:
        user_id, unknown = _resolve_member(client, contact["id"], contact.get("merged_ids", []))
        if unknown:
            decisions.append({"id": contact["id"], "decision": UNKNOWN, "reason": unknown})
            continue
        subscription = NewsletterSubscription.objects.filter(user_id=user_id, category=scope.category).select_related("user").first()
        if subscription is None:
            reason = "no_consent"
        elif not subscription.user.is_active:
            reason = "member_inactive"
        elif not subscription.is_subscribed:
            reason = "consent_withdrawn"
        elif MauticEmailSuppression.objects.filter(user_id=user_id).exists():
            reason = "suppressed"
        else:
            decisions.append({"id": contact["id"], "decision": ALLOW, "reason": "current_consent"})
            continue
        decisions.append({"id": contact["id"], "decision": DENY, "reason": reason})
    return decisions
