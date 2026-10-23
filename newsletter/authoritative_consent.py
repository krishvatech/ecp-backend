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

Every decision reads Mautic and ECP afresh. Nothing (no decision, no Campaign
structure, no Email category, no merge resolution) is cached between requests:
a withdrawal, an Email category change or a Campaign edit applies to the very
next request.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

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


@dataclass(frozen=True)
class StepFacts:
    """What Mautic says about one Campaign step, read for this decision only."""

    campaign: dict[str, Any] | None  # None: the Campaign does not exist
    events: list[dict[str, Any]]  # active events only
    email: Callable[[Any], dict[str, Any] | None]  # the step's Email, None when it does not exist
    merged: dict[str, int | None] | None  # merged id -> contact Mautic resolves it to; None: ask per id


def email_scope_alias(category: NewsletterCategory) -> str:
    return f"{EMAIL_SCOPE_PREFIX}{category.pk}"


def _category_alias(email: dict[str, Any]) -> str:
    category = email.get("category")
    return str(category.get("alias") or "") if isinstance(category, dict) else ""


def read_step(client, campaign_id: int, event_id: int, merged_ids: list[int] | tuple = ()) -> StepFacts:
    """One request to the bridge plugin's consent-step endpoint; with an older
    plugin, the same facts from the Campaign, event-state and Email APIs.
    Nothing is cached across decisions."""
    try:
        data = client.get_consent_step(campaign_id, event_id, list(merged_ids))
    except (PermanentMauticError, TemporaryMauticError) as exc:
        raise ConsentLookupUnavailable("campaign_read_failed") from exc
    if data is not None:
        email = data.get("email")
        merged = {str(key): (int(value) if value is not None else None) for key, value in data["merged"].items()}
        return StepFacts(data.get("campaign"), [e for e in data["events"] if isinstance(e, dict)], lambda _id: email, merged)

    try:
        campaign = client.get_campaign(campaign_id)
        states = client.get_campaign_event_states(campaign_id)
    except PermanentMauticError as exc:
        if "HTTP 404" in str(exc):
            return StepFacts(None, [], lambda _id: None, None)
        raise ConsentLookupUnavailable("campaign_read_failed") from exc
    except TemporaryMauticError as exc:
        raise ConsentLookupUnavailable("campaign_read_failed") from exc
    if not form_source_ids(campaign.get("forms")):
        return StepFacts(campaign, [], lambda _id: None, None)
    try:
        events = active_events(campaign, states.get("activeEventIds") if isinstance(states, dict) else None)
    except DuplicateBlocked as exc:
        raise ConsentLookupUnavailable("campaign_read_failed") from exc
    return StepFacts(campaign, events, lambda email_id: _read_email(client, email_id), None)


def _read_email(client, email_id) -> dict[str, Any] | None:
    try:
        return client.get_email(email_id)
    except PermanentMauticError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise ConsentLookupUnavailable("email_read_failed") from exc
    except TemporaryMauticError as exc:
        raise ConsentLookupUnavailable("email_read_failed") from exc


def step_scope(facts: StepFacts, event_id: int) -> StepScope:
    """The Subscription List that authorises this step's email, or a DENY reason."""
    if facts.campaign is None:
        return StepScope(None, "step_not_found")
    if not form_source_ids(facts.campaign.get("forms")):
        return StepScope(None, "not_form_sourced")
    by_id = {str(event.get("id")): event for event in facts.events}
    step = by_id.get(str(event_id))
    if step is None or str(step.get("type") or "") != "email.send":
        return StepScope(None, "step_not_found")

    lists = {
        category.mautic_segment_id: category
        for category in NewsletterCategory.objects.filter(is_active=True, deletion_state="").exclude(mautic_segment_id="")
    }
    # The same structural rule ECP enforces when publishing. The delay rule is a
    # publish-time precaution only: consent is re-checked here when it is sent.
    problems = [p for p in unsafe_email_steps(facts.events, set(lists)) if p["id"] == str(event_id) and p["reason"] != DELAYED]
    if problems:
        return StepScope(None, problems[0]["reason"])

    parent = by_id.get(str((step.get("parent") or {}).get("id") if isinstance(step.get("parent"), dict) else step.get("parent")))
    gate_lists = [lists[str(s)] for s in ((parent or {}).get("properties") or {}).get("segments") or [] if str(s) in lists]

    email = facts.email((step.get("properties") or {}).get("email"))
    if email is None:
        return StepScope(None, "email_not_found")
    alias = _category_alias(email)
    if not alias.startswith(EMAIL_SCOPE_PREFIX):
        return StepScope(None, "email_scope_missing")
    scoped = [category for category in gate_lists if email_scope_alias(category) == alias]
    if not scoped:
        return StepScope(None, "email_scope_mismatch")
    return StepScope(scoped[0], None)


def protected_step_scope(client, campaign_id: int, event_id: int) -> StepScope:
    """The Subscription List that authorises this step's email, or a DENY reason."""
    return step_scope(read_step(client, campaign_id, event_id), event_id)


def _survivor(client, facts: StepFacts, merged_id: str, seen: dict[str, int | None]) -> int | None:
    """The contact Mautic resolves a merged id to now (None: not resolved)."""
    if facts.merged is not None:
        return facts.merged.get(merged_id)
    if merged_id not in seen:  # this decision only
        try:
            survivor = client.get_contact(merged_id)
        except PermanentMauticError:
            seen[merged_id] = None  # Mautic does not resolve it: the claim is not proven
        except TemporaryMauticError as exc:
            raise ConsentLookupUnavailable("contact_read_failed") from exc
        else:
            value = (survivor or {}).get("id")
            seen[merged_id] = int(value) if str(value or "").isdigit() else None
    return seen[merged_id]


def _resolve_member(client, facts: StepFacts, contact: dict[str, Any], user_by_contact: dict[str, int],
                    seen: dict[str, int | None]) -> tuple[int | None, str | None]:
    """(user id, None) or (None, UNKNOWN reason). Never matches email addresses
    and never re-links a mapping."""
    contact_id = int(contact["id"])
    users = set()
    direct = user_by_contact.get(str(contact_id))
    if direct is not None:
        users.add(direct)
    claimed = [str(m) for m in contact.get("merged_ids", []) if str(m) in user_by_contact]
    unverified = False
    for merged_id in claimed:
        if _survivor(client, facts, merged_id, seen) == contact_id:
            users.add(user_by_contact[merged_id])
        else:
            unverified = True
    if len(users) > 1:
        return None, "identity_conflict"
    if not users:
        return None, "merge_unverified" if claimed or unverified else "identity_unknown"
    return users.pop(), None


def decide(campaign_id: int, event_id: int, contacts: list[dict[str, Any]], client=None) -> list[dict[str, str]]:
    """One decision per requested contact, in request order.

    Mautic is read once for the whole batch (read_step) and ECP's records with a
    fixed number of queries, so cost does not grow with merge claims or contacts.
    Every read happens now, for this decision: nothing is reused across requests."""
    client = client or MauticClient()
    merged_ids = sorted({int(m) for contact in contacts for m in contact.get("merged_ids", [])})
    facts = read_step(client, campaign_id, event_id, merged_ids)
    scope = step_scope(facts, event_id)
    if scope.reason:
        return [{"id": c["id"], "decision": DENY, "reason": scope.reason} for c in contacts]

    wanted = {str(c["id"]) for c in contacts} | {str(m) for m in merged_ids}
    user_by_contact = dict(MauticContactMapping.objects.filter(mautic_contact_id__in=wanted).values_list("mautic_contact_id", "user_id"))
    seen: dict[str, int | None] = {}
    members = [_resolve_member(client, facts, contact, user_by_contact, seen) for contact in contacts]
    user_ids = {user_id for user_id, _ in members if user_id is not None}
    subscriptions = {
        s.user_id: s for s in NewsletterSubscription.objects.filter(user_id__in=user_ids, category=scope.category).select_related("user")
    }
    suppressed = set(MauticEmailSuppression.objects.filter(user_id__in=user_ids).values_list("user_id", flat=True))

    decisions = []
    for contact, (user_id, unknown) in zip(contacts, members):
        if unknown:
            decisions.append({"id": contact["id"], "decision": UNKNOWN, "reason": unknown})
            continue
        subscription = subscriptions.get(user_id)
        if subscription is None:
            reason = "no_consent"
        elif not subscription.user.is_active:
            reason = "member_inactive"
        elif not subscription.is_subscribed:
            reason = "consent_withdrawn"
        elif user_id in suppressed:
            reason = "suppressed"
        else:
            decisions.append({"id": contact["id"], "decision": ALLOW, "reason": "current_consent"})
            continue
        decisions.append({"id": contact["id"], "decision": DENY, "reason": reason})
    return decisions
