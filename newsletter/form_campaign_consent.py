"""Marketing consent for native Mautic Campaigns that use a Form as a source.

Submitting a Form adds the contact to every published Campaign that uses the
Form as a source (Mautic 7.1.3 ``CampaignBundle`` form subscriber). A Form
submission, an email address, or the absence of a Do Not Contact record is not
marketing consent, and Mautic sends a marketing email to any contact without an
email DNC. ECP's evidence of marketing consent is a member's choice to join a
Subscription List (``NewsletterSubscription``), which ECP mirrors into Mautic as
membership of that list's segment (``NewsletterCategory.mautic_segment_id``).

Native Mautic can check that evidence when a step runs: the "Contact segments"
condition (``lead.segments``) passes for a contact who is in any of its segments
and was not manually removed. So in a Campaign with a Form source, ECP only puts
a Send email step into service when it is

* a *marketing* email (Mautic checks Do Not Contact when it sends it),
* the direct YES child of a ``lead.segments`` condition,
* whose segments are all active ECP Subscription List segments, and
* executed immediately after that condition, so consent is checked when the
  email is sent. A delay belongs on the condition, which Mautic evaluates
  when the delay ends.

Transactional email (and a Send email step with no type, which Mautic runs as
transactional) ignores Do Not Contact, so it is not put into service in a
Form-sourced Campaign at all: there is no approved consent policy for it.

The check runs when ECP puts a workflow into service (publishing, or changing
the events or sources of a published Campaign). A Campaign with a Form source
is checked as a whole, whatever other sources it has, because Mautic does not
record which source brought a contact in. Existing Campaigns are never changed
here.

At send time the bridge plugin enforces the same rule inside Mautic
(EcpFormSourceEmailPolicy / EcpFormSourceEmailConsentSubscriber), including for
Campaigns built or published in Mautic itself, and re-reads Subscription List
membership when the email is sent. It only accepts segments in the Mautic
category CONSENT_CATEGORY_ALIAS, which ECP's list sync assigns, so the publish
check also confirms that marker (``unmarked_gate_steps``).
"""

from __future__ import annotations

from typing import Any

from .campaign_email_types import (
    EMAIL_SEND_EVENT,
    STATE_MARKETING,
    classify_email_type,
)
from .category_segment_services import CONSENT_CATEGORY_ALIAS
from .mautic import MauticClient
from .mautic.exceptions import PermanentMauticError, TemporaryMauticError
from .mautic_campaign_canvas_audit import _event_parent
from .models import NewsletterCategory

CONSENT_CONDITION = "lead.segments"
#: Marketing Messages re-dispatch as a Send email step whose properties carry no
#: email type, so Mautic runs them as transactional; never put into service in a
#: Form-sourced Campaign (the plugin refuses them at send time too).
MARKETING_MESSAGE_EVENT = "message.send"
CONSENT_REQUIRED_CODE = "form_source_marketing_consent_required"

NOT_MARKETING = "not_marketing"
NOT_GATED = "not_gated"
NO_PATH = "no_path"
NOT_SUBSCRIPTION_LIST = "not_subscription_list"
DELAYED = "delayed"
NOT_MARKED = "subscription_list_not_marked"
UNVERIFIABLE = "unverifiable"

REASONS = {
    NOT_MARKETING: (
        "it is not a marketing email. Transactional email ignores Do Not Contact, so it cannot be sent "
        "to Form submitters"
    ),
    NOT_GATED: "it does not directly follow a \"Contact segments\" condition that checks a Subscription List",
    NO_PATH: "it is on the NO path of the Subscription List condition",
    NOT_SUBSCRIPTION_LIST: "its condition checks segments that are not active Subscription Lists",
    DELAYED: "it is delayed after the Subscription List check. Put the delay on the condition instead",
    NOT_MARKED: (
        "its Subscription List segment is not marked for consent in Mautic yet (sync the Subscription List), so "
        "Mautic would not send it"
    ),
    UNVERIFIABLE: "Mautic did not report the Campaign's active steps, so they could not be checked",
}


class FormSourceConsentRequired(ValueError):
    """A Form-sourced Campaign would put an email step into service without
    a consent check Mautic can evaluate when the email is sent."""

    code = CONSENT_REQUIRED_CODE

    def __init__(self, steps: list[dict[str, str]]):
        self.steps = steps
        details = "; ".join(f"{step['name'] or step['id']}: {REASONS[step['reason']]}" for step in steps)
        super().__init__(
            "Submitting a Form does not automatically subscribe a Contact to marketing emails. This Campaign uses "
            "a Form as a source, so each Send email step must be a marketing email placed directly on the YES "
            "path of a \"Contact segments\" condition that checks a Subscription List. "
            f"Fix: {details}. Saving it unpublished, or unpublishing it, is still possible."
        )


def subscription_list_consent_segment_ids() -> set[str]:
    """Segments of active Subscription Lists: ECP's consent evidence in Mautic."""
    return {
        str(value).strip()
        for value in NewsletterCategory.objects.filter(is_active=True, deletion_state="")
        .exclude(mautic_segment_id="")
        .values_list("mautic_segment_id", flat=True)
        if str(value or "").strip()
    }


def _collection(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = list(value.values())
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def form_source_ids(forms: Any) -> list[str]:
    ids = []
    for item in forms if isinstance(forms, list) else []:
        value = item.get("id") if isinstance(item, dict) else item
        if value not in (None, "") and str(value) not in ids:
            ids.append(str(value))
    return ids


def _key(event: dict[str, Any]) -> str:
    return str(event.get("key") or event.get("type") or "").strip()


def _immediate(event: dict[str, Any]) -> bool:
    return str(event.get("triggerMode") or "immediate").strip() == "immediate"


def _segment_ids(properties: Any) -> set[str]:
    segments = properties.get("segments") if isinstance(properties, dict) else None
    if not isinstance(segments, list):
        segments = [segments] if segments not in (None, "") else []
    return {str(value).strip() for value in segments if str(value).strip()}


def unsafe_email_steps(events: Any, consent_segments: set[str]) -> list[dict[str, str]]:
    """Send email steps in ``events`` (request or provider shape) that are not
    behind an immediate Subscription List consent check."""
    events = _collection(events)
    by_id = {str(event.get("id")): event for event in events}
    unsafe = []
    for event in events:
        if _key(event) == MARKETING_MESSAGE_EVENT:
            unsafe.append({"id": str(event.get("id") or ""), "name": str(event.get("name") or ""), "reason": NOT_MARKETING})
            continue
        if _key(event) != EMAIL_SEND_EVENT:
            continue
        parent = by_id.get(_event_parent(event) or "")
        if classify_email_type(event.get("properties")) != STATE_MARKETING:
            reason = NOT_MARKETING
        elif parent is None or _key(parent) != CONSENT_CONDITION or str(parent.get("eventType")) != "condition":
            reason = NOT_GATED
        elif str(event.get("decisionPath") or "") != "yes":
            reason = NO_PATH
        elif not (checked := _segment_ids(parent.get("properties"))) or not checked <= consent_segments:
            reason = NOT_SUBSCRIPTION_LIST
        elif not _immediate(event):
            reason = DELAYED
        else:
            continue
        unsafe.append({"id": str(event.get("id") or ""), "name": str(event.get("name") or ""), "reason": reason})
    return unsafe


SEGMENT_CHANGE_ACTION = "lead.changelist"
LIST_WRITE_FORBIDDEN_CODE = "subscription_list_write_forbidden"


class SubscriptionListWriteForbidden(ValueError):
    """A workflow would add contacts to an ECP Subscription List segment from
    Mautic. Membership is consent evidence; only ECP writes it."""

    code = LIST_WRITE_FORBIDDEN_CODE

    def __init__(self, steps: list[dict[str, str]]):
        self.steps = steps
        names = ", ".join(step["name"] or step["id"] for step in steps)
        super().__init__(
            "A Campaign step cannot add contacts to a Subscription List: membership of a Subscription List is a "
            "member's own marketing consent, and only the member's choice in ECP may set it. Mautic also undoes "
            f"such additions when they run. Remove the Subscription List from: {names}."
        )


def subscription_list_writes(events: Any, list_segments: set[str]) -> list[dict[str, str]]:
    """``lead.changelist`` steps that would add contacts to Subscription List
    segments (any lifecycle state). Removing contacts is not refused."""
    steps = []
    for event in _collection(events):
        if _key(event) != SEGMENT_CHANGE_ACTION:
            continue
        properties = event.get("properties") if isinstance(event.get("properties"), dict) else {}
        added = _segment_ids({"segments": properties.get("addToLists") or []})
        if added & list_segments:
            steps.append({"id": str(event.get("id") or ""), "name": str(event.get("name") or ""), "reason": LIST_WRITE_FORBIDDEN_CODE})
    return steps


def require_no_subscription_list_writes(events: Any) -> None:
    """Refuse to put into service a workflow that adds to Subscription Lists.
    ``events`` None (workflow unavailable) is not checked here: the bridge
    plugin undoes such additions at run time whatever the workflow says."""
    if events is None:
        return
    from .form_views import subscription_list_segment_ids

    steps = subscription_list_writes(events, subscription_list_segment_ids())
    if steps:
        raise SubscriptionListWriteForbidden(steps)


def email_consent_scope(events: Any, list_slug_by_segment: dict[str, str]) -> list[dict[str, Any]]:
    """For each Send email step, the Subscription Lists its consent condition
    checks: today the only link between a marketing email and the consent that
    authorises it. Read-only reporting; it decides nothing."""
    events = _collection(events)
    by_id = {str(event.get("id")): event for event in events}
    scope = []
    for event in events:
        if _key(event) != EMAIL_SEND_EVENT:
            continue
        parent = by_id.get(_event_parent(event) or "")
        gated = parent is not None and _key(parent) == CONSENT_CONDITION and str(event.get("decisionPath") or "") == "yes"
        segments = sorted(_segment_ids((parent or {}).get("properties"))) if gated else []
        properties = event.get("properties") if isinstance(event.get("properties"), dict) else {}
        scope.append({
            "step": str(event.get("id") or ""),
            "email": str(properties.get("email") or ""),
            "lists": sorted(list_slug_by_segment[segment] for segment in segments if segment in list_slug_by_segment),
            "otherSegments": [segment for segment in segments if segment not in list_slug_by_segment],
        })
    return scope


#: Native Form submit actions that email the submitter. Mautic sends them with
#: ignoreDNC and offers no email type, so they are transactional by construction.
FORM_CONTACT_EMAIL_ACTION = "email.send.lead"


def form_contact_autoresponders(actions: Any) -> list[dict[str, str]]:
    """Native "Send email to contact" actions on a Form (read-only reporting)."""
    found = []
    for action in _collection(actions):
        if str(action.get("type") or "") != FORM_CONTACT_EMAIL_ACTION:
            continue
        properties = action.get("properties") if isinstance(action.get("properties"), dict) else {}
        found.append({"id": str(action.get("id") or ""), "name": str(action.get("name") or ""), "email": str(properties.get("email") or "")})
    return found


#: Native submit actions that reach the submitter outside any consent check,
#: with the reason the bridge plugin's Form action guard gives for each
#: (EcpFormEmailActionPolicy; enforced only in its "enforce" mode).
CONTACT_FACING_ACTIONS = {
    FORM_CONTACT_EMAIL_ACTION: "autoresponder (sent with ignoreDNC; approved acknowledgments only)",
    "form.email": "form results copied to the contact (no Do Not Contact check)",
    "lead.remove_do_not_contact": "the submission removes the contact's Do Not Contact",
}


def form_contact_facing_actions(actions: Any) -> list[dict[str, str]]:
    """Native submit actions that email the submitter or lift their Do Not
    Contact (read-only reporting). "Send form results" counts only with its
    copy-to-contact option on."""
    found = []
    for action in _collection(actions):
        kind = str(action.get("type") or "")
        properties = action.get("properties") if isinstance(action.get("properties"), dict) else {}
        if kind not in CONTACT_FACING_ACTIONS or (kind == "form.email" and not _truthy(properties.get("copy_lead"))):
            continue
        found.append({"id": str(action.get("id") or ""), "name": str(action.get("name") or ""), "type": kind,
                      "risk": CONTACT_FACING_ACTIONS[kind]})
    return found


def _truthy(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def _read_segment(segment_id: str) -> dict[str, Any]:
    return MauticClient().get_segment(segment_id)


def segment_is_marked(segment: Any) -> bool:
    """What the bridge plugin requires of a consent segment when it sends:
    published and in the Subscription List category."""
    if not isinstance(segment, dict):
        return False
    category = segment.get("category")
    alias = category.get("alias") if isinstance(category, dict) else None
    return segment.get("isPublished") in (True, 1, "1") and alias == CONSENT_CATEGORY_ALIAS


def unmarked_gate_steps(events: Any, reader=None) -> list[dict[str, str]]:
    """Gated Send email steps whose Subscription List segment Mautic would not
    accept as consent evidence (EcpFormSourceEmailPolicy at send time)."""
    reader = reader or _read_segment
    events = _collection(events)
    by_id = {str(event.get("id")): event for event in events}
    checked: dict[str, str | None] = {}
    steps = []
    for event in events:
        if _key(event) != EMAIL_SEND_EVENT:
            continue
        parent = by_id.get(_event_parent(event) or "")
        reason = None
        for segment_id in sorted(_segment_ids((parent or {}).get("properties"))):
            if segment_id not in checked:
                try:
                    checked[segment_id] = None if segment_is_marked(reader(segment_id)) else NOT_MARKED
                except (TemporaryMauticError, PermanentMauticError):
                    checked[segment_id] = UNVERIFIABLE
            reason = reason or checked[segment_id]
        if reason:
            steps.append({"id": str(event.get("id") or ""), "name": str(event.get("name") or ""), "reason": reason})
    return steps


def require_form_source_consent(events: Any, forms: Any) -> None:
    """Refuse to put a Form-sourced workflow with an unsafe Send email step into
    service. ``events`` is None when the live workflow could not be read."""
    if not form_source_ids(forms):
        return
    if events is None:
        raise FormSourceConsentRequired([{"id": "", "name": "Campaign", "reason": UNVERIFIABLE}])
    unsafe = unsafe_email_steps(events, subscription_list_consent_segment_ids())
    if unsafe:
        raise FormSourceConsentRequired(unsafe)
    # Structurally safe: also confirm Mautic will accept the segments when it
    # sends, so a publish never looks fine while every email is refused.
    unmarked = unmarked_gate_steps(events)
    if unmarked:
        raise FormSourceConsentRequired(unmarked)
