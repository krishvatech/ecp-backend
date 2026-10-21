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
