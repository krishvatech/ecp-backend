"""Email type policy for native Mautic Campaign "Send email" actions.

Mautic 7.1.3 classifies an ``email.send`` campaign action by its
``properties.email_type``, which is ``"marketing"`` or ``"transactional"``
(``MailHelper::EMAIL_TYPE_*``). Its campaign form offers ``marketing`` as the
default, but the runtime reads the stored property with a different fallback::

    $type = $config['email_type'] ?? MailHelper::EMAIL_TYPE_TRANSACTIONAL;
    'ignoreDNC' => MailHelper::EMAIL_TYPE_TRANSACTIONAL === $type,

(``EmailBundle/EventListener/CampaignSubscriber.php``). The REST API stores
event properties exactly as sent, so an action saved without ``email_type``
runs as transactional: it is sent to Do Not Contact contacts, and skips the
marketing rule that a contact receives a given email only once.

ECP therefore makes the type explicit:

* a new action without a type is saved as ``marketing``;
* an explicit ``marketing`` or ``transactional`` is kept, and any other value
  is rejected;
* ``transactional`` that is not already stored on that action needs the
  event's ``transactionalEmailConfirmed: true``, because it bypasses DNC;
* a saved action keeps its stored classification: a request that leaves the
  type out never rewrites it. A legacy action stored without a type stays as
  it is until an administrator chooses a type explicitly;
* a workflow is never put into service (published, re-published, or changed
  while published) with a Send email action whose type is missing or
  unsupported. Unpublishing and editing a draft stay possible.
"""

from __future__ import annotations

from typing import Any

EMAIL_SEND_EVENT = "email.send"
EMAIL_TYPE_PROPERTY = "email_type"
EMAIL_TYPE_MARKETING = "marketing"
EMAIL_TYPE_TRANSACTIONAL = "transactional"
EMAIL_TYPES = (EMAIL_TYPE_TRANSACTIONAL, EMAIL_TYPE_MARKETING)

#: Event-level request flag (never a Mautic property) confirming a
#: transactional send. It is removed before the payload reaches Mautic.
CONFIRMATION_FIELD = "transactionalEmailConfirmed"
CONFIRMATION_REQUIRED_CODE = "transactional_email_confirmation_required"

#: How the audit and API describe a stored action.
STATE_MARKETING = "marketing"
STATE_TRANSACTIONAL = "transactional"
STATE_MISSING = "missing"
STATE_INVALID = "invalid"


class TransactionalEmailConfirmationRequired(ValueError):
    """A request sets ``transactional`` on actions without confirming it."""

    code = CONFIRMATION_REQUIRED_CODE

    def __init__(self, events: list[dict[str, str]]):
        self.events = events
        names = ", ".join(event["name"] or event["id"] for event in events)
        super().__init__(
            "Transactional emails are sent even to contacts who unsubscribed or "
            "are marked Do Not Contact, and can be sent to the same contact "
            f"more than once. Confirm the transactional email type for: {names}."
        )


UNRESOLVED_CODE = "email_type_unresolved"


class UnresolvedEmailTypes(ValueError):
    """A campaign would be published with Send email actions whose type is
    missing or unsupported — Mautic would send a missing one as transactional."""

    code = UNRESOLVED_CODE

    def __init__(self, events: list[dict[str, str]]):
        self.events = events
        names = ", ".join(event["name"] or event["id"] for event in events)
        super().__init__(
            "This campaign cannot be published while a Send email step has no "
            "email type: Mautic would send it as transactional, to contacts who "
            "unsubscribed or are marked Do Not Contact too. Choose Marketing or "
            f"Transactional for: {names}. Saving it unpublished, or unpublishing "
            "it, is still possible."
        )


def _event_key(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    return str(item.get("key") or item.get("type") or "").strip()


def is_email_send_action(event: Any) -> bool:
    return (
        isinstance(event, dict)
        and _event_key(event) == EMAIL_SEND_EVENT
        and str(event.get("eventType") or "").strip() == "action"
    )


def request_has_email_send_action(events: Any) -> bool:
    """Whether a raw request ``events`` value contains a Send email action."""
    return isinstance(events, list) and any(
        _event_key(item) == EMAIL_SEND_EVENT for item in events
    )


def _type_value(properties: Any) -> tuple[bool, Any]:
    """``(present, value)``; a blank value counts as not set."""
    if not isinstance(properties, dict) or EMAIL_TYPE_PROPERTY not in properties:
        return False, None
    value = properties.get(EMAIL_TYPE_PROPERTY)
    if value is None or (isinstance(value, str) and not value.strip()):
        return False, value
    return True, value


def classify_email_type(properties: Any) -> str:
    present, value = _type_value(properties)
    if not present:
        return STATE_MISSING
    if value == EMAIL_TYPE_MARKETING:
        return STATE_MARKETING
    if value == EMAIL_TYPE_TRANSACTIONAL:
        return STATE_TRANSACTIONAL
    return STATE_INVALID


def runs_as_transactional(state: str) -> bool:
    """What Mautic does with a stored state: a missing type falls back to
    transactional (DNC ignored, no repeat-send guard)."""
    return state in (STATE_TRANSACTIONAL, STATE_MISSING)


def _collection(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = list(value.values())
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def stored_email_types(campaign: Any) -> dict[str, Any]:
    """``{event id: stored email_type value or None}`` for a campaign's saved
    Send email actions, as returned by Mautic's campaign endpoint."""
    if not isinstance(campaign, dict):
        return {}
    stored = {}
    for event in _collection(campaign.get("events")):
        if str(event.get("type") or "").strip() != EMAIL_SEND_EVENT:
            continue
        event_id = str(event.get("id") or "").strip()
        if not event_id:
            continue
        present, value = _type_value(event.get("properties"))
        stored[event_id] = value if present else None
    return stored


def unresolved_email_send_actions(events: Any) -> list[dict[str, str]]:
    """Send email actions in ``events`` (request or provider shape) whose
    stored type is missing or unsupported."""
    unresolved = []
    for event in _collection(events):
        if _event_key(event) != EMAIL_SEND_EVENT:
            continue
        state = classify_email_type(event.get("properties"))
        if state in (STATE_MISSING, STATE_INVALID):
            unresolved.append(
                {
                    "id": str(event.get("id") or "").strip(),
                    "name": str(event.get("name") or "").strip(),
                    "state": state,
                }
            )
    return unresolved


def require_resolved_email_types(events: Any) -> None:
    """Refuse to publish a workflow with an unresolved Send email action."""
    unresolved = unresolved_email_send_actions(events)
    if unresolved:
        raise UnresolvedEmailTypes(unresolved)


def apply_email_type_policy(
    events: list[dict[str, Any]],
    *,
    stored: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Normalize parsed campaign events in place and return them.

    ``stored`` maps the campaign's saved Send email action IDs to their stored
    type (see :func:`stored_email_types`); an action not in it is new.
    """
    stored = stored or {}
    unconfirmed = []

    for index, event in enumerate(events, start=1):
        confirmed = event.pop(CONFIRMATION_FIELD, None) is True
        if not is_email_send_action(event):
            continue

        properties = event.get("properties")
        if isinstance(properties, list) and not properties:
            properties = {}
        if not isinstance(properties, dict):
            raise ValueError(
                f"Native Mautic Campaign event #{index} properties must be an object."
            )

        event_id = str(event.get("id") or "").strip()
        persisted = event_id in stored
        stored_value = stored.get(event_id)
        present, value = _type_value(properties)

        if present and value not in EMAIL_TYPES:
            raise ValueError(
                f"Native Mautic Campaign event #{index} email type must be "
                f"'{EMAIL_TYPE_MARKETING}' or '{EMAIL_TYPE_TRANSACTIONAL}'."
            )

        if not present:
            if not persisted:
                event["properties"] = {
                    **properties,
                    EMAIL_TYPE_PROPERTY: EMAIL_TYPE_MARKETING,
                }
            elif stored_value in EMAIL_TYPES:
                # The request dropped a stored type; dropping it would turn a
                # marketing send into a transactional one.
                event["properties"] = {
                    **properties,
                    EMAIL_TYPE_PROPERTY: stored_value,
                }
            # A legacy action stored without a type is left exactly as it is.
            continue

        if (
            value == EMAIL_TYPE_TRANSACTIONAL
            and stored_value != EMAIL_TYPE_TRANSACTIONAL
            and not confirmed
        ):
            unconfirmed.append(
                {"id": event_id, "name": str(event.get("name") or "").strip()}
            )

    if unconfirmed:
        raise TransactionalEmailConfirmationRequired(unconfirmed)
    return events
