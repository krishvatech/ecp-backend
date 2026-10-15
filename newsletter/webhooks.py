import base64
import hashlib
import hmac
import json
import logging
from datetime import timezone as datetime_timezone

from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .dnc_services import (
    CONTACTABLE_VERB,
    EMAIL_CHANNEL,
    classify_dnc_reason,
    clear_email_suppression_if_older,
    record_email_suppression,
)
from .models import (
    MauticContactMapping,
    MauticEmailSuppression,
    NewsletterCampaign,
    NewsletterCampaignTrackingEvent,
)


logger = logging.getLogger(__name__)

CHANNEL_SUBSCRIPTION_EVENT = "mautic.lead_channel_subscription_changed"


EVENT_TYPE_MAP = {
    "mautic.email_on_open": NewsletterCampaignTrackingEvent.EventType.OPENED,
    "mautic.email_on_send": NewsletterCampaignTrackingEvent.EventType.DELIVERED,
    "mautic.page_on_hit": NewsletterCampaignTrackingEvent.EventType.CLICKED,
    "mautic.lead_channel_subscription_changed": (
        NewsletterCampaignTrackingEvent.EventType.UNSUBSCRIBED
    ),
}


#: Mautic batches at most ``webhook_limit`` (default 10) events per request;
#: these bounds only stop abuse, never a legitimate delivery.
DEFAULT_MAX_BODY_BYTES = 1024 * 1024
DEFAULT_MAX_EVENTS = 500

_TRACKING_URL_MAX = NewsletterCampaignTrackingEvent._meta.get_field("url").max_length
_PROVIDER_ID_MAX = NewsletterCampaignTrackingEvent._meta.get_field("provider_event_id").max_length
_CONTACT_ID_MAX = NewsletterCampaignTrackingEvent._meta.get_field("mautic_contact_id").max_length
_EMAIL_MAX = NewsletterCampaignTrackingEvent._meta.get_field("recipient_email").max_length

# Delivery observations for diagnostics, in the shared cache (no schema).
OBSERVATION_KEY = "newsletter:mautic-webhook:{name}"
OBSERVATION_TTL_SECONDS = 30 * 24 * 3600


def _setting_int(name, default):
    try:
        value = int(getattr(settings, name, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _observe(name, **fields) -> None:
    """Record one delivery observation. Never raises: diagnostics must not
    change how a delivery is answered."""
    try:
        cache.set(
            OBSERVATION_KEY.format(name=name),
            {"at": timezone.now().isoformat(), **fields},
            timeout=OBSERVATION_TTL_SECONDS,
        )
    except Exception:
        logger.warning("Could not record Mautic webhook observation %s", name, exc_info=True)


def webhook_observations() -> dict:
    """Latest accepted, rejected and failed deliveries (read by diagnostics)."""
    names = ("accepted", "rejected", "failed")
    try:
        values = cache.get_many([OBSERVATION_KEY.format(name=name) for name in names])
    except Exception:
        return {"available": False}
    return {
        "available": True,
        **{name: values.get(OBSERVATION_KEY.format(name=name)) for name in names},
    }


def _validate_mautic_signature(payload_bytes: bytes, signature: str) -> bool:
    secret = str(getattr(settings, "MAUTIC_WEBHOOK_SECRET", "") or "")
    if not secret:
        logger.warning("MAUTIC_WEBHOOK_SECRET is not configured")
        return False
    if not signature:
        return False

    digest = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode()
    return hmac.compare_digest(expected, signature)


def _safe_str(value) -> str:
    return str(value or "").strip()


def _lower_str(value) -> str:
    return _safe_str(value).lower()


def _is_false_value(value) -> bool:
    if value is False:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"false", "0", "no", "unsubscribed"}
    if isinstance(value, int):
        return value == 0
    return False


def _dnc_status_verb(event: dict) -> str:
    """Return Mautic's new DNC status verb for a channel-subscription event.

    Mautic 7.1.3 reports the transition as ``old_status``/``new_status`` verbs
    (ChannelSubscriptionChange::getDncReasonVerb): contactable, unsubscribed,
    bounced or manual. Earlier ECP payload shapes are still accepted.
    """
    for key in ("new_status", "newStatus"):
        verb = _lower_str(event.get(key))
        if verb:
            return verb
    return ""


def _is_email_channel_event(event: dict) -> bool:
    return _lower_str(event.get("channel")) in {"", EMAIL_CHANNEL}


def _is_unsubscribe_event(event: dict) -> bool:
    if not _is_email_channel_event(event):
        return False

    if _dnc_status_verb(event) == "unsubscribed":
        return True

    if _is_false_value(event.get("subscribed")):
        return True
    if _is_false_value(event.get("isSubscribed")):
        return True
    if _is_false_value(event.get("subscribedStatus")):
        return True

    for key in ("reason", "status", "type", "action"):
        if _lower_str(event.get(key)) in {"unsubscribe", "unsubscribed"}:
            return True

    return False


def _is_bounce_subscription_change(event: dict) -> bool:
    if not _is_email_channel_event(event):
        return False

    if _dnc_status_verb(event) == "bounced":
        return True

    bounce_values = {
        "bounce",
        "bounced",
        "hard_bounce",
        "hard-bounce",
        "hard bounce",
        "soft_bounce",
        "soft-bounce",
        "soft bounce",
    }
    for key in (
        "reason",
        "status",
        "type",
        "action",
        "event",
        "dncReason",
        "dnc_reason",
        "channelStatus",
        "channel_status",
    ):
        if _lower_str(event.get(key)) in bounce_values:
            return True

    return False


def _hit_from_event(event: dict) -> dict:
    hit = event.get("hit") or {}
    if isinstance(hit, dict):
        return hit
    return {}


def _stat_from_event(event: dict) -> dict:
    """The email stat Mautic 7.1.3 sends for ``mautic.email_on_open``: the
    open payload is ``{"stat": {...}, "timestamp": ...}`` with the email,
    contact and address inside the stat."""
    stat = event.get("stat") or {}
    if isinstance(stat, dict):
        return stat
    return {}


def _email_id_from_event(event: dict) -> str:
    email = event.get("email") or {}
    if isinstance(email, dict):
        email_id = _safe_str(email.get("id"))
        if email_id:
            return email_id

    for container in (_stat_from_event(event), _hit_from_event(event)):
        email = container.get("email") or {}
        if isinstance(email, dict):
            email_id = _safe_str(email.get("id"))
            if email_id:
                return email_id

    hit = _hit_from_event(event)
    if _safe_str(hit.get("source")).lower() == "email":
        return _safe_str(hit.get("sourceId") or hit.get("sourceID"))
    return ""


def _contact_from_event(event: dict) -> dict:
    contact = event.get("contact") or {}
    if isinstance(contact, dict) and contact:
        return contact
    for container in (_stat_from_event(event), _hit_from_event(event)):
        lead = container.get("lead") or {}
        if isinstance(lead, dict) and lead:
            return lead
    return {}


def _contact_id_from_event(event: dict) -> str:
    return _safe_str(_contact_from_event(event).get("id"))


def _email_value_from_field(field) -> str:
    if isinstance(field, dict):
        return _safe_str(field.get("value")).lower()
    return _safe_str(field).lower()


def _recipient_email_from_event(event: dict) -> str:
    contact = _contact_from_event(event)
    direct_email = _email_value_from_field(contact.get("email"))
    if direct_email:
        return direct_email
    stat_email = _email_value_from_field(_stat_from_event(event).get("emailAddress"))
    if stat_email:
        return stat_email

    fields = contact.get("fields") or {}
    if not isinstance(fields, dict):
        return ""
    core = fields.get("core") or {}
    if not isinstance(core, dict):
        return ""
    return _email_value_from_field(core.get("email"))


def _provider_event_id_from_event(event: dict) -> str:
    for key in ("id", "idHash", "eventId", "event_id"):
        value = _safe_str(event.get(key))
        if value:
            return value
    # An open is identified by its stat (one per email and contact), so
    # repeated opens of one email by one contact are one tracking event. The
    # prefix keeps stat ids apart from page-hit ids, which are also integers.
    stat_id = _safe_str(_stat_from_event(event).get("id"))
    if stat_id:
        return f"stat:{stat_id}"
    return _safe_str(_hit_from_event(event).get("id"))


def _url_from_event(event: dict) -> str:
    url = _safe_str(event.get("url"))
    if url:
        return url
    return _safe_str(_hit_from_event(event).get("url"))


def _event_timestamp(event: dict):
    """The provider time of an event (Mautic stamps every delivered event
    with when it was queued), or None if absent or unparseable."""
    raw = _safe_str(event.get("timestamp"))
    if not raw:
        return None
    try:
        parsed = parse_datetime(raw)
    except ValueError:
        return None
    if parsed is None:
        return None
    if timezone.is_naive(parsed):
        return timezone.make_aware(parsed, timezone=datetime_timezone.utc)
    return parsed


def _occurred_at_from_event(event: dict):
    return _event_timestamp(event) or timezone.now()


def _tracking_payload(provider_event_type: str, event: dict) -> dict:
    """What a tracking row keeps of the provider event: identifiers and
    timing only. Contact fields, IP address, user agent, location and email
    content in Mautic's payload are not needed and are not stored."""
    stat = _stat_from_event(event)
    hit = _hit_from_event(event)
    kept = {
        "event": provider_event_type,
        "timestamp": _safe_str(event.get("timestamp"))[:64],
        "email_id": _email_id_from_event(event)[:64],
        "contact_id": _contact_id_from_event(event)[:_CONTACT_ID_MAX],
    }
    for key in ("idHash", "source", "reason", "channel", "old_status", "new_status"):
        value = event.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            kept[key] = str(value)[:255]
    if stat:
        kept["stat"] = {
            key: str(stat[key])[:64]
            for key in ("id", "dateRead", "openCount", "source", "sourceId")
            if isinstance(stat.get(key), (str, int)) and not isinstance(stat.get(key), bool)
        }
    if hit:
        kept["hit"] = {
            key: str(hit[key])[:2048]
            for key in ("id", "url", "source", "sourceId", "dateHit")
            if isinstance(hit.get(key), (str, int)) and not isinstance(hit.get(key), bool)
        }
    return kept


def _iter_event_items(payload: dict):
    for provider_event_type, events in payload.items():
        if provider_event_type not in EVENT_TYPE_MAP:
            if isinstance(events, list):
                yield provider_event_type, None, len(events)
            else:
                yield provider_event_type, None, 1
            continue

        if not isinstance(events, list):
            yield provider_event_type, None, 1
            continue

        for event in events:
            if isinstance(event, dict):
                yield provider_event_type, event, 0
            else:
                yield provider_event_type, None, 1


def _event_type_for_provider_event(provider_event_type: str, event: dict) -> str:
    event_type = EVENT_TYPE_MAP[provider_event_type]
    if provider_event_type == "mautic.lead_channel_subscription_changed":
        if _is_bounce_subscription_change(event):
            return NewsletterCampaignTrackingEvent.EventType.BOUNCED
        if _is_unsubscribe_event(event):
            return NewsletterCampaignTrackingEvent.EventType.UNSUBSCRIBED
        return ""
    return event_type


def _attributable_campaign(email_id: str):
    """Return the one broadcast a Mautic email id belongs to, or None.

    Only a positive integer id can identify a Mautic email. Anything else —
    in particular the empty id of a contact-level DNC event, which carries no
    email reference — must not be compared against ``mautic_email_id``: every
    unsynced draft has that field blank and would match. An ambiguous match is
    refused too, never resolved by picking one row.
    """
    if not (email_id.isascii() and email_id.isdigit()) or int(email_id) < 1:
        return None
    matches = list(
        NewsletterCampaign.objects.filter(mautic_email_id=str(int(email_id)))[:2]
    )
    if len(matches) != 1:
        if matches:
            logger.warning(
                "Mautic webhook email_id=%s matches several broadcasts; not tracked",
                email_id,
            )
        return None
    return matches[0]


def _create_tracking_event(provider_event_type: str, event: dict) -> str:
    event_type = _event_type_for_provider_event(provider_event_type, event)
    if not event_type:
        return "ignored"

    # Consent for contact-level DNC events is handled separately and does not
    # depend on this: tracking needs a broadcast, suppression does not.
    campaign = _attributable_campaign(_email_id_from_event(event))
    if campaign is None:
        return "ignored"

    source = "mautic"
    provider_event_id = _provider_event_id_from_event(event)
    if provider_event_id and NewsletterCampaignTrackingEvent.objects.filter(
        source=source,
        provider_event_id=provider_event_id,
    ).exists():
        return "duplicate"

    mautic_contact_id = _contact_id_from_event(event)
    mapping = None
    if mautic_contact_id:
        mapping = MauticContactMapping.objects.select_related("user").filter(
            mautic_contact_id=mautic_contact_id,
        ).first()

    recipient_email = _recipient_email_from_event(event)
    try:
        with transaction.atomic():
            NewsletterCampaignTrackingEvent.objects.create(
                campaign=campaign,
                user=mapping.user if mapping else None,
                mautic_contact_id=mautic_contact_id[:_CONTACT_ID_MAX],
                # A longer value would make the insert fail and lose the event.
                recipient_email=recipient_email if len(recipient_email) <= _EMAIL_MAX else "",
                event_type=event_type,
                source=source,
                provider_event_id=provider_event_id[:_PROVIDER_ID_MAX],
                url=_url_from_event(event)[:_TRACKING_URL_MAX],
                payload=_tracking_payload(provider_event_type, event),
                occurred_at=_occurred_at_from_event(event),
            )
    except IntegrityError:
        return "duplicate"

    return "created"


def _suppression_reason_for_event(event: dict) -> str:
    """Classify an email channel-subscription event into an ECP reason.

    Returns "" when the event does not represent a suppression this handler
    should act on, including a transition back to contactable.
    """
    verb = _dnc_status_verb(event)
    if verb:
        if verb == CONTACTABLE_VERB:
            return ""
        return classify_dnc_reason(verb)

    # Older/synthetic payload shapes carry the reason on one of these keys.
    if _is_bounce_subscription_change(event):
        return MauticEmailSuppression.Reason.BOUNCED
    if _is_unsubscribe_event(event):
        return MauticEmailSuppression.Reason.UNSUBSCRIBED
    return ""


def _sync_email_suppression(event: dict) -> str:
    """Mirror one Mautic email DNC change onto ECP consent.

    Runs independently of campaign matching: Mautic's channel-subscription
    payload carries no email/broadcast reference, so consent must not depend on
    recognising a campaign. Scope is global email, because that is the only
    scope Mautic gives — the member's per-category NewsletterSubscription rows
    are deliberately left untouched and are re-applied if the block clears.

    Idempotent by construction: the write is a state upsert keyed by user, so a
    redelivered event converges on the same single row.
    """
    if not _is_email_channel_event(event):
        return "ignored"

    contact_id = _contact_id_from_event(event)
    if not contact_id:
        return "ignored"

    mapping = (
        MauticContactMapping.objects.select_related("user")
        .filter(mautic_contact_id=contact_id)
        .first()
    )
    if mapping is None or mapping.user is None:
        # A Mautic contact with no ECP member is normal (imports, leads).
        logger.info(
            "Mautic email DNC change for unmapped contact_id=%s ignored",
            contact_id,
        )
        return "unmapped"

    reason = _suppression_reason_for_event(event)

    if not reason:
        if _dnc_status_verb(event) == CONTACTABLE_VERB:
            # Only a change newer than the suppression may lift it: a delayed
            # or replayed "contactable" must not undo a later unsubscribe or
            # bounce. Without a provider time the order is unknown, so the
            # suppression stays.
            occurred_at = _event_timestamp(event)
            if occurred_at is None:
                logger.warning(
                    "Mautic contactable change without a timestamp for contact_id=%s; "
                    "suppression kept",
                    contact_id,
                )
                return "ignored"
            cleared = clear_email_suppression_if_older(mapping.user, occurred_at)
            return "unsuppressed" if cleared else "ignored"
        return "ignored"

    record_email_suppression(
        mapping.user,
        reason,
        mautic_contact_id=contact_id,
        comments=_safe_str(event.get("comments")),
        occurred_at=_occurred_at_from_event(event),
    )
    return "suppressed"


def _reject(reason: str, message: str, http_status: int) -> Response:
    _observe("rejected", reason=reason)
    return Response({"error": message}, status=http_status)


class MauticNewsletterWebhookView(APIView):
    """Signed Mautic webhook receiver.

    Acknowledgement contract: 200 when every event was handled (created,
    duplicate, ignored or consent-synced); 500 when any event raised, after
    the rest of the batch was still processed. Mautic keeps and retries a
    failed delivery only in ``command_process`` queue mode, and a retry is
    safe: tracking rows are unique per provider event id and consent writes
    are state upserts guarded by event time.
    """

    permission_classes = [AllowAny]
    authentication_classes = []
    # Mautic delivers from one address, one request per event in immediate
    # queue mode, and does not retry a 429: the anonymous API rate would drop
    # broadcast events and get the webhook unpublished. Requests are bounded
    # by the signature, body size and event count checks below instead.
    throttle_classes = []

    def post(self, request, *args, **kwargs):
        max_bytes = _setting_int("MAUTIC_WEBHOOK_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)
        try:
            declared = int(request.META.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            declared = 0
        if declared > max_bytes:
            return _reject("too_large", "Payload too large", status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

        payload_bytes = request.body
        if len(payload_bytes) > max_bytes:
            return _reject("too_large", "Payload too large", status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

        signature = request.headers.get("Webhook-Signature", "")
        # Nothing from the payload is used before the signature is verified.
        if not _validate_mautic_signature(payload_bytes, signature):
            logger.warning("Invalid Mautic newsletter webhook signature")
            return _reject("invalid_signature", "Invalid signature", status.HTTP_401_UNAUTHORIZED)

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return _reject("invalid_json", "Invalid JSON", status.HTTP_400_BAD_REQUEST)

        if not isinstance(payload, dict):
            return _reject("invalid_json", "Invalid JSON", status.HTTP_400_BAD_REQUEST)

        items = list(_iter_event_items(payload))
        max_events = _setting_int("MAUTIC_WEBHOOK_MAX_EVENTS", DEFAULT_MAX_EVENTS)
        if sum(1 if event is not None else count for _, event, count in items) > max_events:
            return _reject("too_many_events", "Too many events", status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

        created = 0
        ignored = 0
        duplicate = 0
        consent_synced = 0
        failed = 0
        failure_types = set()

        for provider_event_type, event, ignored_count in items:
            if event is None:
                ignored += ignored_count
                continue

            event_failed = False
            # Consent runs before, and independently of, campaign matching:
            # Mautic's DNC payload references no email, and a manual block has
            # no tracking event type, yet both must reach ECP consent.
            if provider_event_type == CHANNEL_SUBSCRIPTION_EVENT:
                try:
                    if _sync_email_suppression(event) in {
                        "suppressed",
                        "unsuppressed",
                    }:
                        consent_synced += 1
                except Exception as exc:
                    event_failed = True
                    failure_types.add(type(exc).__name__)
                    logger.exception("Could not synchronize Mautic email suppression")

            try:
                result = _create_tracking_event(provider_event_type, event)
            except Exception as exc:
                # One bad event must not stop the rest of the batch.
                event_failed = True
                failure_types.add(type(exc).__name__)
                logger.exception("Could not record Mautic %s tracking event", provider_event_type)
                result = "failed"

            if event_failed:
                failed += 1
            elif result == "created":
                created += 1
            elif result == "duplicate":
                duplicate += 1
            else:
                ignored += 1

        counts = {
            "received": True,
            "created": created,
            "ignored": ignored,
            "duplicate": duplicate,
            "consent_synced": consent_synced,
            "failed": failed,
        }
        if failed:
            _observe("failed", failed=failed, error_types=sorted(failure_types)[:5])
            return Response(counts, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        _observe("accepted", created=created, duplicate=duplicate, ignored=ignored, consent_synced=consent_synced)
        return Response(counts, status=status.HTTP_200_OK)
