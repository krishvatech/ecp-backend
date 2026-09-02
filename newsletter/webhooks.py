import base64
import hashlib
import hmac
import json
import logging
from datetime import timezone as datetime_timezone

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    MauticContactMapping,
    NewsletterCampaign,
    NewsletterCampaignTrackingEvent,
)


logger = logging.getLogger(__name__)


EVENT_TYPE_MAP = {
    "mautic.email_on_open": NewsletterCampaignTrackingEvent.EventType.OPENED,
    "mautic.email_on_send": NewsletterCampaignTrackingEvent.EventType.DELIVERED,
    "mautic.page_on_hit": NewsletterCampaignTrackingEvent.EventType.CLICKED,
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


def _hit_from_event(event: dict) -> dict:
    hit = event.get("hit") or {}
    if isinstance(hit, dict):
        return hit
    return {}


def _email_id_from_event(event: dict) -> str:
    email = event.get("email") or {}
    if isinstance(email, dict):
        email_id = _safe_str(email.get("id"))
        if email_id:
            return email_id

    hit = _hit_from_event(event)
    email = hit.get("email") or {}
    if isinstance(email, dict):
        email_id = _safe_str(email.get("id"))
        if email_id:
            return email_id

    if _safe_str(hit.get("source")).lower() == "email":
        return _safe_str(hit.get("sourceId") or hit.get("sourceID"))
    return ""


def _contact_from_event(event: dict) -> dict:
    contact = event.get("contact") or {}
    if isinstance(contact, dict) and contact:
        return contact
    lead = _hit_from_event(event).get("lead") or {}
    if isinstance(lead, dict):
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
    return _safe_str(_hit_from_event(event).get("id"))


def _url_from_event(event: dict) -> str:
    url = _safe_str(event.get("url"))
    if url:
        return url
    return _safe_str(_hit_from_event(event).get("url"))


def _occurred_at_from_event(event: dict):
    raw = _safe_str(event.get("timestamp"))
    if raw:
        parsed = parse_datetime(raw)
        if parsed is not None:
            if timezone.is_naive(parsed):
                return timezone.make_aware(parsed, timezone=datetime_timezone.utc)
            return parsed
    return timezone.now()


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


def _create_tracking_event(provider_event_type: str, event: dict) -> str:
    email_id = _email_id_from_event(event)
    campaign = NewsletterCampaign.objects.filter(mautic_email_id=email_id).first()
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

    try:
        with transaction.atomic():
            NewsletterCampaignTrackingEvent.objects.create(
                campaign=campaign,
                user=mapping.user if mapping else None,
                mautic_contact_id=mautic_contact_id,
                recipient_email=_recipient_email_from_event(event),
                event_type=EVENT_TYPE_MAP[provider_event_type],
                source=source,
                provider_event_id=provider_event_id,
                url=_url_from_event(event),
                payload=event,
                occurred_at=_occurred_at_from_event(event),
            )
    except IntegrityError:
        return "duplicate"

    return "created"


class MauticNewsletterWebhookView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        payload_bytes = request.body
        signature = request.headers.get("Webhook-Signature", "")

        if not _validate_mautic_signature(payload_bytes, signature):
            logger.warning("Invalid Mautic newsletter webhook signature")
            return Response(
                {"error": "Invalid signature"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return Response(
                {"error": "Invalid JSON"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not isinstance(payload, dict):
            return Response(
                {"error": "Invalid JSON"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        created = 0
        ignored = 0
        duplicate = 0

        for provider_event_type, event, ignored_count in _iter_event_items(payload):
            if event is None:
                ignored += ignored_count
                continue

            result = _create_tracking_event(provider_event_type, event)
            if result == "created":
                created += 1
            elif result == "duplicate":
                duplicate += 1
            else:
                ignored += 1

        return Response(
            {
                "received": True,
                "created": created,
                "ignored": ignored,
                "duplicate": duplicate,
            },
            status=status.HTTP_200_OK,
        )
