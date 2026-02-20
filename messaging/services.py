# messaging/services.py
from __future__ import annotations

import csv
import io
from typing import Optional

import logging
import requests
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.dateparse import parse_datetime
from django.utils import timezone

from .models import Conversation, Message
from events.models import Event,EventRegistration     # you already reference Event in views
from django.db.models import Q

logger = logging.getLogger(__name__)

User = get_user_model()


def _find_event_for_meeting(meeting_id: str) -> Optional[Event]:
    """
    Map RealtimeKit meetingId -> Event.

    We use Event.dyte_meeting_id as the source of truth.
    """
    return Event.objects.filter(dyte_meeting_id=meeting_id).first()


def _get_or_create_event_conversation(event: Event) -> Conversation:
    """
    Ensure there's a Conversation row linked to this Event.

    Mirrors ConversationViewSet.ensure_event logic.
    """
    title = (
        getattr(event, "title", "")
        or getattr(event, "name", "")
        or f"Event #{event.pk}"
    )

    conv, created = Conversation.objects.get_or_create(
        event=event,
        defaults={
            "created_by": getattr(event, "created_by", None),
            "title": title,
        },
    )

    if not created:
        # Backfill title if empty
        changed = False
        if not conv.title:
            conv.title = title
            changed = True
        if changed:
            conv.save(update_fields=["title"])

    return conv


def _resolve_sender(
    participant_id: str,
    display_name: str,
    event: Optional[Event],
) -> User:
    """
    Map Dyte participant -> Django User using displayName.

    Priority:
      1) EventRegistration for this event (best match).
      2) Global user lookup.
      3) Event creator / superuser / first user fallback.
    """
    name = (display_name or "").strip()

    # 1) Try to match among users registered for THIS event
    if event and name:
        reg = (
            EventRegistration.objects
            .select_related("user__profile")
            .filter(event=event)
            .filter(
                Q(user__profile__full_name__iexact=name)
                | Q(user__first_name__iexact=name)
                | Q(user__last_name__iexact=name)
                | Q(user__username__iexact=name)
            )
            .first()
        )
        if reg:
            return reg.user

    # 2) Global user lookup (in case the user wasn't in registrations)
    if name:
        u = (
            User.objects
            .select_related("profile")
            .filter(
                Q(profile__full_name__iexact=name)
                | Q(first_name__iexact=name)
                | Q(last_name__iexact=name)
                | Q(username__iexact=name)
            )
            .first()
        )
        if u:
            return u

    # 3) Fallbacks
    if event and getattr(event, "created_by_id", None):
        return event.created_by

    return (
        User.objects.filter(is_superuser=True).first()
        or User.objects.first()
    )


def import_chat_csv_from_url(
    chat_download_url: str,
    meeting_id: str,
) -> int:
    """
    Download RealtimeKit chat CSV from `chat_download_url`,
    and insert rows into Message under the Event's Conversation.

    Returns: number of messages imported.
    """
    # 1) Find the related Event
    event = _find_event_for_meeting(meeting_id)
    if not event:
        # You probably want to log this, but don't crash the webhook.
        return 0

    # 2) Ensure Conversation exists for this Event
    conv = _get_or_create_event_conversation(event)

    # 3) Download CSV into memory (no local file on disk)
    try:
        resp = requests.get(chat_download_url, timeout=60)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.warning("Chat CSV download failed for meeting %s: %s", meeting_id, e)
        return 0

    csv_text = resp.content.decode("utf-8", errors="ignore")

    reader = csv.DictReader(io.StringIO(csv_text))

    imported = 0

    with transaction.atomic():
        for row in reader:
            ext_id = (row.get("id") or "").strip()
            if not ext_id:
                continue

            # Skip duplicates safely
            if Message.objects.filter(
                meeting_id=meeting_id,
                external_id=ext_id,
            ).exists():
                continue

            payload_type = (row.get("payloadType") or "").upper()
            raw_payload = row.get("payload") or ""

            # For now: only text; other types you can handle later
            if payload_type == "TEXT_MESSAGE":
                body = raw_payload
            else:
                body = f"[{payload_type}] {raw_payload}"

            display_name = row.get("displayName") or ""
            participant_id = row.get("participantId") or ""

            sender = _resolve_sender(
                participant_id=participant_id,
                display_name=display_name,
                event=event,
            )

            created_at_str = row.get("createdAt") or ""
            created_at = parse_datetime(created_at_str) or timezone.now()

            Message.objects.create(
                conversation=conv,
                sender=sender,
                body=body,
                event=event,
                meeting_id=meeting_id,
                external_id=ext_id,
                created_at=created_at,
            )
            imported += 1

    return imported
