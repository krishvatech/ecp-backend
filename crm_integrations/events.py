"""Durable CRM domain event creation helpers."""

import hashlib
import json
import uuid

from django.db import transaction

from .models import CRMConnection, CRMSyncEvent
from .services import build_user_contact_payload


USER_CREATED = "user.created"
USER_UPDATED = "user.updated"
USER_DEACTIVATED = "user.deactivated"


def _payload_fingerprint(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def build_user_event_idempotency_key(
    connection: CRMConnection,
    event_type: str,
    user_id: int | str,
    payload: dict,
) -> str:
    fingerprint = _payload_fingerprint(payload)
    return (
        f"{connection.provider}:{connection.pk}:{event_type}:"
        f"user:{user_id}:{fingerprint}"
    )


def create_user_sync_events(user, event_type: str) -> list[CRMSyncEvent]:
    """Persist one event per active CRM connection.

    Equal in-flight state is deduplicated, but a state seen in a completed event
    must produce a new event. Otherwise an A -> B -> A change would reuse the
    first succeeded event and never send the final A state to the CRM.
    """
    if event_type not in {USER_CREATED, USER_UPDATED, USER_DEACTIVATED}:
        raise ValueError(f"Unsupported user CRM event type: {event_type}")

    payload = build_user_contact_payload(user)
    events = []

    with transaction.atomic():
        connections = CRMConnection.objects.filter(is_active=True).order_by("pk")
        for connection in connections:
            idempotency_key = build_user_event_idempotency_key(
                connection,
                event_type,
                user.pk,
                payload,
            )
            event = CRMSyncEvent.objects.filter(
                idempotency_key=idempotency_key,
                status__in=(
                    CRMSyncEvent.Status.PENDING,
                    CRMSyncEvent.Status.PROCESSING,
                    CRMSyncEvent.Status.RETRYING,
                ),
            ).first()
            if event is None:
                if CRMSyncEvent.objects.filter(idempotency_key=idempotency_key).exists():
                    idempotency_key = f"{idempotency_key}:{uuid.uuid4().hex[:12]}"
                event = CRMSyncEvent.objects.create(
                    idempotency_key=idempotency_key,
                    connection=connection,
                    event_type=event_type,
                    object_type="user",
                    object_id=str(user.pk),
                    payload=payload,
                )
            events.append(event)

    return events
