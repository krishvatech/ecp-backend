"""Participant sync outbox helpers for IMAA Connect.

This module creates participant sync jobs only for authenticated users that are
linked to Cognito. Email/name are included as display metadata only; the stable
cross-platform identity is canonical_event_id + cognito_sub.
"""

from __future__ import annotations

from django.conf import settings

from .models import (
    EventPlatform,
    EventPublication,
    EventRegistration,
    ExternalEventMapping,
    MANDA_PLATFORM_SLUG,
    PlatformSyncJob,
)


ACTIVE_REGISTRATION_STATUSES = {"registered", "cancellation_requested"}


def _iso(value):
    return value.isoformat() if value else None


def get_user_cognito_sub(user) -> str:
    """Return the Cognito sub linked to a Django user, or an empty string.

    Legacy/local users can still register locally, but they are intentionally not
    synced because email-only matching is not safe enough for cross-platform
    participant identity.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return ""

    try:
        return (
            user.cognito_identities.order_by("id")
            .values_list("cognito_sub", flat=True)
            .first()
            or ""
        )
    except Exception:
        return ""


def _target_platform(platform_slug: str):
    return EventPlatform.objects.filter(slug=platform_slug, is_active=True).first()


def _event_has_enabled_publication(event, platform_slug: str) -> bool:
    return EventPublication.objects.filter(
        event=event,
        platform__slug=platform_slug,
        platform__is_active=True,
        is_enabled=True,
    ).exists()


def _event_is_linked_to_platform(event, platform_slug: str) -> bool:
    """Return True when this event is an imported/linked copy from a platform.

    Some MANDA-origin events in IMAA Connect are identified by
    ExternalEventMapping rather than by an enabled EventPublication row. For
    participant sync, a MANDA-origin IMAA registration must still sync back to
    MANDA so both platforms show the same registered/cancelled state.
    """
    return ExternalEventMapping.objects.filter(
        local_event=event,
        source_platform=platform_slug,
        canonical_event_id=event.canonical_event_id,
        is_active=True,
    ).exists()


def _event_allows_participant_sync_to_platform(event, platform_slug: str) -> bool:
    return (
        _event_has_enabled_publication(event, platform_slug)
        or _event_is_linked_to_platform(event, platform_slug)
    )


def should_sync_registration_to_platform(
    registration: EventRegistration,
    platform_slug: str = MANDA_PLATFORM_SLUG,
) -> bool:
    """Decide whether this local registration can be synced.

    Participant sync is intentionally different from event sync: even when the
    event originally came from MANDA, an IMAA-side registration should still be
    synced to MANDA so both platforms can show "Already registered".
    """
    event = registration.event
    return bool(
        registration.pk
        and event
        and event.canonical_event_id
        and registration.user_id
        and get_user_cognito_sub(registration.user)
        and _target_platform(platform_slug)
        and _event_allows_participant_sync_to_platform(event, platform_slug)
    )


def _display_name(user) -> str:
    first = (getattr(user, "first_name", "") or "").strip()
    last = (getattr(user, "last_name", "") or "").strip()
    full_name = f"{first} {last}".strip()
    return full_name or (getattr(user, "username", "") or "")


def build_participant_payload(registration: EventRegistration, *, status: str | None = None) -> dict:
    """Build the stable participant payload sent to MANDA."""
    event = registration.event
    user = registration.user
    return {
        "source_platform": "imaa_connect",
        "source_participant_id": str(registration.pk),
        "source_registration_id": str(registration.pk),
        "source_event_id": str(event.pk),
        "canonical_event_id": str(event.canonical_event_id),
        "cognito_sub": get_user_cognito_sub(user),
        "email": getattr(user, "email", "") or "",
        "name": _display_name(user),
        "status": status or _participant_status(registration),
        "registered_at": _iso(registration.registered_at),
        "updated_at": _iso(getattr(registration, "updated_at", None)),
    }


def _participant_status(registration: EventRegistration) -> str:
    if registration.status in {"cancelled", "deregistered"} or registration.attendee_status == "cancelled":
        return "cancelled"
    return "confirmed"


def enqueue_participant_upsert(registration: EventRegistration) -> list[PlatformSyncJob]:
    """Create participant_upsert jobs for eligible MANDA publications."""
    if registration.status not in ACTIVE_REGISTRATION_STATUSES:
        return []
    if registration.attendee_status == "cancelled":
        return []
    return _enqueue_participant_job(
        registration,
        PlatformSyncJob.JobType.PARTICIPANT_UPSERT,
        status="confirmed",
    )


def enqueue_participant_cancel(registration: EventRegistration) -> list[PlatformSyncJob]:
    """Create participant_cancel jobs for eligible MANDA publications."""
    return _enqueue_participant_job(
        registration,
        PlatformSyncJob.JobType.PARTICIPANT_CANCEL,
        status="cancelled",
    )


def _enqueue_participant_job(
    registration: EventRegistration,
    job_type: str,
    *,
    status: str,
) -> list[PlatformSyncJob]:
    target_slug = MANDA_PLATFORM_SLUG
    if not should_sync_registration_to_platform(registration, target_slug):
        return []

    platform = _target_platform(target_slug)
    if not platform:
        return []

    payload = build_participant_payload(registration, status=status)
    if not payload.get("cognito_sub"):
        return []
    payload["job_type"] = job_type

    return [
        PlatformSyncJob.objects.create(
            event=registration.event,
            platform=platform,
            job_type=job_type,
            payload=payload,
        )
    ]


def trigger_platform_sync_processing():
    """Best-effort Celery trigger for pending participant sync jobs."""
    if not getattr(settings, "EVENT_PLATFORM_SYNC_TRIGGER_ON_COMMIT", True):
        return

    try:
        from .tasks import process_platform_sync_jobs

        process_platform_sync_jobs.delay(getattr(settings, "EVENT_PLATFORM_SYNC_BATCH_SIZE", 50))
    except Exception:
        # Registration/cancellation must not fail just because Redis/Celery is down.
        # Celery Beat or the manual management command can process pending jobs later.
        pass
