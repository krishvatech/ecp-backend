"""Event platform sync outbox for IMAA Connect.

This module syncs event data only. Participant sync must wait until both
MANDA and IMAA Connect use the same Cognito User Pool, so duplicate checks
can use canonical_event_id + cognito_sub instead of email.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import requests
from django.conf import settings
from django.db.models import F
from django.utils import timezone

from .models import (
    Event,
    EventPlatform,
    ExternalEventMapping,
    IMAA_CONNECT_PLATFORM_SLUG,
    MANDA_PLATFORM_SLUG,
    PlatformSyncJob,
)


class PlatformSyncConfigurationError(RuntimeError):
    """Raised when external platform sync settings are missing."""


class PlatformSyncError(RuntimeError):
    """Raised when an external platform rejects a sync request."""


@dataclass(frozen=True)
class PlatformSyncResult:
    ok: bool
    platform_slug: str
    job_type: str
    message: str = ""
    response_status: int | None = None
    response_body: dict | list | str | None = None


def _iso(value):
    return value.isoformat() if value else None


def _status_for_manda(event: Event) -> str:
    """Map IMAA Connect status values to MANDA status values."""
    if event.status in {"published", "live"} and not event.is_hidden:
        return "published"
    return "draft"


def _enabled_platform_slugs(event: Event) -> list[str]:
    return list(
        event.publications.filter(is_enabled=True, platform__is_active=True)
        .values_list("platform__slug", flat=True)
    )


def _source_platform_slugs_for_event(event: Event) -> set[str]:
    """Return platforms where this local event originally came from.

    A synced target copy must not automatically sync back to its source platform,
    otherwise editing the copied event can create bounce-back updates or duplicate
    events on the source platform. The source/original platform remains the owner
    of that event.
    """
    return set(
        ExternalEventMapping.objects.filter(local_event=event)
        .values_list("source_platform", flat=True)
    )


def build_event_payload(event: Event) -> dict:
    """Build the event payload shared with MANDA.

    Keep this focused on event data only. Registration, participant, payment and
    application data stay platform-specific until the shared-Cognito phase.
    """
    venue_name = (event.venue_name or "").strip()
    venue_address = (event.venue_address or "").strip()
    city = (event.location_city or event.location or "").strip()
    country = (event.location_country or "").strip()
    if not venue_name:
        venue_name = event.location or event.location_city or event.location_country or "IMAA Connect event"

    return {
        "source_platform": "imaa_connect",
        "source_event_id": event.pk,
        "canonical_event_id": str(event.canonical_event_id),
        "title": event.title,
        "slug": event.slug,
        "description": event.description or "",
        "start_at": _iso(event.start_time),
        "end_at": _iso(event.end_time),
        "venue": {
            "name": venue_name,
            "address": venue_address,
            "city": city,
            "country": country,
        },
        "status": _status_for_manda(event),
        "platform_slugs": _enabled_platform_slugs(event),
    }


def enqueue_event_sync_jobs(
    event: Event,
    *,
    upsert_slugs: Iterable[str] | None = None,
    disable_slugs: Iterable[str] | None = None,
) -> list[PlatformSyncJob]:
    """Create outbox jobs for selected external platforms.

    IMAA Connect itself is local, so it is skipped. For now only MANDA receives
    event_upsert/event_disable jobs; participant job types are reserved for the
    later Cognito phase.
    """
    created_jobs: list[PlatformSyncJob] = []
    requested = {
        PlatformSyncJob.JobType.EVENT_UPSERT: set(upsert_slugs or []),
        PlatformSyncJob.JobType.EVENT_DISABLE: set(disable_slugs or []),
    }
    external_slugs = {
        slug
        for slugs in requested.values()
        for slug in slugs
        if slug and slug != IMAA_CONNECT_PLATFORM_SLUG
    }

    # Do not sync a target copy back to the platform it came from.
    # Example: an event created in MANDA and copied into IMAA Connect should not
    # send an upsert back to MANDA when someone edits the IMAA copy.
    source_platforms = _source_platform_slugs_for_event(event)
    external_slugs = {slug for slug in external_slugs if slug not in source_platforms}

    if not external_slugs:
        return created_jobs

    platforms = {
        platform.slug: platform
        for platform in EventPlatform.objects.filter(slug__in=external_slugs, is_active=True)
    }
    payload = build_event_payload(event)

    for job_type, slugs in requested.items():
        for slug in sorted(slugs):
            if slug == IMAA_CONNECT_PLATFORM_SLUG:
                continue
            platform = platforms.get(slug)
            if not platform:
                continue
            job_payload = dict(payload)
            job_payload["job_type"] = job_type
            if job_type == PlatformSyncJob.JobType.EVENT_DISABLE:
                job_payload["status"] = "disabled"
            created_jobs.append(
                PlatformSyncJob.objects.create(
                    event=event,
                    platform=platform,
                    job_type=job_type,
                    payload=job_payload,
                )
            )
    return created_jobs


def sync_event_to_platform(
    event: Event,
    platform: EventPlatform,
    *,
    job_type: str = PlatformSyncJob.JobType.EVENT_UPSERT,
) -> PlatformSyncResult:
    if platform.slug == MANDA_PLATFORM_SLUG:
        return sync_event_to_manda(event, job_type=job_type)

    return PlatformSyncResult(
        ok=True,
        platform_slug=platform.slug,
        job_type=job_type,
        message="No sync handler configured for this platform; skipped.",
    )


def sync_event_to_manda(
    event: Event,
    *,
    job_type: str = PlatformSyncJob.JobType.EVENT_UPSERT,
) -> PlatformSyncResult:
    base_url = getattr(settings, "MANDA_API_BASE_URL", "").rstrip("/")
    secret = getattr(settings, "MANDA_API_INTEGRATION_SECRET", "")
    timeout = getattr(settings, "MANDA_API_TIMEOUT", 20)

    if not base_url or not secret:
        raise PlatformSyncConfigurationError(
            "MANDA_API_BASE_URL and MANDA_API_INTEGRATION_SECRET must be set before processing jobs."
        )

    if job_type == PlatformSyncJob.JobType.EVENT_DISABLE:
        path = "/api/integrations/imaa-connect/events/disable/"
    else:
        path = "/api/integrations/imaa-connect/events/upsert/"

    payload = build_event_payload(event)
    payload["job_type"] = job_type
    if job_type == PlatformSyncJob.JobType.EVENT_DISABLE:
        payload["status"] = "disabled"

    response = requests.post(
        f"{base_url}{path}",
        json=payload,
        headers={"X-IMAA-Connect-Integration-Secret": secret},
        timeout=timeout,
    )

    try:
        body = response.json()
    except ValueError:
        body = response.text

    if response.status_code >= 400:
        raise PlatformSyncError(f"MANDA sync failed: {response.status_code} {body}")

    return PlatformSyncResult(
        ok=True,
        platform_slug=MANDA_PLATFORM_SLUG,
        job_type=job_type,
        message="Synced to MANDA.",
        response_status=response.status_code,
        response_body=body,
    )


def process_platform_sync_job(job: PlatformSyncJob) -> PlatformSyncResult:
    job.mark_processing()
    try:
        result = sync_event_to_platform(job.event, job.platform, job_type=job.job_type)
    except Exception as exc:
        delay = min(3600, 300 * max(1, job.attempts + 1))
        job.mark_failed(exc, retry_delay_seconds=delay)
        raise

    job.mark_succeeded()
    return result


def process_pending_platform_sync_jobs(*, limit: int = 20) -> dict:
    due_jobs = (
        PlatformSyncJob.objects
        .select_related("event", "platform")
        .filter(
            status__in=[PlatformSyncJob.Status.PENDING, PlatformSyncJob.Status.FAILED],
            next_attempt_at__lte=timezone.now(),
            attempts__lt=F("max_attempts"),
        )
        .order_by("next_attempt_at", "id")[:limit]
    )

    summary = {"processed": 0, "succeeded": 0, "failed": 0, "errors": []}
    for job in due_jobs:
        summary["processed"] += 1
        try:
            process_platform_sync_job(job)
            summary["succeeded"] += 1
        except Exception as exc:
            summary["failed"] += 1
            summary["errors"].append({"job_id": job.pk, "error": str(exc)})
    return summary
