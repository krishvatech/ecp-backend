"""Protected MANDA integration endpoints for event sharing.

These endpoints receive event-only payloads from MANDA. They do not create users,
participants, event registrations, payments, or application statuses. Those flows
must stay platform-specific until MANDA uses the same Cognito user pool as IMAA
Connect.
"""

from __future__ import annotations

import hmac
import re
import uuid
from html import unescape

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.html import strip_tags
from django.utils.text import slugify
from rest_framework import status
from rest_framework.exceptions import APIException, AuthenticationFailed
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from community.models import Community
from .models import (
    Event,
    EventPlatform,
    EventPublication,
    ExternalEventMapping,
    IMAA_CONNECT_PLATFORM_SLUG,
    MANDA_PLATFORM_SLUG,
)

User = get_user_model()

MANDA_SOURCE_PLATFORM = ExternalEventMapping.SOURCE_MANDA
INTEGRATION_SECRET_HEADER = "X-Manda-Integration-Secret"


def _configured_secret() -> str:
    return str(getattr(settings, "MANDA_INTEGRATION_SECRET", "") or "").strip()


def _request_secret(request) -> str:
    return str(request.headers.get(INTEGRATION_SECRET_HEADER, "") or "").strip()


def _is_authorized(request) -> bool:
    configured = _configured_secret()
    provided = _request_secret(request)
    return bool(configured and provided and hmac.compare_digest(configured, provided))


def _int_setting(name: str):
    raw = getattr(settings, name, "")
    if raw in (None, ""):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _integration_context():
    """Return the community/user that should own MANDA-synced events."""
    community_id = _int_setting("MANDA_SYNC_DEFAULT_COMMUNITY_ID")
    user_id = _int_setting("MANDA_SYNC_DEFAULT_USER_ID")

    if not community_id:
        raise ValueError("MANDA_SYNC_DEFAULT_COMMUNITY_ID is not configured.")

    try:
        community = Community.objects.select_related("owner").get(pk=community_id)
    except Community.DoesNotExist as exc:
        raise ValueError("MANDA_SYNC_DEFAULT_COMMUNITY_ID does not match any community.") from exc

    if user_id:
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist as exc:
            raise ValueError("MANDA_SYNC_DEFAULT_USER_ID does not match any user.") from exc
    else:
        user = community.owner

    if not user:
        raise ValueError("MANDA synced event owner user could not be resolved.")

    return community, user


def _parse_uuid(value, field_name="canonical_event_id"):
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a valid UUID.") from exc


def _parse_datetime(value):
    if not value:
        return None
    parsed = parse_datetime(str(value))
    if parsed is None:
        raise ValueError(f"Invalid datetime value: {value}")
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


def _status_from_payload(raw_status: str) -> str:
    valid_statuses = {choice[0] for choice in Event.STATUS_CHOICES}
    status_value = (raw_status or "draft").strip().lower()
    if status_value == "disabled":
        return "draft"
    if status_value in valid_statuses:
        return status_value
    return "draft"


def _unique_slug(base_slug: str, *, exclude_event_id=None) -> str:
    base = slugify(base_slug or "event")[:240] or "event"
    slug = base
    suffix = 2
    qs = Event.objects.all()
    if exclude_event_id:
        qs = qs.exclude(pk=exclude_event_id)
    while qs.filter(slug=slug).exists():
        suffix_text = f"-{suffix}"
        slug = f"{base[:255 - len(suffix_text)]}{suffix_text}"
        suffix += 1
    return slug


def _plain_text_from_html(value: str) -> str:
    """Convert MANDA rich-text HTML into readable plain text for IMAA Connect forms.

    MANDA stores event descriptions as HTML because its public event editor is rich text.
    IMAA Connect event forms currently use plain textarea fields, so storing raw HTML
    would show tags like <h2> and <p> in the UI. Keep the original HTML in
    ExternalEventMapping.last_payload and save a clean text version on Event.
    """
    raw = str(value or "")
    if not raw.strip():
        return ""

    # Add line breaks around common block tags before stripping them so headings,
    # paragraphs and list items remain readable in the plain textarea.
    text = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", raw)
    text = re.sub(r"(?i)</\s*(p|div|h[1-6]|li|ul|ol|section|article)\s*>", "\n", text)
    text = re.sub(r"(?i)<\s*li[^>]*>", "- ", text)
    text = strip_tags(text)
    text = unescape(text)

    # Normalize whitespace but keep paragraph/list separation.
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()]
    compact_lines = []
    previous_blank = False
    for line in lines:
        if line:
            compact_lines.append(line)
            previous_blank = False
        elif not previous_blank and compact_lines:
            compact_lines.append("")
            previous_blank = True
    return "\n".join(compact_lines).strip()


def _publication_slugs_from_payload(payload: dict) -> set[str]:
    raw = payload.get("platform_slugs") or []
    if isinstance(raw, str):
        raw = [part.strip() for part in raw.split(",")]
    if not isinstance(raw, (list, tuple, set)):
        raw = []
    selected = {str(slug).strip().lower() for slug in raw if str(slug or "").strip()}
    # Keep source metadata and local IMAA visibility for a MANDA upsert.
    selected.add(MANDA_PLATFORM_SLUG)
    selected.add(IMAA_CONNECT_PLATFORM_SLUG)
    return selected


def _save_publications(event: Event, payload: dict, *, enabled: bool):
    selected = _publication_slugs_from_payload(payload) if enabled else {MANDA_PLATFORM_SLUG}
    platforms = {platform.slug: platform for platform in EventPlatform.objects.filter(is_active=True)}
    for slug, platform in platforms.items():
        should_enable = enabled and slug in selected
        EventPublication.objects.update_or_create(
            event=event,
            platform=platform,
            defaults={"is_enabled": should_enable},
        )


def _normalise_venue(payload: dict) -> dict:
    venue = payload.get("venue") or {}
    if not isinstance(venue, dict):
        venue = {}
    venue_name = str(venue.get("name") or "").strip()
    venue_address = str(venue.get("address") or "").strip()
    venue_city = str(venue.get("city") or "").strip()
    venue_country = str(venue.get("country") or "").strip()
    location_parts = [part for part in [venue_name, venue_city, venue_country] if part]
    return {
        "venue_name": venue_name,
        "venue_address": venue_address,
        "location_city": venue_city,
        "location_country": venue_country,
        "location": ", ".join(location_parts),
    }


def _event_response(event: Event, mapping: ExternalEventMapping, message: str):
    return Response(
        {
            "ok": True,
            "message": message,
            "event": {
                "id": event.id,
                "slug": event.slug,
                "title": event.title,
                "status": event.status,
                "is_hidden": event.is_hidden,
            },
            "mapping": {
                "source_platform": mapping.source_platform,
                "source_event_id": mapping.source_event_id,
                "canonical_event_id": str(mapping.canonical_event_id),
                "local_event_id": mapping.local_event_id,
                "is_active": mapping.is_active,
            },
        },
        status=status.HTTP_200_OK,
    )


class IntegrationNotConfigured(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "MANDA integration secret is not configured."
    default_code = "integration_not_configured"


class MandaIntegrationBaseView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        """Validate integration auth inside DRF's request/response lifecycle.

        Returning a DRF Response directly from dispatch() can bypass
        finalize_response() and cause AssertionError pages such as
        ".accepted_renderer not set on Response". Raising DRF exceptions here
        returns proper JSON 401/503 responses instead of a 500 HTML page.
        """
        super().initial(request, *args, **kwargs)
        if not _configured_secret():
            raise IntegrationNotConfigured()
        if not _is_authorized(request):
            raise AuthenticationFailed("Invalid MANDA integration secret.")


class MandaEventUpsertView(MandaIntegrationBaseView):
    """Create or update an IMAA Connect event from a MANDA event payload."""

    def post(self, request):
        payload = request.data if isinstance(request.data, dict) else {}

        source_event_id = str(payload.get("source_event_id") or "").strip()
        title = str(payload.get("title") or "").strip()

        try:
            canonical_event_id = _parse_uuid(payload.get("canonical_event_id"))
            start_time = _parse_datetime(payload.get("start_at"))
            end_time = _parse_datetime(payload.get("end_at"))
            community, owner = _integration_context()
        except ValueError as exc:
            return Response({"ok": False, "detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        if not source_event_id:
            return Response({"ok": False, "detail": "source_event_id is required."}, status=status.HTTP_400_BAD_REQUEST)
        if not title:
            return Response({"ok": False, "detail": "title is required."}, status=status.HTTP_400_BAD_REQUEST)

        description = _plain_text_from_html(payload.get("description"))
        source_slug = str(payload.get("slug") or title).strip()
        venue_fields = _normalise_venue(payload)
        event_status = _status_from_payload(payload.get("status"))

        with transaction.atomic():
            mapping = (
                ExternalEventMapping.objects.select_for_update()
                .select_related("local_event")
                .filter(source_platform=MANDA_SOURCE_PLATFORM, source_event_id=source_event_id)
                .first()
            )
            if not mapping:
                mapping = (
                    ExternalEventMapping.objects.select_for_update()
                    .select_related("local_event")
                    .filter(source_platform=MANDA_SOURCE_PLATFORM, canonical_event_id=canonical_event_id)
                    .first()
                )

            if not mapping:
                existing_local_event = (
                    Event.objects.select_for_update()
                    .filter(canonical_event_id=canonical_event_id)
                    .first()
                )
                if existing_local_event:
                    # Bounce-back guard: the original IMAA Connect event already
                    # exists locally. Do not create a second IMAA event when a
                    # copied MANDA event sends the same canonical_event_id back.
                    return Response({
                        "ok": True,
                        "message": "Event already exists locally for this canonical_event_id; bounce-back upsert ignored.",
                        "event": {
                            "id": existing_local_event.id,
                            "slug": existing_local_event.slug,
                            "title": existing_local_event.title,
                            "status": existing_local_event.status,
                            "is_hidden": existing_local_event.is_hidden,
                        },
                    }, status=status.HTTP_200_OK)

            if mapping:
                event = mapping.local_event
                event.title = title
                event.description = description
                event.start_time = start_time
                event.end_time = end_time
                event.status = event_status
                event.is_hidden = False
                event.community = community
                event.created_by = event.created_by or owner
                event.slug = _unique_slug(source_slug, exclude_event_id=event.id)
                for field, value in venue_fields.items():
                    setattr(event, field, value)
                event.save()
                created = False
            else:
                event = Event.objects.create(
                    community=community,
                    created_by=owner,
                    title=title,
                    slug=_unique_slug(source_slug),
                    description=description,
                    start_time=start_time,
                    end_time=end_time,
                    status=event_status,
                    is_hidden=False,
                    **venue_fields,
                )
                created = True

            _save_publications(event, payload, enabled=event_status in {"published", "live"} and not event.is_hidden)

            if mapping:
                mapping.source_event_id = source_event_id
                mapping.canonical_event_id = canonical_event_id
                mapping.local_event = event
                mapping.is_active = True
                mapping.last_payload = dict(payload)
                mapping.last_synced_at = timezone.now()
                mapping.disabled_at = None
                mapping.save(update_fields=[
                    "source_event_id",
                    "canonical_event_id",
                    "local_event",
                    "is_active",
                    "last_payload",
                    "last_synced_at",
                    "disabled_at",
                    "updated_at",
                ])
            else:
                mapping = ExternalEventMapping.objects.create(
                    source_platform=MANDA_SOURCE_PLATFORM,
                    source_event_id=source_event_id,
                    canonical_event_id=canonical_event_id,
                    local_event=event,
                    is_active=True,
                    last_payload=dict(payload),
                    last_synced_at=timezone.now(),
                )

        return _event_response(event, mapping, "Event created from MANDA." if created else "Event updated from MANDA.")


class MandaEventDisableView(MandaIntegrationBaseView):
    """Hide an IMAA Connect event that was unticked in MANDA."""

    def post(self, request):
        payload = request.data if isinstance(request.data, dict) else {}
        source_event_id = str(payload.get("source_event_id") or "").strip()
        canonical_raw = payload.get("canonical_event_id")

        if not source_event_id and not canonical_raw:
            return Response(
                {"ok": False, "detail": "source_event_id or canonical_event_id is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        mapping_qs = ExternalEventMapping.objects.select_related("local_event").filter(
            source_platform=MANDA_SOURCE_PLATFORM
        )
        if source_event_id:
            mapping_qs = mapping_qs.filter(source_event_id=source_event_id)
        else:
            try:
                mapping_qs = mapping_qs.filter(canonical_event_id=_parse_uuid(canonical_raw))
            except ValueError as exc:
                return Response({"ok": False, "detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            mapping = mapping_qs.select_for_update().first()
            if not mapping:
                # Idempotent success: MANDA can safely mark disable jobs as done.
                return Response(
                    {"ok": True, "message": "No mapped IMAA Connect event found; nothing to disable."},
                    status=status.HTTP_200_OK,
                )

            event = mapping.local_event
            event.is_hidden = True
            event.save(update_fields=["is_hidden", "updated_at"])
            EventPublication.objects.filter(event=event, platform__slug=IMAA_CONNECT_PLATFORM_SLUG).update(is_enabled=False)
            mapping.is_active = False
            mapping.last_payload = dict(payload)
            mapping.last_synced_at = timezone.now()
            mapping.disabled_at = timezone.now()
            mapping.save(update_fields=["is_active", "last_payload", "last_synced_at", "disabled_at", "updated_at"])

        return _event_response(event, mapping, "Event disabled from MANDA.")
