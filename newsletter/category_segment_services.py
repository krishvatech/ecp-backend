"""Subscription List (NewsletterCategory) <-> Mautic segment mapping.

The single authoritative implementation of how an ECP Subscription List is
bound to a native Mautic segment: validating the stored mapping, repairing it
when the provider proves the segment is gone, and queueing desired-state
reconciliation when the mapping moves.

It lives in its own module because both the Subscription List admin endpoints
and broadcast synchronization need it, and business logic must not be reached
by importing a views module.

Execution identity: this is *infrastructure* synchronization and always runs on
the service account, never as the human who happened to trigger it. A segment
recreated while saving a broadcast is a system repair; only the broadcast email
mutation itself is attributed to the acting user.
"""

from __future__ import annotations

import logging

from django.db import transaction

from .mautic import MauticClient, PermanentMauticError
from .models import NewsletterCategory, NewsletterSubscription
from .sync_events import create_newsletter_sync_event


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider segment shape
# ---------------------------------------------------------------------------


def normalize_segment_filter_row(row):
    """Present a filter row the way Mautic evaluates it.

    ContactSegmentFilterCrate reads `properties.filter` and only falls back to the
    legacy top-level `filter`. A PATCH can leave a stale legacy value behind, so
    resolving it the same way keeps the editor showing what actually runs.
    """
    if not isinstance(row, dict):
        return row

    properties = row.get("properties")
    properties = dict(properties) if isinstance(properties, dict) else {}
    if "filter" not in properties and "filter" in row:
        properties["filter"] = row.get("filter")

    normalized = {
        "glue": row.get("glue") or "and",
        "field": row.get("field"),
        "object": row.get("object") or "lead",
        "type": row.get("type"),
        "operator": row.get("operator"),
        "properties": properties,
    }
    for extra in ("display", "merged_property", "null_value", "decisionPath"):
        if extra in row and extra not in ("display",):
            normalized[extra] = row.get(extra)
    return normalized


def segment_filters(segment):
    filters = segment.get("filters")
    if filters in (None, "", [], {}):
        return []
    if isinstance(filters, dict):
        rows = [item for item in filters.values() if item]
    elif isinstance(filters, list):
        rows = filters
    else:
        return []
    return [normalize_segment_filter_row(row) for row in rows]


def segment_is_static(segment):
    return not bool(segment_filters(segment))


def segment_payload_for_category(category, *, include_alias=False):
    payload = {
        "name": category.name,
        "description": category.description,
        "isPublished": bool(category.is_active),
        "isPreferenceCenter": False,
        "filters": [],
    }
    if include_alias:
        payload["alias"] = category.slug
    return payload


def segments_from_response(data):
    segments = data.get("lists") or data.get("segments") or {}
    if isinstance(segments, dict):
        return [segment for segment in segments.values() if isinstance(segment, dict)]
    if isinstance(segments, list):
        return [segment for segment in segments if isinstance(segment, dict)]
    return []


def find_segment_by_exact_alias(client, alias):
    data = client.list_segments(search=f"alias:{alias}", limit=20)
    for segment in segments_from_response(data):
        if str(segment.get("alias") or "").strip() == alias:
            return segment
    return None


def mapped_category_for_segment(segment_id, *, exclude_category=None):
    qs = NewsletterCategory.objects.filter(mautic_segment_id=str(segment_id))
    if exclude_category is not None:
        qs = qs.exclude(pk=exclude_category.pk)
    return qs.first()


def is_missing_segment_error(exc):
    """True only when the provider definitively proved the segment is gone.

    Deliberately narrow. A timeout, a 5xx, an auth failure or any other
    ambiguous provider error must never be read as "this segment does not
    exist", because that would turn a transient outage into segment creation.
    """
    return "HTTP 404" in str(exc)


def compensate_created_segment(client, segment_id):
    try:
        client.update_segment(segment_id, {"isPublished": False})
    except Exception:
        logger.exception(
            "Could not compensate newly-created Mautic segment_id=%s",
            segment_id,
        )


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------


def queue_category_reconciliation(category):
    """Queue desired-state sync events for every subscription in a category.

    Intentionally covers subscribed *and* unsubscribed rows: when a category
    points at a different Mautic segment, the new segment has to learn both who
    belongs in it and who must stay out of it.
    """
    event_ids = []
    subscriptions = NewsletterSubscription.objects.filter(category=category).select_related(
        "category"
    )
    for subscription in subscriptions.iterator():
        event = create_newsletter_sync_event(subscription)
        event_ids.append(event.pk)

    def dispatch_events():
        from .tasks import process_newsletter_sync_event

        for event_id in event_ids:
            try:
                process_newsletter_sync_event.delay(event_id)
            except Exception:
                logger.exception(
                    "Could not dispatch newsletter reconciliation event_id=%s",
                    event_id,
                )

    if event_ids:
        transaction.on_commit(dispatch_events)
    return len(event_ids)


# ---------------------------------------------------------------------------
# Mapping validation and repair
# ---------------------------------------------------------------------------


def ensure_category_segment(category, *, client=None):
    """Return (segment_id, mapping_changed) for one Subscription List.

    Order of preference: keep a mapping the provider still honours, otherwise
    adopt an exact-alias segment that is safe to adopt, otherwise create one.
    Raises rather than guessing whenever ownership is ambiguous.
    """
    client = client or MauticClient()
    segment_id = str(category.mautic_segment_id or "").strip()
    if segment_id:
        try:
            segment = client.get_segment(segment_id)
        except PermanentMauticError as exc:
            # Anything other than a definitive 404 propagates untouched.
            if not is_missing_segment_error(exc):
                raise
            segment = None
        if segment is not None:
            if not segment_is_static(segment):
                raise PermanentMauticError("Mapped Mautic segment is dynamic.")
            client.update_segment(segment_id, segment_payload_for_category(category))
            return segment_id, False

    existing = find_segment_by_exact_alias(client, category.slug)
    if existing is not None:
        if not segment_is_static(existing):
            raise PermanentMauticError(
                "A dynamic Mautic segment already uses this newsletter slug."
            )
        segment_id = str(existing["id"])
        mapped = mapped_category_for_segment(segment_id, exclude_category=category)
        if mapped is not None:
            raise PermanentMauticError(
                "Mautic segment is already mapped to another newsletter category."
            )
        client.update_segment(segment_id, segment_payload_for_category(category))
        category.mautic_segment_id = segment_id
        category.save(update_fields=["mautic_segment_id", "updated_at"])
        return segment_id, True

    segment = client.create_segment(
        segment_payload_for_category(category, include_alias=True)
    )
    category.mautic_segment_id = str(segment["id"])
    try:
        category.save(update_fields=["mautic_segment_id", "updated_at"])
    except Exception:
        compensate_created_segment(client, category.mautic_segment_id)
        raise
    return category.mautic_segment_id, True


def repair_campaign_audience_segments(campaign, *, client=None):
    """Validate every audience mapping a broadcast is about to be sent to.

    Returns the number of mappings that were repaired. A broadcast payload is
    built from `category.mautic_segment_id`, so a mapping that no longer exists
    in Mautic makes the provider reject the whole email. Checking here means a
    stale mapping is healed by the save that would otherwise have failed.

    Each category row is locked for the check so two concurrent saves cannot
    both decide the segment is missing and create two replacements.

    The campaign's prefetched `audiences` cache is dropped whenever anything
    changed, so the caller's very next read — validation and payload building —
    sees the repaired ID rather than the stale one it was loaded with.
    """
    repaired = 0
    category_ids = list(
        campaign.audiences.all().order_by("slug", "id").values_list("pk", flat=True)
    )

    for category_id in category_ids:
        with transaction.atomic():
            category = (
                NewsletterCategory.objects.select_for_update()
                .filter(pk=category_id)
                .first()
            )
            if category is None:
                continue

            _, changed = ensure_category_segment(category, client=client)
            if not changed:
                continue

            repaired += 1
            queue_category_reconciliation(category)
            logger.info(
                "Repaired stale Mautic segment mapping for newsletter category "
                "slug=%s new_segment_id=%s",
                category.slug,
                category.mautic_segment_id,
            )

    if repaired:
        # Without this the already-prefetched audience objects would still hold
        # the old segment id and the payload would target the missing segment.
        prefetched = getattr(campaign, "_prefetched_objects_cache", None)
        if prefetched is not None:
            prefetched.pop("audiences", None)

    return repaired
