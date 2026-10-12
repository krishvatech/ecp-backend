"""Permanent deletion of an ECP Subscription List and its Mautic segment.

Deactivate (``is_active=False``) stays the reversible operation. Deletion is a
separate, one-way lifecycle on ``NewsletterCategory.deletion_state``:

1. Validate. Nothing changes if any dependency would be silently broken —
   Mautic's own API delete does *not* run the dependency check its UI runs, so
   a segment used by a campaign, an email or another segment's filter would
   simply vanish from it. That check therefore lives here.
2. Mark the row ``deleting`` (and inactive) under a row lock. From this point
   the list is hidden from members and broadcasts, cannot be reactivated, and
   no sync path will write to or recreate its segment.
3. Delete the linked Mautic segment as the acting administrator (the view runs
   this through the identity-attributed mutation helper).
4. Mark the row ``deleted``.

A failure in step 3 leaves the row ``deleting``; repeating the request resumes
at step 1 and treats a segment Mautic already reports missing (HTTP 404) as
deleted, so retries after an ambiguous timeout are safe. The row and every
PROTECTed record (subscriptions, sync events, broadcast audiences) are kept.
"""

from __future__ import annotations

import logging

from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from .category_segment_services import is_missing_segment_error, segment_filters
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .models import (
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterSyncEvent,
)


logger = logging.getLogger(__name__)

LOCK_PREFIX = "newsletter:category-delete:lock"
LOCK_SECONDS = 300
PAGE_SIZE = 100
# A dependency scan that cannot see everything must not report "no
# dependencies"; past this many provider rows it fails closed instead.
MAX_SCAN_ITEMS = 5000

ACTIVE_BROADCAST_STATUSES = (
    NewsletterCampaign.Status.SCHEDULED,
    NewsletterCampaign.Status.SENDING,
)
ACTIVE_SEND_EVENT_STATUSES = (
    NewsletterCampaignSendEvent.Status.PENDING,
    NewsletterCampaignSendEvent.Status.PROCESSING,
)
# Campaign event properties that hold segment ids: "Modify contact's segments"
# (addToLists/removeFromLists) and the "Contact segments" condition (segments).
CAMPAIGN_EVENT_SEGMENT_KEYS = ("addToLists", "removeFromLists", "segments")


class CategoryDeleteError(Exception):
    def __init__(self, message, *, code, status, dependencies=None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.dependencies = dependencies or []

    def as_payload(self):
        payload = {"detail": str(self), "code": self.code}
        if self.dependencies:
            payload["dependencies"] = self.dependencies
        return payload


def live_categories():
    """Every Subscription List that has not been permanently deleted."""
    return NewsletterCategory.objects.exclude(
        deletion_state=NewsletterCategory.DeletionState.DELETED
    )


def client_for_reads() -> MauticClient:
    return MauticClient()


# ------------------------------------------------------------------- locks --


def acquire_lock(category) -> bool:
    try:
        return bool(cache.add(f"{LOCK_PREFIX}:{category.pk}", 1, LOCK_SECONDS))
    except Exception:
        raise CategoryDeleteError(
            "Deletion cannot run right now. Nothing was deleted.",
            code="storage_unavailable",
            status=503,
        ) from None


def release_lock(category) -> None:
    try:
        cache.delete(f"{LOCK_PREFIX}:{category.pk}")
    except Exception:
        pass


# --------------------------------------------------------- ECP dependencies --


def _dependency(kind, *, id, name, detail=""):
    return {"type": kind, "id": str(id), "name": name, "detail": detail}


def ecp_dependencies(category):
    """Return (blockers, warnings) found in the ECP database."""
    blockers = []
    warnings = []

    segment_id = str(category.mautic_segment_id or "").strip()
    if segment_id:
        others = live_categories().filter(mautic_segment_id=segment_id).exclude(pk=category.pk)
        for other in others.order_by("name"):
            blockers.append(
                _dependency(
                    "subscription_list",
                    id=other.slug,
                    name=other.name,
                    detail="Another Subscription List is linked to the same Mautic segment.",
                )
            )

    broadcasts = NewsletterCampaign.objects.filter(audiences=category).order_by("name", "id")
    for campaign in broadcasts.filter(status__in=ACTIVE_BROADCAST_STATUSES):
        blockers.append(
            _dependency(
                "broadcast",
                id=campaign.uuid,
                name=campaign.name,
                detail=f"Broadcast is {campaign.get_status_display().lower()}.",
            )
        )
    pending_sends = (
        broadcasts.exclude(status__in=ACTIVE_BROADCAST_STATUSES)
        .filter(send_event__status__in=ACTIVE_SEND_EVENT_STATUSES)
    )
    for campaign in pending_sends:
        blockers.append(
            _dependency(
                "broadcast",
                id=campaign.uuid,
                name=campaign.name,
                detail="Broadcast has a send in progress.",
            )
        )
    for campaign in broadcasts.filter(status=NewsletterCampaign.Status.DRAFT):
        warnings.append(
            _dependency(
                "broadcast",
                id=campaign.uuid,
                name=campaign.name,
                detail="Draft broadcast targets this list and will need a new audience.",
            )
        )
    return blockers, warnings


# ------------------------------------------------------ Mautic dependencies --


def _rows(data, *keys):
    for key in keys:
        value = data.get(key)
        if isinstance(value, dict):
            return [row for row in value.values() if isinstance(row, dict)]
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def _iterate(fetch, *keys):
    """Yield every row of a paginated Mautic collection, or fail closed."""
    start = 0
    while True:
        data = fetch(start=start, limit=PAGE_SIZE)
        rows = _rows(data, *keys)
        yield from rows
        start += len(rows)
        try:
            total = int(data.get("total"))
        except (TypeError, ValueError):
            total = None
        if not rows or (total is not None and start >= total):
            return
        if start >= MAX_SCAN_ITEMS:
            raise TemporaryMauticError(
                "Mautic dependency scan is too large to complete safely."
            )


def _ids(value):
    if isinstance(value, dict):
        value = list(value.values())
    if not isinstance(value, (list, tuple)):
        value = [value]
    found = set()
    for item in value:
        if isinstance(item, dict):
            item = item.get("id")
        normalized = str(item if item is not None else "").strip()
        if normalized:
            found.add(normalized)
    return found


def _segment_references(segment, segment_id):
    for row in segment_filters(segment):
        if row.get("type") != "leadlist" and row.get("field") != "leadlist":
            continue
        if segment_id in _ids(row.get("properties", {}).get("filter")):
            return True
    return False


def _campaign_references(campaign, segment_id):
    if segment_id in _ids(campaign.get("lists") or []):
        return True
    events = campaign.get("events") or []
    if isinstance(events, dict):
        events = list(events.values())
    for event in events:
        properties = event.get("properties") if isinstance(event, dict) else None
        if not isinstance(properties, dict):
            continue
        for key in CAMPAIGN_EVENT_SEGMENT_KEYS:
            if segment_id in _ids(properties.get(key)):
                return True
    return False


def mautic_dependencies(client, segment_id):
    """Return (segment_missing, blockers) for the linked Mautic segment.

    Reads only. Raises provider errors other than a definitive 404 unchanged,
    so an outage can never be mistaken for "no dependencies".
    """
    try:
        segment = client.get_segment(segment_id)
    except PermanentMauticError as exc:
        if is_missing_segment_error(exc):
            return True, []
        raise

    blockers = []
    if segment_filters(segment):
        blockers.append(
            _dependency(
                "mautic_segment",
                id=segment_id,
                name=str(segment.get("name") or segment_id),
                detail="The linked Mautic segment is dynamic, so ECP does not own it.",
            )
        )

    for other in _iterate(client.list_segments, "lists", "segments"):
        other_id = str(other.get("id") or "").strip()
        if other_id and other_id != segment_id and _segment_references(other, segment_id):
            blockers.append(
                _dependency(
                    "mautic_segment",
                    id=other_id,
                    name=str(other.get("name") or other_id),
                    detail="Another Mautic segment filters on this segment.",
                )
            )

    for campaign in _iterate(client.list_campaigns, "campaigns"):
        if _campaign_references(campaign, segment_id):
            campaign_id = str(campaign.get("id") or "")
            blockers.append(
                _dependency(
                    "mautic_campaign",
                    id=campaign_id,
                    name=str(campaign.get("name") or campaign_id),
                    detail="Mautic campaign uses this segment.",
                )
            )

    # Emails owned by an ECP broadcast are judged by that broadcast's own state
    # (see ecp_dependencies); any other Mautic email targeting the segment
    # would silently lose its audience.
    ecp_email_ids = set(
        NewsletterCampaign.objects.exclude(mautic_email_id="").values_list(
            "mautic_email_id", flat=True
        )
    )
    for email in _iterate(client.list_emails, "emails"):
        email_id = str(email.get("id") or "").strip()
        if email_id in ecp_email_ids:
            continue
        if segment_id in _ids(email.get("lists") or []):
            blockers.append(
                _dependency(
                    "mautic_email",
                    id=email_id,
                    name=str(email.get("name") or email_id),
                    detail="Mautic email targets this segment.",
                )
            )
    return False, blockers


# --------------------------------------------------------------- preflight --


def _counts(category):
    subscriptions = NewsletterSubscription.objects.filter(category=category)
    return {
        "subscriber_count": subscriptions.filter(is_subscribed=True).count(),
        "subscription_record_count": subscriptions.count(),
        "sync_event_count": NewsletterSyncEvent.objects.filter(category=category).count(),
    }


def check_category(category, *, mautic_enabled, client=None):
    """Read-only deletion check. Returns the preflight payload."""
    blockers, warnings = ecp_dependencies(category)
    segment_id = str(category.mautic_segment_id or "").strip()
    segment_missing = None

    if segment_id:
        if not mautic_enabled:
            blockers.append(
                _dependency(
                    "mautic_segment",
                    id=segment_id,
                    name=segment_id,
                    detail=(
                        "Mautic synchronization is disabled, so the linked "
                        "segment cannot be deleted."
                    ),
                )
            )
        else:
            segment_missing, mautic_blockers = mautic_dependencies(
                client or client_for_reads(), segment_id
            )
            blockers.extend(mautic_blockers)

    return {
        "slug": category.slug,
        "name": category.name,
        "is_active": category.is_active,
        "deletion_state": category.deletion_state,
        "mautic_segment_id": segment_id or None,
        "mautic_segment_missing": segment_missing,
        **_counts(category),
        "can_delete": not blockers,
        "blockers": blockers,
        "warnings": warnings,
    }


def raise_if_blocked(report):
    if report["blockers"]:
        raise CategoryDeleteError(
            "This Subscription List cannot be deleted until its dependencies are removed.",
            code="dependency_conflict",
            status=409,
            dependencies=report["blockers"],
        )


# --------------------------------------------------------------- lifecycle --


def begin_deletion(category, *, actor):
    """Move a live list to ``deleting``. Returns the locked, refreshed row.

    ECP broadcast dependencies are re-checked under the row lock, so a
    broadcast scheduled after the provider scan cannot slip through.
    """
    with transaction.atomic():
        locked = NewsletterCategory.objects.select_for_update().get(pk=category.pk)
        if locked.is_deleted:
            return locked
        blockers, _ = ecp_dependencies(locked)
        if blockers:
            raise CategoryDeleteError(
                "This Subscription List cannot be deleted until its dependencies are removed.",
                code="dependency_conflict",
                status=409,
                dependencies=blockers,
            )
        if locked.deletion_state != NewsletterCategory.DeletionState.DELETING:
            locked.deletion_state = NewsletterCategory.DeletionState.DELETING
            locked.is_active = False
            locked.deleted_by = actor
            locked.save(
                update_fields=["deletion_state", "is_active", "deleted_by", "updated_at"]
            )
            logger.info(
                "Subscription List deletion started slug=%s segment_id=%s actor=%s",
                locked.slug,
                locked.mautic_segment_id,
                getattr(actor, "pk", None),
            )
    return locked


def delete_remote_segment(client, segment_id):
    """Delete one Mautic segment. Returns True if Mautic had already lost it."""
    try:
        client.delete_segment(segment_id)
    except PermanentMauticError as exc:
        if is_missing_segment_error(exc):
            return True
        raise
    return False


def finish_deletion(category):
    with transaction.atomic():
        locked = NewsletterCategory.objects.select_for_update().get(pk=category.pk)
        if not locked.is_deleted:
            locked.deletion_state = NewsletterCategory.DeletionState.DELETED
            locked.is_active = False
            locked.deleted_at = timezone.now()
            locked.save(
                update_fields=["deletion_state", "is_active", "deleted_at", "updated_at"]
            )
            logger.info(
                "Subscription List deleted slug=%s segment_id=%s",
                locked.slug,
                locked.mautic_segment_id,
            )
    return locked


def deletion_payload(category, *, already_deleted=False, segment_already_missing=False, warnings=None):
    segment_id = str(category.mautic_segment_id or "").strip()
    return {
        "slug": category.slug,
        "name": category.name,
        "deletion_state": category.deletion_state,
        "deleted_at": category.deleted_at,
        "mautic_segment_id": segment_id or None,
        "mautic_segment_deleted": bool(segment_id),
        "mautic_segment_already_missing": segment_already_missing,
        "already_deleted": already_deleted,
        "warnings": warnings or [],
    }
