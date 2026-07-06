"""WordPress IMAA BuddyPress group discovery sync.

Phase 1 intentionally imports only the WordPress group catalog into
WordPressGroupSource. Phase 2 can also create/update selected Connect Group rows.
"""

import html
import logging
import re
from typing import Any, Dict, Iterable

from django.db import transaction
from django.utils import timezone
from django.utils.html import strip_tags
from django.utils.text import slugify

from users.wordpress_api import WordPressAPIClient
from .models import Group, WordPressGroupSource

logger = logging.getLogger(__name__)


def _text(value: Any) -> str:
    """Normalize WordPress/BuddyPress text values that may be strings or rendered dicts."""
    if value is None:
        return ""
    if isinstance(value, dict):
        value = value.get("rendered") or value.get("raw") or value.get("plaintext") or ""
    value = html.unescape(strip_tags(str(value)))
    value = re.sub(r"\s+", " ", value).strip()
    return value


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_buddypress_group(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Map a BuddyPress REST group payload into our source table shape."""
    group_id = _int(payload.get("id") or payload.get("ID") or payload.get("group_id"))
    name = _text(payload.get("name") or payload.get("title"))
    slug = str(payload.get("slug") or "").strip()
    description = _text(
        payload.get("description")
        or payload.get("content")
        or payload.get("excerpt")
        or payload.get("description_raw")
    )
    status = str(payload.get("status") or payload.get("privacy") or "").strip().lower()
    member_count = _int(
        payload.get("total_member_count")
        or payload.get("members_count")
        or payload.get("member_count")
        or payload.get("count")
    )
    group_url = str(payload.get("link") or payload.get("permalink") or payload.get("url") or "").strip()

    return {
        "wp_group_id": group_id,
        "name": name or f"WordPress Group {group_id}",
        "slug": slug,
        "description": description,
        "status": status,
        "member_count": member_count,
        "group_url": group_url,
        "raw_payload": payload,
    }


def refresh_wordpress_group_sources(groups: Iterable[Dict[str, Any]] | None = None) -> Dict[str, int]:
    """
    Refresh discovered WordPress groups.

    Returns counters. Existing sync_enabled values are preserved so a refresh
    never disables an admin-selected group.
    """
    client = None
    if groups is None:
        # Use the dedicated IMAA group-sync WordPress configuration. Do not use
        # the existing WP_IMAA_* config here because that may already be used
        # for staging.manda.sg / MANDA sync.
        client = WordPressAPIClient.for_group_sync()
        groups = client.get_all_buddypress_groups()

    now = timezone.now()
    created = 0
    updated = 0
    skipped = 0

    for payload in groups:
        normalized = normalize_buddypress_group(payload)
        wp_group_id = normalized.get("wp_group_id")
        if not wp_group_id:
            skipped += 1
            logger.warning("Skipping WordPress group without ID: %s", payload)
            continue

        member_count = normalized["member_count"]
        if member_count == 0 and client is not None:
            # BuddyPress group list can return total_member_count=0 for private
            # groups even when the admin screen shows members. The members
            # endpoint exposes the real count in the X-WP-Total header.
            try:
                member_count = client.get_buddypress_group_member_count(wp_group_id)
            except Exception as exc:  # pragma: no cover - network safety
                logger.warning(
                    "Unable to fetch member count for WordPress group %s: %s",
                    wp_group_id,
                    exc,
                )

        defaults = {
            "name": normalized["name"],
            "slug": normalized["slug"],
            "description": normalized["description"],
            "status": normalized["status"],
            "member_count": member_count,
            "group_url": normalized["group_url"],
            "raw_payload": normalized["raw_payload"],
            "last_fetched_at": now,
        }
        _, was_created = WordPressGroupSource.objects.update_or_create(
            wp_group_id=wp_group_id,
            defaults=defaults,
        )
        if was_created:
            created += 1
        else:
            updated += 1

    return {"created": created, "updated": updated, "skipped": skipped}



def _visibility_from_status(status: str) -> str:
    """Map BuddyPress group privacy to the existing Connect visibility choices."""
    return Group.VISIBILITY_PUBLIC if str(status or "").lower() == "public" else Group.VISIBILITY_PRIVATE


def _join_policy_from_status(status: str) -> str:
    """Map BuddyPress privacy to the safest Connect join policy."""
    status = str(status or "").lower()
    if status == "public":
        return Group.JOIN_OPEN
    if status == "hidden":
        return Group.JOIN_INVITE
    # Private BuddyPress groups generally require request/approval. This keeps
    # them private without allowing open joins inside Connect.
    return Group.JOIN_APPROVAL


def _unique_group_slug(base_value: str, wp_group_id: int, existing_group: Group | None = None) -> str:
    """Return a unique Connect group slug for a WordPress source group."""
    base = slugify(base_value or "") or f"wordpress-group-{wp_group_id}"
    base = base[:180].strip("-") or f"wordpress-group-{wp_group_id}"

    qs = Group.objects.all()
    if existing_group and existing_group.pk:
        qs = qs.exclude(pk=existing_group.pk)

    if not qs.filter(slug=base).exists():
        return base

    wp_slug = f"{base}-wp-{wp_group_id}"[:220].strip("-")
    if not qs.filter(slug=wp_slug).exists():
        return wp_slug

    for i in range(2, 1000):
        suffix = f"-wp-{wp_group_id}-{i}"
        candidate = f"{base[:220 - len(suffix)]}{suffix}".strip("-")
        if not qs.filter(slug=candidate).exists():
            return candidate

    raise ValueError(f"Unable to generate a unique slug for WordPress group {wp_group_id}")


def sync_wordpress_source_to_connect_group(source: WordPressGroupSource, *, actor) -> tuple[Group, bool]:
    """
    Create or update the existing Connect Group row for a selected WP group.

    Phase 2 only creates/updates the group shell. It does not create users or
    group memberships. Existing manual groups are never overwritten.
    """
    if not actor or not getattr(actor, "is_authenticated", False):
        raise ValueError("An authenticated admin user is required to sync a WordPress group.")

    now = timezone.now()
    source_group_id = str(source.wp_group_id)

    group = source.linked_group
    if not group:
        group = Group.objects.filter(
            source=Group.SOURCE_WORDPRESS,
            source_group_id=source_group_id,
        ).first()

    created = group is None

    raw = source.raw_payload or {}
    forum_enabled = bool(raw.get("enable_forum")) if isinstance(raw, dict) else False

    with transaction.atomic():
        if created:
            group = Group(
                name=source.name,
                slug=_unique_group_slug(source.slug or source.name, source.wp_group_id),
                description=source.description,
                visibility=_visibility_from_status(source.status),
                join_policy=_join_policy_from_status(source.status),
                forum_enabled=forum_enabled,
                source=Group.SOURCE_WORDPRESS,
                source_group_id=source_group_id,
                source_slug=source.slug or "",
                source_url=source.group_url or "",
                source_synced_at=now,
                created_by=actor,
                owner=actor,
            )
        else:
            group.name = source.name
            # Do not change an existing slug because local URLs may already be shared.
            if not group.slug:
                group.slug = _unique_group_slug(source.slug or source.name, source.wp_group_id, existing_group=group)
            group.description = source.description
            group.visibility = _visibility_from_status(source.status)
            group.join_policy = _join_policy_from_status(source.status)
            group.forum_enabled = forum_enabled
            group.source = Group.SOURCE_WORDPRESS
            group.source_group_id = source_group_id
            group.source_slug = source.slug or ""
            group.source_url = source.group_url or ""
            group.source_synced_at = now
            if group.owner_id is None:
                group.owner = actor
            if group.created_by_id is None:
                group.created_by = actor

        group.save()

        source.linked_group = group
        source.sync_enabled = True
        source.last_synced_at = now
        source.save(update_fields=["linked_group", "sync_enabled", "last_synced_at", "updated_at"])

    return group, created


def sync_enabled_wordpress_sources_to_connect_groups(*, actor) -> Dict[str, int]:
    """Create/update Connect groups for all WordPress sources marked sync_enabled."""
    created = 0
    updated = 0
    failed = 0

    qs = WordPressGroupSource.objects.filter(sync_enabled=True).select_related("linked_group").order_by("name")
    for source in qs:
        try:
            _, was_created = sync_wordpress_source_to_connect_group(source, actor=actor)
        except Exception as exc:  # pragma: no cover - defensive sync logging
            failed += 1
            logger.exception("Unable to sync WordPress group %s into Connect: %s", source.wp_group_id, exc)
            continue
        if was_created:
            created += 1
        else:
            updated += 1

    return {"created": created, "updated": updated, "failed": failed}
