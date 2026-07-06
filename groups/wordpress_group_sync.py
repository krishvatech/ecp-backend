"""WordPress IMAA BuddyPress group discovery sync.

Phase 1 intentionally imports only the WordPress group catalog into
WordPressGroupSource. It does not create Connect users or group memberships.
"""

import html
import logging
import re
from typing import Any, Dict, Iterable

from django.utils import timezone
from django.utils.html import strip_tags

from users.wordpress_api import WordPressAPIClient
from .models import WordPressGroupSource

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
