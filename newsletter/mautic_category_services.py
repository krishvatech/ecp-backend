"""Mautic categories: shared reads and the check every category picker uses.

Mautic categories organise emails, landing pages, forms, campaigns, segments
and assets (a "global" category shows in every picker); they are not ECP
Subscription Lists. The category with alias ``ecp-subscription-lists`` in the
segment bundle marks the segments that gate Form-sourced marketing email, so
it is reported as protected and no picker accepts it.
"""

from __future__ import annotations

import re
from typing import Any

from . import marketing_cache
from .category_segment_services import CONSENT_CATEGORY_ALIAS
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError

BUNDLES = {
    "email": "Emails",
    "page": "Landing Pages",
    "form": "Forms",
    "campaign": "Campaigns",
    "segment": "Segments",
    "asset": "Assets",
    "plugin:focus": "Focus Items",
    "global": "Global (every type)",
}
TITLE_MAX = 191
DESCRIPTION_MAX = 2000
LIST_LIMIT = 500
COLOR_PATTERN = re.compile(r"^[0-9a-fA-F]{6}$")
ITEM_LABELS = {
    "assets": "assets", "campaigns": "campaigns", "dynamic_content": "dynamic content items", "emails": "emails",
    "focus": "focus items", "forms": "forms", "lead_lists": "segments", "messages": "marketing messages",
    "monitoring": "social monitors", "pages": "landing pages", "point_triggers": "point triggers",
    "points": "point actions", "push_notifications": "push notifications", "sms_messages": "text messages",
    "stages": "stages", "tweets": "tweets", "webhooks": "webhooks",
}


def alias_for(title: str) -> str:
    """The alias Mautic derives from a new category's title."""
    return re.sub(r"[^a-z0-9]+", "-", str(title or "").lower()).strip("-")


def is_protected(category: dict[str, Any]) -> bool:
    return category.get("alias") == CONSENT_CATEGORY_ALIAS and category.get("bundle") == "segment"


def truthy(value) -> bool:
    return value in (True, 1, "1", "true", "True")


def normalize(category: dict[str, Any]) -> dict[str, Any]:
    color = str(category.get("color") or "").lstrip("#")
    normalized = {
        "id": int(category.get("id") or 0),
        "title": str(category.get("title") or ""),
        "alias": str(category.get("alias") or ""),
        "description": str(category.get("description") or ""),
        "color": color if COLOR_PATTERN.match(color) else "",
        "bundle": str(category.get("bundle") or ""),
    }
    normalized["protected"] = is_protected(normalized)
    return normalized


def all_categories(client: MauticClient | None = None, *, fresh: bool = False,
                   published: dict[int, bool] | None = None) -> list[dict[str, Any]]:
    """Every category; ``published`` (from get_category_overview) fills in the
    state the native API leaves out, else isPublished is None (unknown)."""
    client = client or MauticClient()
    data = client.list_categories(start=0, limit=LIST_LIMIT) if fresh else marketing_cache.categories(client, limit=LIST_LIMIT)
    rows = data.get("categories") if isinstance(data, dict) else None
    rows = rows.values() if isinstance(rows, dict) else rows or []
    categories = [normalize(row) for row in rows if isinstance(row, dict) and row.get("id")]
    for category in categories:
        category["isPublished"] = published.get(category["id"]) if published is not None else None
    return sorted(categories, key=lambda category: (category["bundle"], category["title"].lower()))


def publish_states(client: MauticClient | None = None) -> dict[int, bool] | None:
    """Published state per category, or None when the plugin cannot say."""
    try:
        return (client or MauticClient()).get_category_overview()["published"]
    except (TemporaryMauticError, PermanentMauticError):
        return None


def category_choice(value, bundle: str, *, client: MauticClient | None = None) -> int | None:
    """Check a category picked for an item of ``bundle``: None clears it.

    Raises ValueError with a message for the admin. A category created in
    Mautic a moment ago may not be in the cached list yet, so a miss re-reads."""
    if value in (None, "", 0, "0"):
        return None
    try:
        category_id = int(value)
    except (TypeError, ValueError):
        raise ValueError("Choose a category from the list.") from None
    found = None
    for fresh in (False, True):
        found = next((category for category in all_categories(client, fresh=fresh) if category["id"] == category_id), None)
        if found:
            break
    if found is None:
        raise ValueError("That category no longer exists. Refresh and choose again.")
    states = publish_states(client)
    if states is not None and states.get(category_id) is False:
        raise ValueError("That category is unpublished. Publish it under Categories or choose another.")
    if found["protected"]:
        raise ValueError("The Subscription List category is managed by ECP and can't be chosen here.")
    if found["bundle"] not in (bundle, "global"):
        raise ValueError(f"Choose a category for {BUNDLES.get(bundle, bundle).lower()}.")
    return category_id
