"""Native Mautic tag administration.

Tags are stored only in Mautic. ECP keeps no tag table and no synchronization layer, so
a tag created here is immediately selectable from the Contact tag picker, which reads
the same native tag records.

Verified Mautic 7.1.3 behaviour this module is built around:

* ``POST /api/tags/new`` accepts only ``tag``. Mautic's TagApiController::getNewEntity
  resolves it through ``getTagByNameOrCreateNewOne``, so creating an existing tag name
  returns that existing tag instead of duplicating it.
* ``description`` is exposed on read but is not bound by the tag form, so Mautic
  silently discards it on write. ECP therefore never offers it as an editable value.
* ``GET /api/tags`` ignores the ``search`` parameter, so name filtering is applied here.
* ``DELETE /api/tags/{id}/delete`` fails when the tag is still in use; that provider
  error is surfaced rather than forced.
"""

from __future__ import annotations

import math
from typing import Any

from .mautic import MauticClient


MAX_TAG_FETCH = 500


def _tags_from_response(data: dict[str, Any]) -> list[dict[str, Any]]:
    tags = data.get("tags")
    if isinstance(tags, dict):
        return [item for item in tags.values() if isinstance(item, dict)]
    if isinstance(tags, list):
        return [item for item in tags if isinstance(item, dict)]
    return []


def normalize_admin_tag(tag: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(tag.get("id") or ""),
        "tag": str(tag.get("tag") or "").strip(),
        "description": tag.get("description"),
    }


def _normalize_tag_name(value, *, field_name: str = "tag") -> str:
    name = str(value or "").strip()
    if not name:
        raise ValueError(f"{field_name} is required.")
    if len(name) > 191:
        raise ValueError(f"{field_name} must be 191 characters or fewer.")
    return name


def list_admin_tag_directory(
    *,
    page: int = 1,
    page_size: int = 25,
    search: str = "",
) -> dict[str, Any]:
    page = max(1, int(page))
    page_size = max(1, min(int(page_size), 100))

    # Mautic ignores `search` on this endpoint, so the full directory is fetched once
    # and filtered/paged here instead of returning misleading provider-side results.
    data = MauticClient().list_tags(limit=MAX_TAG_FETCH)
    tags = [normalize_admin_tag(tag) for tag in _tags_from_response(data)]
    tags = [tag for tag in tags if tag["tag"]]

    search = str(search or "").strip().lower()
    if search:
        tags = [tag for tag in tags if search in tag["tag"].lower()]

    tags.sort(key=lambda tag: tag["tag"].lower())

    count = len(tags)
    start = (page - 1) * page_size
    return {
        "count": count,
        "page": page,
        "page_size": page_size,
        "num_pages": max(1, math.ceil(count / page_size)) if count else 1,
        "results": tags[start : start + page_size],
    }


def get_admin_tag(tag_id) -> dict[str, Any]:
    tag_id = _require_tag_id(tag_id)
    return normalize_admin_tag(MauticClient().get_tag(tag_id))


def _require_tag_id(tag_id) -> str:
    normalized = str(tag_id or "").strip()
    if not normalized:
        raise ValueError("Mautic tag ID is required.")
    return normalized


def create_admin_tag(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Tag payload must be an object.")
    unsupported = sorted(set(payload.keys()) - {"tag"})
    if unsupported:
        raise ValueError("Unsupported tag field(s): " + ", ".join(unsupported))

    name = _normalize_tag_name(payload.get("tag"))
    return normalize_admin_tag(MauticClient().create_tag({"tag": name}))


def update_admin_tag(tag_id, payload: dict[str, Any]) -> dict[str, Any]:
    tag_id = _require_tag_id(tag_id)
    if not isinstance(payload, dict):
        raise ValueError("Tag payload must be an object.")
    unsupported = sorted(set(payload.keys()) - {"tag"})
    if unsupported:
        raise ValueError("Unsupported tag field(s): " + ", ".join(unsupported))

    name = _normalize_tag_name(payload.get("tag"))
    return normalize_admin_tag(MauticClient().update_tag(tag_id, {"tag": name}))


def delete_admin_tag(tag_id) -> dict[str, Any]:
    tag_id = _require_tag_id(tag_id)
    MauticClient().delete_tag(tag_id)
    return {"deleted": True, "id": tag_id}
