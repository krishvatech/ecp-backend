"""Paging and searching Mautic's bundled reference catalogs.

Mautic publishes country, region, timezone and locale lists whole — the bridge
endpoint that exposes them takes no search or page parameters, and the region
catalog alone is ~268 KB. So whoever asks for a page of one of these catalogs
gets the whole list from the provider and narrows it here.

The catalogs themselves are never stored in ECP; only the provider's own rows
are filtered and sliced.
"""

from __future__ import annotations

from typing import Any


# The catalogs the marketing bridge publishes at /ecp/fields/choices/{type}.
REFERENCE_CHOICE_SOURCES = {"country", "region", "timezone", "locale"}


def normalize_choice_rows(rows: Any) -> list[dict[str, Any]]:
    """Provider rows as {value, label} pairs, keeping any grouping it sent."""
    normalized = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        value = row.get("value")
        if value is None:
            continue
        choice = {
            "value": value,
            "label": str(row.get("label") or value),
        }
        if row.get("group"):
            choice["group"] = str(row["group"])
        normalized.append(choice)
    return normalized


def filter_reference_choices(
    choices: list[dict[str, Any]],
    *,
    search: str,
    values: list[str],
) -> list[dict[str, Any]]:
    """Resolve specific values, or narrow the catalog by a search term."""
    if values:
        wanted = {str(value) for value in values}
        return [choice for choice in choices if str(choice["value"]) in wanted]

    if search:
        needle = search.lower()
        return [
            choice
            for choice in choices
            if needle in str(choice["label"]).lower()
            or needle in str(choice["value"]).lower()
        ]

    return choices


def reference_choice_page(
    rows: Any,
    *,
    search: str,
    values: list[str],
    start: int,
    limit: int,
) -> dict[str, Any]:
    """One page of a provider catalog, in the shape every choice API returns.

    A value lookup answers with exactly the values asked for: it is resolving a
    saved selection, not browsing.
    """
    choices = filter_reference_choices(
        normalize_choice_rows(rows),
        search=search,
        values=values,
    )
    total = len(choices)

    if values:
        return {
            "results": choices,
            "total": total,
            "start": 0,
            "limit": total,
            "hasMore": False,
        }

    return {
        "results": choices[start : start + limit],
        "total": total,
        "start": start,
        "limit": limit,
        "hasMore": (start + limit) < total,
    }
