"""Native Mautic company administration.

Every company and every contact↔company relationship lives in Mautic. This module
holds no Django mirror model and no local join table; it maps the ECP admin shape onto
the official Mautic REST company API and the native `company_id` contact search.

Creating a company here creates a Mautic company only. It never creates an ECP user,
organization, or account.
"""

from __future__ import annotations

import math
from typing import Any

from .contact_services import list_admin_contacts
from .field_services import list_admin_fields
from .mautic import MauticClient


# Mautic requires a company name; everything else is optional and discovered from the
# live company field metadata rather than hardcoded here.
COMPANY_NAME_ALIAS = "companyname"

# Aliases promoted into the flat company summary the list/detail UI reads. These are
# presentation hints only - they are never used to restrict what can be written.
_SUMMARY_ALIASES = {
    "name": "companyname",
    "email": "companyemail",
    "phone": "companyphone",
    "website": "companywebsite",
    "address1": "companyaddress1",
    "address2": "companyaddress2",
    "city": "companycity",
    "state": "companystate",
    "zipcode": "companyzipcode",
    "country": "companycountry",
    "industry": "companyindustry",
    "description": "companydescription",
}


def _field_value(value):
    if isinstance(value, dict):
        if "value" in value:
            return value.get("value")
        if "normalizedValue" in value:
            return value.get("normalizedValue")
        return None
    return value


def _flatten_company_fields(company: dict[str, Any]) -> dict[str, Any]:
    """Flatten Mautic's grouped company `fields` payload into alias -> value."""
    fields = company.get("fields")
    flattened: dict[str, Any] = {}

    if isinstance(fields, dict):
        for group_name, group in fields.items():
            if group_name == "all":
                continue
            if not isinstance(group, dict):
                continue
            for alias, raw_value in group.items():
                flattened[str(alias)] = _field_value(raw_value)

        # Some Mautic responses only populate the flat `all` bucket.
        all_bucket = fields.get("all")
        if isinstance(all_bucket, dict):
            for alias, raw_value in all_bucket.items():
                flattened.setdefault(str(alias), _field_value(raw_value))

    for alias in _SUMMARY_ALIASES.values():
        if alias not in flattened and alias in company:
            flattened[alias] = _field_value(company.get(alias))

    return flattened


def _grouped_company_fields(company: dict[str, Any]) -> dict[str, Any]:
    fields = company.get("fields")
    if not isinstance(fields, dict):
        return {}
    grouped: dict[str, Any] = {}
    for group_name, group in fields.items():
        if group_name == "all" or not isinstance(group, dict):
            continue
        grouped[str(group_name)] = {
            str(alias): _field_value(raw_value) for alias, raw_value in group.items()
        }
    return grouped


def normalize_admin_company(company: dict[str, Any]) -> dict[str, Any]:
    values = _flatten_company_fields(company)

    summary = {
        key: values.get(alias) for key, alias in _SUMMARY_ALIASES.items()
    }
    summary["name"] = str(summary.get("name") or "").strip()

    return {
        "id": str(company.get("id") or ""),
        **summary,
        "score": company.get("score"),
        "is_published": bool(company.get("isPublished", True)),
        "date_added": company.get("dateAdded") or company.get("date_added"),
        "date_modified": company.get("dateModified") or company.get("date_modified"),
        "values": values,
        "field_groups": _grouped_company_fields(company),
    }


def _companies_from_response(data: dict[str, Any]) -> list[dict[str, Any]]:
    companies = data.get("companies")
    if isinstance(companies, dict):
        return [item for item in companies.values() if isinstance(item, dict)]
    if isinstance(companies, list):
        return [item for item in companies if isinstance(item, dict)]
    return []


def _provider_total(data: dict[str, Any], *, start: int, returned: int) -> int:
    try:
        total = int(data.get("total"))
    except (TypeError, ValueError):
        total = start + returned
    return max(0, total)


def list_admin_companies(
    *,
    page: int = 1,
    page_size: int = 25,
    search: str = "",
) -> dict[str, Any]:
    page = max(1, int(page))
    page_size = max(1, min(int(page_size), 100))
    start = (page - 1) * page_size

    params: dict[str, Any] = {"start": start, "limit": page_size}
    search = str(search or "").strip()
    if search:
        params["search"] = search

    data = MauticClient().list_companies(**params)
    companies = _companies_from_response(data)
    results = [normalize_admin_company(company) for company in companies]
    count = _provider_total(data, start=start, returned=len(companies))

    return {
        "count": count,
        "page": page,
        "page_size": page_size,
        "num_pages": max(1, math.ceil(count / page_size)) if count else 1,
        "results": results,
    }


def get_admin_company(company_id) -> dict[str, Any]:
    company_id = _require_company_id(company_id)
    return normalize_admin_company(MauticClient().get_company(company_id))


def _require_company_id(company_id) -> str:
    normalized = str(company_id or "").strip()
    if not normalized:
        raise ValueError("Mautic company ID is required.")
    return normalized


def _writable_company_aliases() -> set[str]:
    """Aliases Mautic currently defines for companies, from live field metadata."""
    metadata = list_admin_fields("company", limit=500)
    return {field["alias"] for field in metadata["results"] if field["alias"]}


def _normalize_company_payload(
    payload: dict[str, Any],
    *,
    partial: bool,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Company payload must be an object.")

    # The accepted keys come from Mautic's own company field definitions, so a custom
    # company field added in Mautic is writable here without any code change.
    allowed = _writable_company_aliases()
    unsupported = sorted(set(payload.keys()) - allowed)
    if unsupported:
        raise ValueError("Unsupported company field(s): " + ", ".join(unsupported))

    data: dict[str, Any] = {}
    for alias, value in payload.items():
        data[str(alias)] = "" if value is None else value

    if not partial and not str(data.get(COMPANY_NAME_ALIAS) or "").strip():
        raise ValueError("companyname is required.")

    if partial and not data:
        raise ValueError("At least one company field is required.")

    return data


def create_admin_company(payload: dict[str, Any]) -> dict[str, Any]:
    data = _normalize_company_payload(payload, partial=False)
    company = MauticClient().create_company(data)
    return get_admin_company(company.get("id"))


def update_admin_company(company_id, payload: dict[str, Any]) -> dict[str, Any]:
    company_id = _require_company_id(company_id)
    # Only the aliases the caller actually sent are forwarded, so a PATCH never
    # overwrites company values the admin did not edit.
    data = _normalize_company_payload(payload, partial=True)
    MauticClient().update_company(company_id, data)
    return get_admin_company(company_id)


def delete_admin_company(company_id) -> dict[str, Any]:
    company_id = _require_company_id(company_id)
    MauticClient().delete_company(company_id)
    return {"deleted": True, "id": company_id}


def list_admin_company_contacts(
    company_id,
    *,
    page: int = 1,
    page_size: int = 25,
    search: str = "",
) -> dict[str, Any]:
    """List the contacts Mautic associates with a company.

    Mautic has no `/api/companies/{id}/contacts` route, but its contact search exposes
    the native `company_id:` command, which joins `companies_leads` in core. Reusing the
    normal admin contact listing keeps ECP enrichment and paging identical to the
    Contacts screen.
    """
    company_id = _require_company_id(company_id)
    if not company_id.isdigit():
        raise ValueError("Mautic company ID must be a positive integer.")

    search = str(search or "").strip()
    combined = f"company_id:{company_id}"
    if search:
        combined = f"{combined} {search}"

    data = list_admin_contacts(page=page, page_size=page_size, search=combined)
    data["company_id"] = company_id
    return data


def add_admin_company_contact(company_id, contact_id) -> dict[str, Any]:
    company_id = _require_company_id(company_id)
    contact_id = str(contact_id or "").strip()
    if not contact_id:
        raise ValueError("Mautic contact ID is required.")

    MauticClient().add_contact_to_company(company_id, contact_id)
    return {"company_id": company_id, "contact_id": contact_id, "associated": True}


def remove_admin_company_contact(company_id, contact_id) -> dict[str, Any]:
    company_id = _require_company_id(company_id)
    contact_id = str(contact_id or "").strip()
    if not contact_id:
        raise ValueError("Mautic contact ID is required.")

    MauticClient().remove_contact_from_company(company_id, contact_id)
    return {"company_id": company_id, "contact_id": contact_id, "associated": False}
