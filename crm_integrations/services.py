"""Provider-neutral CRM payload mapping and service entry points."""

from typing import Any

from .providers.base import CRMContactPayload


def _clean(value: Any) -> str:
    return str(value or "").strip()


def build_user_contact_payload(user: Any) -> CRMContactPayload:
    """Build a stable CRM payload from Django User and optional UserProfile."""
    profile = getattr(user, "profile", None)

    return {
        "ecp_user_id": str(user.pk),
        "first_name": _clean(getattr(user, "first_name", "")),
        "last_name": _clean(getattr(user, "last_name", "")),
        "email": _clean(getattr(user, "email", "")).lower(),
        "company": _clean(getattr(profile, "company", "")),
        "job_title": _clean(getattr(profile, "job_title", "")),
        "country": _clean(getattr(profile, "location_country", "")),
        "country_code": _clean(
            getattr(profile, "location_country_code", "")
        ).upper(),
        "is_active": bool(getattr(user, "is_active", True)),
        "profile_status": _clean(getattr(profile, "profile_status", "active"))
        or "active",
    }
