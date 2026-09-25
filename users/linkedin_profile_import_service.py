from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher

import phonenumbers
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction

from .models import (
    Education,
    Experience,
    ProfileCertification,
    UserEmailAlias,
    UserProfile,
)


DEFAULT_IMPORT_PHONE_REGION = "IN"


def _resolve_phone_region(profile) -> str:
    """Pick the region used to read a phone number written in national format.

    A LinkedIn PDF prints the number exactly as the member typed it, so a
    national number carries no country of its own.  The member's own profile
    country is the best available signal; the configured default is used only
    when the profile does not record one.
    """
    country_code = str(
        getattr(profile, "location_country_code", "") or ""
    ).strip().upper()

    if len(country_code) == 2 and country_code.isalpha():
        return country_code

    return getattr(
        settings,
        "LINKEDIN_IMPORT_DEFAULT_PHONE_REGION",
        DEFAULT_IMPORT_PHONE_REGION,
    )


def normalize_import_phone_number(phone, region: str | None = None):
    """
    Normalize a phone number imported from a LinkedIn PDF into E.164.

    The platform stores contact phone numbers with a country code and
    validates them as international numbers, so the imported value has to
    carry one too.  A number that already states its own country code is
    parsed as-is; a number written in national format is read using
    ``region``, which the caller resolves from the member's own profile.

    Returns ``None`` when the number is missing or cannot be parsed into a
    valid number, so an unusable value is never written to the profile.
    """
    if not phone:
        return None

    phone = str(phone).strip()
    if not phone:
        return None

    region = (region or DEFAULT_IMPORT_PHONE_REGION).strip().upper() or None

    try:
        parsed = phonenumbers.parse(phone, region)
    except phonenumbers.NumberParseException:
        return None

    if not phonenumbers.is_valid_number(parsed):
        return None

    return phonenumbers.format_number(
        parsed,
        phonenumbers.PhoneNumberFormat.E164,
    )


def _experience_exists(user, item):
    return Experience.objects.filter(
        user=user,
        community_name__iexact=(item.get("community_name") or "").strip(),
        position__iexact=(item.get("position") or "").strip(),
        start_date=item.get("start_date"),
    ).exists()


def _education_exists(user, item):
    return Education.objects.filter(
        user=user,
        school__iexact=(item.get("school") or "").strip(),
        degree__iexact=(item.get("degree") or "").strip(),
    ).exists()


def _certification_exists(user, item):
    return ProfileCertification.objects.filter(
        user=user,
        certification_name__iexact=(
            item.get("certification_name") or ""
        ).strip(),
    ).exists()


def account_email_addresses(user) -> set[str]:
    """Return every email address that identifies ``user``, lower-cased.

    This is the primary account email plus any verified, still-active email
    alias, so a member who exported their PDF under a secondary address is not
    blocked from importing it.
    """
    emails = set()

    primary = (getattr(user, "email", "") or "").strip().lower()
    if primary:
        emails.add(primary)

    alias_emails = UserEmailAlias.objects.filter(
        user=user,
        verified=True,
        is_active=True,
    ).values_list("email", flat=True)

    for alias in alias_emails:
        alias = (alias or "").strip().lower()
        if alias:
            emails.add(alias)

    return emails


_IGNORED_NAME_TOKENS = {
    "mr", "mrs", "ms", "miss", "mx", "dr", "prof", "professor",
    "phd", "ph", "d", "mba", "msc", "bsc", "ma", "ba", "md", "jd",
    "cfa", "ca", "esq",
}


def _normalized_name_tokens(value) -> list[str]:
    """Normalize a person's name for conservative fuzzy comparison."""
    raw = unicodedata.normalize("NFKD", str(value or ""))
    ascii_value = "".join(char for char in raw if not unicodedata.combining(char))
    tokens = re.findall(r"[a-z0-9]+", ascii_value.lower())
    return [token for token in tokens if token not in _IGNORED_NAME_TOKENS]


def _account_display_name(user) -> str:
    profile = getattr(user, "profile", None)
    candidates = [
        getattr(profile, "full_name", "") if profile else "",
        user.get_full_name() if hasattr(user, "get_full_name") else "",
    ]

    for candidate in candidates:
        candidate = (candidate or "").strip()
        if candidate:
            return candidate

    return ""


def _person_names_match(account_name: str, imported_name: str) -> bool:
    """Return True for strong name matches while avoiding surname-only matches.

    Credentials/honorifics are ignored (for example ``Christopher Kummer, PhD``
    vs ``Christopher Kummer``).  For non-exact matches, the surname must match
    and the first names must be exact, a meaningful prefix (Chris/Christopher),
    or very similar.
    """
    account_tokens = _normalized_name_tokens(account_name)
    imported_tokens = _normalized_name_tokens(imported_name)

    if not account_tokens or not imported_tokens:
        return False

    if account_tokens == imported_tokens:
        return True

    if account_tokens[-1] != imported_tokens[-1]:
        return False

    account_first = account_tokens[0]
    imported_first = imported_tokens[0]
    if account_first == imported_first:
        return True

    shorter, longer = sorted((account_first, imported_first), key=len)
    if len(shorter) >= 4 and longer.startswith(shorter):
        return True

    return SequenceMatcher(None, account_first, imported_first).ratio() >= 0.82


def assess_linkedin_import_identity(user, profile_data: dict) -> dict:
    """Describe whether the uploaded LinkedIn identity matches the account.

    This is intentionally advisory for preview and is re-evaluated during
    confirmation.  It never changes Cognito or login credentials.
    """
    imported_email = (profile_data.get("email") or "").strip().lower()
    primary_email = (getattr(user, "email", "") or "").strip().lower()
    imported_name = (profile_data.get("full_name") or "").strip()
    account_name = _account_display_name(user)
    known_emails = account_email_addresses(user)

    result = {
        "status": "matched",
        "email_match": None,
        "name_match": None,
        "requires_confirmation": False,
        "can_add_email": False,
        "account_email": primary_email,
        "linkedin_email": imported_email,
        "account_name": account_name,
        "linkedin_name": imported_name,
    }

    # Preserve the existing behavior for PDFs without an email, or accounts
    # that have no comparable email address.
    if not imported_email or not known_emails:
        return result

    if imported_email in known_emails:
        result["email_match"] = True
        return result

    name_match = _person_names_match(account_name, imported_name)
    result.update({
        "status": "review" if name_match else "blocked",
        "email_match": False,
        "name_match": name_match,
        "requires_confirmation": bool(name_match),
        "can_add_email": bool(name_match),
    })
    return result


def validate_linkedin_import_identity(
    user,
    profile_data: dict,
    *,
    ownership_confirmed: bool = False,
) -> dict:
    """Enforce identity checks before writing imported profile data."""
    assessment = assess_linkedin_import_identity(user, profile_data)

    if assessment["status"] == "blocked":
        raise ValidationError(
            "This LinkedIn profile appears to belong to another person. "
            "Please upload your own LinkedIn profile."
        )

    if assessment["status"] == "review" and not ownership_confirmed:
        raise ValidationError(
            "The LinkedIn profile email differs from your account email. "
            "Please confirm that this is your LinkedIn profile to continue."
        )

    return assessment


def validate_linkedin_import_email(user, profile_data):
    """Backward-compatible strict validation used by older callers/tests."""
    return validate_linkedin_import_identity(
        user,
        profile_data,
        ownership_confirmed=False,
    )


def _add_secondary_profile_email(profile, email: str) -> bool:
    """Add an email using the same structure as Profile -> Edit E-Mail."""
    email = (email or "").strip().lower()
    if not email:
        return False

    links = dict(profile.links) if isinstance(profile.links, dict) else {}
    contact = links.get("contact", {})
    contact = dict(contact) if isinstance(contact, dict) else {}
    emails = contact.get("emails", [])
    emails = list(emails) if isinstance(emails, list) else []

    for item in emails:
        if not isinstance(item, dict):
            continue
        if (item.get("email") or "").strip().lower() == email:
            return False

    emails.append({
        "email": email,
        "type": "professional",
        "visibility": "contacts",
    })
    contact["emails"] = emails
    links["contact"] = contact
    profile.links = links
    return True


@transaction.atomic
def import_linkedin_profile_data(
    *,
    user,
    profile_data: dict,
    ownership_confirmed: bool = False,
    add_linkedin_email: bool = False,
) -> dict:
    """
    Import validated LinkedIn profile preview data.

    This is intentionally separate from the preview endpoint.
    It only writes data after an explicit confirmation request.
    """
    identity = validate_linkedin_import_identity(
        user=user,
        profile_data=profile_data,
        ownership_confirmed=ownership_confirmed,
    )

    imported = {
        "profile_updated": False,
        "experiences_created": 0,
        "educations_created": 0,
        "certifications_created": 0,
        "skills_updated": False,
        "email_added": False,
    }

    profile = getattr(user, "profile", None)
    if profile is None:
        profile = UserProfile.objects.create(user=user)

    profile_fields = {
        "full_name": profile_data.get("full_name"),
        "headline": profile_data.get("headline"),
        "bio": profile_data.get("bio"),
        "location": profile_data.get("location"),
        "location_city": profile_data.get("location_city"),
        "location_country": profile_data.get("location_country"),
        "job_title": profile_data.get("current_job_title"),
        "company": profile_data.get("current_company"),
    }

    changed = False
    for field, value in profile_fields.items():
        if value and getattr(profile, field) != value:
            setattr(profile, field, value)
            changed = True

    # Import LinkedIn social profile URL.
    # Keep existing links data and only update LinkedIn entry.
    linkedin_url = (profile_data.get("linkedin_url") or "").strip()
    links = dict(profile.links) if isinstance(profile.links, dict) else {}

    if (
        add_linkedin_email
        and identity["status"] == "review"
        and identity["linkedin_email"]
        and _add_secondary_profile_email(profile, identity["linkedin_email"])
    ):
        links = dict(profile.links) if isinstance(profile.links, dict) else {}
        changed = True
        imported["email_added"] = True

    if linkedin_url:
        if links.get("linkedin") != linkedin_url:
            links["linkedin"] = linkedin_url
            changed = True

    # Import phone number into the existing profile links contact structure.
    # Profile model expects contact.phones list.
    phone = normalize_import_phone_number(
        profile_data.get("phone"),
        region=_resolve_phone_region(profile),
    )
    if phone:
        contact = links.get("contact", {})
        if not isinstance(contact, dict):
            contact = {}

        phones = contact.get("phones", [])
        if not isinstance(phones, list):
            phones = []

        exists = any(
            isinstance(item, dict)
            and item.get("number") == phone
            for item in phones
        )

        if not exists:
            phones.append(
                {
                    # "type" and "visibility" must stay within the values the
                    # profile contact editor offers, or the saved entry shows
                    # up blank there.
                    "number": phone,
                    "type": "personal",
                    "visibility": "contacts",
                }
            )
            changed = True

        contact["phones"] = phones
        links["contact"] = contact

    if changed:
        profile.links = links
        profile.save()
        imported["profile_updated"] = True

    for item in profile_data.get("experiences", []):
        exists = _experience_exists(user, item)

        if exists:
            continue

        Experience.objects.create(
            user=user,
            community_name=item.get("community_name") or "",
            position=item.get("position") or "",
            start_date=item.get("start_date"),
            end_date=item.get("end_date"),
            currently_work_here=bool(item.get("currently_work_here")),
            location=item.get("location") or "",
            description=item.get("description") or "",
        )
        imported["experiences_created"] += 1

    for item in profile_data.get("educations", []):
        exists = _education_exists(user, item)

        if exists:
            continue

        Education.objects.create(
            user=user,
            school=item.get("school") or "",
            degree=item.get("degree") or "",
            field_of_study=item.get("field_of_study") or "",
            start_date=item.get("start_date"),
            end_date=item.get("end_date"),
            grade=item.get("grade") or "",
            description=item.get("description") or "",
        )
        imported["educations_created"] += 1

    linkedin_skills = profile_data.get("skills", [])
    if linkedin_skills:
        cleaned_skills = []
        seen_skills = set()

        for skill in linkedin_skills:
            if not isinstance(skill, str):
                continue

            value = skill.strip()
            key = value.lower()
            if value and key not in seen_skills:
                seen_skills.add(key)
                cleaned_skills.append(value)

        if profile.skills != cleaned_skills:
            profile.skills = cleaned_skills
            profile.save(update_fields=["skills"])
            imported["skills_updated"] = True

    for item in profile_data.get("certifications", []):
        exists = _certification_exists(user, item)

        if exists:
            continue

        ProfileCertification.objects.create(
            user=user,
            certification_name=item.get("certification_name") or "",
            issuing_organization=item.get("issuing_organization") or "",
            issue_date=item.get("issue_date"),
            expiration_date=item.get("expiration_date"),
            no_expiration=bool(item.get("no_expiration")),
            credential_id=item.get("credential_id") or "",
            credential_url=item.get("credential_url") or "",
        )
        imported["certifications_created"] += 1

    return imported
