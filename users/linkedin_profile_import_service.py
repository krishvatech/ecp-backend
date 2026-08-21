from __future__ import annotations

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


def validate_linkedin_import_email(user, profile_data):
    """
    Prevent importing another person's LinkedIn PDF into the current account.
    """
    imported_email = (
        profile_data.get("email") or ""
    ).strip().lower()

    # Some LinkedIn PDFs may not contain email.
    # Keep import compatible with those PDFs.
    if not imported_email:
        return

    known_emails = account_email_addresses(user)

    # The account has no email address on record, so there is nothing to
    # compare the PDF against.  Blocking here would lock such accounts out of
    # the importer entirely.
    if not known_emails:
        return

    if imported_email not in known_emails:
        raise ValidationError(
            "The LinkedIn profile email does not match your account email."
        )


@transaction.atomic
def import_linkedin_profile_data(*, user, profile_data: dict) -> dict:
    """
    Import validated LinkedIn profile preview data.

    This is intentionally separate from the preview endpoint.
    It only writes data after an explicit confirmation request.
    """
    validate_linkedin_import_email(
        user=user,
        profile_data=profile_data,
    )

    imported = {
        "profile_updated": False,
        "experiences_created": 0,
        "educations_created": 0,
        "certifications_created": 0,
        "skills_updated": False,
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
    links = profile.links if isinstance(profile.links, dict) else {}

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
