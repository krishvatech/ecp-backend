"""Read-only participation roster shared by event counters and the owner Companion tab.

An accepted *free* application is an eligible participant, but is NOT automatically
an EventRegistration, an authenticated user, or an authorized networking target.
Paid application-only entries are excluded until there is a real registration and
its existing payment workflow has been completed. Nothing in this module mutates
users, registrations, payments, or application decisions.
"""
from django.contrib.auth import get_user_model
from django.db.models.functions import Lower

from events.models import (
    EventApplicationTrackApplication,
    EventRegistration,
    GuestAttendee,
)


def _email(value):
    return (value or "").strip().lower()


def extra_participant_rows(event, *, include_superusers=False):
    """Deduplicated accepted-free applicants and verified guests not in registrations.

    Existing registration identities, even if cancelled, take precedence: an
    accepted legacy application must not silently resurrect a cancelled member.
    Email matching here ONLY deduplicates counts; it does not link identities.
    """
    accepted = list(
        EventApplicationTrackApplication.objects.filter(
            track__event=event,
            status="accepted",
            accepted_tier__price=0,
        ).exclude(
            application__status__in=("cancelled", "declined")
        ).select_related("application", "application__user", "track", "accepted_tier")
        .order_by("accepted_at", "id")
    )
    guests = list(
        GuestAttendee.objects.filter(
            event=event, email_verified=True, is_banned=False,
            converted_user__isnull=True,
        ).order_by("created_at", "id")
    )

    if not accepted and not guests:
        return []

    registrations = list(
        EventRegistration.objects.filter(event=event).select_related("user")
    )
    reserved_users = {reg.user_id for reg in registrations}
    reserved_emails = {_email(reg.user.email) for reg in registrations if reg.user.email}

    candidates = {_email(ta.application.email) for ta in accepted}
    candidates.update(_email(guest.email) for guest in guests)
    candidates.discard("")
    # Identifies *superuser* accounts only; does not claim an application for them.
    # Fail closed on ambiguous duplicate email matches involving a superuser.
    superuser_emails = set(
        get_user_model().objects.filter(is_superuser=True)
        .annotate(email_lower=Lower("email"))
        .filter(email_lower__in=candidates)
        .values_list("email_lower", flat=True)
    ) if not include_superusers and candidates else set()

    rows = {}
    for ta in accepted:
        app = ta.application
        key = _email(app.email or (app.user.email if app.user_id else ""))
        if (not key or key in reserved_emails or key in superuser_emails
                or (app.user_id and (app.user_id in reserved_users
                                    or (not include_superusers and app.user.is_superuser)))):
            continue
        if key not in rows:
            rows[key] = {
                "id": f"application:{app.id}",
                "registration_id": None,
                "user_id": None,  # Unclaimed applications are not authenticated identities
                "user_name": " ".join(x for x in (app.first_name, app.last_name) if x).strip() or key,
                "user_email": key,
                "source": "accepted_application",
                "badge_labels": [],
                "can_assign_labels": False,
                "track_labels": [],
            }
        if ta.track.label not in rows[key]["track_labels"]:
            rows[key]["track_labels"].append(ta.track.label)

    for guest in guests:
        key = _email(guest.email)
        if (not key or key in reserved_emails or key in superuser_emails
                or key in rows):
            continue
        rows[key] = {
            "id": f"verified-guest:{guest.id}",
            "registration_id": None,
            "user_id": None,
            "user_name": " ".join(x for x in (guest.first_name, guest.last_name) if x).strip() or key,
            "user_email": key,
            "source": "verified_guest",
            "badge_labels": [],
            "can_assign_labels": False,
            "track_labels": [],
        }
    return list(rows.values())


def public_participant_count(event):
    """Publicly visible registered users + unique eligible application/guest rows.

    Virtual speakers are deliberately not counted as registrations unless they
    also hold a registration, matching the pre-existing public count convention.
    """
    cached = getattr(event, "_cached_public_participant_count", None)
    if cached is not None:
        return cached
    from events.serializers import compute_public_registered_count
    registered_count = getattr(event, "_cached_public_registered_count", None)
    if registered_count is None:
        registered_count = getattr(event, "public_registered_count_annotated", None)
    if registered_count is None:
        registered_count = compute_public_registered_count(event)
    value = registered_count + len(extra_participant_rows(event))
    event._cached_public_participant_count = value
    return value


def public_directory_extra_rows(event, *, companion=False):
    """Directory-safe names for accepted free applicants and verified guests.

    Only call from authenticated, access-controlled directory endpoints. Never
    return applicant email, user id or registration id for an unlinked entry:
    being counted does not authorize private profiles or meeting requests.
    """
    rows = []
    for candidate in extra_participant_rows(event):
        source = candidate["source"]
        display_name = (candidate["user_name"] or "").strip()
        # The owner roster can fall back to an email when an application has no
        # name. Never propagate that fallback into a participant-facing directory.
        if not display_name or display_name.lower() == (candidate["user_email"] or "").strip().lower():
            display_name = "Event participant"
        row = {
            "participant_key": candidate["id"],
            "source": source,
            "registration_id": None,
            "user_id": None,
            "display_name": display_name,
            "avatar_url": None,
            "profile_url": None,
            "is_profile_clickable": False,
        }
        if companion:
            row.update({
                "job_title": "", "company": "", "badge_key": "attendee",
                "badge_label": "Accepted application" if source == "accepted_application" else "Verified guest",
                "badge_labels": [], "roles": [], "registered_at": None,
                "is_networking_eligible": False,
            })
        else:
            row.update({
                "email": "", "kyc_status": "", "roles": [],
                "primary_role": None, "role_labels": [],
                "is_public_role_visible": True, "is_hidden_from_public_role_display": False,
                "registered_at": None, "participant_id": None, "display_order": None,
            })
        rows.append(row)
    return rows
