"""
Field-level redaction for the public profile endpoint.

``GET /api/users/<id>/profile/`` is reachable without authentication, but it
reuses ``PublicProfileSerializer``, which is also used by screens where the
viewer is the profile owner or platform staff. Rather than splitting the
serializer (and changing what admin screens receive), the response is reduced
here for viewers who are neither the profile owner nor staff.

Only the keys listed below are removed; everything else the endpoint already
returned is left untouched, so existing public screens keep working.
"""

# Contact details and verification state: not needed to render a public card.
PRIVATE_USER_FIELDS = (
    "email",
    "kyc_status",
)

# Contact links, precise location, verification and moderation state.
PRIVATE_PROFILE_FIELDS = (
    "links",
    "location_lat",
    "location_lng",
    "kyc_status",
    "can_edit_profiles",
    "profile_status",
    "profile_status_reason",
    "profile_status_updated_at",
    "last_activity_at",
)

# Uploaded evidence (diplomas, certificates, membership proof) attached to the
# CV-style sections. Never public.
SECTIONS_WITH_DOCUMENTS = (
    "educations",
    "trainings",
    "certifications",
    "memberships",
)


def redact_public_profile(data, viewer_is_privileged: bool):
    """
    Return ``data`` with private fields removed unless the viewer is the
    profile owner or platform staff.

    The input is the already-serialized dict; it is mutated and returned so
    callers can use it inline.
    """
    if viewer_is_privileged:
        return data
    if not isinstance(data, dict):
        return data

    user = data.get("user")
    if isinstance(user, dict):
        for field in PRIVATE_USER_FIELDS:
            user.pop(field, None)

    profile = data.get("profile")
    if isinstance(profile, dict):
        for field in PRIVATE_PROFILE_FIELDS:
            profile.pop(field, None)

    for section in SECTIONS_WITH_DOCUMENTS:
        entries = data.get(section)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict):
                entry.pop("documents", None)

    return data
