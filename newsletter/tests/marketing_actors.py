"""Shared fixtures for the Marketing Hub access contract.

An authorized Marketing actor is an **active ECP superuser with an active
Mautic user connection**. Both halves are required: superuser alone cannot
reach the Marketing Hub, and a mapping cannot let a non-superuser in.

Tests that exercise Marketing admin endpoints as a permitted user call
``grant_marketing_access`` on their actor. Tests that exercise denial should use
a plain staff or normal user instead.
"""

from newsletter.models import MauticUserConnection

# Derived from the ECP user id so two actors in the same test never collide on
# the "one active mapping per Mautic user" constraint.
FIXTURE_MAUTIC_USER_ID_BASE = 900000


def marketing_mautic_user_id(user) -> int:
    return FIXTURE_MAUTIC_USER_ID_BASE + user.pk


def grant_marketing_access(user, mautic_user_id=None) -> MauticUserConnection:
    """Make ``user`` a fully authorized Marketing Hub actor."""
    if not user.is_superuser or not user.is_active:
        user.is_superuser = True
        user.is_active = True
        user.save(update_fields=["is_superuser", "is_active"])

    return MauticUserConnection.objects.create(
        user=user,
        mautic_user_id=mautic_user_id or marketing_mautic_user_id(user),
        mautic_username=f"ecp-fixture-{user.pk}",
        mautic_role_name="Administrator",
        status=MauticUserConnection.Status.ACTIVE,
        is_active=True,
    )
