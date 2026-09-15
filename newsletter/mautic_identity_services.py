"""ECP staff user <-> Mautic user connection management (Phase 1).

These helpers record a mapping to an *existing* Mautic user whose id was
obtained by a trusted administrator. They never create Mautic users, never
look users up by email, and never change how Mautic API calls authenticate.
"""

from __future__ import annotations

from django.db import IntegrityError, transaction
from django.utils import timezone

from .mautic.exceptions import MauticIdentityError
from .mautic.identity import MauticAuthMode, actor_has_marketing_hub_access
from .mautic.identity_assertion import is_identity_assertion_configured
from .models import MauticUserConnection


def _normalize_mautic_user_id(value) -> int:
    if isinstance(value, bool):
        raise MauticIdentityError("Mautic user id must be a positive integer")
    try:
        normalized = int(value)
    except (TypeError, ValueError):
        raise MauticIdentityError("Mautic user id must be a positive integer") from None
    if normalized < 1 or str(value).strip() != str(normalized):
        raise MauticIdentityError("Mautic user id must be a positive integer")
    return normalized


def connect_mautic_user(
    user,
    *,
    mautic_user_id,
    mautic_username: str = "",
    mautic_email: str = "",
    mautic_display_name: str = "",
    mautic_role_name: str = "",
    created_by=None,
) -> MauticUserConnection:
    """Make ``mautic_user_id`` the single active Mautic identity for ``user``.

    Any previous active connection for the user is disabled (kept for audit).
    A Mautic user already actively connected to a different ECP user is
    rejected rather than silently moved.
    """
    if not actor_has_marketing_hub_access(user):
        raise MauticIdentityError("Only active Marketing Hub staff users can be connected to Mautic")
    mautic_user_id = _normalize_mautic_user_id(mautic_user_id)
    metadata = {
        "mautic_username": str(mautic_username or "").strip()[:191],
        "mautic_email": str(mautic_email or "").strip()[:254],
        "mautic_display_name": str(mautic_display_name or "").strip()[:255],
        "mautic_role_name": str(mautic_role_name or "").strip()[:191],
    }
    now = timezone.now()

    try:
        with transaction.atomic():
            if (
                MauticUserConnection.objects.select_for_update()
                .filter(is_active=True, mautic_user_id=mautic_user_id)
                .exclude(user=user)
                .exists()
            ):
                raise MauticIdentityError(
                    "This Mautic user is already connected to another ECP user"
                )

            active = list(
                MauticUserConnection.objects.select_for_update().filter(
                    is_active=True,
                    user=user,
                )
            )
            for connection in active:
                if connection.mautic_user_id == mautic_user_id:
                    for field_name, value in metadata.items():
                        setattr(connection, field_name, value)
                    connection.last_error = ""
                    connection.save(update_fields=[*metadata.keys(), "last_error", "updated_at"])
                    return connection

            for connection in active:
                connection.is_active = False
                connection.status = MauticUserConnection.Status.DISABLED
                connection.disabled_at = now
                connection.save(update_fields=["is_active", "status", "disabled_at", "updated_at"])

            return MauticUserConnection.objects.create(
                user=user,
                mautic_user_id=mautic_user_id,
                status=MauticUserConnection.Status.ACTIVE,
                is_active=True,
                created_by=created_by,
                connected_at=now,
                **metadata,
            )
    except IntegrityError:
        # Concurrent connect for the same user or Mautic user lost the race to
        # the partial unique indexes.
        raise MauticIdentityError("Mautic user connection changed concurrently; retry") from None


def disable_mautic_user_connection(user, *, reason: str = "") -> int:
    """Disable the user's active Mautic connection. Returns rows disabled."""
    with transaction.atomic():
        connections = list(
            MauticUserConnection.objects.select_for_update().filter(user=user, is_active=True)
        )
        now = timezone.now()
        for connection in connections:
            connection.is_active = False
            connection.status = MauticUserConnection.Status.DISABLED
            connection.disabled_at = now
            connection.last_error = str(reason or "")[:500]
            connection.save(
                update_fields=["is_active", "status", "disabled_at", "last_error", "updated_at"]
            )
    return len(connections)


def get_mautic_identity_connection_status(user) -> dict:
    """Non-sensitive identity-connection state for the given ECP user."""
    connection = (
        MauticUserConnection.objects.filter(user_id=user.pk)
        .order_by("-is_active", "-created_at", "-id")
        .first()
    )
    connected = bool(connection and connection.is_usable)
    return {
        "connected": connected,
        "status": connection.status if connection else "not_connected",
        "mautic_user_id": connection.mautic_user_id if connected else None,
        "mautic_username": (connection.mautic_username or None) if connected else None,
        "last_verified_at": connection.last_verified_at if connection else None,
        # Phase 1: all Mautic calls still run as the configured service account.
        "auth_mode": MauticAuthMode.SERVICE_ACCOUNT.value,
        "per_user_execution_enabled": False,
        "identity_signing_configured": is_identity_assertion_configured(),
    }
