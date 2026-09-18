"""ECP staff user <-> Mautic user connection management.

These helpers record a mapping to an *existing* Mautic user whose id was
obtained by a trusted administrator. They never create Mautic users, never
look users up by email, and never change how Mautic API calls authenticate.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db import IntegrityError, models, transaction
from django.utils import timezone

from .mautic.client import MauticClient
from .mautic.exceptions import (
    MauticIdentityError,
    MauticUserConnectionMissingError,
    MauticUserVerificationInvalidError,
    MauticUserVerificationUnavailableError,
    PermanentMauticError,
    TemporaryMauticError,
)
from .mautic.identity import (
    MauticExecutionContext,
    actor_has_marketing_hub_access,
    per_user_execution_enabled,
    resolve_mautic_execution_identity,
)
from .mautic.identity_assertion import is_identity_assertion_configured
from .models import MauticUserConnection


@dataclass(frozen=True)
class VerifiedMauticUser:
    mautic_user_id: int
    username: str
    email: str
    display_name: str
    role_name: str
    is_active: bool


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


def _string(value, *, max_length: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise MauticUserVerificationUnavailableError("Mautic user response is malformed")
    return value.strip()[:max_length]


def _required_string(value, *, max_length: int) -> str:
    result = _string(value, max_length=max_length)
    if not result:
        raise MauticUserVerificationUnavailableError("Mautic user response is malformed")
    return result


def normalize_verified_mautic_user(payload: dict, *, requested_user_id: int) -> VerifiedMauticUser:
    if not isinstance(payload, dict):
        raise MauticUserVerificationUnavailableError("Mautic user response is malformed")

    try:
        returned_id = int(payload.get("id"))
    except (TypeError, ValueError):
        raise MauticUserVerificationUnavailableError("Mautic user response is malformed") from None
    if returned_id != requested_user_id:
        raise MauticUserVerificationInvalidError(
            "Mautic user verification returned a mismatched user"
        )

    is_published = payload.get("isPublished", payload.get("is_published", True))
    if not isinstance(is_published, bool):
        raise MauticUserVerificationUnavailableError("Mautic user response is malformed")
    if not is_published:
        raise MauticUserVerificationInvalidError("Mautic user is not active")

    username = _required_string(payload.get("username"), max_length=191)
    email = _required_string(payload.get("email"), max_length=254)
    first_name = _string(payload.get("firstName", payload.get("first_name")), max_length=191)
    last_name = _string(payload.get("lastName", payload.get("last_name")), max_length=191)
    display_name = _string(payload.get("name"), max_length=255)
    if not display_name:
        display_name = f"{first_name} {last_name}".strip()[:255]

    role = payload.get("role") or {}
    if role is None:
        role = {}
    if not isinstance(role, dict):
        raise MauticUserVerificationUnavailableError("Mautic user response is malformed")
    role_name = _required_string(role.get("name"), max_length=191)

    return VerifiedMauticUser(
        mautic_user_id=returned_id,
        username=username,
        email=email,
        display_name=display_name,
        role_name=role_name,
        is_active=is_published,
    )


def verify_mautic_user(mautic_user_id) -> VerifiedMauticUser:
    requested_user_id = _normalize_mautic_user_id(mautic_user_id)
    try:
        payload = MauticClient().get_user(requested_user_id)
    except TemporaryMauticError as exc:
        raise MauticUserVerificationUnavailableError("Mautic user verification failed") from exc
    except PermanentMauticError as exc:
        raise MauticUserVerificationInvalidError("Mautic user could not be verified") from exc
    return normalize_verified_mautic_user(payload, requested_user_id=requested_user_id)


def _metadata_from_verified_user(verified: VerifiedMauticUser) -> dict:
    return {
        "mautic_username": verified.username,
        "mautic_email": verified.email,
        "mautic_display_name": verified.display_name,
        "mautic_role_name": verified.role_name,
    }


def connect_mautic_user(
    user,
    *,
    mautic_user_id,
    created_by=None,
) -> MauticUserConnection:
    """Make ``mautic_user_id`` the single active Mautic identity for ``user``.

    Any previous active connection for the user is disabled (kept for audit).
    A Mautic user already actively connected to a different ECP user is
    rejected rather than silently moved.
    """
    if not actor_has_marketing_hub_access(user):
        raise MauticIdentityError(
            "Only active Marketing Hub staff users can be connected to Mautic"
        )
    verified_user = verify_mautic_user(mautic_user_id)
    mautic_user_id = verified_user.mautic_user_id
    metadata = _metadata_from_verified_user(verified_user)
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
                    connection.last_verified_at = now
                    connection.last_error = ""
                    connection.save(
                        update_fields=[
                            *metadata.keys(),
                            "last_verified_at",
                            "last_error",
                            "updated_at",
                        ]
                    )
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
                last_verified_at=now,
                **metadata,
            )
    except IntegrityError:
        # Concurrent connect for the same user or Mautic user lost the race to
        # the partial unique indexes.
        raise MauticIdentityError("Mautic user connection changed concurrently; retry") from None


def activate_mautic_user_connection(connection, *, actor=None) -> MauticUserConnection:
    """Re-enable a previously disabled connection.

    Re-checks the same invariants as ``connect_mautic_user`` so a stale row can
    never bypass them.
    """
    if not actor_has_marketing_hub_access(connection.user):
        raise MauticIdentityError(
            "Only active Marketing Hub staff users can be connected to Mautic"
        )

    existing = MauticUserConnection.objects.filter(pk=connection.pk).first()
    if existing is None:
        raise MauticUserConnectionMissingError("Mautic user connection no longer exists")
    if existing.is_usable:
        return existing

    verified_user = verify_mautic_user(connection.mautic_user_id)
    metadata = _metadata_from_verified_user(verified_user)
    now = timezone.now()

    with transaction.atomic():
        locked = (
            MauticUserConnection.objects.select_for_update()
            .filter(pk=connection.pk)
            .first()
        )
        if locked is None:
            raise MauticUserConnectionMissingError("Mautic user connection no longer exists")
        if locked.is_usable:
            return locked

        conflicting = (
            MauticUserConnection.objects.select_for_update()
            .filter(is_active=True)
            .filter(
                models.Q(user_id=locked.user_id) | models.Q(mautic_user_id=locked.mautic_user_id)
            )
            .exclude(pk=locked.pk)
            .first()
        )
        if conflicting is not None:
            if conflicting.user_id != locked.user_id:
                raise MauticIdentityError(
                    "This Mautic user is already connected to another ECP user"
                )
            raise MauticIdentityError(
                "This ECP user already has a different active Mautic connection"
            )

        locked.is_active = True
        locked.status = MauticUserConnection.Status.ACTIVE
        locked.disabled_at = None
        locked.last_error = ""
        locked.connected_at = locked.connected_at or now
        locked.last_verified_at = now
        for field_name, value in metadata.items():
            setattr(locked, field_name, value)
        locked.save(
            update_fields=[
                "is_active",
                "status",
                "disabled_at",
                "last_error",
                "connected_at",
                "last_verified_at",
                *metadata.keys(),
                "updated_at",
            ]
        )
        return locked


def deactivate_mautic_user_connection(connection, *, reason: str = "") -> MauticUserConnection:
    """Disable one specific connection row."""
    with transaction.atomic():
        locked = (
            MauticUserConnection.objects.select_for_update()
            .filter(pk=connection.pk)
            .first()
        )
        if locked is None:
            raise MauticUserConnectionMissingError("Mautic user connection no longer exists")
        if not locked.is_active:
            return locked

        locked.is_active = False
        locked.status = MauticUserConnection.Status.DISABLED
        locked.disabled_at = timezone.now()
        locked.last_error = str(reason or "")[:500]
        locked.save(
            update_fields=["is_active", "status", "disabled_at", "last_error", "updated_at"]
        )
        return locked


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
    auth_mode, blocked_code = _interactive_auth_mode_for(user)
    # Eligibility (active ECP superuser) and access (eligible + active mapping)
    # are reported from the same helper the Marketing Hub permission uses, so
    # this status can never disagree with what the endpoints actually allow.
    eligible = actor_has_marketing_hub_access(user)
    return {
        "eligible": eligible,
        "has_marketing_access": bool(eligible and connected),
        "connected": connected,
        "status": connection.status if connection else "not_connected",
        "mautic_user_id": connection.mautic_user_id if connected else None,
        "mautic_username": (connection.mautic_username or None) if connected else None,
        "last_verified_at": connection.last_verified_at if connection else None,
        "auth_mode": auth_mode,
        "per_user_execution_enabled": per_user_execution_enabled(),
        "identity_signing_configured": is_identity_assertion_configured(),
        "interactive_blocked_code": blocked_code,
    }


def _interactive_auth_mode_for(user) -> tuple[str | None, str]:
    """How an interactive Mautic action by ``user`` would actually authenticate.

    Delegated to the resolver rather than recomputed here, so this status can
    never drift from the real decision. When per-user execution is on but a
    precondition is missing the resolver fails closed, and that is reported as
    ``auth_mode: None`` plus the same code the endpoints return.
    """
    # Imported here: mautic_identity_errors imports the exception types this
    # module also raises, and a module-level import would be circular.
    from .mautic_identity_errors import classify_identity_error

    try:
        identity = resolve_mautic_execution_identity(
            user, MauticExecutionContext.INTERACTIVE
        )
    except MauticIdentityError as exc:
        return None, classify_identity_error(exc)[1]
    return identity.auth_mode.value, ""


def get_mautic_user_connection_or_raise(connection_id) -> MauticUserConnection:
    connection = MauticUserConnection.objects.filter(pk=connection_id).first()
    if connection is None:
        raise MauticUserConnectionMissingError("Mautic user connection does not exist")
    return connection


def describe_mautic_user_connection(connection) -> dict:
    """Non-sensitive representation shared by the admin endpoints."""
    return {
        "id": connection.pk,
        "ecp_user_id": connection.user_id,
        "ecp_username": connection.user.get_username(),
        "mautic_user_id": connection.mautic_user_id,
        "mautic_username": connection.mautic_username or None,
        "mautic_display_name": connection.mautic_display_name or None,
        "mautic_role_name": connection.mautic_role_name or None,
        "status": connection.status,
        "is_active": connection.is_active,
        "connected_at": connection.connected_at,
        "disabled_at": connection.disabled_at,
        "last_verified_at": connection.last_verified_at,
        "created_at": connection.created_at,
        "updated_at": connection.updated_at,
    }
