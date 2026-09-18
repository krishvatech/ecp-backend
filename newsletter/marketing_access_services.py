"""Marketing Access: who may use the Marketing Hub, and how they get there.

One human login exists (Cognito/ECP). A Mautic user is a provider-side identity,
authorization and attribution principal only: the person never logs into Mautic,
never sees Mautic credentials and never supplies a ``mautic_user_id``.

Current scope is deliberately narrow:

* eligible target  = active ECP **superuser** (staff are not eligible)
* eligible manager = active ECP **superuser**
* Marketing Hub access = eligible target **and** an active MauticUserConnection

The mapping is always keyed by the immutable ECP user id and the immutable
Mautic user id. Email is used to *discover* an existing provider identity so
provisioning can refuse to guess; it never becomes the runtime mapping key.
"""

from __future__ import annotations

import logging
import re
import secrets

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.exceptions import (
    MarketingAccessAlreadyActiveError,
    MarketingAccessNotEligibleError,
    MarketingIdentityConflictError,
    MarketingProvisioningFailedError,
    MarketingSelfManagementError,
    MauticIdentityError,
)
from .mautic.identity import per_user_execution_enabled
from .mautic_identity_services import (
    activate_mautic_user_connection,
    connect_mautic_user,
    deactivate_mautic_user_connection,
    get_mautic_identity_connection_status,
)
from .models import MauticUserConnection

logger = logging.getLogger(__name__)

User = get_user_model()

# Mautic's users.username column is varchar(191); stay well inside it.
MAX_USERNAME_LENGTH = 100
_USERNAME_SAFE_RE = re.compile(r"[^a-z0-9]+")
# Bounded so a pathological provider state cannot loop forever.
_MAX_USERNAME_ATTEMPTS = 20


class MarketingState:
    """Marketing status as the Users UI renders it.

    Derived from ECP flags plus the connection row: no separate table mirrors
    state that MauticUserConnection already models.
    """

    NOT_ELIGIBLE = "not_eligible"
    ELIGIBLE_NOT_ADDED = "eligible_not_added"
    ACTIVE = "active"
    INACTIVE = "inactive"
    PROVISIONING_ERROR = "provisioning_error"


def is_marketing_eligible(user) -> bool:
    """Only an active ECP superuser may hold Marketing access."""
    return bool(
        user is not None
        and getattr(user, "is_authenticated", True)
        and getattr(user, "is_active", False)
        and getattr(user, "is_superuser", False)
    )


def is_marketing_manager(user) -> bool:
    """Only an active ECP superuser may manage other people's Marketing access."""
    return bool(
        user is not None
        and getattr(user, "is_authenticated", False)
        and getattr(user, "is_active", False)
        and getattr(user, "is_superuser", False)
    )


def latest_connection_for(user) -> MauticUserConnection | None:
    """The row that represents this user's Marketing access, active first."""
    return (
        MauticUserConnection.objects.filter(user_id=getattr(user, "pk", None))
        .order_by("-is_active", "-created_at", "-id")
        .first()
    )


def marketing_state_for(user, connection=None) -> str:
    if not is_marketing_eligible(user):
        return MarketingState.NOT_ELIGIBLE
    if connection is None:
        return MarketingState.ELIGIBLE_NOT_ADDED
    if connection.is_usable:
        return MarketingState.ACTIVE
    if connection.status == MauticUserConnection.Status.ERROR:
        return MarketingState.PROVISIONING_ERROR
    return MarketingState.INACTIVE


def has_marketing_hub_access(user) -> bool:
    """The authoritative Marketing Hub rule.

    Superuser alone is not enough, and a stale/inactive mapping is not enough.
    """
    if not is_marketing_eligible(user):
        return False
    connection = (
        MauticUserConnection.objects.filter(user_id=user.pk, is_active=True)
        .filter(status=MauticUserConnection.Status.ACTIVE)
        .first()
    )
    return connection is not None


def describe_marketing_access(user, connection=None) -> dict:
    """One row of the Marketing Access tab. Never includes credentials."""
    state = marketing_state_for(user, connection)
    return {
        "ecp_user_id": user.pk,
        "username": user.get_username(),
        "email": getattr(user, "email", "") or "",
        "first_name": getattr(user, "first_name", "") or "",
        "last_name": getattr(user, "last_name", "") or "",
        "is_active": bool(getattr(user, "is_active", False)),
        "is_staff": bool(getattr(user, "is_staff", False)),
        "is_superuser": bool(getattr(user, "is_superuser", False)),
        "eligible": is_marketing_eligible(user),
        "marketing_state": state,
        "has_marketing_access": state == MarketingState.ACTIVE,
        "connection_id": connection.pk if connection else None,
        "connection_status": connection.status if connection else None,
        "connection_active": bool(connection.is_active) if connection else False,
        "mautic_user_id": connection.mautic_user_id if connection else None,
        "mautic_username": (connection.mautic_username or None) if connection else None,
        "mautic_display_name": (
            (connection.mautic_display_name or None) if connection else None
        ),
        "mautic_role_name": (connection.mautic_role_name or None) if connection else None,
        "connected_at": connection.connected_at if connection else None,
        "disabled_at": connection.disabled_at if connection else None,
        "last_verified_at": connection.last_verified_at if connection else None,
    }


def list_marketing_access() -> list[dict]:
    """Every eligible ECP superuser plus anyone who still holds a mapping.

    A user who lost superuser after being added is still listed, so an admin can
    see and revoke access that is no longer legitimate.
    """
    mapped_user_ids = set(
        MauticUserConnection.objects.values_list("user_id", flat=True).distinct()
    )
    users = list(
        User.objects.filter(Q(is_superuser=True) | Q(pk__in=mapped_user_ids)).order_by(
            "email", "id"
        )
    )

    connections = {}
    for connection in MauticUserConnection.objects.filter(
        user_id__in=[user.pk for user in users]
    ).order_by("-is_active", "-created_at", "-id"):
        connections.setdefault(connection.user_id, connection)

    return [describe_marketing_access(user, connections.get(user.pk)) for user in users]


def marketing_status_for_actor(user) -> dict:
    """Authoritative per-user status the frontend gates Marketing Hub on."""
    connection = latest_connection_for(user)
    state = marketing_state_for(user, connection)
    identity_status = get_mautic_identity_connection_status(user)
    return {
        "ecp_user_id": getattr(user, "pk", None),
        "eligible": is_marketing_eligible(user),
        "is_superuser": bool(getattr(user, "is_superuser", False)),
        "is_staff": bool(getattr(user, "is_staff", False)),
        "can_manage_marketing_access": is_marketing_manager(user),
        "marketing_state": state,
        "has_marketing_access": has_marketing_hub_access(user),
        "connected": identity_status["connected"],
        "connection_active": bool(connection.is_active) if connection else False,
        "connection_status": identity_status["status"],
        "mautic_user_id": identity_status["mautic_user_id"],
        "mautic_username": identity_status["mautic_username"],
        "auth_mode": identity_status["auth_mode"],
        "per_user_execution_enabled": identity_status["per_user_execution_enabled"],
        "interactive_blocked_code": identity_status["interactive_blocked_code"],
    }


# --------------------------------------------------------------------------
# Provider provisioning
# --------------------------------------------------------------------------


def _marketing_role_id(client: MauticClient) -> int:
    """Resolve the configured Marketing role provider-side.

    The numeric id is never hard-coded: it is either configured explicitly or
    resolved from the configured role name at provisioning time. Failing to
    resolve it is fatal, so a user is never created with the wrong authority.
    """
    configured_id = str(getattr(settings, "ECP_MAUTIC_MARKETING_ROLE_ID", "") or "").strip()
    if configured_id:
        if not configured_id.isdigit() or int(configured_id) < 1:
            raise MarketingProvisioningFailedError(
                "ECP_MAUTIC_MARKETING_ROLE_ID is not a valid Mautic role id"
            )
        try:
            role = client.get_role(int(configured_id))
        except (TemporaryMauticError, PermanentMauticError) as exc:
            raise MarketingProvisioningFailedError(
                "The configured Mautic Marketing role could not be resolved"
            ) from exc
        return int(role["id"])

    role_name = str(getattr(settings, "ECP_MAUTIC_MARKETING_ROLE_NAME", "") or "").strip()
    if not role_name:
        raise MarketingProvisioningFailedError(
            "No Mautic Marketing role is configured for provisioning"
        )
    try:
        role = client.get_role_by_name(role_name)
    except (TemporaryMauticError, PermanentMauticError) as exc:
        raise MarketingProvisioningFailedError(
            "The configured Mautic Marketing role could not be resolved"
        ) from exc
    if not role or not role.get("id"):
        raise MarketingProvisioningFailedError(
            "The configured Mautic Marketing role does not exist in Mautic"
        )
    return int(role["id"])


def _username_base(user) -> str:
    """Stable, readable slug derived from ECP identity (never the email)."""
    raw = str(user.get_username() or "").strip().lower()
    if "@" in raw:
        # Some ECP accounts use the email as the username; keep only the local
        # part so the provider username does not look like a mailbox.
        raw = raw.split("@", 1)[0]
    slug = _USERNAME_SAFE_RE.sub("-", raw).strip("-")
    if not slug:
        slug = _USERNAME_SAFE_RE.sub(
            "-",
            f"{getattr(user, 'first_name', '')} {getattr(user, 'last_name', '')}".lower(),
        ).strip("-")
    return slug or "user"


def candidate_usernames(user):
    """Deterministic username candidates, most preferred first.

    The immutable ECP user id is always part of the name, so two different ECP
    users can never derive the same username, and the same ECP user always
    derives the same one.
    """
    prefix = str(
        getattr(settings, "ECP_MAUTIC_MARKETING_USERNAME_PREFIX", "ecp") or "ecp"
    ).strip("-")
    base = f"{prefix}-{_username_base(user)}-{user.pk}" if prefix else f"{_username_base(user)}-{user.pk}"
    base = base[:MAX_USERNAME_LENGTH]
    yield base
    for suffix in range(2, _MAX_USERNAME_ATTEMPTS + 1):
        tail = f"-{suffix}"
        yield f"{base[: MAX_USERNAME_LENGTH - len(tail)]}{tail}"


def _resolve_provisioning_username(client: MauticClient, user) -> str:
    for candidate in candidate_usernames(user):
        try:
            existing = client.find_user_by_username(candidate)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            raise MarketingProvisioningFailedError(
                "Mautic could not be queried for an available username"
            ) from exc
        if existing is None:
            return candidate
    raise MarketingProvisioningFailedError(
        "No available Mautic username could be derived for this user"
    )


def _assert_no_existing_provider_identity(client: MauticClient, user) -> None:
    """Refuse to claim a Mautic human that ECP did not provision.

    Linking is permanent and grants that person's Mautic authority to this ECP
    account, so a mere email match is never enough. The administrator resolves
    it explicitly through the low-level connection endpoint.
    """
    email = str(getattr(user, "email", "") or "").strip()
    if not email:
        return
    try:
        matches = client.find_users_by_email(email)
    except (TemporaryMauticError, PermanentMauticError) as exc:
        raise MarketingProvisioningFailedError(
            "Mautic could not be queried for existing users"
        ) from exc
    if matches:
        raise MarketingIdentityConflictError(
            "A Mautic user with this email already exists; link it explicitly "
            "instead of provisioning a new one"
        )


def _disable_provider_user(client: MauticClient, mautic_user_id: int) -> bool:
    """Best-effort compensation when mapping fails after provider creation."""
    try:
        client.set_user_published(mautic_user_id, False)
        return True
    except Exception:
        logger.exception(
            "Could not disable orphaned Mautic user %s after a failed mapping",
            mautic_user_id,
        )
        return False


def provision_mautic_user_for(user, *, client: MauticClient | None = None) -> int:
    """Create the provider-side Mautic human for ``user``; return its id.

    The generated password is a provider-side credential only: it is never
    returned, stored, displayed or logged, and no ECP user ever types it.
    """
    client = client or MauticClient()
    _assert_no_existing_provider_identity(client, user)
    role_id = _marketing_role_id(client)
    username = _resolve_provisioning_username(client, user)

    email = str(getattr(user, "email", "") or "").strip()
    if not email:
        raise MarketingProvisioningFailedError(
            "This ECP user has no email address, which Mautic requires"
        )

    password = secrets.token_urlsafe(48)
    try:
        created = client.create_user(
            username=username,
            email=email,
            first_name=getattr(user, "first_name", "") or username,
            last_name=getattr(user, "last_name", "") or "",
            role_id=role_id,
            password=password,
        )
    except (TemporaryMauticError, PermanentMauticError) as exc:
        raise MarketingProvisioningFailedError(
            "Mautic rejected the new Marketing user"
        ) from exc

    try:
        return int(created["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise MarketingProvisioningFailedError(
            "Mautic returned an invalid user id for the new Marketing user"
        ) from exc


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------


def _require_manager_and_distinct_target(actor, target) -> None:
    """Marketing access is always granted or removed by somebody else.

    Self-service is refused even though the actor is already a superuser: every
    change should carry a second person's name in the audit trail. Recovery for
    the bootstrap case stays with the low-level connection endpoints.
    """
    if not is_marketing_manager(actor):
        raise MarketingAccessNotEligibleError(
            "Only an active ECP superuser can manage Marketing access"
        )
    if getattr(actor, "pk", None) is not None and actor.pk == getattr(target, "pk", None):
        raise MarketingSelfManagementError(
            "You cannot change your own Marketing access"
        )


class MarketingGrantResult:
    """What ``grant_marketing_access`` actually did, for audit and response."""

    PROVISIONED = "provisioned"
    REACTIVATED = "reactivated"

    def __init__(self, connection, outcome: str):
        self.connection = connection
        self.outcome = outcome


def grant_marketing_access(target, *, actor, client: MauticClient | None = None):
    """Give ``target`` Marketing access, provisioning Mautic only if needed.

    The target's ECP row is locked for the duration, so two racing Add requests
    cannot both provision a Mautic user for the same person.
    """
    _require_manager_and_distinct_target(actor, target)

    with transaction.atomic():
        locked_target = User.objects.select_for_update().filter(pk=target.pk).first()
        if locked_target is None:
            raise MarketingAccessNotEligibleError("ECP user does not exist")
        if not is_marketing_eligible(locked_target):
            raise MarketingAccessNotEligibleError(
                "Only active ECP superusers can be given Marketing access"
            )

        connections = list(
            MauticUserConnection.objects.select_for_update().filter(user=locked_target)
        )
        active = next((row for row in connections if row.is_usable), None)
        if active is not None:
            raise MarketingAccessAlreadyActiveError(
                "This user already has active Marketing access"
            )

        reusable = next(
            (
                row
                for row in sorted(connections, key=lambda r: (-r.pk,))
                if row.mautic_user_id
            ),
            None,
        )
        if reusable is not None:
            # CASE C/J: reuse the same provider identity, never a second one.
            connection = activate_mautic_user_connection(reusable, actor=actor)
            return MarketingGrantResult(connection, MarketingGrantResult.REACTIVATED)

        mautic_user_id = provision_mautic_user_for(locked_target, client=client)
        try:
            connection = connect_mautic_user(
                locked_target,
                mautic_user_id=mautic_user_id,
                created_by=actor,
            )
        except Exception as exc:
            # CASE H: the provider identity exists but ECP could not record it.
            # Disable it so no unmapped, fully-privileged Mautic human is left
            # enabled, and surface the failure rather than swallowing it.
            disabled = _disable_provider_user(client or MauticClient(), mautic_user_id)
            logger.error(
                "Mautic user %s was provisioned for ECP user %s but mapping failed "
                "(provider user disabled=%s)",
                mautic_user_id,
                locked_target.pk,
                disabled,
            )
            if isinstance(exc, MauticIdentityError):
                raise
            raise MarketingProvisioningFailedError(
                "The Mautic user was created but could not be linked to this ECP user"
            ) from exc

        return MarketingGrantResult(connection, MarketingGrantResult.PROVISIONED)


def revoke_marketing_access(target, *, actor, reason: str = ""):
    """Remove Marketing access without destroying history.

    The mapping row, its Mautic user id and every audit record are kept: the
    provider user and everything it owns in Mautic stay exactly as they are.
    """
    _require_manager_and_distinct_target(actor, target)

    connection = (
        MauticUserConnection.objects.filter(user_id=target.pk, is_active=True)
        .order_by("-id")
        .first()
    )
    if connection is None:
        raise MauticIdentityError("This user does not have active Marketing access")

    return deactivate_mautic_user_connection(
        connection,
        reason=reason or f"Marketing access removed by ECP user {actor.pk}",
    )


__all__ = [
    "MarketingGrantResult",
    "MarketingState",
    "candidate_usernames",
    "describe_marketing_access",
    "grant_marketing_access",
    "has_marketing_hub_access",
    "is_marketing_eligible",
    "is_marketing_manager",
    "latest_connection_for",
    "list_marketing_access",
    "marketing_state_for",
    "marketing_status_for_actor",
    "per_user_execution_enabled",
    "provision_mautic_user_for",
    "revoke_marketing_access",
]
