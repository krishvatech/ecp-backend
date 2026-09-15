"""Execution identity for ECP -> Mautic calls.

Every Mautic call belongs to exactly one execution context:

* ``INTERACTIVE`` - a human staff user acting in the Marketing Hub.
* ``SYSTEM`` - machine work not tied to a person (diagnostics, sync plumbing).
* ``BACKGROUND`` - Celery/beat/cron/webhook processing, even when a human
  originally requested the work.
* ``READ_ONLY`` - non-mutating machine reads.

Only ``INTERACTIVE`` may ever be executed as a mapped Mautic user. Background
work must keep the service identity; the originating ECP user is carried as
audit metadata only, so a queued job can never impersonate a human.

PHASE 1: every context authenticates with the configured Mautic service
account. ``get_mautic_client`` resolves and records identity metadata but does
not change credentials. Existing call sites still construct ``MauticClient``
directly and are intentionally not migrated yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .client import MauticClient
from .exceptions import (
    MauticActorRequiredError,
    MauticIdentityError,
    MauticUserConnectionInactiveError,
    MauticUserConnectionMissingError,
)


class MauticExecutionContext(StrEnum):
    INTERACTIVE = "interactive"
    SYSTEM = "system"
    BACKGROUND = "background"
    READ_ONLY = "readonly"


class MauticAuthMode(StrEnum):
    SERVICE_ACCOUNT = "service_account"
    # Phase 2 adds a mode where the Mautic bridge executes as the user named in
    # a verified ECP identity assertion. It must only be reachable from
    # INTERACTIVE contexts.


@dataclass(frozen=True)
class MauticExecutionIdentity:
    context: MauticExecutionContext
    auth_mode: MauticAuthMode
    # ECP user who triggered the work. Audit metadata only.
    actor_id: int | None = None
    # Resolved mapped Mautic user for INTERACTIVE contexts. Not used for
    # authentication in Phase 1.
    mautic_user_id: int | None = None

    @property
    def is_human(self) -> bool:
        return self.context is MauticExecutionContext.INTERACTIVE


def _coerce_context(purpose) -> MauticExecutionContext:
    try:
        return MauticExecutionContext(purpose)
    except ValueError:
        raise MauticIdentityError("Unknown Mautic execution context") from None


def _is_authenticated(user) -> bool:
    return bool(user is not None and getattr(user, "is_authenticated", False))


def actor_has_marketing_hub_access(user) -> bool:
    """Mirror of the Marketing Hub API rule (``IsStaffOrSuperuser``)."""
    return bool(
        _is_authenticated(user)
        and getattr(user, "is_active", False)
        and (getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))
    )


def require_marketing_hub_actor(user):
    if not actor_has_marketing_hub_access(user):
        raise MauticActorRequiredError(
            "An active Marketing Hub staff user is required for interactive Mautic operations"
        )
    return user


def get_active_mautic_user_connection(actor):
    """Return the actor's usable MauticUserConnection or raise.

    Identity is resolved strictly by the ECP user primary key. Email is never
    consulted.
    """
    from newsletter.models import MauticUserConnection

    require_marketing_hub_actor(actor)
    connections = MauticUserConnection.objects.filter(user_id=actor.pk)
    connection = connections.filter(
        is_active=True,
        status=MauticUserConnection.Status.ACTIVE,
    ).first()
    if connection is not None:
        return connection
    if connections.exists():
        raise MauticUserConnectionInactiveError("Mautic user connection is not active")
    raise MauticUserConnectionMissingError("No Mautic user connection exists for this user")


def _auth_mode_for(context: MauticExecutionContext) -> MauticAuthMode:
    # Single decision point for Phase 2. Do not add per-user credentials
    # anywhere else.
    return MauticAuthMode.SERVICE_ACCOUNT


def resolve_mautic_execution_identity(
    actor=None,
    purpose=MauticExecutionContext.SYSTEM,
) -> MauticExecutionIdentity:
    context = _coerce_context(purpose)
    actor_id = actor.pk if _is_authenticated(actor) else None

    if context is not MauticExecutionContext.INTERACTIVE:
        return MauticExecutionIdentity(
            context=context,
            auth_mode=_auth_mode_for(context),
            actor_id=actor_id,
        )

    require_marketing_hub_actor(actor)
    try:
        mautic_user_id = get_active_mautic_user_connection(actor).mautic_user_id
    except (MauticUserConnectionMissingError, MauticUserConnectionInactiveError):
        # Phase 1: an unmapped staff user keeps working through the service
        # account exactly as before.
        mautic_user_id = None

    return MauticExecutionIdentity(
        context=context,
        auth_mode=_auth_mode_for(context),
        actor_id=actor_id,
        mautic_user_id=mautic_user_id,
    )


def get_mautic_client(
    actor=None,
    purpose=MauticExecutionContext.SYSTEM,
    *,
    session=None,
) -> MauticClient:
    """Central construction point for Mautic API clients.

    Phase 1 always returns a client authenticated with the configured service
    account, for every context.
    """
    identity = resolve_mautic_execution_identity(actor=actor, purpose=purpose)
    return MauticClient(session=session, execution_identity=identity)
