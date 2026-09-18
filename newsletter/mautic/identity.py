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

PHASE 2: when ``ECP_MAUTIC_PER_USER_EXECUTION_ENABLED`` is on, an INTERACTIVE
context resolves to ``ASSERTED_USER``. That mode still authenticates the caller
with the service credentials; it additionally attaches a short-lived signed
assertion to the dedicated Mautic bridge endpoints, so Mautic can execute the
operation as the mapped human user. Every other context stays on the service
account, and only the migrated campaign create/update paths use the factory so
far.

With the flag on, per-user execution is mandatory for INTERACTIVE work: a
missing or inactive mapping, or missing signing configuration, raises a
``MauticIdentityError`` instead of quietly running as the service account. A
human action must never be attributed to the shared identity when the operator
has asked for per-user attribution.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum

from django.conf import settings

from .client import MauticClient
from .exceptions import (
    MauticActorRequiredError,
    MauticIdentityConfigurationError,
    MauticIdentityError,
    MauticUserConnectionInactiveError,
    MauticUserConnectionMissingError,
)

logger = logging.getLogger(__name__)


class MauticExecutionContext(StrEnum):
    INTERACTIVE = "interactive"
    SYSTEM = "system"
    BACKGROUND = "background"
    READ_ONLY = "readonly"


class MauticAuthMode(StrEnum):
    SERVICE_ACCOUNT = "service_account"
    # Service credentials still authenticate the caller; a signed assertion
    # additionally names the human the bridge should execute as. Only reachable
    # from INTERACTIVE contexts.
    ASSERTED_USER = "asserted_user"


@dataclass(frozen=True)
class MauticExecutionIdentity:
    context: MauticExecutionContext
    auth_mode: MauticAuthMode
    # ECP user who triggered the work. Audit metadata only.
    actor_id: int | None = None
    # Resolved mapped Mautic user for INTERACTIVE contexts. Named in the signed
    # assertion when auth_mode is ASSERTED_USER; never used as a credential.
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
    """Who may hold Marketing access at all.

    Deliberately narrower than the old ``is_staff or is_superuser`` rule: only
    an active ECP **superuser** is eligible. Staff are not, and cannot be
    mapped. This is eligibility only; holding access additionally requires an
    active mapping, which ``get_active_mautic_user_connection`` enforces.
    """
    return bool(
        _is_authenticated(user)
        and getattr(user, "is_active", False)
        and getattr(user, "is_superuser", False)
    )


def require_marketing_hub_actor(user):
    if not actor_has_marketing_hub_access(user):
        raise MauticActorRequiredError(
            "An active ECP superuser is required for interactive Mautic operations"
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


def per_user_execution_enabled() -> bool:
    """Phase 2 feature flag. Off by default."""
    return bool(getattr(settings, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED", False))


def _auth_mode_for(
    context: MauticExecutionContext,
    *,
    mautic_user_id: int | None,
) -> MauticAuthMode:
    """Single decision point for per-user execution.

    Non-interactive contexts can never reach ASSERTED_USER, so background work
    cannot execute as a human no matter what actor it carries.

    With the flag on, every requirement for INTERACTIVE work is mandatory:
    failing one raises rather than downgrading to the service account, because
    a silent downgrade would attribute a human action to the shared identity.
    """
    if context is not MauticExecutionContext.INTERACTIVE:
        return MauticAuthMode.SERVICE_ACCOUNT
    if not per_user_execution_enabled():
        return MauticAuthMode.SERVICE_ACCOUNT

    if not mautic_user_id:
        raise MauticUserConnectionMissingError(
            "Per-user Mautic execution is enabled but this user has no active "
            "Mautic user connection"
        )

    from .identity_assertion import is_identity_assertion_configured

    if not is_identity_assertion_configured():
        logger.error(
            "Per-user Mautic execution is enabled but identity signing is not configured"
        )
        raise MauticIdentityConfigurationError(
            "Mautic identity signing is not configured for per-user execution"
        )

    return MauticAuthMode.ASSERTED_USER


def resolve_mautic_execution_identity(
    actor=None,
    purpose=MauticExecutionContext.SYSTEM,
) -> MauticExecutionIdentity:
    context = _coerce_context(purpose)
    actor_id = actor.pk if _is_authenticated(actor) else None

    if context is not MauticExecutionContext.INTERACTIVE:
        return MauticExecutionIdentity(
            context=context,
            auth_mode=_auth_mode_for(context, mautic_user_id=None),
            actor_id=actor_id,
        )

    require_marketing_hub_actor(actor)
    try:
        mautic_user_id = get_active_mautic_user_connection(actor).mautic_user_id
    except (MauticUserConnectionMissingError, MauticUserConnectionInactiveError):
        if per_user_execution_enabled():
            # Fail closed: the operator asked for per-user attribution, so this
            # operation must not run as the shared service account.
            logger.warning(
                "No active Mautic user connection for ECP user %s; refusing "
                "interactive Mautic execution",
                actor_id,
            )
            raise
        # Flag off: unchanged Phase 1 behaviour.
        mautic_user_id = None

    return MauticExecutionIdentity(
        context=context,
        auth_mode=_auth_mode_for(context, mautic_user_id=mautic_user_id),
        actor_id=actor_id,
        mautic_user_id=mautic_user_id,
    )


class _AssertionMinter:
    """Mints a fresh single-use assertion per bridge request.

    Callable taking the operation to authorise and returning the token, so the
    client's provider contract is ``(operation: str) -> str``. The jti of the
    most recent one is kept so the caller can record which assertion authorised
    an operation; it is an identifier, not a credential, and the token itself is
    never retained.
    """

    def __init__(self, actor):
        self._actor = actor
        self.last_jti = ""

    def __call__(self, operation: str) -> str:
        from .identity_assertion import issue_identity_assertion

        assertion = issue_identity_assertion(self._actor, operation=operation)
        self.last_jti = assertion.jti
        return assertion.token


def get_mautic_client(
    actor=None,
    purpose=MauticExecutionContext.SYSTEM,
    *,
    session=None,
    client_factory=None,
    correlation_id=None,
) -> MauticClient:
    """Central construction point for Mautic API clients.

    The returned client always authenticates with the configured service
    account. In ASSERTED_USER mode it additionally carries a per-request signed
    identity assertion, which it sends only to the dedicated bridge endpoints.

    ``client_factory`` lets a caller keep its own module-level ``MauticClient``
    as the construction point, so service-account behaviour (and the existing
    tests that patch that name) stay exactly as they were.
    """
    identity = resolve_mautic_execution_identity(actor=actor, purpose=purpose)

    assertion_provider = None
    if identity.auth_mode is MauticAuthMode.ASSERTED_USER:
        assertion_provider = _AssertionMinter(actor)

    factory = client_factory or MauticClient

    return factory(
        session=session,
        execution_identity=identity,
        assertion_provider=assertion_provider,
        correlation_id=correlation_id,
    )
