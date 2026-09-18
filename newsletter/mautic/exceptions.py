"""Error contract for the Mautic newsletter adapter."""


class MauticError(Exception):
    """Base error raised by the Mautic adapter."""


class TemporaryMauticError(MauticError):
    """Retryable transport, rate-limit, or provider failure."""


class PermanentMauticError(MauticError):
    """Non-retryable configuration, validation, or provider failure."""


class MauticIdentityError(MauticError):
    """Base error for ECP -> Mautic user identity resolution and assertions.

    Messages are safe to log: they never include tokens, keys, or credentials.
    """


class MauticIdentityConfigurationError(MauticIdentityError):
    """Identity assertion signing is not (correctly) configured."""


class MauticActorRequiredError(MauticIdentityError):
    """An interactive Mautic operation was requested without a usable actor."""


class MauticUserConnectionMissingError(MauticIdentityError):
    """The actor has no Mautic user connection."""


class MauticUserConnectionInactiveError(MauticIdentityError):
    """The actor's Mautic user connection exists but is not active."""


class MauticIdentityAssertionError(MauticIdentityError):
    """An identity assertion cannot be issued for this actor or purpose."""


class MauticUserVerificationInvalidError(MauticIdentityError):
    """A target Mautic user does not exist or is not usable for mapping."""


class MauticUserVerificationUnavailableError(MauticIdentityError):
    """Canonical Mautic user verification cannot currently be completed."""


class MarketingAccessNotEligibleError(MauticIdentityError):
    """The target ECP user may not hold Marketing access (not an active superuser)."""


class MarketingAccessAlreadyActiveError(MauticIdentityError):
    """The target ECP user already holds active Marketing access."""


class MarketingSelfManagementError(MauticIdentityError):
    """A superuser tried to grant or remove their own Marketing access.

    Marketing access is granted by one superuser to another, so that the change
    always has a second person's name against it in the audit trail.
    """


class MarketingIdentityConflictError(MauticIdentityError):
    """A provider identity exists that ECP must not claim automatically.

    Raised instead of silently linking a Mautic user found by email: linking is
    permanent, so it stays an explicit administrator decision.
    """


class MarketingProvisioningFailedError(MauticIdentityError):
    """A Mautic human could not be provisioned for the target ECP user."""


class MauticBridgeRejectedError(PermanentMauticError):
    """The Mautic identity bridge refused an asserted-user operation.

    Subclasses PermanentMauticError so existing provider error handling keeps
    working; views that care can report it as an authorization failure.
    """
