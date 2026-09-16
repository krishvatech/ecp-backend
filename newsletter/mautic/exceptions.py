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


class MauticBridgeRejectedError(PermanentMauticError):
    """The Mautic identity bridge refused an asserted-user operation.

    Subclasses PermanentMauticError so existing provider error handling keeps
    working; views that care can report it as an authorization failure.
    """
