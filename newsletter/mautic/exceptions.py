"""Error contract for the Mautic newsletter adapter."""


class MauticError(Exception):
    """Base error raised by the Mautic adapter."""


class TemporaryMauticError(MauticError):
    """Retryable transport, rate-limit, or provider failure."""


class PermanentMauticError(MauticError):
    """Non-retryable configuration, validation, or provider failure."""
