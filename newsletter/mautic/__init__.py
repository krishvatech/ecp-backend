"""Mautic API integration helpers for newsletter synchronization."""

from .client import MauticClient
from .exceptions import (
    MauticError,
    PermanentMauticError,
    TemporaryMauticError,
)
from .identity import (
    MauticAuthMode,
    MauticExecutionContext,
    MauticExecutionIdentity,
    get_mautic_client,
)

__all__ = [
    "MauticAuthMode",
    "MauticClient",
    "MauticError",
    "MauticExecutionContext",
    "MauticExecutionIdentity",
    "PermanentMauticError",
    "TemporaryMauticError",
    "get_mautic_client",
]
