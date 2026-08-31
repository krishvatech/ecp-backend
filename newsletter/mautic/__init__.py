"""Mautic API integration helpers for newsletter synchronization."""

from .client import MauticClient
from .exceptions import (
    MauticError,
    PermanentMauticError,
    TemporaryMauticError,
)

__all__ = [
    "MauticClient",
    "MauticError",
    "PermanentMauticError",
    "TemporaryMauticError",
]
