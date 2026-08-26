"""Provider-neutral contracts shared by CRM adapters."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TypedDict


class CRMContactPayload(TypedDict):
    ecp_user_id: str
    first_name: str
    last_name: str
    email: str
    company: str
    job_title: str
    country: str
    country_code: str
    is_active: bool
    profile_status: str


@dataclass(frozen=True)
class CRMUpsertResult:
    external_id: str
    external_object_type: str
    created: bool | None = None


class CRMProviderError(Exception):
    """Base error raised by provider adapters."""


class TemporaryCRMError(CRMProviderError):
    """A retryable timeout, rate-limit, authentication, or provider failure."""


class PermanentCRMError(CRMProviderError):
    """A non-retryable payload, permission, or provider configuration failure."""


class CRMProvider(ABC):
    @abstractmethod
    def health_check(self) -> bool:
        """Return whether the configured provider can accept requests."""

    @abstractmethod
    def upsert_contact(self, payload: CRMContactPayload) -> CRMUpsertResult:
        """Create or update one provider contact idempotently."""

    @abstractmethod
    def deactivate_contact(
        self,
        external_id: str,
        payload: CRMContactPayload,
    ) -> CRMUpsertResult:
        """Apply the provider-specific inactive-contact policy."""
