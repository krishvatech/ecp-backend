"""CRM provider adapter factory."""

from .base import PermanentCRMError


def get_crm_provider(connection, **kwargs):
    if connection.provider == "salesforce":
        from .salesforce import SalesforceProvider

        return SalesforceProvider(connection=connection, **kwargs)
    raise PermanentCRMError(f"Unsupported CRM provider: {connection.provider}")
