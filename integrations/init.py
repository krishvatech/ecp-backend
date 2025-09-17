"""
Integrations app package for the events & community platform backend.

This app enables synchronization of platform events and data with
external systems such as CRM providers (e.g. HubSpot).  It stores
configuration for each organization and logs sync attempts for audit
purposes.
"""

default_app_config = "integrations.apps.IntegrationsConfig"
