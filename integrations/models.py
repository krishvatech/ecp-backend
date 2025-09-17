"""
Database models for the integrations app.

Defines configuration for external integrations (e.g. HubSpot) and
logs of sync attempts.  Each config is scoped to an organization
and can be enabled or disabled.  Secrets and settings are stored in
JSON fields (consider encrypting in production).  Sync logs capture
payload snippets and any errors for debugging purposes.
"""
from __future__ import annotations

from django.db import models
from organizations.models import Organization


class IntegrationConfig(models.Model):
    """Configuration for an external integration service for an organization."""

    TYPE_HUBSPOT = "hubspot"
    TYPE_CHOICES = [
        (TYPE_HUBSPOT, "HubSpot"),
    ]

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="integration_configs",
    )
    type = models.CharField(max_length=50, choices=TYPE_CHOICES)
    enabled = models.BooleanField(default=False)
    secrets = models.JSONField(
        default=dict,
        blank=True,
        help_text="Sensitive credentials (e.g. API tokens) for the integration.",
    )
    settings = models.JSONField(
        default=dict,
        blank=True,
        help_text="Non-sensitive configuration values (e.g. property mappings).",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (
            "organization",
            "type",
        )
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"IntegrationConfig({self.organization_id}, {self.type})"


class SyncLog(models.Model):
    """Record of a single synchronization attempt with an external service."""

    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILED, "Failed"),
    ]

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="integration_sync_logs",
    )
    integration_type = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    payload_snippet = models.TextField(blank=True, help_text="Partial payload sent to the integration.")
    error = models.TextField(blank=True, help_text="Error message if the sync failed.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "integration_type", "created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"SyncLog({self.integration_type}, {self.status})"
