"""Durable, provider-neutral CRM integration state."""

import uuid

from django.db import models


class CRMConnection(models.Model):
    class Provider(models.TextChoices):
        SALESFORCE = "salesforce", "Salesforce"

    provider = models.CharField(max_length=32, choices=Provider.choices)
    name = models.CharField(max_length=120)
    is_active = models.BooleanField(default=False, db_index=True)
    instance_url = models.URLField(blank=True, default="")
    api_version = models.CharField(max_length=16, blank=True, default="")
    configuration_reference = models.CharField(
        max_length=120,
        blank=True,
        default="",
        help_text="Non-secret reference to the environment or secret-manager configuration.",
    )
    last_health_check_at = models.DateTimeField(null=True, blank=True)
    last_health_check_status = models.BooleanField(null=True, blank=True)
    last_error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["provider", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["provider", "name"],
                name="crm_unique_provider_connection_name",
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_provider_display()})"


class CRMObjectMapping(models.Model):
    connection = models.ForeignKey(
        CRMConnection,
        on_delete=models.CASCADE,
        related_name="object_mappings",
    )
    local_object_type = models.CharField(max_length=64)
    local_object_id = models.CharField(max_length=128)
    external_object_type = models.CharField(max_length=64)
    external_id = models.CharField(max_length=255)
    last_synced_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["local_object_type", "local_object_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["connection", "local_object_type", "local_object_id"],
                name="crm_unique_local_object_mapping",
            ),
            models.UniqueConstraint(
                fields=["connection", "external_object_type", "external_id"],
                name="crm_unique_external_object_mapping",
            ),
        ]
        indexes = [
            models.Index(
                fields=["local_object_type", "local_object_id"],
                name="crm_mapping_local_idx",
            ),
        ]

    def __str__(self):
        return (
            f"{self.local_object_type}:{self.local_object_id} -> "
            f"{self.external_object_type}:{self.external_id}"
        )


class CRMSyncEvent(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PROCESSING = "processing", "Processing"
        SUCCEEDED = "succeeded", "Succeeded"
        RETRYING = "retrying", "Retrying"
        FAILED = "failed", "Failed"
        SKIPPED = "skipped", "Skipped"

    event_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    idempotency_key = models.CharField(max_length=255, unique=True)
    connection = models.ForeignKey(
        CRMConnection,
        on_delete=models.PROTECT,
        related_name="sync_events",
    )
    event_type = models.CharField(max_length=64, db_index=True)
    object_type = models.CharField(max_length=64)
    object_id = models.CharField(max_length=128)
    payload = models.JSONField(default=dict, blank=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    attempt_count = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True, default="")
    next_retry_at = models.DateTimeField(null=True, blank=True, db_index=True)
    processing_started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(
                fields=["connection", "status", "created_at"],
                name="crm_event_queue_idx",
            ),
            models.Index(
                fields=["object_type", "object_id"],
                name="crm_event_object_idx",
            ),
        ]

    def __str__(self):
        return f"{self.event_type} {self.object_type}:{self.object_id} [{self.status}]"
