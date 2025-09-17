"""
Django admin configuration for the integrations app.

Registers IntegrationConfig and SyncLog with useful filters.
"""
from django.contrib import admin
from .models import IntegrationConfig, SyncLog


@admin.register(IntegrationConfig)
class IntegrationConfigAdmin(admin.ModelAdmin):
    list_display = (
        "organization",
        "type",
        "enabled",
        "created_at",
    )
    list_filter = ("type", "enabled", "organization")
    search_fields = ("organization__name",)
    ordering = ("-created_at",)


@admin.register(SyncLog)
class SyncLogAdmin(admin.ModelAdmin):
    list_display = (
        "organization",
        "integration_type",
        "status",
        "created_at",
    )
    list_filter = ("integration_type", "status", "organization")
    search_fields = ("payload_snippet",)
    ordering = ("-created_at",)
