"""Django admin registrations for CRM integrations."""

from django.contrib import admin, messages

from .models import CRMConnection, CRMObjectMapping, CRMSyncEvent
from .operations import check_connection_health, requeue_sync_events


@admin.register(CRMConnection)
class CRMConnectionAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "provider",
        "is_active",
        "last_health_check_status",
        "last_health_check_at",
    )
    list_filter = ("provider", "is_active", "last_health_check_status")
    search_fields = ("name", "instance_url", "configuration_reference")
    readonly_fields = ("created_at", "updated_at")
    actions = ("test_selected_connections",)

    @admin.action(description="Test selected CRM connections")
    def test_selected_connections(self, request, queryset):
        healthy = 0
        unhealthy = 0
        for connection in queryset:
            result = check_connection_health(connection)
            if result["healthy"]:
                healthy += 1
            else:
                unhealthy += 1
        level = messages.SUCCESS if unhealthy == 0 else messages.WARNING
        self.message_user(
            request,
            f"CRM health checks complete: {healthy} healthy, {unhealthy} unhealthy.",
            level=level,
        )


@admin.register(CRMObjectMapping)
class CRMObjectMappingAdmin(admin.ModelAdmin):
    list_display = (
        "connection",
        "local_object_type",
        "local_object_id",
        "external_object_type",
        "external_id",
        "last_synced_at",
    )
    list_filter = ("connection", "local_object_type", "external_object_type")
    search_fields = ("local_object_id", "external_id")
    readonly_fields = ("created_at", "updated_at")


@admin.register(CRMSyncEvent)
class CRMSyncEventAdmin(admin.ModelAdmin):
    list_display = (
        "event_type",
        "object_type",
        "object_id",
        "connection",
        "status",
        "attempt_count",
        "created_at",
    )
    list_filter = ("connection", "status", "event_type", "object_type")
    search_fields = ("event_uuid", "idempotency_key", "object_id", "last_error")
    readonly_fields = (
        "event_uuid",
        "idempotency_key",
        "connection",
        "event_type",
        "object_type",
        "object_id",
        "payload",
        "status",
        "attempt_count",
        "last_error",
        "next_retry_at",
        "processing_started_at",
        "completed_at",
        "created_at",
        "updated_at",
    )
    actions = ("retry_selected_events",)

    @admin.action(description="Retry selected CRM events")
    def retry_selected_events(self, request, queryset):
        result = requeue_sync_events(queryset)
        level = messages.SUCCESS if result["failed"] == 0 else messages.WARNING
        self.message_user(
            request,
            (
                f"Requeued {result['selected']} CRM event(s); "
                f"dispatched {result['dispatched']}, dispatch failures {result['failed']}."
            ),
            level=level,
        )
