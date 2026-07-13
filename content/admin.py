# content/admin.py
from django.contrib import admin

from .models import Resource


@admin.register(Resource)
class ResourceAdmin(admin.ModelAdmin):
    list_display = (
        "title", "type", "community", "event", "uploaded_by",
        "is_published", "is_deleted", "publish_at", "created_at",
    )
    list_filter = ("community", "event", "type", "is_published", "is_deleted")
    search_fields = ("title", "description", "deletion_reason")
    ordering = ("-created_at",)
    readonly_fields = ("deleted_at", "deleted_by", "deletion_reason")
    actions = ["publish_now", "restore_selected"]

    def get_queryset(self, request):
        return Resource.all_objects.select_related(
            "community", "event", "uploaded_by", "deleted_by"
        )

    @admin.action(description="Publish selected active resources now")
    def publish_now(self, request, queryset):
        for resource in queryset.filter(is_deleted=False):
            resource.is_published = True
            resource.publish_at = None
            resource.save(update_fields=["is_published", "publish_at", "updated_at"])

    @admin.action(description="Restore selected soft-deleted resources as unpublished")
    def restore_selected(self, request, queryset):
        restored = 0
        for resource in queryset.filter(is_deleted=True):
            restored += int(resource.restore())
        self.message_user(
            request,
            f"Restored {restored} resource(s). Restored resources remain unpublished.",
        )
