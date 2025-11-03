# content/admin.py
from django.contrib import admin
from .models import Resource

@admin.register(Resource)
class ResourceAdmin(admin.ModelAdmin):
    list_display = ("title", "type", "community", "event", "uploaded_by",
                    "is_published", "publish_at", "created_at") 
    list_filter = ("community", "event", "type", "is_published")
    search_fields = ("title", "description")
    ordering = ("-created_at",)
    actions = ["publish_now"]

    @admin.action(description="Publish selected resources now")
    def publish_now(self, request, queryset):
        for r in queryset:
            r.publish_now(save=True)
