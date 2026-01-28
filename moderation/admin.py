from django.contrib import admin
from .models import Report, ModerationAction


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("id", "content_type", "object_id", "reason", "reporter", "created_at")
    list_filter = ("reason", "content_type")
    search_fields = ("object_id", "reporter__username", "reporter__email")


@admin.register(ModerationAction)
class ModerationActionAdmin(admin.ModelAdmin):
    list_display = ("id", "content_type", "object_id", "action", "performed_by", "created_at")
    list_filter = ("action", "content_type")
    search_fields = ("object_id", "performed_by__username", "performed_by__email")
