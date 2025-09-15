"""
Admin configuration for the events app.

Defines the list display and search fields for events in the Django
admin site.
"""
from django.contrib import admin

from .models import Event


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "organization",
        "status",
        "is_live",
        "active_speaker",
        "live_started_at",
        "live_ended_at",
        "created_by",
        "created_at",
    )
    list_filter = ("status", "organization", "is_live")
    search_fields = ("title", "organization__name")
    prepopulated_fields = {"slug": ("title",)}