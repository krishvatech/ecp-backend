"""
Admin configuration for the events app.

Defines the list display and search fields for events in the Django
admin site.
"""
from django.contrib import admin

from .models import Event


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ("title", "community", "status", "is_live", "created_by", "created_at")
    list_filter = ("status", "community")
    search_fields = ("title", "community__name")
    prepopulated_fields = {"slug": ("title",)}