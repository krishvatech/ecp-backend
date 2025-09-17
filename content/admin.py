"""
Django admin configuration for the content app.

Registers the Resource model with filters on organization, event and
type to aid review of uploaded materials.
"""
from django.contrib import admin
from .models import Resource

@admin.register(Resource)
class ResourceAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "type",
        "organization",
        "event",
        "uploaded_by",
        "is_published",
        "created_at",
    )
    list_filter = ("organization", "event", "type", "is_published")
    search_fields = ("title", "description")
    ordering = ("-created_at",)
