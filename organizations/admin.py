"""
Admin configuration for the organizations app.

Defines how organizations are displayed in the Django admin list view.
"""
from django.contrib import admin

from .models import Organization


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "created_at")
    search_fields = ("name", "owner__username")
    prepopulated_fields = {"slug": ("name",)}