"""
Admin configuration for the community app.

Defines how community are displayed in the Django admin list view.
"""
from django.contrib import admin

from .models import Community


@admin.register(Community)
class CommunityAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "created_at")
    search_fields = ("name", "owner__username")
    prepopulated_fields = {"slug": ("name",)}