"""
Django admin configuration for the messaging app.

Registers Conversation and Message models with list filters and search
capabilities on participant usernames.
"""
from django.contrib import admin

from .models import Conversation, Message


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = ("id", "is_group", "room_key", "title", "user1", "user2", "updated_at", "created_at")
    list_filter = ("is_group", "updated_at")
    search_fields = ("room_key", "title", "user1__username", "user2__username")
    ordering = ("-updated_at",)


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ("id", "conversation", "sender", "is_read", "is_hidden", "is_deleted", "created_at")
    list_filter  = ("is_read", "is_hidden", "is_deleted", "created_at")
    search_fields = ("sender__username", "body")
    ordering = ("-created_at",)
