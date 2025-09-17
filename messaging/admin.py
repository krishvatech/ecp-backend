"""
Django admin configuration for the messaging app.

Registers Conversation and Message models with list filters and search
capabilities on participant usernames.
"""
from django.contrib import admin

from .models import Conversation, Message


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = ("id", "user1", "user2", "updated_at", "created_at")
    list_filter = ("updated_at",)
    search_fields = ("user1__username", "user2__username")
    ordering = ("-updated_at",)


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ("id", "conversation", "sender", "short_body", "is_read", "created_at")
    list_filter = ("is_read", "created_at")
    search_fields = ("sender__username", "body")
    ordering = ("-created_at",)

    def short_body(self, obj: Message) -> str:
        return obj.body[:50]
    short_body.short_description = "Body"
