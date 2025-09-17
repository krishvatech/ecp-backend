"""
Admin registration for the interactions app.

Registers ChatMessage and Question models for basic moderation and review.
"""

from django.contrib import admin

from .models import ChatMessage, Question


@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ("id", "event", "user", "short_content", "created_at")
    list_filter = ("event",)
    search_fields = ("content", "user__username", "event__title")
    readonly_fields = ("created_at", "updated_at")
    date_hierarchy = "created_at"

    @admin.display(description="content")
    def short_content(self, obj: ChatMessage) -> str:
        return (obj.content or "")[:80]


@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    list_display = ("id", "event", "user", "is_answered", "short_question", "answered_by", "answered_at", "created_at")
    list_filter = ("event", "is_answered")
    search_fields = ("content", "answer", "user__username", "event__title")
    readonly_fields = ("created_at", "updated_at", "answered_at")
    date_hierarchy = "created_at"

    @admin.display(description="question")
    def short_question(self, obj: Question) -> str:
        return (obj.content or "")[:80]
