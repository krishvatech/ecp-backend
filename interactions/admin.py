"""
Admin registration for the interactions app.

Registers ChatMessage and Question models for basic moderation and review.
"""

from django.contrib import admin

from .models import ChatMessage, Question,QuestionUpvote


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
    list_display = ("id", "event", "user", "short_question", "upvote_count", "is_hidden", "created_at")
    list_filter = ("event", "is_hidden")
    search_fields = ("content", "user__username", "event__title")
    readonly_fields = ("created_at", "updated_at", "hidden_by", "hidden_at")
    fieldsets = (
        ("Question Details", {
            "fields": ("event", "user", "content", "created_at", "updated_at")
        }),
        ("Visibility Control", {
            "fields": ("is_hidden", "hidden_by", "hidden_at"),
            "classes": ("collapse",),
        }),
    )
    date_hierarchy = "created_at"

    @admin.display(description="question")
    def short_question(self, obj: Question) -> str:
        return (obj.content or "")[:80]

@admin.register(QuestionUpvote)
class QuestionUpvoteAdmin(admin.ModelAdmin):
    list_display = ("id", "question", "user", "created_at")
    list_filter = ("question__event",)
    search_fields = ("question__content", "user__username")
    readonly_fields = ("created_at",)