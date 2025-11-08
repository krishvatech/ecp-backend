from django.contrib import admin
from .models import Comment, Reaction, Share

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ("id", "content_type", "object_id", "user", "parent", "created_at")
    list_filter = ("created_at",)
    search_fields = ("text", "user__username")

@admin.register(Reaction)
class ReactionAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "reaction", "content_type", "object_id", "created_at")
    list_filter = ("reaction", "created_at")
    search_fields = ("user__username",)

@admin.register(Share)
class ShareAdmin(admin.ModelAdmin):
    list_display = (
        "id", "content_type", "object_id", "user", "to_user", "to_group", "created_at"
    )
    list_filter = ("created_at", "content_type")
    search_fields = ("user__username", "note", "to_user__username", "to_group__name")