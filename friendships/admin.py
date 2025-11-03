from django.contrib import admin
from .models import Friendship, FriendRequest


@admin.register(Friendship)
class FriendshipAdmin(admin.ModelAdmin):
    list_display = ("id", "user1", "user2", "created_at")
    search_fields = ("user1__username", "user2__username")
    list_filter = ()
    ordering = ("-created_at",)


@admin.register(FriendRequest)
class FriendRequestAdmin(admin.ModelAdmin):
    list_display = ("id", "from_user", "to_user", "status", "created_at", "responded_at")
    search_fields = ("from_user__username", "to_user__username")
    list_filter = ("status",)
    ordering = ("-created_at",)
