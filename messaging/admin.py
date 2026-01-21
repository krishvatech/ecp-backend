# messaging/admin.py
from django.contrib import admin
from .models import Conversation, Message

class ConversationTypeFilter(admin.SimpleListFilter):
    title = "Type"
    parameter_name = "type"

    def lookups(self, request, model_admin):
        return (("dm", "Direct"), ("group", "Group"), ("event", "Event"), ("lounge", "Lounge"))

    def queryset(self, request, qs):
        v = self.value()
        if v == "dm":
            return qs.filter(group__isnull=True, event__isnull=True, lounge_table__isnull=True)
        if v == "group":
            return qs.filter(group__isnull=False, event__isnull=True, lounge_table__isnull=True)
        if v == "event":
            return qs.filter(event__isnull=False, group__isnull=True, lounge_table__isnull=True)
        if v == "lounge":
            return qs.filter(lounge_table__isnull=False)
        return qs

@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = ("id", "chat_type", "room_key", "title", "user1", "user2", "group", "event", "lounge_table", "updated_at", "created_at")
    list_filter = (ConversationTypeFilter, "updated_at")
    search_fields = ("room_key", "title", "user1__username", "user2__username", "group__name", "event__title", "lounge_table__name")
    ordering = ("-updated_at",)

    def chat_type(self, obj):
        if obj.group_id: return "Group"
        if obj.event_id: return "Event"
        if obj.lounge_table_id: return "Lounge"
        return "Direct"

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ("id", "conversation", "sender",  "is_hidden", "is_deleted", "created_at")
    list_filter  = ( "is_hidden", "is_deleted", "created_at")
    search_fields = ("sender__username", "body")
    ordering = ("-created_at",)
