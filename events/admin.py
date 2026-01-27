from django.contrib import admin
from .models import Event, LoungeTable, LoungeParticipant

@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ("title", "community", "status", "is_live", "is_on_break", "created_by", "created_at")
    list_filter = ("status", "community", "lounge_enabled_before", "lounge_enabled_during", "lounge_enabled_after")
    search_fields = ("title", "community__name")
    prepopulated_fields = {"slug": ("title",)}
    fieldsets = (
        (None, {"fields": ("community", "title", "slug", "description", "start_time", "end_time", "timezone", "status", "is_live", "is_on_break")}),
        ("Lounge Timing Settings", {
            "fields": (
                "lounge_enabled_before", "lounge_before_buffer",
                "lounge_enabled_during", "lounge_enabled_breaks",
                "lounge_enabled_after", "lounge_after_buffer"
            )
        }),
        ("Meta", {"fields": ("category", "format", "location", "price", "is_free", "preview_image")}),
    )

@admin.register(LoungeTable)
class LoungeTableAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "category", "event", "max_seats", "created_at")
    list_filter = ("category", "event")
    search_fields = ("name", "event__title")

@admin.register(LoungeParticipant)
class LoungeParticipantAdmin(admin.ModelAdmin):
    list_display = ("user", "table", "seat_index")
    list_filter = ("table__event",)