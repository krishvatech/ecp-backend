from django.contrib import admin
from django.contrib.auth.models import User
from django import forms
from .models import (
    Event, EventParticipant, LoungeTable, LoungeParticipant, EventRegistration,
    EventSession, SessionParticipant, SessionAttendance
)


class EventParticipantForm(forms.ModelForm):
    """Custom form for EventParticipant with dynamic field filtering."""

    class Meta:
        model = EventParticipant
        fields = ['event', 'participant_type', 'role', 'display_order', 'user',
                  'event_bio', 'event_image', 'guest_name', 'guest_email', 'guest_bio', 'guest_image']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Always filter user field to is_staff=True
        self.fields['user'].queryset = User.objects.filter(is_staff=True)

        # Get the current participant_type
        participant_type = self.instance.participant_type if self.instance.pk else None

        # If participant_type is 'guest', make user field optional and not required
        if participant_type == EventParticipant.PARTICIPANT_TYPE_GUEST:
            self.fields['user'].required = False
            self.fields['user'].widget.attrs['disabled'] = True

        # Add JavaScript to handle dynamic field updates
        self.fields['participant_type'].widget.attrs['onchange'] = (
            "toggleParticipantFields(this.value)"
        )


class EventParticipantInline(admin.TabularInline):
    """Inline admin for EventParticipant supporting both staff and guest types."""
    model = EventParticipant
    extra = 1
    fields = ('participant_type', 'user', 'guest_name', 'role', 'display_order')
    # Use raw_id_fields instead of autocomplete_fields for better control
    raw_id_fields = ['user']
    ordering = ['display_order', 'created_at']

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        """Filter user field to show only staff users."""
        if db_field.name == 'user':
            kwargs['queryset'] = User.objects.filter(is_staff=True)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


class EventSessionInline(admin.TabularInline):
    """Inline for managing sessions within Event admin."""
    model = EventSession
    extra = 0
    fields = ('title', 'session_type', 'start_time', 'end_time', 'display_order', 'is_live')
    readonly_fields = ('is_live',)
    ordering = ['display_order', 'start_time']
    show_change_link = True


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ("title", "community", "status", "is_live", "is_on_break", "created_by", "created_at")
    list_filter = ("status", "community", "lounge_enabled_before", "lounge_enabled_during", "lounge_enabled_after")
    search_fields = ("title", "community__name")
    prepopulated_fields = {"slug": ("title",)}
    inlines = [EventParticipantInline, EventSessionInline]
    fieldsets = (
        (None, {"fields": ("community", "title", "slug", "description", "start_time", "end_time", "timezone", "status", "is_live", "is_on_break")}),
        ("Lounge Timing Settings", {
            "fields": (
                "lounge_enabled_before", "lounge_before_buffer",
                "lounge_enabled_during", "lounge_enabled_breaks",
                "lounge_enabled_after", "lounge_after_buffer"
            )
        }),
        ("Meta", {"fields": ("category", "format", "location", "price", "is_free", "max_participants", "saleor_product_id", "saleor_variant_id", "preview_image")}),
    )

    def save_model(self, request, obj, form, change):
        """Automatically set created_by to the current user when creating events."""
        if not change:  # Only on creation, not on edit
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(EventParticipant)
class EventParticipantAdmin(admin.ModelAdmin):
    """Standalone admin for EventParticipant supporting staff and guest participants."""
    form = EventParticipantForm
    list_display = ('get_participant_name', 'event', 'role', 'participant_type', 'display_order', 'created_at')
    list_filter = ('participant_type', 'role', 'event__status', 'created_at')
    search_fields = ('user__username', 'user__first_name', 'user__last_name', 'guest_name', 'guest_email', 'event__title')
    # Use raw_id_fields instead of autocomplete to have more control
    raw_id_fields = ('user', 'event')
    ordering = ['event', 'display_order', 'created_at']
    readonly_fields = ('created_at', 'updated_at')

    fieldsets = (
        (None, {
            'fields': ('event', 'participant_type', 'role', 'display_order')
        }),
        ('Staff Participant', {
            'fields': ('user', 'event_bio', 'event_image'),
            'description': 'For staff members. Leave empty if using guest type.',
            'classes': ('collapse',)
        }),
        ('Guest Participant', {
            'fields': ('guest_name', 'guest_email', 'guest_bio', 'guest_image'),
            'description': 'For external guest speakers not in the system.',
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_participant_name(self, obj):
        """Display name of participant based on type."""
        return obj.get_name()
    get_participant_name.short_description = 'Participant Name'

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        """Filter user field to show only staff users."""
        if db_field.name == 'user':
            kwargs['queryset'] = User.objects.filter(is_staff=True)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    class Media:
        """Add inline JavaScript to handle dynamic field toggling."""
        js = ('admin/js/event_participant_admin.js',)
        css = {'all': ('admin/css/event_participant_admin.css',)}


@admin.register(LoungeTable)
class LoungeTableAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "category", "event", "max_seats", "created_at")
    list_filter = ("category", "event")
    search_fields = ("name", "event__title")

@admin.register(LoungeParticipant)
class LoungeParticipantAdmin(admin.ModelAdmin):
    list_display = ("user", "table", "seat_index")
    list_filter = ("table__event",)

@admin.register(EventRegistration)
class EventRegistrationAdmin(admin.ModelAdmin):
    list_display = ("user", "event", "status", "registered_at", "admission_status")
    list_filter = ("status", "admission_status", "event", "registered_at")
    search_fields = ("user__username", "user__email", "event__title")
    readonly_fields = ("registered_at", "admitted_at", "rejected_at")
    
    fieldsets = (
        ("Registration Info", {
            "fields": ("event", "user", "status", "registered_at")
        }),
        ("Admission", {
            "fields": ("admission_status", "admitted_at", "admitted_by", "rejected_at", "rejected_by", "rejection_reason")
        }),
        ("Session", {
            "fields": ("was_ever_admitted", "joined_live", "joined_live_at", "watched_replay", "session_token")
        }),
        ("Other", {
            "fields": ("is_online", "online_count", "is_banned")
        }),
    )


# ============================================================
# ==================== Session Admin Classes ================
# ============================================================

class SessionParticipantInline(admin.TabularInline):
    """Inline for managing session participants."""
    model = SessionParticipant
    extra = 1
    fields = ('participant_type', 'user', 'guest_name', 'role', 'display_order')
    raw_id_fields = ['user']
    ordering = ['display_order', 'created_at']

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        if db_field.name == 'user':
            kwargs['queryset'] = User.objects.filter(is_staff=True)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


@admin.register(EventSession)
class EventSessionAdmin(admin.ModelAdmin):
    """Admin for event sessions."""
    list_display = ('title', 'event', 'session_type', 'start_time', 'is_live', 'display_order')
    list_filter = ('session_type', 'is_live', 'use_parent_meeting')
    search_fields = ('title', 'event__title')
    raw_id_fields = ('event',)
    readonly_fields = ('is_live', 'live_started_at', 'live_ended_at', 'dyte_meeting_id', 'created_at', 'updated_at')
    inlines = [SessionParticipantInline]

    fieldsets = (
        (None, {
            'fields': ('event', 'title', 'description', 'session_type', 'display_order')
        }),
        ('Timing', {
            'fields': ('start_time', 'end_time')
        }),
        ('Live Status', {
            'fields': ('is_live', 'live_started_at', 'live_ended_at')
        }),
        ('Dyte Integration', {
            'fields': ('use_parent_meeting', 'dyte_meeting_id', 'recording_url')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(SessionAttendance)
class SessionAttendanceAdmin(admin.ModelAdmin):
    """Admin for session attendance tracking."""
    list_display = ('user', 'session', 'joined_at', 'duration_seconds', 'is_online')
    list_filter = ('session__event', 'is_online')
    search_fields = ('user__username', 'session__title')
    readonly_fields = ('joined_at', 'created_at', 'updated_at')
    raw_id_fields = ('session', 'user')
