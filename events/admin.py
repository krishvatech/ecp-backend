from django.contrib import admin
from django.contrib.auth.models import User
from django import forms
from django.utils import timezone
from .models import (
    Event, EventParticipant, LoungeTable, LoungeParticipant, EventRegistration,
    EventSession, SessionBreak, SessionParticipant, SessionAttendance, EventApplication,
    EventPreApprovalCode, EventPreApprovalAllowlist, EventSaleorDiscount, EventSessionBookmark,
    EventRole, EventApplicationTrack, TrackPricingTier,
    SharedQuestionCategory, SharedQuestion, FormField,
    EventApplicationTrackApplication, EventAttendeeOrigin,
    PostAcceptanceFormTemplate, PostAcceptanceFormAssignment, ExternalEventMapping, ExternalParticipantMapping,
    EventPlatform, EventPublication, PlatformSyncJob, EventSeries, EventBadgeLabel, NetworkingTable
)




@admin.action(description='Restore selected deactivated networking tables')
def restore_networking_tables(modeladmin, request, queryset):
    queryset.update(
        is_active=True,
        deactivated_at=None,
        deactivated_by=None,
        deactivation_reason='',
    )


@admin.register(NetworkingTable)
class NetworkingTableAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'event', 'table_number', 'is_active', 'deactivated_at', 'updated_at'
    )
    list_filter = ('is_active', 'event')
    search_fields = ('name', 'event__title', 'location_note')
    readonly_fields = (
        'created_at', 'updated_at', 'deactivated_at', 'deactivated_by', 'deactivation_reason'
    )
    actions = [restore_networking_tables]


@admin.action(description='Restore selected soft-deleted badge labels')
def restore_badge_labels(modeladmin, request, queryset):
    queryset.update(
        is_active=True,
        deactivated_at=None,
        deactivated_by=None,
        deactivation_reason='',
    )


@admin.register(EventBadgeLabel)
class EventBadgeLabelAdmin(admin.ModelAdmin):
    list_display = ('name', 'event', 'color', 'is_active', 'deactivated_at', 'created_at')
    list_filter = ('is_active', 'event')
    search_fields = ('name', 'event__title')
    readonly_fields = ('created_at', 'updated_at', 'deactivated_at', 'deactivated_by')
    actions = [restore_badge_labels]



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


class EventRoleInline(admin.TabularInline):
    """Inline for managing roles within Event admin."""
    model = EventRole
    extra = 0
    fields = ('key', 'label', 'visibility', 'sort_priority', 'triggers_promotional_profile', 'is_system_default')
    ordering = ['sort_priority', 'label']


class EventApplicationTrackInline(admin.TabularInline):
    """Inline for managing application tracks within Event admin."""
    model = EventApplicationTrack
    extra = 0
    fields = ('key', 'label', 'status', 'is_active', 'sort_order')
    ordering = ['sort_order', 'label']


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ("title", "community", "status", "is_live", "is_on_break", "created_by", "created_at")
    list_filter = ("status", "community", "lounge_enabled_before", "lounge_enabled_during", "lounge_enabled_after")
    search_fields = ("title", "community__name")
    prepopulated_fields = {"slug": ("title",)}
    inlines = [EventParticipantInline, EventSessionInline, EventRoleInline, EventApplicationTrackInline]
    fieldsets = (
        (None, {"fields": ("community", "title", "slug", "description", "start_time", "end_time", "timezone", "status", "is_live", "is_on_break")}),
        ("Application Pre-Approval", {
            "fields": (
                "registration_type",
                "preapproval_code_enabled",
                "preapproval_allowlist_enabled",
                "attendee_marker_enabled",
                "attendee_marker_label",
            )
        }),
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


@admin.register(EventSeries)
class EventSeriesAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "community",
        "status",
        "is_deleted",
        "created_by",
        "created_at",
        "deleted_at",
    )
    list_filter = ("status", "is_deleted", "community", "created_at")
    search_fields = ("title", "slug", "created_by__username", "created_by__email")
    readonly_fields = ("created_at", "updated_at", "deleted_at", "deleted_by", "deletion_reason")
    actions = ("restore_selected_series",)

    def get_queryset(self, request):
        return EventSeries.all_objects.select_related("community", "created_by", "deleted_by")

    @admin.action(description="Restore selected soft-deleted series")
    def restore_selected_series(self, request, queryset):
        restored = 0
        for series in queryset.filter(is_deleted=True):
            series.restore()
            restored += 1
        self.message_user(request, f"Restored {restored} series.")

    def has_delete_permission(self, request, obj=None):
        # Platform deletion policy must run through the API so history checks are
        # never bypassed by an accidental Django Admin hard delete.
        return False


@admin.register(EventPlatform)
class EventPlatformAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "is_active", "display_order")
    list_editable = ("is_active", "display_order")
    search_fields = ("name", "slug")
    ordering = ("display_order", "name")


@admin.register(EventPublication)
class EventPublicationAdmin(admin.ModelAdmin):
    list_display = ("event", "platform", "is_enabled", "sync_status", "external_event_id", "last_synced_at")
    list_filter = ("platform", "is_enabled", "sync_status")
    search_fields = ("event__title", "event__slug", "platform__name", "platform__slug", "external_event_id")
    raw_id_fields = ("event",)
    readonly_fields = ("created_at", "updated_at", "last_synced_at")


@admin.register(PlatformSyncJob)
class PlatformSyncJobAdmin(admin.ModelAdmin):
    list_display = ("id", "event", "platform", "job_type", "status", "attempts", "next_attempt_at", "processed_at")
    list_filter = ("platform", "job_type", "status")
    search_fields = ("event__title", "event__slug", "last_error")
    readonly_fields = (
        "event", "platform", "job_type", "status", "payload", "attempts", "max_attempts",
        "next_attempt_at", "locked_at", "processed_at", "last_error", "created_at", "updated_at",
    )
    raw_id_fields = ("event",)
    ordering = ("-id",)


@admin.register(ExternalEventMapping)
class ExternalEventMappingAdmin(admin.ModelAdmin):
    list_display = (
        "source_platform",
        "source_event_id",
        "canonical_event_id",
        "local_event",
        "is_active",
        "last_synced_at",
        "disabled_at",
    )
    list_filter = ("source_platform", "is_active")
    search_fields = ("source_event_id", "canonical_event_id", "local_event__title", "local_event__slug")
    readonly_fields = ("created_at", "updated_at", "last_synced_at", "disabled_at", "last_payload")
    raw_id_fields = ("local_event",)


@admin.register(ExternalParticipantMapping)
class ExternalParticipantMappingAdmin(admin.ModelAdmin):
    list_display = (
        "source_platform",
        "source_participant_id",
        "canonical_event_id",
        "cognito_sub",
        "local_registration",
        "is_active",
        "last_source_updated_at",
    )
    list_filter = ("source_platform", "is_active")
    search_fields = (
        "source_participant_id",
        "canonical_event_id",
        "cognito_sub",
        "local_registration__event__title",
        "local_registration__user__email",
        "local_registration__user__username",
    )
    readonly_fields = ("created_at", "updated_at", "last_source_updated_at", "last_payload")
    raw_id_fields = ("local_registration",)



@admin.register(EventParticipant)
class EventParticipantAdmin(admin.ModelAdmin):
    """Standalone admin for EventParticipant supporting staff and guest participants."""
    form = EventParticipantForm
    list_display = ('get_participant_name', 'event', 'role', 'participant_type', 'is_deleted', 'display_order', 'created_at')
    list_filter = ('is_deleted', 'participant_type', 'role', 'event__status', 'created_at')
    search_fields = ('user__username', 'user__first_name', 'user__last_name', 'guest_name', 'guest_email', 'event__title')
    # Use raw_id_fields instead of autocomplete to have more control
    raw_id_fields = ('user', 'event', 'deleted_by')
    ordering = ['event', 'display_order', 'created_at']
    readonly_fields = ('is_deleted', 'deleted_at', 'deleted_by', 'deletion_reason', 'created_at', 'updated_at')
    actions = ('soft_delete_selected_participants', 'restore_selected_participants')

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
        ('Deletion audit', {
            'fields': ('is_deleted', 'deleted_at', 'deleted_by', 'deletion_reason'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return EventParticipant.all_objects.select_related('event', 'user', 'deleted_by')

    @admin.action(description='Soft delete selected event participants')
    def soft_delete_selected_participants(self, request, queryset):
        for participant in queryset.filter(is_deleted=False):
            participant.soft_delete(
                user=request.user,
                reason='Removed from Django admin.',
            )

    @admin.action(description='Restore selected event participants')
    def restore_selected_participants(self, request, queryset):
        for participant in queryset.filter(is_deleted=True):
            participant.restore()

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


@admin.action(description="Restore selected deactivated lounge tables")
def restore_lounge_tables(modeladmin, request, queryset):
    for table in queryset:
        table.restore()


@admin.register(LoungeTable)
class LoungeTableAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "category",
        "event",
        "max_seats",
        "is_active",
        "deactivated_at",
        "created_at",
    )
    list_filter = ("is_active", "category", "event")
    search_fields = ("name", "event__title", "rtk_meeting_id")
    readonly_fields = ("created_at", "deactivated_at", "deactivated_by")
    actions = [restore_lounge_tables]

    def get_queryset(self, request):
        return LoungeTable.all_objects.select_related("event", "deactivated_by")

@admin.register(LoungeParticipant)
class LoungeParticipantAdmin(admin.ModelAdmin):
    list_display = ("user", "table", "seat_index")
    list_filter = ("table__event",)

class EventAttendeeOriginInline(admin.TabularInline):
    """Phase 11: Inline for viewing/managing attendee origin metadata per role."""
    model = EventAttendeeOrigin
    extra = 0
    fields = ('role', 'track', 'submission_mode', 'accepted_tier', 'accepted_by', 'accepted_at', 'nominator_name', 'status')
    readonly_fields = ('role', 'track', 'submission_mode', 'accepted_tier', 'accepted_by', 'accepted_at', 'nominator_name', 'created_at')
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(EventRegistration)
class EventRegistrationAdmin(admin.ModelAdmin):
    list_display = ("user", "event", "status", "attendee_status", "registered_at", "admission_status")
    list_filter = ("status", "attendee_status", "admission_status", "event", "registered_at")
    search_fields = ("user__username", "user__email", "event__title")
    readonly_fields = ("registered_at", "admitted_at", "rejected_at", "marked_paid_at", "marked_paid_by")

    fieldsets = (
        ("Registration Info", {
            "fields": ("event", "user", "status", "attendee_status", "registered_at")
        }),
        ("Admission", {
            "fields": ("admission_status", "admitted_at", "admitted_by", "rejected_at", "rejected_by", "rejection_reason")
        }),
        ("Session", {
            "fields": ("was_ever_admitted", "joined_live", "joined_live_at", "watched_replay", "session_token")
        }),
        ("Phase 11: Payment Tracking", {
            "fields": ("marked_paid_by", "marked_paid_at", "payment_reference"),
            "classes": ("collapse",),
            "description": "Manual payment tracking for payment_pending → confirmed transition"
        }),
        ("Other", {
            "fields": ("is_online", "online_count", "is_banned")
        }),
    )
    inlines = [EventAttendeeOriginInline]


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
    """Admin for active and soft-deleted event sessions."""
    list_display = ('title', 'event', 'session_type', 'start_time', 'is_live', 'is_deleted', 'display_order')
    list_filter = ('is_deleted', 'session_type', 'is_live', 'use_parent_meeting')
    search_fields = ('title', 'event__title')
    raw_id_fields = ('event', 'deleted_by')
    readonly_fields = (
        'is_live', 'live_started_at', 'live_ended_at', 'rtk_meeting_id',
        'deleted_at', 'deleted_by', 'created_at', 'updated_at',
    )
    inlines = [SessionParticipantInline]
    actions = ('soft_delete_selected_sessions', 'restore_selected_sessions')

    def get_queryset(self, request):
        return EventSession.all_objects.select_related('event', 'deleted_by')

    @admin.action(description='Soft delete selected sessions')
    def soft_delete_selected_sessions(self, request, queryset):
        now = timezone.now()
        for session in queryset.filter(is_deleted=False, is_live=False):
            SessionBreak.objects.filter(session=session).update(
                is_deleted=True,
                deleted_at=now,
                deleted_by=request.user,
                deletion_reason='Deleted with parent session from Django admin.',
                deleted_with_session=True,
            )
            session.is_deleted = True
            session.deleted_at = now
            session.deleted_by = request.user
            session.deletion_reason = 'Deleted from Django admin.'
            session.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by', 'deletion_reason', 'updated_at'])

    @admin.action(description='Restore selected soft-deleted sessions')
    def restore_selected_sessions(self, request, queryset):
        for session in queryset.filter(is_deleted=True):
            session.is_deleted = False
            session.deleted_at = None
            session.deleted_by = None
            session.deletion_reason = ''
            session.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by', 'deletion_reason', 'updated_at'])
            SessionBreak.all_objects.filter(
                session=session,
                is_deleted=True,
                deleted_with_session=True,
            ).update(
                is_deleted=False,
                deleted_at=None,
                deleted_by=None,
                deletion_reason='',
                deleted_with_session=False,
            )

    def has_delete_permission(self, request, obj=None):
        # Prevent Django admin from invoking a cascading hard delete.
        return False

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
        ('RTK Integration', {
            'fields': ('use_parent_meeting', 'rtk_meeting_id', 'recording_url')
        }),
        ('Soft delete', {
            'fields': ('is_deleted', 'deleted_at', 'deleted_by', 'deletion_reason')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(SessionBreak)
class SessionBreakAdmin(admin.ModelAdmin):
    list_display = ('label', 'session', 'break_type', 'duration_minutes', 'is_deleted', 'deleted_with_session')
    list_filter = ('is_deleted', 'deleted_with_session', 'break_type')
    search_fields = ('label', 'session__title', 'session__event__title')
    raw_id_fields = ('session', 'deleted_by')
    readonly_fields = ('deleted_at', 'deleted_by', 'created_at')
    actions = ('restore_selected_breaks',)

    def get_queryset(self, request):
        return SessionBreak.all_objects.select_related('session', 'session__event', 'deleted_by')

    @admin.action(description='Restore selected soft-deleted breaks')
    def restore_selected_breaks(self, request, queryset):
        queryset.filter(is_deleted=True, session__is_deleted=False).update(
            is_deleted=False,
            deleted_at=None,
            deleted_by=None,
            deletion_reason='',
            deleted_with_session=False,
        )

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(SessionAttendance)
class SessionAttendanceAdmin(admin.ModelAdmin):
    """Admin for session attendance tracking."""
    list_display = ('user', 'session', 'joined_at', 'duration_seconds', 'is_online')
    list_filter = ('session__event', 'is_online')
    search_fields = ('user__username', 'session__title')
    readonly_fields = ('joined_at', 'created_at', 'updated_at')
    raw_id_fields = ('session', 'user')


# Phase 7: Multi-track applications inline
class EventApplicationTrackApplicationInline(admin.TabularInline):
    """Inline admin for EventApplicationTrackApplication within EventApplication."""
    model = EventApplicationTrackApplication
    extra = 0
    fields = ('track', 'submission_mode', 'status', 'tier_preference', 'reviewed_by', 'reviewed_at')
    raw_id_fields = ('track', 'tier_preference', 'reviewed_by')
    readonly_fields = ('track', 'submission_mode', 'created_at', 'reviewed_at')
    can_delete = False


@admin.register(EventApplication)
class EventApplicationAdmin(admin.ModelAdmin):
    list_display = ("id", "event", "email", "status", "is_preapproved", "preapproval_source", "applied_at")
    list_filter = ("status", "is_preapproved", "preapproval_source", "event")
    search_fields = ("email", "first_name", "last_name", "event__title")
    inlines = [EventApplicationTrackApplicationInline]
    readonly_fields = ('selected_tracks', 'applied_at')

    fieldsets = (
        (None, {
            'fields': ('event', 'first_name', 'last_name', 'email', 'job_title', 'company_name', 'linkedin_url')
        }),
        ('Application', {
            'fields': ('status', 'is_preapproved', 'preapproval_source', 'preapproved_at', 'submission_mode', 'application_track_id', 'applied_at')
        }),
        ('Multi-Track Support', {
            'fields': ('selected_tracks',),
            'description': 'Phase 7: List of track IDs selected in multi-track application',
            'classes': ('collapse',)
        }),
        ('Review', {
            'fields': ('reviewed_by', 'reviewed_at', 'rejection_message')
        }),
        ('Additional Info', {
            'fields': ('attendee_marker_value', 'comments'),
            'classes': ('collapse',)
        }),
    )


@admin.register(EventPreApprovalCode)
class EventPreApprovalCodeAdmin(admin.ModelAdmin):
    # Phase 8: Added track and submission_mode to display and filtering
    list_display = ("id", "event", "track", "submission_mode", "code", "status", "used_by_email", "used_at", "created_at")
    list_filter = ("status", "event", "track", "submission_mode")
    search_fields = ("code", "used_by_email", "event__title")
    raw_id_fields = ("event", "track", "created_by", "used_by_user", "used_by_application")

    fieldsets = (
        ("Basic Info", {
            "fields": ("event", "track", "submission_mode", "code")
        }),
        ("Status", {
            "fields": ("status", "notes")
        }),
        ("Usage Tracking", {
            "fields": ("used_by_email", "used_by_user", "used_by_application", "used_at")
        }),
        ("Metadata", {
            "fields": ("created_by", "created_at"),
            "classes": ("collapse",)
        }),
    )


@admin.register(EventPreApprovalAllowlist)
class EventPreApprovalAllowlistAdmin(admin.ModelAdmin):
    # Phase 8: Added track and submission_mode to display and filtering
    list_display = ("id", "event", "track", "submission_mode", "email", "first_name", "last_name", "is_active", "created_at")
    list_filter = ("is_active", "event", "track", "submission_mode")
    search_fields = ("email", "first_name", "last_name", "event__title")
    raw_id_fields = ("event", "track", "created_by", "removed_by")

    fieldsets = (
        ("Basic Info", {
            "fields": ("event", "track", "submission_mode", "email", "first_name", "last_name")
        }),
        ("Status", {
            "fields": ("is_active", "notes")
        }),
        ("Metadata", {
            "fields": ("created_by", "created_at", "removed_by", "removed_at"),
            "classes": ("collapse",)
        }),
    )


@admin.register(EventSaleorDiscount)
class EventSaleorDiscountAdmin(admin.ModelAdmin):
    list_display = ("id", "event", "name", "channel_name", "reward_value_type", "reward_value", "badge_label", "start_date", "end_date", "saleor_promotion_id", "created_at")
    list_filter = ("badge_label", "reward_value_type", "event", "created_at")
    search_fields = ("name", "event__title", "saleor_promotion_id")
    readonly_fields = ("saleor_promotion_id", "saleor_rule_id", "discount_type", "channel_name", "channel_slug", "currency", "created_by", "created_at", "updated_at", "last_sync_error")
    raw_id_fields = ("event", "created_by")

    fieldsets = (
        ("Basic Info", {
            "fields": ("event", "name", "description", "discount_type", "badge_label")
        }),
        ("Channel & Reward", {
            "fields": ("channel_id", "channel_name", "channel_slug", "currency", "reward_value_type", "reward_value")
        }),
        ("Dates", {
            "fields": ("start_date", "end_date")
        }),
        ("Saleor Integration", {
            "fields": ("saleor_promotion_id", "saleor_rule_id", "last_sync_error")
        }),
        ("Metadata", {
            "fields": ("created_by", "created_at", "updated_at"),
            "classes": ("collapse",)
        }),
    )


@admin.register(EventSessionBookmark)
class EventSessionBookmarkAdmin(admin.ModelAdmin):
    """Admin for session bookmarks."""
    list_display = ['id', 'user', 'session', 'event', 'created_at']
    list_filter = ['event', 'created_at']
    search_fields = ['user__username', 'session__title', 'event__title']
    readonly_fields = ['created_at']
    raw_id_fields = ['event', 'session', 'user']


@admin.register(EventRole)
class EventRoleAdmin(admin.ModelAdmin):
    """Admin for EventRole - attendee role catalog."""
    list_display = ('label', 'event', 'key', 'visibility', 'triggers_promotional_profile', 'sort_priority', 'created_at')
    list_filter = ('event', 'visibility', 'triggers_promotional_profile', 'is_system_default', 'created_at')
    search_fields = ('event__title', 'label', 'key')
    raw_id_fields = ('event',)
    readonly_fields = ('is_system_default', 'created_at', 'updated_at')
    ordering = ['event', 'sort_priority', 'label']

    fieldsets = (
        (None, {
            'fields': ('event', 'key', 'label', 'description')
        }),
        ('Display Settings', {
            'fields': ('visibility', 'sort_priority', 'badge_color', 'badge_style')
        }),
        ('Profile Settings', {
            'fields': ('triggers_promotional_profile',)
        }),
        ('System', {
            'fields': ('is_system_default', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


class TrackPricingTierInline(admin.TabularInline):
    """Inline for managing pricing tiers within EventApplicationTrack admin."""
    model = TrackPricingTier
    extra = 0
    fields = ('key', 'label', 'price', 'currency', 'is_default', 'is_active', 'sort_order')
    ordering = ['sort_order', 'label']

    def get_readonly_fields(self, request, obj=None):
        """Make key read-only on edit."""
        if obj:
            return self.readonly_fields + ['key']
        return self.readonly_fields


@admin.action(description='Restore selected application tracks')
def restore_application_tracks(modeladmin, request, queryset):
    restored = 0
    for track in queryset.filter(is_active=False):
        track.is_active = True
        track.status = track.status_before_deactivation or 'closed'
        track.status_before_deactivation = ''
        track.deactivated_at = None
        track.deactivated_by = None
        track.deactivation_reason = ''
        track.save(update_fields=[
            'is_active', 'status', 'status_before_deactivation',
            'deactivated_at', 'deactivated_by', 'deactivation_reason',
            'updated_at',
        ])
        restored += 1
    modeladmin.message_user(request, f'Restored {restored} application track(s).')


@admin.action(description='Restore selected pricing tiers as non-default')
def restore_pricing_tiers(modeladmin, request, queryset):
    restored = 0
    for tier in queryset.filter(is_active=False, track__is_active=True):
        tier.is_active = True
        tier.is_default = False
        tier.was_default_before_deactivation = False
        tier.deactivated_at = None
        tier.deactivated_by = None
        tier.deactivation_reason = ''
        tier.save(update_fields=[
            'is_active', 'is_default', 'was_default_before_deactivation',
            'deactivated_at', 'deactivated_by', 'deactivation_reason',
            'updated_at',
        ])
        restored += 1
    modeladmin.message_user(
        request,
        f'Restored {restored} pricing tier(s) as non-default. Review defaults before reopening applications.'
    )


@admin.register(EventApplicationTrack)
class EventApplicationTrackAdmin(admin.ModelAdmin):
    """Admin for EventApplicationTrack - application track configuration."""
    list_display = ('label', 'event', 'key', 'status', 'is_active', 'deactivated_at', 'sort_order', 'created_at')
    list_filter = ('event', 'status', 'is_active', 'is_system_default', 'created_at')
    search_fields = ('event__title', 'label', 'key')
    raw_id_fields = ('event',)
    readonly_fields = (
        'is_system_default', 'deactivated_at', 'deactivated_by',
        'deactivation_reason', 'status_before_deactivation',
        'created_at', 'updated_at'
    )
    ordering = ['event', 'sort_order', 'label']
    inlines = [TrackPricingTierInline]
    actions = [restore_application_tracks]

    fieldsets = (
        (None, {
            'fields': ('event', 'key', 'label', 'short_description')
        }),
        ('Track Settings', {
            'fields': ('status', 'is_active', 'sort_order')
        }),
        ('Submission Configuration', {
            'fields': ('enabled_submission_modes', 'form_schema', 'preapproval_configuration'),
            'classes': ('collapse',)
        }),
        ('Role & Content', {
            'fields': ('role_mappings_on_acceptance', 'content_surfaces'),
            'classes': ('collapse',)
        }),
        ('Content Blocks (Markdown)', {
            'fields': ('landing_page_content', 'form_header_notice', 'confirmation_page_content'),
            'description': 'Markdown-formatted content blocks displayed to applicants at different stages',
            'classes': ('collapse',)
        }),
        ('Removal audit', {
            'fields': (
                'deactivated_at', 'deactivated_by', 'deactivation_reason',
                'status_before_deactivation'
            ),
            'classes': ('collapse',)
        }),
        ('System', {
            'fields': ('is_system_default', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(TrackPricingTier)
class TrackPricingTierAdmin(admin.ModelAdmin):
    """Admin for TrackPricingTier - track-specific pricing configuration."""
    list_display = ('label', 'track', 'key', 'price', 'currency', 'is_default', 'is_active', 'deactivated_at', 'sort_order', 'created_at')
    list_filter = ('track__event', 'track', 'currency', 'is_default', 'is_active', 'created_at')
    search_fields = ('track__label', 'label', 'key', 'track__event__title')
    raw_id_fields = ('track',)
    readonly_fields = (
        'deactivated_at', 'deactivated_by', 'deactivation_reason',
        'was_default_before_deactivation', 'created_at', 'updated_at'
    )
    ordering = ['track', 'sort_order', 'label']
    actions = [restore_pricing_tiers]

    fieldsets = (
        (None, {
            'fields': ('track', 'key', 'label', 'description')
        }),
        ('Pricing', {
            'fields': ('price', 'currency')
        }),
        ('Configuration', {
            'fields': ('visibility', 'is_default', 'is_active', 'sort_order')
        }),
        ('Removal audit', {
            'fields': (
                'deactivated_at', 'deactivated_by', 'deactivation_reason',
                'was_default_before_deactivation'
            ),
            'classes': ('collapse',)
        }),
        ('System', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


# Phase 5: Form Schema Primitives and Shared Question Library

class SharedQuestionInline(admin.TabularInline):
    """Inline admin for SharedQuestion within category."""
    model = SharedQuestion
    extra = 0
    fields = ('label', 'field_type', 'placeholder', 'options')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ['id']


@admin.register(SharedQuestionCategory)
class SharedQuestionCategoryAdmin(admin.ModelAdmin):
    """Admin for SharedQuestionCategory - categories for form question library."""
    list_display = ('name', 'sort_order', 'question_count', 'created_at')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ['sort_order', 'name']
    inlines = [SharedQuestionInline]

    fieldsets = (
        (None, {
            'fields': ('name', 'description')
        }),
        ('Display', {
            'fields': ('sort_order',)
        }),
        ('System', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def question_count(self, obj):
        """Show count of questions in this category."""
        return obj.questions.count()
    question_count.short_description = 'Questions'


@admin.register(SharedQuestion)
class SharedQuestionAdmin(admin.ModelAdmin):
    """Admin for SharedQuestion - reusable form questions."""
    list_display = ('label', 'category', 'field_type', 'created_at')
    list_filter = ('category', 'field_type', 'created_at')
    search_fields = ('label', 'help_text', 'category__name')
    raw_id_fields = ('category',)
    readonly_fields = ('created_at', 'updated_at')
    ordering = ['category__sort_order', 'id']

    fieldsets = (
        (None, {
            'fields': ('category', 'label', 'field_type')
        }),
        ('Content', {
            'fields': ('help_text', 'placeholder')
        }),
        ('Options', {
            'fields': ('options',),
            'description': 'JSON array of {label, value} objects for select/radio/checkbox fields'
        }),
        ('System', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


class FormFieldInline(admin.TabularInline):
    """Inline admin for FormField within track."""
    model = FormField
    extra = 0
    fields = ('label', 'field_type', 'required', 'sort_order', 'shared_question')
    raw_id_fields = ('shared_question',)
    readonly_fields = ('created_at', 'updated_at')
    ordering = ['sort_order', 'id']


@admin.register(FormField)
class FormFieldAdmin(admin.ModelAdmin):
    """Admin for FormField - form schema for application tracks."""
    list_display = ('label', 'track', 'field_type', 'required', 'sort_order', 'visible_in_review_detail', 'created_at')
    list_filter = ('track__event', 'track', 'field_type', 'required', 'visible_in_review_detail', 'created_at')
    search_fields = ('label', 'track__label', 'track__event__title', 'help_text')
    raw_id_fields = ('track', 'shared_question')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ['track', 'sort_order', 'id']

    fieldsets = (
        (None, {
            'fields': ('track', 'label', 'field_type', 'shared_question')
        }),
        ('Content', {
            'fields': ('help_text', 'placeholder', 'required')
        }),
        ('Validation', {
            'fields': ('min_length', 'max_length', 'min_value', 'max_value'),
            'classes': ('collapse',)
        }),
        ('Options', {
            'fields': ('options',),
            'description': 'JSON array of {label, value} objects for select/radio/checkbox fields',
            'classes': ('collapse',)
        }),
        ('Profile Binding', {
            'fields': ('profile_binding', 'profile_binding_mode'),
            'description': 'Bind field to user profile for auto-prefill',
            'classes': ('collapse',)
        }),
        ('Visibility', {
            'fields': ('visibility_per_mode', 'conditional_visibility', 'visible_in_review_list', 'visible_in_review_detail'),
            'classes': ('collapse',)
        }),
        ('Display', {
            'fields': ('sort_order',)
        }),
        ('System', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(EventApplicationTrackApplication)
class EventApplicationTrackApplicationAdmin(admin.ModelAdmin):
    """Admin for EventApplicationTrackApplication - per-track application data."""
    list_display = (
        'get_applicant_email', 'track', 'submission_mode', 'status',
        'created_at', 'reviewed_by', 'reviewed_at'
    )
    list_filter = ('status', 'track__event', 'track', 'submission_mode', 'created_at')
    search_fields = (
        'application__email', 'application__first_name', 'application__last_name',
        'track__label'
    )
    raw_id_fields = ('application', 'track', 'tier_preference', 'reviewed_by')
    readonly_fields = ('application', 'track', 'submission_mode', 'form_answers', 'file_uploads', 'created_at', 'updated_at')
    ordering = ['-created_at']

    fieldsets = (
        (None, {
            'fields': ('application', 'track', 'submission_mode', 'status')
        }),
        ('Pricing', {
            'fields': ('tier_preference',)
        }),
        ('Form Data', {
            'fields': ('form_answers', 'file_uploads'),
            'classes': ('collapse',),
            'description': 'Read-only form answers and uploaded file metadata'
        }),
        ('Review', {
            'fields': ('reviewed_by', 'reviewed_at')
        }),
        ('System', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = ['mark_as_accepted', 'mark_as_declined', 'mark_as_waitlisted']

    def get_applicant_email(self, obj):
        """Display applicant email."""
        return obj.application.email
    get_applicant_email.short_description = 'Applicant Email'

    def mark_as_accepted(self, request, queryset):
        """Admin action to mark selected as accepted."""
        from django.utils import timezone
        updated = queryset.update(status='accepted', reviewed_by=request.user, reviewed_at=timezone.now())
        self.message_user(request, f'{updated} application(s) marked as accepted.')
    mark_as_accepted.short_description = "Mark selected as Accepted"

    def mark_as_declined(self, request, queryset):
        """Admin action to mark selected as declined."""
        from django.utils import timezone
        updated = queryset.update(status='declined', reviewed_by=request.user, reviewed_at=timezone.now())
        self.message_user(request, f'{updated} application(s) marked as declined.')
    mark_as_declined.short_description = "Mark selected as Declined"

    def mark_as_waitlisted(self, request, queryset):
        """Admin action to mark selected as waitlisted."""
        from django.utils import timezone
        updated = queryset.update(status='waitlisted', reviewed_by=request.user, reviewed_at=timezone.now())
        self.message_user(request, f'{updated} application(s) marked as waitlisted.')
    mark_as_waitlisted.short_description = "Mark selected as Waitlisted"


# Phase 11: Attendee Origin Admin
@admin.register(EventAttendeeOrigin)
class EventAttendeeOriginAdmin(admin.ModelAdmin):
    """Admin for Phase 11 attendee origin metadata tracking."""
    list_display = ('get_attendee_name', 'role', 'track', 'submission_mode', 'accepted_tier', 'accepted_at', 'status')
    list_filter = ('track', 'submission_mode', 'status', 'accepted_at')
    search_fields = ('registration__user__username', 'registration__user__email', 'track__label', 'role__label')
    readonly_fields = ('registration', 'role', 'track', 'submission_mode', 'accepted_tier', 'accepted_by', 'accepted_at', 'created_at', 'updated_at')
    raw_id_fields = ('registration',)

    fieldsets = (
        ('Attendee & Role', {
            'fields': ('registration', 'role')
        }),
        ('Origin Information', {
            'fields': ('track', 'submission_mode', 'accepted_tier')
        }),
        ('Decision Details', {
            'fields': ('accepted_by', 'accepted_at')
        }),
        ('Nomination (if applicable)', {
            'fields': ('nominator_name', 'nominator_email'),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('status',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_attendee_name(self, obj):
        """Display attendee name."""
        return f"{obj.registration.user.first_name} {obj.registration.user.last_name}".strip() or obj.registration.user.username
    get_attendee_name.short_description = 'Attendee'

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class PostAcceptanceFormAssignmentAdmin(admin.ModelAdmin):
    """Admin interface for post-acceptance form assignments."""
    list_display = ('id', 'event', 'attendee', 'form_type', 'status', 'created_at')
    list_filter = ('form_type', 'status', 'event', 'created_at')
    search_fields = ('event__title', 'event_registration__user__username', 'event_registration__user__email')
    readonly_fields = ('id', 'event', 'event_registration', 'completed_at', 'created_at', 'updated_at')

    fieldsets = (
        ('Assignment Info', {
            'fields': ('id', 'event', 'event_registration', 'form_type', 'status'),
        }),
        ('Timeline', {
            'fields': ('completed_at', 'deadline', 'created_at', 'updated_at'),
        }),
    )

    ordering = ('-created_at',)

    def get_queryset(self, request):
        """Filter to show only participant_information forms by default."""
        qs = super().get_queryset(request)
        # Show all forms, but participant_information is the default filter
        return qs

    def attendee(self, obj):
        """Display attendee name."""
        return f"{obj.event_registration.user.first_name} {obj.event_registration.user.last_name}".strip() or obj.event_registration.user.username
    attendee.short_description = 'Attendee'


class ParticipantInformationFormManager(PostAcceptanceFormAssignmentAdmin):
    """Admin interface specifically for participant_information forms."""

    def get_queryset(self, request):
        """Filter to show ONLY participant_information forms."""
        qs = super(PostAcceptanceFormAssignmentAdmin, self).get_queryset(request)
        return qs.filter(form_type='participant_information')


# Register admin classes
admin.site.register(PostAcceptanceFormAssignment, PostAcceptanceFormAssignmentAdmin)
admin.site.register(PostAcceptanceFormTemplate)
