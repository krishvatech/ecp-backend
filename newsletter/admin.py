from django import forms
from django.contrib import admin

from .models import (
    MauticContactMapping,
    MauticUserConnection,
    NewsletterAudience,
    NewsletterCampaign,
    NewsletterCampaignTrackingEvent,
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterSyncEvent,
)


class NewsletterCategoryAdminForm(forms.ModelForm):
    class Meta:
        model = NewsletterCategory
        fields = "__all__"

    def clean_name(self):
        # The live-name constraint is conditional on deletion_state, which is
        # never a form field, so Django skips it during form validation. Check
        # it here so a duplicate is a form error rather than a database error.
        name = self.cleaned_data["name"]
        duplicates = NewsletterCategory.objects.filter(name=name).exclude(
            deletion_state=NewsletterCategory.DeletionState.DELETED
        )
        if self.instance.pk:
            duplicates = duplicates.exclude(pk=self.instance.pk)
        if duplicates.exists():
            raise forms.ValidationError("Newsletter category with this Name already exists.")
        return name


@admin.register(NewsletterCategory)
class NewsletterCategoryAdmin(admin.ModelAdmin):
    """Permanent deletion runs only through the Marketing Hub delete endpoint,
    which also deletes the Mautic segment. Here the lifecycle fields are never
    editable, and a deleted (or deletion-pending) list is view-only and cannot
    be removed, so it can be neither reactivated nor stripped of its history.
    """

    form = NewsletterCategoryAdminForm
    list_display = (
        "name",
        "slug",
        "is_active",
        "deletion_state",
        "mautic_segment_id",
        "updated_at",
    )
    list_filter = ("is_active", "deletion_state")
    search_fields = ("name", "slug", "mautic_segment_id")
    readonly_fields = (
        "deletion_state",
        "deleted_at",
        "deleted_by",
        "created_at",
        "updated_at",
    )
    prepopulated_fields = {"slug": ("name",)}

    def has_change_permission(self, request, obj=None):
        if obj is not None and obj.deletion_started:
            return False
        return super().has_change_permission(request, obj)

    def has_delete_permission(self, request, obj=None):
        if obj is not None and obj.deletion_started:
            return False
        return super().has_delete_permission(request, obj)


@admin.register(NewsletterAudience)
class NewsletterAudienceAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "audience_type",
        "status",
        "is_active",
        "estimated_count",
        "updated_at",
    )
    list_filter = ("audience_type", "status", "is_active")
    search_fields = ("name", "description", "mautic_segment_id")
    readonly_fields = ("uuid", "created_at", "updated_at")
    autocomplete_fields = ("created_by",)


@admin.register(NewsletterSubscription)
class NewsletterSubscriptionAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "category",
        "is_subscribed",
        "source",
        "subscribed_at",
        "unsubscribed_at",
        "updated_at",
    )
    list_filter = ("is_subscribed", "source", "category")
    search_fields = (
        "user__email",
        "user__username",
        "category__name",
        "category__slug",
    )
    readonly_fields = ("created_at", "updated_at")
    autocomplete_fields = ("user", "category")


@admin.register(NewsletterCampaign)
class NewsletterCampaignAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "subject",
        "status",
        "scheduled_at",
        "sent_at",
        "updated_at",
    )
    list_filter = ("status", "created_at", "scheduled_at")
    search_fields = ("name", "subject", "from_email", "mautic_email_id")
    readonly_fields = (
        "uuid",
        "status",
        "scheduled_at",
        "send_started_at",
        "sent_at",
        "mautic_email_id",
        "last_synced_to_mautic_at",
        "last_error",
        "created_at",
        "updated_at",
    )
    autocomplete_fields = ("created_by", "updated_by")
    filter_horizontal = ("audiences",)


@admin.register(MauticContactMapping)
class MauticContactMappingAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "mautic_contact_id",
        "last_synced_at",
        "updated_at",
    )
    search_fields = (
        "user__email",
        "user__username",
        "mautic_contact_id",
    )
    readonly_fields = ("created_at", "updated_at")
    autocomplete_fields = ("user",)


@admin.register(NewsletterCampaignTrackingEvent)
class NewsletterCampaignTrackingEventAdmin(admin.ModelAdmin):
    list_display = (
        "event_uuid",
        "campaign",
        "event_type",
        "source",
        "recipient_email",
        "mautic_contact_id",
        "occurred_at",
        "created_at",
    )
    list_filter = ("event_type", "source", "occurred_at")
    search_fields = (
        "event_uuid",
        "campaign__name",
        "campaign__subject",
        "recipient_email",
        "mautic_contact_id",
        "provider_event_id",
    )
    readonly_fields = (
        "event_uuid",
        "campaign",
        "user",
        "mautic_contact_id",
        "recipient_email",
        "event_type",
        "source",
        "provider_event_id",
        "url",
        "payload",
        "occurred_at",
        "created_at",
    )
    autocomplete_fields = ("campaign", "user")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(NewsletterSyncEvent)
class NewsletterSyncEventAdmin(admin.ModelAdmin):
    list_display = (
        "event_uuid",
        "user_id",
        "category",
        "desired_subscribed",
        "status",
        "attempt_count",
        "next_retry_at",
        "updated_at",
    )
    list_filter = ("status", "desired_subscribed", "category")
    search_fields = (
        "event_uuid",
        "idempotency_key",
        "user_id",
        "last_error",
    )
    readonly_fields = (
        "event_uuid",
        "idempotency_key",
        "user_id",
        "category",
        "desired_subscribed",
        "status",
        "attempt_count",
        "last_error",
        "next_retry_at",
        "processing_started_at",
        "completed_at",
        "created_at",
        "updated_at",
    )


@admin.register(MauticUserConnection)
class MauticUserConnectionAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "mautic_user_id",
        "mautic_username",
        "status",
        "is_active",
        "last_verified_at",
        "updated_at",
    )
    list_filter = ("status", "is_active")
    # Search is for locating rows only; identity is always mautic_user_id.
    search_fields = ("user__username", "user__email", "mautic_username")
    raw_id_fields = ("user", "created_by")
    readonly_fields = ("connected_at", "disabled_at", "created_at", "updated_at")
