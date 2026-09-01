from django.contrib import admin

from .models import (
    MauticContactMapping,
    NewsletterCampaign,
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterSyncEvent,
)


@admin.register(NewsletterCategory)
class NewsletterCategoryAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "slug",
        "is_active",
        "mautic_segment_id",
        "updated_at",
    )
    list_filter = ("is_active",)
    search_fields = ("name", "slug", "mautic_segment_id")
    readonly_fields = ("created_at", "updated_at")
    prepopulated_fields = {"slug": ("name",)}


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
