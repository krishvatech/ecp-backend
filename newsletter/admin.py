from django.contrib import admin

from .models import NewsletterCategory, NewsletterSubscription


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
