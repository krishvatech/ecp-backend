"""
Django admin configuration for the analytics app.

Registers MetricDaily with date and organization filters to aid
inspection of aggregated metrics.
"""
from django.contrib import admin
from .models import MetricDaily


@admin.register(MetricDaily)
class MetricDailyAdmin(admin.ModelAdmin):
    list_display = (
        "date",
        "organization",
        "event",
        "message_count",
        "resource_count",
        "registrations_count",
        "purchases_count",
        "revenue_cents",
    )
    list_filter = ("date", "organization", "event")
    ordering = ("-date",)
