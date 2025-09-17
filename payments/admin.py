"""
Django admin registration for the payments app.

Provides list displays and filters for TicketPlan and TicketPurchase
to facilitate management and troubleshooting by administrators.
"""
from django.contrib import admin
from .models import TicketPlan, TicketPurchase


@admin.register(TicketPlan)
class TicketPlanAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "organization",
        "price_cents",
        "currency",
        "is_active",
        "created_at",
    )
    list_filter = ("organization", "is_active", "currency")
    search_fields = ("name",)
    ordering = ("-created_at",)


@admin.register(TicketPurchase)
class TicketPurchaseAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "event",
        "user",
        "plan",
        "status",
        "amount_cents",
        "currency",
        "created_at",
    )
    list_filter = ("status", "event", "plan", "currency")
    search_fields = ("user__username", "stripe_payment_intent_id")
    ordering = ("-created_at",)
