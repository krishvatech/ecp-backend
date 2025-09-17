"""
Database models for the payments app.

This module defines the core entities for selling paid tickets to
events.  Ticket plans are scoped to organizations and may be
activated or deactivated.  Ticket purchases record a user's
transaction against a specific event and plan, tying into Stripe via
payment intent IDs.  Enumerated statuses track the lifecycle of a
purchase (pending, succeeded, failed).
"""
from __future__ import annotations

from django.conf import settings
from django.db import models
from organizations.models import Organization
from events.models import Event


class TicketPlan(models.Model):
    """A paid ticket plan offered by an organization for its events."""

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="ticket_plans",
    )
    name = models.CharField(max_length=255)
    price_cents = models.PositiveIntegerField(help_text="Ticket price in cents")
    currency = models.CharField(max_length=10, default="usd")
    stripe_price_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="Corresponding Stripe Price identifier",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "is_active"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.name} ({self.currency} {self.price_cents / 100:.2f})"


class TicketPurchase(models.Model):
    """Represents an individual purchase of a ticket to an event."""

    STATUS_PENDING = "pending"
    STATUS_SUCCEEDED = "succeeded"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_SUCCEEDED, "Succeeded"),
        (STATUS_FAILED, "Failed"),
    ]

    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name="ticket_purchases",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ticket_purchases",
    )
    plan = models.ForeignKey(
        TicketPlan,
        on_delete=models.PROTECT,
        related_name="purchases",
    )
    stripe_payment_intent_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="Associated Stripe PaymentIntent identifier",
    )
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
    )
    amount_cents = models.PositiveIntegerField(help_text="Charged amount in cents")
    currency = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["event", "user", "status"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Purchase {self.id} ({self.get_status_display()})"
