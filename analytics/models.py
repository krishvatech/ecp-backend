"""
Database models for the analytics app.

The ``MetricDaily`` model stores counters aggregated per day, per
organization and optionally per event.  Metrics include counts for
messages, resources, registrations, purchases and the sum of
revenue.  Unique constraints ensure one row per date/org/event.
"""
from __future__ import annotations

from django.db import models
from organizations.models import Organization
from events.models import Event


class MetricDaily(models.Model):
    """Aggregated metrics for a given day, optionally scoped to an organization and event."""

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="metric_dailies",
    )
    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="metric_dailies",
    )
    date = models.DateField()
    message_count = models.PositiveIntegerField(default=0)
    resource_count = models.PositiveIntegerField(default=0)
    registrations_count = models.PositiveIntegerField(default=0)
    purchases_count = models.PositiveIntegerField(default=0)
    revenue_cents = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (
            "organization",
            "event",
            "date",
        )
        ordering = ["-date"]

    def __str__(self) -> str:
        parts = []
        if self.organization_id:
            parts.append(f"org {self.organization_id}")
        if self.event_id:
            parts.append(f"event {self.event_id}")
        return f"Metrics for {self.date} (" + ", ".join(parts) + ")"
