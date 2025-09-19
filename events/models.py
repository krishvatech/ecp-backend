"""
Models for the events app.

An `Event` is associated with a single organization and has a state
machine to represent its current status.  Slugs are automatically
generated based on the title and organization ID.  The creator of the
event is stored in the `created_by` field.
"""
from django.db import models
from django.contrib.auth.models import User
from organizations.models import Organization
from django.utils.text import slugify


class Event(models.Model):
    """Represents an event within an organization."""

    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("published", "Published"),
        ("live", "Live"),
        ("ended", "Ended"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="events")
    title = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    description = models.TextField(blank=True)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="draft")
    is_live = models.BooleanField(default=False)
    # The current speaker for live sessions (optional).  Stored as a
    # reference to a user who is currently broadcasting.  This is
    # updated via state transition endpoints.
    active_speaker = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="active_events",
    )
    recording_url = models.URLField(blank=True)
    agora_resource_id = models.CharField(max_length=128, blank=True, null=True)
    agora_sid = models.CharField(max_length=128, blank=True, null=True)
    agora_channel = models.CharField(max_length=128, blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="created_events")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Timestamps tracking when a live session was started/stopped.  These
    # are useful for analytics and for cleaning up resources.  They may
    # remain null if the event never goes live.
    live_started_at = models.DateTimeField(null=True, blank=True)
    live_ended_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.slug:
            base = f"{self.title}-{self.organization_id}"
            self.slug = slugify(base)
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.title} ({self.organization.name})"