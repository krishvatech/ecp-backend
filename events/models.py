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
    recording_url = models.URLField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="created_events")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.slug:
            base = f"{self.title}-{self.organization_id}"
            self.slug = slugify(base)
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.title} ({self.organization.name})"