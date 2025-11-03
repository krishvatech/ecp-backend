"""
Models for the events app.

An `Event` is associated with a single community and has a state
machine to represent its current status.  Slugs are automatically
generated based on the title and community ID.  The creator of the
event is stored in the `created_by` field.
"""

from django.db import models
from django.contrib.auth.models import User
from community.models import Community
from django.utils.text import slugify
from django.conf import settings
from django.core.files.storage import FileSystemStorage
import os, uuid


_preview_storage = FileSystemStorage(
    location=getattr(settings, "PREVIEW_MEDIA_ROOT", settings.MEDIA_ROOT),
    base_url=getattr(settings, "PREVIEW_MEDIA_URL", settings.MEDIA_URL),
)

def event_preview_upload_to(instance, filename):
    """
    Save preview images directly under:
      media_previews/event/<file>
    (No tmp/, no <id>/, no preview/ subfolder)
    """
    name, ext = os.path.splitext(filename or "")
    base = slugify(name) or "preview"

    return f"event/{base}-{uuid.uuid4().hex[:8]}{ext.lower()}"


class Event(models.Model):
    """Represents an event within an community."""
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("published", "Published"),
        ("live", "Live"),
        ("ended", "Ended"),
    ]
    FORMAT_CHOICES = [
        ("in_person", "In-Person"),
        ("virtual", "Virtual"),
        ("hybrid", "Hybrid"),
    ]
    community = models.ForeignKey(
        Community,
        on_delete=models.CASCADE,
        related_name="events"
    )
    title = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    description = models.TextField(blank=True)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="draft")
    is_live = models.BooleanField(default=False)
    # New fields
    category = models.CharField(max_length=100, blank=True)
    format = models.CharField(max_length=20, choices=FORMAT_CHOICES, default="in_person")
    location = models.CharField(max_length=255, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    attending_count = models.PositiveIntegerField(default=0)
    preview_image = models.ImageField(
        upload_to=event_preview_upload_to,  
        storage=_preview_storage,         
        blank=True,
        null=True,
    )
    attendees = models.ManyToManyField(
        User,
        through='EventRegistration',
        related_name='events_joined',
        blank=True,
    )
    # Speaker & Recording
    active_speaker = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="active_events",
    )
    recording_url = models.URLField(blank=True)
    agora_resource_id = models.CharField(max_length=255, blank=True, null=True)
    agora_sid = models.CharField(max_length=255, blank=True, null=True)
    agora_channel = models.CharField(max_length=255, blank=True, null=True)
    agora_recorder_uid = models.CharField(max_length=64, blank=True, null=True)
    # Meta
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="created_events")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    live_started_at = models.DateTimeField(null=True, blank=True)
    live_ended_at = models.DateTimeField(null=True, blank=True)
    class Meta:
        ordering = ["-created_at"]
    def save(self, *args, **kwargs):
        if not self.slug:
            base = f"{self.title}-{self.community_id}"
            self.slug = slugify(base)
        super().save(*args, **kwargs)
    def __str__(self) -> str:
        return f"{self.title} ({self.community.name})"
    
class EventRegistration(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='registrations')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='event_registrations')
    registered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'event_registrations'
        unique_together = ('event', 'user')                 
        indexes = [
            models.Index(fields=['event', 'user']),
            models.Index(fields=['user']),
        ]

    def __str__(self):
        return f'{self.user_id} -> {self.event_id}'