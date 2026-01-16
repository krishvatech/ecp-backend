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
import os, uuid
def event_preview_upload_to(instance, filename):
    """
    Save preview images directly under:
      media_previews/event/<file>
    (No tmp/, no <id>/, no preview/ subfolder)
    """
    name, ext = os.path.splitext(filename or "")
    base = slugify(name) or "preview"
    return f"previews/event/{base}-{uuid.uuid4().hex[:8]}{ext.lower()}"
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
    timezone = models.CharField(max_length=64, default=settings.TIME_ZONE, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="draft")
    is_live = models.BooleanField(default=False)
    # New fields
    category = models.CharField(max_length=100, blank=True)
    format = models.CharField(max_length=20, choices=FORMAT_CHOICES, default="in_person")
    location = models.CharField(max_length=255, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    is_free = models.BooleanField(default=False)
    attending_count = models.PositiveIntegerField(default=0)
    preview_image = models.ImageField(
        upload_to=event_preview_upload_to,
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
    # Dyte live meeting fields
    dyte_meeting_id = models.CharField(max_length=255, blank=True, null=True)
    dyte_meeting_title = models.CharField(max_length=255, blank=True, null=True)

    # Saleor integration fields
    saleor_product_id = models.CharField(max_length=255, blank=True, null=True)
    saleor_variant_id = models.CharField(max_length=255, blank=True, null=True)

    # Legacy Agora recording fields (no longer used)
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
            base_slug = slugify(f"{self.title}-{self.community_id}")
            slug = base_slug
            suffix = 1
            while Event.objects.filter(slug=slug).exists():
                slug = f"{base_slug}-{suffix}"
                suffix += 1
            self.slug = slug
        super().save(*args, **kwargs)
    def __str__(self) -> str:
        return f"{self.title} ({self.community.name})"
    
class EventRegistration(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='registrations')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='event_registrations')
    
    STATUS_CHOICES = [
        ('registered', 'Registered'),
        ('cancellation_requested', 'Cancellation Requested'),
        ('cancelled', 'Cancelled'),
    ]
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='registered')
    registered_at = models.DateTimeField(auto_now_add=True)
    joined_live = models.BooleanField(default=False)
    watched_replay = models.BooleanField(default=False)
    class Meta:
        db_table = 'event_registrations'
        unique_together = ('event', 'user')                 
        indexes = [
            models.Index(fields=['event', 'user']),
            models.Index(fields=['user']),
        ]
    def __str__(self):
        return f'{self.user_id} -> {self.event_id}'
