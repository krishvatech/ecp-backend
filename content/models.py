"""
Models for the content app.

The ``Resource`` model represents a piece of post‑event content such as
uploaded files, external links or embedded videos.  Resources belong to
an community and may optionally be associated with a specific event.
They can be tagged to aid discoverability and filtered by publication
state.  When a resource is created and marked as published a signal
emits an activity entry via Celery (see ``content.signals``).
"""
from django.conf import settings
from django.db import models
from django.contrib.postgres.fields import ArrayField
from community.models import Community
from events.models import Event
from django.utils import timezone
# content/models.py
def resource_upload_path(instance, filename):
    ev = getattr(instance, "event", None)
    if ev and ev.title:
        event_name = ev.title.replace(" ", "_")
    elif instance.event_id:
        event_name = f"event_{instance.event_id}"
    else:
        event_name = "unscoped"   # <- when no event selected
    return f"event_resources/{event_name}/{filename}"

class Resource(models.Model):
    """Represents a file, link or video uploaded after an event."""
    TYPE_FILE = "file"
    TYPE_LINK = "link"
    TYPE_VIDEO = "video"
    TYPE_CHOICES = [
        (TYPE_FILE, "File"),
        (TYPE_LINK, "Link"),
        (TYPE_VIDEO, "Video"),
    ]

    community = models.ForeignKey(
        Community, on_delete=models.CASCADE, related_name="resources"
    )
    event = models.ForeignKey(
        Event,
        on_delete=models.SET_NULL,
        related_name="resources",
        blank=True,
        null=True,
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    file = models.FileField(
        upload_to=resource_upload_path,
        blank=True,
        null=True,
        help_text="Uploaded file (required when type='file')",
    )
    link_url = models.URLField(blank=True, help_text="External URL (required when type='link')")
    video_url = models.URLField(blank=True, help_text="Video URL (required when type='video')")
    tags = ArrayField(
        models.CharField(max_length=50),
        default=list,
        blank=True,
        help_text="List of tags as strings",
    )
    is_published = models.BooleanField(default=True)
    publish_at = models.DateTimeField(null=True, blank=True, db_index=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="uploaded_resources",
        blank=True,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["community", "event", "type", "is_published"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.title} ({self.get_type_display()})"
