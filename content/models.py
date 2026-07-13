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


class ActiveResourceManager(models.Manager):
    """Hide soft-deleted resources from normal application queries."""

    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)


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

    # Soft-delete lifecycle. The database row and physical file are retained.
    is_deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True, db_index=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="resources_soft_deleted",
    )
    deletion_reason = models.TextField(blank=True, default="")

    objects = ActiveResourceManager()
    all_objects = models.Manager()
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
        default_manager_name = "objects"
        base_manager_name = "all_objects"
        indexes = [
            models.Index(fields=["community", "event", "type", "is_published"]),
            models.Index(fields=["is_deleted", "created_at"]),
        ]
        ordering = ["-created_at"]

    def soft_delete(self, *, user=None, reason=""):
        """Remove the resource from the platform without deleting its history/file."""
        if self.is_deleted:
            return False

        deleted_at = timezone.now()
        self.is_deleted = True
        self.is_published = False
        self.deleted_at = deleted_at
        self.deleted_by = user if getattr(user, "pk", None) else None
        self.deletion_reason = str(reason or "").strip()
        self.save(update_fields=[
            "is_deleted",
            "is_published",
            "deleted_at",
            "deleted_by",
            "deletion_reason",
            "updated_at",
        ])

        # A published resource may have an activity FeedItem. Hide that item too,
        # but retain the feed row, comments, reactions, reports, and target IDs.
        try:
            from django.contrib.contenttypes.models import ContentType
            from activity_feed.models import FeedItem

            content_type = ContentType.objects.get_for_model(Resource)
            for item in FeedItem.objects.filter(
                target_content_type=content_type,
                target_object_id=self.pk,
                is_deleted=False,
            ):
                item.soft_delete(user=user, reason=self.deletion_reason)
        except Exception:
            # Resource deletion must not fail because optional feed cleanup failed.
            pass

        return True

    def restore(self):
        """Restore visibility, keeping the resource unpublished for safety."""
        if not self.is_deleted:
            return False
        self.is_deleted = False
        self.is_published = False
        self.deleted_at = None
        self.deleted_by = None
        self.deletion_reason = ""
        self.save(update_fields=[
            "is_deleted",
            "is_published",
            "deleted_at",
            "deleted_by",
            "deletion_reason",
            "updated_at",
        ])
        return True

    def __str__(self) -> str:
        return f"{self.title} ({self.get_type_display()})"
