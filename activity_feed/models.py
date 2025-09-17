"""
Models for the activity feed app.

The ``FeedItem`` model stores a record of an action taken within the
platform.  Each item may be associated with an organization and/or an
event, the user who performed the action, and an arbitrary target
object via Django’s generic relations.  Additional metadata is stored
in a JSON field to allow clients to render rich feed entries without
needing to query the target.
"""
from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from organizations.models import Organization
from events.models import Event

class FeedItem(models.Model):
    """Represents a single activity entry in the community feed."""
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="feed_items",
        blank=True,
        null=True,
    )
    event = models.ForeignKey(
        Event,
        on_delete=models.SET_NULL,
        related_name="feed_items",
        blank=True,
        null=True,
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="activity_feed_items",
        blank=True,
        null=True,
    )
    verb = models.CharField(max_length=255)
    # Generic relation to any model
    target_content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        related_name="feed_items",
    )
    target_object_id = models.PositiveIntegerField()
    target = GenericForeignKey("target_content_type", "target_object_id")
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "event", "created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.verb} by {self.actor_id} on {self.created_at.isoformat()}"
