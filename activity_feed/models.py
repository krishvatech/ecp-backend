"""
Models for the activity feed app.

The ``FeedItem`` model stores a record of an action taken within the
platform.  Each item may be associated with an community and/or an
event, the user who performed the action, and an arbitrary target
object via Django’s generic relations.  Additional metadata is stored
in a JSON field to allow clients to render rich feed entries without
needing to query the target.
"""
from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils import timezone
from community.models import Community
from events.models import Event
from groups.models import Group

class FeedItem(models.Model):
    """Represents a single activity entry in the community feed."""
    community = models.ForeignKey(
        Community,
        on_delete=models.CASCADE,
        related_name="feed_items",
        blank=True,
        null=True,
    )
    group = models.ForeignKey(
        Group, 
        on_delete=models.CASCADE,
        related_name="feed_items",
        blank=True, 
        null=True,
        db_index=True
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
    is_deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    deletion_reason = models.TextField(blank=True, default="")

    MOD_STATUS_CLEAR = "clear"
    MOD_STATUS_UNDER_REVIEW = "under_review"
    MOD_STATUS_REMOVED = "removed"
    MODERATION_STATUS_CHOICES = [
        (MOD_STATUS_CLEAR, "Clear"),
        (MOD_STATUS_UNDER_REVIEW, "Under review"),
        (MOD_STATUS_REMOVED, "Removed"),
    ]
    moderation_status = models.CharField(
        max_length=20,
        choices=MODERATION_STATUS_CHOICES,
        default=MOD_STATUS_CLEAR,
        db_index=True,
    )
    moderation_updated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["community", "event", "created_at"]),
            models.Index(fields=["group", "created_at"]),
            models.Index(fields=["community", "group", "created_at"]),
            models.Index(fields=["is_deleted", "created_at"]),
        ]
        ordering = ["-created_at"]

    def soft_delete(self, *, user=None, reason=""):
        """Hide this feed item while retaining its content and related history."""
        if self.is_deleted:
            return False

        deleted_at = timezone.now()
        metadata = dict(self.metadata or {})
        metadata.update({
            "is_deleted": True,
            "deleted_at": deleted_at.isoformat(),
        })
        if reason:
            metadata["deletion_reason"] = str(reason).strip()

        self.is_deleted = True
        self.deleted_at = deleted_at
        self.deleted_by = user if getattr(user, "pk", None) else None
        self.deletion_reason = str(reason or "").strip()
        self.metadata = metadata
        self.save(update_fields=[
            "is_deleted",
            "deleted_at",
            "deleted_by",
            "deletion_reason",
            "metadata",
        ])
        return True

    def __str__(self) -> str:
        return f"{self.verb} by {self.actor_id} on {self.created_at.isoformat()}"
    
class Poll(models.Model):
    community = models.ForeignKey(
        Community, on_delete=models.CASCADE, related_name="polls", null=True, blank=True
    )
    group = models.ForeignKey(
        Group, on_delete=models.CASCADE, related_name="polls", null=True, blank=True
    )
    question = models.CharField(max_length=500)
    allows_multiple = models.BooleanField(default=False)
    is_anonymous = models.BooleanField(default=False)
    is_closed = models.BooleanField(default=False)
    ends_at = models.DateTimeField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    deletion_reason = models.TextField(blank=True, default="")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="polls_created"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["community", "is_closed", "created_at"]),
            models.Index(fields=["group", "is_closed", "created_at"]),
            models.Index(fields=["is_deleted", "created_at"]),
        ]

    def soft_delete(self, *, user=None, reason=""):
        """Hide the poll while retaining options and votes for audit/history."""
        if self.is_deleted:
            return False
        self.is_deleted = True
        self.is_closed = True
        self.deleted_at = timezone.now()
        self.deleted_by = user if getattr(user, "pk", None) else None
        self.deletion_reason = str(reason or "").strip()
        self.save(update_fields=[
            "is_deleted",
            "is_closed",
            "deleted_at",
            "deleted_by",
            "deletion_reason",
        ])
        return True

    def __str__(self):
        return f"Poll[{self.id}] {self.question[:40]}"


class PollOption(models.Model):
    poll = models.ForeignKey(Poll, on_delete=models.CASCADE, related_name="options")
    text = models.CharField(max_length=300)
    index = models.IntegerField(default=0)

    class Meta:
        unique_together = ("poll", "index")
        indexes = [models.Index(fields=["poll", "index"])]

    def __str__(self):
        return f"PollOption[{self.poll_id}#{self.index}] {self.text[:30]}"


class PollVote(models.Model):
    poll = models.ForeignKey(Poll, on_delete=models.CASCADE, related_name="votes")
    option = models.ForeignKey(PollOption, on_delete=models.CASCADE, related_name="votes")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="poll_votes")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("poll", "user", "option")
        indexes = [
            models.Index(fields=["poll", "user"]),
            models.Index(fields=["option"]),
        ]

    def __str__(self):
        return f"Vote[poll={self.poll_id}, user={self.user_id}, option={self.option_id}]"
