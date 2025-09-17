"""
Database models for the messaging app.

The messaging app supports one‑to‑one conversations between users.
Each ``Conversation`` stores two participants in a normalized order
(user1_id < user2_id) and timestamps.  A ``Message`` belongs to a
conversation and has a sender, textual body, optional attachments and
read state.  When a message is created the parent conversation’s
``updated_at`` is refreshed to allow sorting by recent activity.
"""
from __future__ import annotations

from django.conf import settings
from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.contrib.postgres.fields import ArrayField


class Conversation(models.Model):
    """Represents a 1‑to‑1 conversation between two users."""

    user1 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="conversations_as_user1",
    )
    user2 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="conversations_as_user2",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["user1", "user2"])]
        constraints = [
            models.UniqueConstraint(
                fields=["user1", "user2"], name="unique_conversation_users"
            ),
        ]

    def save(self, *args, **kwargs):
        """Normalize participant ordering and prevent self‑conversations."""
        if self.user1_id and self.user2_id:
            if self.user1_id == self.user2_id:
                raise ValidationError("A conversation requires two distinct participants.")
            if self.user1_id > self.user2_id:
                self.user1_id, self.user2_id = self.user2_id, self.user1_id
        super().save(*args, **kwargs)

    def participants(self) -> tuple[int, int]:
        """Return a tuple of participant IDs."""
        return self.user1_id, self.user2_id

    def __str__(self) -> str:
        return f"Conversation({self.user1_id}, {self.user2_id})"


class Message(models.Model):
    """Represents an individual message within a conversation."""

    conversation = models.ForeignKey(
        Conversation,
        on_delete=models.CASCADE,
        related_name="messages",
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sent_messages",
    )
    body = models.TextField()
    attachments = ArrayField(
        models.JSONField(),
        default=list,
        blank=True,
        help_text="List of JSON objects representing attachments (files/images)",
    )
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["conversation", "created_at"])]
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        """Update the conversation's updated_at timestamp on new messages."""
        is_new = self.pk is None
        super().save(*args, **kwargs)
        if is_new:
            Conversation.objects.filter(pk=self.conversation_id).update(updated_at=timezone.now())

    def __str__(self) -> str:
        return f"Message<{self.id}> in Conversation<{self.conversation_id}>"
