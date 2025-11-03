"""
Database models for the messaging app.

Supports:
1) Direct (1:1) conversations.
2) Common Group chats          -> is_group=True,  group=<Group>,  event=None
3) Event live/group chats      -> is_event_group=True, event=<Event>, group=None

room_key is kept for legacy/external integrations (e.g., "group:5", "event:85").
"""
from __future__ import annotations

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.contrib.postgres.fields import ArrayField


class Conversation(models.Model):
    """Represents a 1:1 conversation, a common group room, or an event live chat room."""

    # --- direct (1:1) participants (nullable for group/event rooms) ---
    user1 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="conversations_as_user1",
        null=True,
        blank=True,
    )
    user2 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="conversations_as_user2",
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # --- flags & relations ---
    # Event live chat
    is_event_group = models.BooleanField(default=False, help_text="Event live chat room")
    # Common group chat
    is_group = models.BooleanField(default=False, help_text="Common group chat room")

    # Explicit links (preferred over room_key)
    group = models.ForeignKey(
        "groups.Group", null=True, blank=True, on_delete=models.CASCADE, related_name="conversations"
    )
    event = models.ForeignKey(
        "events.Event", null=True, blank=True, on_delete=models.CASCADE, related_name="chat_conversations"
    )

    # Legacy/external integration key (e.g., "group:5" or "event:85")
    room_key = models.CharField(max_length=128, unique=True, null=True, blank=True)

    title = models.CharField(max_length=200, default="", blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_conversations",
    )

    class Meta:
        ordering = ["-updated_at"]
        indexes = [
            models.Index(fields=["user1", "user2"]),
            models.Index(fields=["room_key"]),
            models.Index(fields=["group"]),
            models.Index(fields=["event"]),
            models.Index(fields=["updated_at"]),
            models.Index(fields=["created_at"]),
        ]
        # Unique 1:1 DM between two users (only when it's actually a DM)
        constraints = [
            models.UniqueConstraint(
                fields=["user1", "user2"],
                name="unique_conversation_users",
                condition=Q(is_group=False) & Q(is_event_group=False) &
                          Q(user1__isnull=False) & Q(user2__isnull=False),
            ),
        ]
        # NOTE: Intentionally NOT adding the conv_valid_context CheckConstraint here
        # to avoid blocking migration on existing rows. Add it later in a separate migration
        # after backfilling data if you want strict enforcement.

    def save(self, *args, **kwargs):
        """
        Normalize participant ordering for DMs and forbid self-conversations.
        Skip normalization for group/event rooms.
        """
        if not self.is_group and not self.is_event_group and self.user1_id and self.user2_id:
            if self.user1_id == self.user2_id:
                raise ValidationError("A conversation requires two distinct participants.")
            if self.user1_id > self.user2_id:
                self.user1_id, self.user2_id = self.user2_id, self.user1_id
        super().save(*args, **kwargs)

    def participants(self) -> tuple[int | None, int | None]:
        return self.user1_id, self.user2_id

    def __str__(self) -> str:
        if self.is_group:
            return f"[Group] {self.group_id or self.room_key}"
        if self.is_event_group:
            return f"[Event] {self.event_id or self.room_key}"
        return f"Conversation({self.user1_id}, {self.user2_id})"


class Message(models.Model):
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name="messages")
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sent_messages")
    body = models.TextField()
    attachments = ArrayField(models.JSONField(), default=list, blank=True)
    is_read = models.BooleanField(default=False)

    # already had:
    is_hidden = models.BooleanField(default=False)

    # NEW: soft delete
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["conversation", "created_at"]),
            models.Index(fields=["conversation", "is_deleted", "created_at"]),  # (optional) speeds normal lists
        ]
        ordering = ["-created_at"]


    def save(self, *args, **kwargs):
        """Update the conversation's updated_at timestamp on new messages."""
        is_new = self.pk is None
        super().save(*args, **kwargs)
        if is_new:
            Conversation.objects.filter(pk=self.conversation_id).update(updated_at=timezone.now())

    def __str__(self) -> str:
        return f"Message<{self.id}> in Conversation<{self.conversation_id}>"
