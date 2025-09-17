"""
Database models for the interactions app.

We persist:
- ChatMessage: freeform chat lines by members during an event.
- Question: Q&A entries; can later be answered and marked resolved.

Both models link to:
- Event (events.Event)
- User (AUTH_USER_MODEL)

Indexes + ordering are chosen for the most common queries (latest-first).
"""

from django.conf import settings
from django.db import models
from django.utils import timezone

# Avoid circular import at module import time by referencing Event lazily through the app label.
# However, for type clarity we import within typing context only.
# from events.models import Event  # not needed at import time; use "events.Event" in ForeignKey.


class ChatMessage(models.Model):
    """
    A persisted chat line posted by a user during an event.

    Fields:
        event: FK to the event that this message belongs to.
        user: FK to the authoring user.
        content: The text body of the message.
        created_at/updated_at: audit timestamps.

    Notes:
        We index (event, created_at desc) for efficient per-event timelines.
    """

    event = models.ForeignKey(
        "events.Event",
        on_delete=models.CASCADE,
        related_name="chat_messages",
        help_text="Event this chat message belongs to.",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="chat_messages",
        help_text="User who authored the message.",
    )
    content = models.TextField(help_text="Message content.")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Creation timestamp.")
    updated_at = models.DateTimeField(auto_now=True, help_text="Last update timestamp.")

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["event", "-created_at"], name="chat_event_created_idx"),
        ]
        verbose_name = "Chat message"
        verbose_name_plural = "Chat messages"

    def __str__(self) -> str:
        return f"[{self.event_id}] {self.user_id}: {self.content[:50]}"


class Question(models.Model):
    """
    A Q&A question posted by a participant. Can be answered and marked as resolved.

    Fields:
        event: FK to the event.
        user: FK to the authoring user.
        content: The question text.
        is_answered: True when an answer is provided.
        answer: The answer text (optional).
        answered_by: FK to the user who answered (optional).
        answered_at: timestamp of answering (optional).
        created_at/updated_at: audit timestamps.
    """

    event = models.ForeignKey(
        "events.Event",
        on_delete=models.CASCADE,
        related_name="questions",
        help_text="Event this question belongs to.",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="questions",
        help_text="User who asked the question.",
    )
    content = models.TextField(help_text="Question text.")
    is_answered = models.BooleanField(default=False, help_text="Whether the question has an answer.")
    answer = models.TextField(blank=True, default="", help_text="Answer text, if provided.")
    answered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="answered_questions",
        help_text="User who answered the question.",
    )
    answered_at = models.DateTimeField(null=True, blank=True, help_text="When the question was answered.")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Creation timestamp.")
    updated_at = models.DateTimeField(auto_now=True, help_text="Last update timestamp.")

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["event", "-created_at"], name="qna_event_created_idx"),
            models.Index(fields=["event", "is_answered"], name="qna_event_answered_idx"),
        ]
        verbose_name = "Question"
        verbose_name_plural = "Questions"

    def mark_answered(self, answer: str, by_user_id: int) -> None:
        """Convenience method to set answer metadata."""
        self.answer = answer
        self.is_answered = True
        self.answered_by_id = by_user_id
        self.answered_at = timezone.now()
        self.save(update_fields=["answer", "is_answered", "answered_by", "answered_at", "updated_at"])

    def __str__(self) -> str:
        status = "answered" if self.is_answered else "open"
        return f"[{self.event_id}] {status}: {self.content[:50]}"
