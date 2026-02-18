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
        is_hidden: Whether the question is hidden from attendees (hosts only).
        hidden_by: FK to the user who hid the question (optional).
        hidden_at: Timestamp when hidden (optional).
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
    created_at = models.DateTimeField(auto_now_add=True, help_text="Creation timestamp.")
    updated_at = models.DateTimeField(auto_now=True, help_text="Last update timestamp.")
    upvoters = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through="QuestionUpvote",
        related_name="upvoted_questions",
        blank=True,
        help_text="Users who upvoted this question.",
    )
    is_hidden = models.BooleanField(
        default=False,
        help_text="Whether this question is hidden from attendees (hosts can still see it).",
    )
    hidden_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="hidden_questions",
        help_text="User who hid this question (null if not hidden).",
    )
    hidden_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the question was hidden (null if not hidden).",
    )
    lounge_table = models.ForeignKey(
        "events.LoungeTable",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="questions",
        help_text="Lounge table (if applicable). Null means Main Room.",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["event", "-created_at"], name="qna_event_created_idx"),
            models.Index(fields=["lounge_table", "-created_at"], name="qna_table_created_idx"),
        ]
        verbose_name = "Question"
        verbose_name_plural = "Questions"

    def upvote_count(self) -> int:
        return self.upvoters.count()

    def __str__(self) -> str:
        hidden_status = " [HIDDEN]" if self.is_hidden else ""
        return f"[{self.event_id}] {self.content[:50]} (▲{self.upvote_count}){hidden_status}"
    

class QuestionUpvote(models.Model):
    """
    Through table for Question <-> User upvotes.
    One user can upvote a question at most once.
    """

    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name="upvote_links")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="question_upvotes")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("question", "user")
        indexes = [
            models.Index(fields=["question", "created_at"], name="qna_upvote_time_idx"),
            models.Index(fields=["user", "question"], name="qna_upvote_user_q_idx"),
        ]

    def __str__(self) -> str:
        return f"Q{self.question_id} ▲ by U{self.user_id}"
