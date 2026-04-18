"""
Database models for the interactions app.

We persist:
- ChatMessage: freeform chat lines by members during an event.
- Question: Q&A entries; can later be answered and marked resolved.
- QnAEngagementPrompt: Host-triggered prompt to encourage Q&A participation.
- QnAEngagementPromptReceipt: Per-attendee delivery tracking for cap enforcement.

Both models link to:
- Event (events.Event)
- User (AUTH_USER_MODEL)

Indexes + ordering are chosen for the most common queries (latest-first).
"""

from django.conf import settings
from django.db import models
from django.utils import timezone

# -----------------------------------------------------------------
# Q&A Engagement Prompt constants
# These defaults can later be moved to event-level settings.
# -----------------------------------------------------------------
QNA_PROMPT_MAX_PER_USER = 3          # max prompts shown per attendee per event
QNA_PROMPT_AUTO_HIDE_SECONDS = 10    # seconds before banner auto-hides

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
        null=True,
        blank=True,
        help_text="User who asked the question.",
    )
    guest_asker = models.ForeignKey(
        "events.GuestAttendee",
        on_delete=models.SET_NULL,
        related_name="questions",
        null=True,
        blank=True,
        help_text="Guest attendee who asked the question.",
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
    moderation_status = models.CharField(
        max_length=20,
        choices=[("pending", "Pending"), ("approved", "Approved"), ("rejected", "Rejected")],
        default="approved",
        help_text="Approval status when qna_moderation_enabled on event.",
    )
    rejection_reason = models.TextField(
        null=True,
        blank=True,
        help_text="Host-provided reason when rejecting a question.",
    )
    is_answered = models.BooleanField(
        default=False,
        help_text="Whether this question has been answered.",
    )
    answered_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the question was marked as answered.",
    )
    answered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="answered_questions",
        help_text="User who marked this question as answered.",
    )
    requires_followup = models.BooleanField(
        default=False,
        help_text="Flag question for follow-up after event.",
    )
    is_pinned = models.BooleanField(
        default=False,
        help_text="Whether this question is pinned to the top.",
    )
    pinned_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the question was pinned.",
    )
    pinned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="pinned_questions",
        help_text="User who pinned this question.",
    )
    is_anonymous = models.BooleanField(
        default=False,
        help_text="Whether the question was submitted anonymously.",
    )
    anonymized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="anonymized_questions",
        help_text="Host who anonymized this question (null if self-anonymized by submitter).",
    )
    display_order = models.IntegerField(
        default=0,
        help_text="Manual sort order for host reorder. Lower = higher in list.",
    )
    is_seed = models.BooleanField(
        default=False,
        help_text="True for host-created seed questions added before the event goes live.",
    )
    attribution_label = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Display attribution for seed questions, e.g. 'Host', 'Event Team', 'Dr. Smith'.",
    )
    speaker_note = models.TextField(
        blank=True,
        default="",
        help_text="Private host/speaker note visible only to the host. Not shown to attendees.",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["event", "-created_at"], name="qna_event_created_idx"),
            models.Index(fields=["lounge_table", "-created_at"], name="qna_table_created_idx"),
            models.Index(fields=["event", "moderation_status"], name="qna_event_status_idx"),
            models.Index(fields=["event", "is_pinned"], name="qna_event_pinned_idx"),
            models.Index(fields=["event", "is_seed"], name="qna_event_seed_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                name="question_has_user_or_guest",
                check=models.Q(user__isnull=False) | models.Q(guest_asker__isnull=False),
            ),
        ]
        verbose_name = "Question"
        verbose_name_plural = "Questions"

    def upvote_count(self) -> int:
        return self.upvoters.count() + self.guest_upvotes.count()

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


class QuestionGuestUpvote(models.Model):
    """
    Through table for Question <-> GuestAttendee upvotes.
    One guest can upvote a question at most once.
    """

    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name="guest_upvotes")
    guest = models.ForeignKey("events.GuestAttendee", on_delete=models.CASCADE, related_name="question_upvotes")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("question", "guest")
        indexes = [
            models.Index(fields=["question", "created_at"], name="qna_guest_upvote_time_idx"),
            models.Index(fields=["guest", "question"], name="qna_guest_upvote_guest_q_idx"),
        ]

    def __str__(self) -> str:
        return f"Q{self.question_id} ▲ by G{self.guest_id}"


# -----------------------------------------------------------------
# Q&A Reply Models (one-level threaded follow-ups under questions)
# -----------------------------------------------------------------

class QnAReply(models.Model):
    """
    A one-level reply posted under a Q&A question.

    Replies cannot have child replies (one-level only).
    Inherits event and lounge_table from the parent question.

    Fields:
        question: FK to the parent Question.
        event: Denormalized event FK for efficient queries.
        lounge_table: Denormalized table FK (nullable = Main Room).
        user: FK to the authenticated author (null for guests).
        guest_asker: FK to the GuestAttendee author (null for auth users).
        content: The reply text.
        created_at/updated_at: audit timestamps.
        upvoters: M2M to User through QnAReplyUpvote.
        moderation_status: pending/approved/rejected.
        rejection_reason: Host reason when rejecting.
        is_anonymous: Whether the reply is anonymous.
        is_hidden/hidden_by/hidden_at: Soft-hide by host.
        anonymized_by: Host who anonymized the reply.
    """

    question = models.ForeignKey(
        Question,
        on_delete=models.CASCADE,
        related_name="replies",
        help_text="The parent question this reply belongs to.",
    )
    event = models.ForeignKey(
        "events.Event",
        on_delete=models.CASCADE,
        related_name="qna_replies",
        help_text="Event this reply belongs to.",
    )
    lounge_table = models.ForeignKey(
        "events.LoungeTable",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="qna_replies",
        help_text="Lounge table (if applicable). Null means Main Room.",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="qna_replies",
        null=True,
        blank=True,
        help_text="User who authored the reply.",
    )
    guest_asker = models.ForeignKey(
        "events.GuestAttendee",
        on_delete=models.SET_NULL,
        related_name="qna_replies",
        null=True,
        blank=True,
        help_text="Guest attendee who authored the reply.",
    )
    content = models.TextField(help_text="Reply text content.")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Creation timestamp.")
    updated_at = models.DateTimeField(auto_now=True, help_text="Last update timestamp.")
    upvoters = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through="QnAReplyUpvote",
        related_name="upvoted_replies",
        blank=True,
        help_text="Users who upvoted this reply.",
    )
    moderation_status = models.CharField(
        max_length=20,
        choices=[("pending", "Pending"), ("approved", "Approved"), ("rejected", "Rejected")],
        default="approved",
        help_text="Approval status for the reply.",
    )
    rejection_reason = models.TextField(
        null=True,
        blank=True,
        help_text="Host-provided reason when rejecting a reply.",
    )
    is_anonymous = models.BooleanField(
        default=False,
        help_text="Whether the reply was submitted anonymously.",
    )
    is_hidden = models.BooleanField(
        default=False,
        help_text="Whether this reply is hidden from attendees.",
    )
    hidden_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="hidden_replies",
        help_text="User who hid this reply.",
    )
    hidden_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the reply was hidden.",
    )
    anonymized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="anonymized_replies",
        help_text="Host who anonymized this reply.",
    )

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["question", "created_at"], name="reply_q_created_idx"),
            models.Index(fields=["event", "moderation_status"], name="reply_event_status_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                name="reply_has_user_or_guest",
                check=models.Q(user__isnull=False) | models.Q(guest_asker__isnull=False),
            ),
        ]
        verbose_name = "Q&A Reply"
        verbose_name_plural = "Q&A Replies"

    def upvote_count(self) -> int:
        return self.upvoters.count() + self.guest_upvotes.count()

    def __str__(self) -> str:
        return f"Reply {self.id} on Q{self.question_id}: {self.content[:50]}"


class QnAReplyUpvote(models.Model):
    """Through table for QnAReply <-> User upvotes."""

    reply = models.ForeignKey(QnAReply, on_delete=models.CASCADE, related_name="upvote_links")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="qna_reply_upvotes",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("reply", "user")
        indexes = [
            models.Index(fields=["reply", "created_at"], name="reply_upvote_time_idx"),
        ]

    def __str__(self) -> str:
        return f"Reply{self.reply_id} ▲ by U{self.user_id}"


class QnAReplyGuestUpvote(models.Model):
    """Through table for QnAReply <-> GuestAttendee upvotes."""

    reply = models.ForeignKey(QnAReply, on_delete=models.CASCADE, related_name="guest_upvotes")
    guest = models.ForeignKey(
        "events.GuestAttendee",
        on_delete=models.CASCADE,
        related_name="qna_reply_upvotes",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("reply", "guest")
        indexes = [
            models.Index(fields=["reply", "created_at"], name="reply_guest_upvote_time_idx"),
        ]

    def __str__(self) -> str:
        return f"Reply{self.reply_id} ▲ by G{self.guest_id}"


# -----------------------------------------------------------------
# Q&A Engagement Prompt Models
# -----------------------------------------------------------------

class QnAEngagementPrompt(models.Model):
    """
    One row per host-triggered Q&A engagement prompt.

    Fields:
        event: The event this prompt belongs to.
        triggered_by: The host/moderator who sent the prompt.
        message: Custom or default message shown in the banner.
        auto_hide_seconds: Seconds before the banner auto-hides on the client.
        created_at: Timestamp of dispatch.
    """

    event = models.ForeignKey(
        "events.Event",
        on_delete=models.CASCADE,
        related_name="qna_engagement_prompts",
        help_text="Event this prompt belongs to.",
    )
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="triggered_qna_prompts",
        help_text="Host/moderator who triggered the prompt.",
    )
    PROMPT_TYPE_BANNER = "banner"
    PROMPT_TYPE_MODAL = "modal"
    PROMPT_TYPE_CHOICES = [
        (PROMPT_TYPE_BANNER, "Banner"),
        (PROMPT_TYPE_MODAL, "Modal"),
    ]

    prompt_type = models.CharField(
        max_length=10,
        choices=PROMPT_TYPE_CHOICES,
        default=PROMPT_TYPE_BANNER,
        help_text="UI type: banner (bottom bar) or modal (centered popup).",
    )
    message = models.TextField(
        default="Have a question? Submit it in Q&A now.",
        help_text="Banner or modal message shown to attendees.",
    )
    auto_hide_seconds = models.PositiveIntegerField(
        default=QNA_PROMPT_AUTO_HIDE_SECONDS,
        help_text="Seconds before the prompt auto-hides on the client.",
    )
    created_at = models.DateTimeField(auto_now_add=True, help_text="When this prompt was dispatched.")

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["event", "-created_at"], name="qna_prompt_event_created_idx"),
        ]
        verbose_name = "Q&A Engagement Prompt"
        verbose_name_plural = "Q&A Engagement Prompts"

    def __str__(self) -> str:
        return f"[Event {self.event_id}] Prompt {self.id} by {self.triggered_by_id}"


class QnAEngagementPromptReceipt(models.Model):
    """
    Tracks per-attendee delivery of a QnAEngagementPrompt.

    Used to enforce the max-prompts-per-user-per-event cap server-side.
    Either `user` or `guest` must be set (enforced by CheckConstraint).

    Fields:
        prompt: The prompt that was delivered.
        event: Denormalized event FK for efficient cap counting.
        user: Authenticated user (nullable).
        guest: Guest attendee (nullable).
        shown_at: When the receipt was created (i.e., banner was shown).
        dismissed_at: When the attendee dismissed the banner (null = not dismissed).
    """

    prompt = models.ForeignKey(
        QnAEngagementPrompt,
        on_delete=models.CASCADE,
        related_name="receipts",
        help_text="The prompt this receipt belongs to.",
    )
    event = models.ForeignKey(
        "events.Event",
        on_delete=models.CASCADE,
        related_name="qna_prompt_receipts",
        help_text="Denormalized event FK for efficient cap counting.",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="qna_prompt_receipts",
        help_text="Authenticated user (null for guests).",
    )
    guest = models.ForeignKey(
        "events.GuestAttendee",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="qna_prompt_receipts",
        help_text="Guest attendee (null for auth users).",
    )
    shown_at = models.DateTimeField(auto_now_add=True, help_text="When the banner was shown.")
    dismissed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the attendee dismissed the banner (null = not dismissed or auto-hidden).",
    )

    class Meta:
        ordering = ["-shown_at"]
        indexes = [
            models.Index(fields=["event", "user", "-shown_at"], name="qna_receipt_event_user_idx"),
            models.Index(fields=["event", "guest", "-shown_at"], name="qna_receipt_event_guest_idx"),
            models.Index(fields=["prompt", "user"], name="qna_receipt_prompt_user_idx"),
            models.Index(fields=["prompt", "guest"], name="qna_receipt_prompt_guest_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                name="qna_receipt_has_user_or_guest",
                check=models.Q(user__isnull=False) | models.Q(guest__isnull=False),
            ),
        ]
        verbose_name = "Q&A Engagement Prompt Receipt"
        verbose_name_plural = "Q&A Engagement Prompt Receipts"

    def __str__(self) -> str:
        attendee = f"U{self.user_id}" if self.user_id else f"G{self.guest_id}"
        return f"Prompt {self.prompt_id} → {attendee} @ event {self.event_id}"


# -----------------------------------------------------------------
# Q&A Grouping Models
# -----------------------------------------------------------------

class QnAQuestionGroupSuggestion(models.Model):
    """
    Stores AI-generated suggestions for grouping questions.
    """
    event = models.ForeignKey(
        "events.Event",
        on_delete=models.CASCADE,
        related_name="qna_ai_group_suggestions"
    )
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="generated_qna_group_suggestions"
    )
    status = models.CharField(
        max_length=20,
        choices=[("pending", "Pending"), ("approved", "Approved"), ("rejected", "Rejected")],
        default="pending"
    )
    raw_ai_response = models.JSONField(blank=True, null=True)
    suggested_title = models.CharField(max_length=255)
    suggested_summary = models.TextField(blank=True, null=True)
    confidence_score = models.FloatField(default=0.0)
    suggested_question_ids = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_qna_group_suggestions",
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Q&A Group Suggestion"
        verbose_name_plural = "Q&A Group Suggestions"

    def __str__(self) -> str:
        return f"Suggestion {self.id}: {self.status} - {self.suggested_title}"


class QnAQuestionGroup(models.Model):
    """
    A grouping of Q&A questions by a host, manual or AI assisted.
    """
    event = models.ForeignKey(
        "events.Event",
        on_delete=models.CASCADE,
        related_name="qna_question_groups"
    )
    title = models.CharField(max_length=255)
    summary = models.TextField(blank=True, null=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="created_qna_question_groups"
    )
    
    SOURCE_MANUAL = "manual"
    SOURCE_AI = "ai"
    SOURCE_CHOICES = [(SOURCE_MANUAL, "Manual"), (SOURCE_AI, "AI")]
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default=SOURCE_MANUAL)
    
    ai_suggestion = models.ForeignKey(
        QnAQuestionGroupSuggestion,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="resulting_groups"
    )
    display_order = models.IntegerField(default=0)
    is_visible_to_attendees = models.BooleanField(
        default=False,
        help_text="If true, attendees can see the group visually. Currently disabled by default."
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["display_order", "-created_at"]
        verbose_name = "Q&A Question Group"
        verbose_name_plural = "Q&A Question Groups"

    def __str__(self) -> str:
        return f"Group {self.id}: {self.title}"


class QnAQuestionGroupMembership(models.Model):
    """
    Maps a question to a group. One question can be in at most one active group at a time.
    """
    group = models.ForeignKey(
        QnAQuestionGroup,
        on_delete=models.CASCADE,
        related_name="memberships"
    )
    question = models.OneToOneField(
        Question,
        on_delete=models.CASCADE,
        related_name="group_membership"
    )
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="added_qna_group_memberships"
    )
    display_order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["display_order", "created_at"]
        verbose_name = "Q&A Question Group Membership"
        verbose_name_plural = "Q&A Question Group Memberships"

    def __str__(self) -> str:
        return f"Question {self.question_id} in Group {self.group_id}"


# -----------------------------------------------------------------
# Q&A Content Context (presentation grounding for AI suggestions)
# -----------------------------------------------------------------

class QnAContentContext(models.Model):
    """
    Stores normalized presentation content that grounds AI question suggestions.

    A host or admin adds one or more context records for an event before or
    during the session.  The AI suggestion service concatenates them and asks
    the LLM to suggest thoughtful audience questions.

    Supported source types mirror the migration choices:
        event_description  – the event's own description field
        session_agenda     – agenda text for a named session
        slides             – extracted text from uploaded slide decks
        transcript         – live or post-event transcript excerpts
        host_notes         – freeform notes the host types in directly

    Notes:
        - Suggestions are never persisted; context is what persists.
        - Table already created by migration 0012_qnacontentcontext.
    """

    SOURCE_EVENT_DESCRIPTION = "event_description"
    SOURCE_SESSION_AGENDA = "session_agenda"
    SOURCE_SLIDES = "slides"
    SOURCE_TRANSCRIPT = "transcript"
    SOURCE_HOST_NOTES = "host_notes"

    SOURCE_TYPE_CHOICES = [
        (SOURCE_EVENT_DESCRIPTION, "Event Description"),
        (SOURCE_SESSION_AGENDA, "Session Agenda"),
        (SOURCE_SLIDES, "Slides Content"),
        (SOURCE_TRANSCRIPT, "Live/Post Transcript"),
        (SOURCE_HOST_NOTES, "Host/Speaker Notes"),
    ]

    event = models.ForeignKey(
        "events.Event",
        on_delete=models.CASCADE,
        related_name="qna_contexts",
        help_text="The event this context belongs to.",
    )
    session = models.ForeignKey(
        "events.EventSession",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="qna_contexts",
        help_text="The optional session this context belongs to.",
    )
    source_type = models.CharField(
        max_length=30,
        choices=SOURCE_TYPE_CHOICES,
        default=SOURCE_HOST_NOTES,
    )
    source_title = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Optional title of the source (e.g. 'Slide Deck 1', 'Session Agenda').",
    )
    content_text = models.TextField(
        help_text="The normalized text content used for AI grounding.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Q&A Content Context"
        verbose_name_plural = "Q&A Content Contexts"

    def __str__(self) -> str:
        return f"[Event {self.event_id}] {self.get_source_type_display()}: {self.source_title or self.content_text[:40]}"
