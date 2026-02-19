# messaging/models.py
from django.conf import settings
from django.db import models
from django.core.exceptions import ValidationError

# add if not present
from django.contrib.postgres.fields import ArrayField  # already used in Message

class Conversation(models.Model):
    # 1:1 participants (nullable for group/event rooms)
    user1 = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="conversations_as_user1", null=True, blank=True
    )
    user2 = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name="conversations_as_user2", null=True, blank=True
    )

    
    # preferred links
    group = models.ForeignKey("groups.Group", null=True, blank=True,
                              on_delete=models.CASCADE, related_name="conversations")
    event = models.ForeignKey("events.Event", null=True, blank=True,
                              on_delete=models.CASCADE, related_name="chat_conversations")
    lounge_table = models.ForeignKey(
        "events.LoungeTable",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="chat_conversations",
    )

    room_key = models.CharField(max_length=128, unique=True, null=True, blank=True)
    title   = models.CharField(max_length=255, null=True, blank=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        related_name="created_conversations", null=True, blank=True
    )
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # ---------- NEW: computed flags to preserve .is_group / .is_event_group usage ----------
    @property
    def is_group(self) -> bool:
        return self.group_id is not None and self.event_id is None

    @property
    def is_event_group(self) -> bool:
        return self.event_id is not None and self.group_id is None

    @property
    def is_lounge(self) -> bool:
        return self.lounge_table_id is not None

    def user_can_view(self, user) -> bool:
        """Mirror permission logic so views can call it quickly."""
        if not user or not getattr(user, "is_authenticated", False):
            return False

        # Group rooms → only members (active or pending)
        if self.group_id:
            from groups.models import GroupMembership

            member_statuses = [
                GroupMembership.STATUS_ACTIVE,
                GroupMembership.STATUS_PENDING,
            ]
            return GroupMembership.objects.filter(
                group_id=self.group_id,
                user_id=user.id,
                status__in=member_statuses,
            ).exists()

        # Event rooms → keep open for now (you can later restrict via event registrations)
        if self.event_id:
            from events.models import Event, EventRegistration

            if getattr(self, "event", None) and self.event.created_by_id == user.id:
                return True
            if Event.objects.filter(pk=self.event_id, created_by_id=user.id).exists():
                return True
            return EventRegistration.objects.filter(
                event_id=self.event_id,
                user_id=user.id,
            ).exists()

        # Lounge room → only seated users
        if self.lounge_table_id:
            from events.models import LoungeParticipant

            return LoungeParticipant.objects.filter(
                table_id=self.lounge_table_id,
                user_id=user.id,
            ).exists()

        # DM → only the two participants
        return user.id in (self.user1_id, self.user2_id)

    
    # ---------- validation ----------
    def clean(self):
        super().clean()

        # Only one “context” allowed
        if self.group_id and self.event_id:
            raise ValidationError("Conversation cannot be linked to both a Group and an Event.")
        if self.lounge_table_id and (self.group_id or self.event_id):
            raise ValidationError("Conversation cannot be linked to both a Lounge Table and a Group/Event.")

        # DM must have both users; group/event/lounge must NOT have user1/user2
        if self.group_id or self.event_id or self.lounge_table_id:
            if self.user1_id or self.user2_id:
                raise ValidationError("Group/Event/Lounge conversations must not have user1/user2.")
        else:
            # DM
            if not self.user1_id or not self.user2_id:
                raise ValidationError("Direct conversations require both user1 and user2.")
            if self.user1_id == self.user2_id:
                raise ValidationError("A conversation requires two distinct participants.")

    def save(self, *args, **kwargs):
        # keep DM pairs canonical (smaller id in user1)
        if (self.group_id is None and self.event_id is None
            and self.user1_id and self.user2_id and self.user1_id > self.user2_id):
            self.user1_id, self.user2_id = self.user2_id, self.user1_id
        super().save(*args, **kwargs)

    def participants(self):
        return self.user1_id, self.user2_id

    def __str__(self):
        if self.is_group:
            return f"[Group] {self.group_id or self.room_key}"
        if self.is_event_group:
            return f"[Event] {self.event_id or self.room_key}"
        if self.is_lounge:
            return f"[Lounge] {self.lounge_table_id or self.room_key}"
        return f"Conversation({self.user1_id}, {self.user2_id})"

    class Meta:
        # Keep/merge your existing indexes; add strict integrity
        constraints = [
            # One unique conversation per group
            models.UniqueConstraint(
                fields=["group"], name="uniq_conversation_per_group",
                condition=models.Q(group__isnull=False),
            ),
            # One unique conversation per event
            models.UniqueConstraint(
                fields=["event"], name="uniq_conversation_per_event",
                condition=models.Q(event__isnull=False),
            ),
            # One unique conversation per lounge table
            models.UniqueConstraint(
                fields=["lounge_table"], name="uniq_conversation_per_lounge_table",
                condition=models.Q(lounge_table__isnull=False),
            ),
            # One unique DM per (user1,user2)
            models.UniqueConstraint(
                fields=["user1", "user2"], name="uniq_conversation_per_user_pair",
                condition=models.Q(group__isnull=True, event__isnull=True,
                                   lounge_table__isnull=True,
                                   user1__isnull=False, user2__isnull=False),
            ),
            # Valid shapes only: exactly one of [DM, group, event, lounge]
            models.CheckConstraint(
                name="conversation_valid_context",
                check=(
                    # group room
                    (models.Q(group__isnull=False, event__isnull=True,
                              lounge_table__isnull=True,
                              user1__isnull=True, user2__isnull=True))
                    |
                    # event room
                    (models.Q(event__isnull=False, group__isnull=True,
                              lounge_table__isnull=True,
                              user1__isnull=True, user2__isnull=True))
                    |
                    # lounge room
                    (models.Q(lounge_table__isnull=False, group__isnull=True,
                              event__isnull=True, user1__isnull=True, user2__isnull=True))
                    |
                    # DM
                    (models.Q(group__isnull=True, event__isnull=True,
                              lounge_table__isnull=True,
                              user1__isnull=False, user2__isnull=False))
                ),
            ),
        ]

class Message(models.Model):
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name="messages")
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sent_messages")
    body = models.TextField()
    attachments = ArrayField(models.JSONField(), default=list, blank=True)
    
    meeting_id = models.CharField(
        max_length=128,
        null=True,
        blank=True,
        help_text="RealtimeKit meetingId for imported chat messages",
    )
    external_id = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="RealtimeKit chat message id (id column from CSV)",
    )

    is_hidden = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    is_edited = models.BooleanField(default=False)
    edited_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

# --- NEW ---
class MessageReadReceipt(models.Model):
    """
    One row per (message, user) indicating the user has read the message.
    - In DMs: the recipient marks read
    - In Group/Event chats: each member marks read independently
    """
    message = models.ForeignKey(
        Message, on_delete=models.CASCADE, related_name="read_receipts"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="message_reads"
    )
    read_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "messaging_message_read_receipt"
        constraints = [
            models.UniqueConstraint(
                fields=["message", "user"], name="uniq_message_read_by_user"
            ),
        ]
        indexes = [
            models.Index(fields=["user", "message"], name="idx_read_user_msg"),
            models.Index(fields=["message"], name="idx_read_msg"),
        ]

    def __str__(self):
        return f"read: msg={self.message_id} by user={self.user_id} @ {self.read_at}"

class MessageFlag(models.Model):
    """
    One row per (message, user) indicating the user flagged the message.
    """
    message = models.ForeignKey(
        Message, on_delete=models.CASCADE, related_name="flags"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="message_flags"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "messaging_message_flag"
        constraints = [
            models.UniqueConstraint(
                fields=["message", "user"], name="uniq_message_flag_by_user"
            ),
        ]
        indexes = [
            models.Index(fields=["message"], name="idx_flag_msg"),
            models.Index(fields=["user"], name="idx_flag_user"),
        ]

    def __str__(self):
        return f"flag: msg={self.message_id} by user={self.user_id}"
    
    
class ConversationPinnedMessage(models.Model):
    """
    Generic pin record for any chat (DM / group / event).
    One row per pinned message in a conversation.
    """
    conversation = models.ForeignKey(
        Conversation,
        on_delete=models.CASCADE,
        related_name="pinned_messages",
    )
    message = models.OneToOneField(
        Message,
        on_delete=models.CASCADE,
        related_name="pinned_state",
        help_text="Pinned message inside this conversation",
    )
    pinned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="conversation_pins",
    )
    pinned_at = models.DateTimeField(auto_now_add=True)
    scope = models.CharField(max_length=20, default='global', choices=[('global', 'Global'), ('private', 'Private')])

    class Meta:
        db_table = "messaging_conversation_pinned_message"
        constraints = [
            models.UniqueConstraint(
                fields=["conversation", "message"],
                name="uniq_pin_per_conversation_message",
            )
        ]
        indexes = [
            models.Index(fields=["conversation", "pinned_at"]),
        ]

    def __str__(self):
        return f"Pin(conv={self.conversation_id}, msg={self.message_id})"
    
class ConversationPin(models.Model):
    """Records that a specific user has pinned a conversation."""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="pinned_conversations"
    )
    conversation = models.ForeignKey(
        Conversation,
        on_delete=models.CASCADE,
        related_name="pins"
    )
    pinned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'conversation'], name='unique_conversation_pin')
        ]
        ordering = ['-pinned_at']

    def __str__(self):
        return f"{self.user} pinned {self.conversation}"
