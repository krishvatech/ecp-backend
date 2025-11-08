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

    
    # ---------- validation ----------
    def clean(self):
        super().clean()

        # Only one “context” allowed
        if self.group_id and self.event_id:
            raise ValidationError("Conversation cannot be linked to both a Group and an Event.")

        # DM must have both users; group/event must NOT have user1/user2
        if self.group_id or self.event_id:
            if self.user1_id or self.user2_id:
                raise ValidationError("Group/Event conversations must not have user1/user2.")
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
            # One unique DM per (user1,user2)
            models.UniqueConstraint(
                fields=["user1", "user2"], name="uniq_conversation_per_user_pair",
                condition=models.Q(group__isnull=True, event__isnull=True,
                                   user1__isnull=False, user2__isnull=False),
            ),
            # Valid shapes only: exactly one of [DM, group, event]
            models.CheckConstraint(
                name="conversation_valid_context",
                check=(
                    # group room
                    (models.Q(group__isnull=False, event__isnull=True,
                              user1__isnull=True, user2__isnull=True))
                    |
                    # event room
                    (models.Q(event__isnull=False, group__isnull=True,
                              user1__isnull=True, user2__isnull=True))
                    |
                    # DM
                    (models.Q(group__isnull=True, event__isnull=True,
                              user1__isnull=False, user2__isnull=False))
                ),
            ),
        ]


class Message(models.Model):
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name="messages")
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sent_messages")
    body = models.TextField()
    attachments = ArrayField(models.JSONField(), default=list, blank=True)
    is_read = models.BooleanField(default=False)

    is_hidden = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
