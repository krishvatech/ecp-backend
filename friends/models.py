from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models, transaction
from django.db.models import Q, F
from django.utils import timezone

User = get_user_model()


class Friendship(models.Model):
    """
    A mutual friendship stored once per pair.
    We normalize ordering so (min(user_id), max(user_id)) is always stored.
    """

    user1 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="friends_as_user1",
        on_delete=models.CASCADE,
    )
    user2 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="friends_as_user2",
        on_delete=models.CASCADE,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=~Q(user1=F("user2")), name="friendship_no_self"
            ),
            models.UniqueConstraint(
                fields=["user1", "user2"], name="uniq_friendship_pair"
            ),
        ]
        indexes = [
            models.Index(fields=["user1"]),
            models.Index(fields=["user2"]),
        ]

    def save(self, *args, **kwargs):
        # Normalize ordering so smaller id is always user1
        if self.user1_id and self.user2_id and self.user1_id > self.user2_id:
            self.user1_id, self.user2_id = self.user2_id, self.user1_id
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Friendship({self.user1_id}, {self.user2_id})"

    @classmethod
    def are_friends(cls, a_id: int, b_id: int) -> bool:
        if a_id == b_id:
            return False
        u1, u2 = (a_id, b_id) if a_id < b_id else (b_id, a_id)
        return cls.objects.filter(user1_id=u1, user2_id=u2).exists()


class FriendRequest(models.Model):
    """
    Request/approval flow for friends.
    """

    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    CANCELED = "canceled"

    STATUS_CHOICES = [
        (PENDING, "Pending"),
        (ACCEPTED, "Accepted"),
        (DECLINED, "Declined"),
        (CANCELED, "Canceled"),
    ]

    from_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="friend_requests_sent",
        on_delete=models.CASCADE,
    )
    to_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="friend_requests_received",
        on_delete=models.CASCADE,
    )
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=~Q(from_user=F("to_user")), name="friendreq_no_self"
            ),
            # Only one *pending* request for a given direction
            models.UniqueConstraint(
                fields=["from_user", "to_user", "status"],
                name="uniq_pending_request",
                condition=Q(status="pending"),
            ),
        ]
        indexes = [
            models.Index(fields=["to_user", "status"]),
            models.Index(fields=["from_user", "status"]),
        ]

    def __str__(self):
        return f"FriendRequest({self.from_user_id} → {self.to_user_id}, {self.status})"

    @transaction.atomic
    def accept(self):
        if self.status != self.PENDING:
            return self

        # Create friendship (normalized small->big)
        u1, u2 = (self.from_user_id, self.to_user_id)
        if u1 > u2:
            u1, u2 = u2, u1
        Friendship.objects.get_or_create(user1_id=u1, user2_id=u2)

        self.status = self.ACCEPTED
        self.responded_at = timezone.now()
        self.save(update_fields=["status", "responded_at"])

        # Update recipient's pending notification to accepted
        Notification.objects.filter(
            recipient_id=self.to_user_id,
            kind="friend_request",
            data__friend_request_id=self.id,
        ).update(state="accepted", is_read=True, updated_at=timezone.now())

        # Notify sender that request was accepted
        Notification.objects.create(
            recipient=self.from_user,
            actor=self.to_user,
            kind="friend_request",
            title="accepted your friend request",
            state="accepted",
            data={"friend_request_id": self.id, "to_user_id": self.to_user_id},
        )
        return self

    @transaction.atomic
    def decline(self):
        if self.status != self.PENDING:
            return self

        self.status = self.DECLINED
        self.responded_at = timezone.now()
        self.save(update_fields=["status", "responded_at"])

        # Update recipient's pending notification to declined
        Notification.objects.filter(
            recipient_id=self.to_user_id,
            kind="friend_request",
            data__friend_request_id=self.id,
        ).update(state="declined", is_read=True, updated_at=timezone.now())

        # Notify sender that request was declined (optional; remove if you don't want this)
        Notification.objects.create(
            recipient=self.from_user,
            actor=self.to_user,
            kind="friend_request",
            title="declined your friend request",
            state="declined",
            data={"friend_request_id": self.id, "to_user_id": self.to_user_id},
        )
        return self

    @transaction.atomic
    def cancel(self):
        if self.status != self.PENDING:
            return self

        self.status = self.CANCELED
        self.responded_at = timezone.now()
        self.save(update_fields=["status", "responded_at"])

        # Update recipient's pending notification to canceled
        Notification.objects.filter(
            recipient_id=self.to_user_id,
            kind="friend_request",
            data__friend_request_id=self.id,
        ).update(state="canceled", is_read=True, updated_at=timezone.now())

        # (Usually we don't notify the recipient separately on cancel.)
        return self


class Notification(models.Model):
    KIND_CHOICES = [
        ("friend_request", "Friend Request"),
        ("follow", "Follow"),
        ("mention", "Mention"),
        ("comment", "Comment"),
        ("reaction", "Reaction"),
        ("event", "Event"),
        ("suggestion_digest", "Suggestion Digest"),
    ]

    recipient = models.ForeignKey(
        User, related_name="notifications", on_delete=models.CASCADE
    )
    actor = models.ForeignKey(
        User,
        related_name="notifications_as_actor",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    kind = models.CharField(max_length=32, choices=KIND_CHOICES)
    title = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True, default="")
    # For friend requests: "pending" | "accepted" | "declined" | "canceled"
    state = models.CharField(max_length=16, blank=True)
    data = models.JSONField(default=dict, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["recipient", "is_read", "created_at"]),
            models.Index(fields=["kind"]),
        ]

    def __str__(self):
        return f"Notification(to={self.recipient_id}, kind={self.kind}, state={self.state})"


def notify_friend_request_created(fr: FriendRequest):
    """
    Create (or ensure there is) a 'pending' notification on the recipient when a friend request is created.
    Safe to call from serializer OR via a signal; it guards against duplicates.
    """
    if not fr or not fr.id:
        return

    exists = Notification.objects.filter(
        recipient_id=fr.to_user_id,
        kind="friend_request",
        data__friend_request_id=fr.id,
        state="pending",
    ).exists()
    if exists:
        return

    Notification.objects.create(
        recipient=fr.to_user,
        actor=fr.from_user,
        kind="friend_request",
        title="sent you a friend request",
        state="pending",
        data={"friend_request_id": fr.id, "from_user_id": fr.from_user_id},
    )
