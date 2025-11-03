from django.conf import settings
from django.db import models
from django.db.models import Q, F
from django.utils import timezone


class Friendship(models.Model):
    """
    A mutual friendship stored once per pair.
    We normalize ordering so (min(user_id), max(user_id)) is always stored.
    """

    user1 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="friendships_as_user1",
        on_delete=models.CASCADE,
    )
    user2 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="friendships_as_user2",
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
    Request/approval flow for friendships.
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

    def accept(self):
        if self.status != self.PENDING:
            return self
        # Create friendship
        u1, u2 = (self.from_user_id, self.to_user_id)
        if u1 > u2:
            u1, u2 = u2, u1
        Friendship.objects.get_or_create(user1_id=u1, user2_id=u2)
        self.status = self.ACCEPTED
        self.responded_at = timezone.now()
        self.save(update_fields=["status", "responded_at"])
        return self

    def decline(self):
        if self.status != self.PENDING:
            return self
        self.status = self.DECLINED
        self.responded_at = timezone.now()
        self.save(update_fields=["status", "responded_at"])
        return self

    def cancel(self):
        if self.status != self.PENDING:
            return self
        self.status = self.CANCELED
        self.responded_at = timezone.now()
        self.save(update_fields=["status", "responded_at"])
        return self
