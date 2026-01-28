from django.conf import settings
from django.db import models
from django.db.models import Q
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType

# ---------- COMMENTS (generic target) ----------
class Comment(models.Model):
    # Generic target (post, feed item, photo, etc.)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveBigIntegerField()
    target = GenericForeignKey("content_type", "object_id")

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    text = models.TextField()
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
    parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.CASCADE, related_name="replies"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["content_type", "object_id", "created_at"]),
            models.Index(fields=["parent", "created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"Comment({self.id}) by {self.user}"

# ---------- REACTIONS (likes; already generic) ----------
class Reaction(models.Model):
    # ✅ Supported reaction types
    LIKE = "like"
    INTRIGUING = "intriguing"
    SPOT_ON = "spot_on"
    VALIDATED = "validated"
    DEBATABLE = "debatable"

    REACTION_CHOICES = [
        (LIKE, "Like"),
        (INTRIGUING, "Intriguing"),
        (SPOT_ON, "Spot On"),
        (VALIDATED, "Validated"),
        (DEBATABLE, "Debatable"),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    reaction = models.CharField(max_length=24, choices=REACTION_CHOICES, default=LIKE)

    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveBigIntegerField()
    content_object = GenericForeignKey("content_type", "object_id")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # ✅ only ONE reaction per user per target (can change type)
        constraints = [
            models.UniqueConstraint(
                fields=["user", "content_type", "object_id"],
                name="unique_user_reaction_per_target",
            )
        ]
        indexes = [
            models.Index(fields=["content_type", "object_id", "reaction"]),
            models.Index(fields=["user", "created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user} {self.reaction} {self.content_type_id}:{self.object_id}"



# ---------- SHARES (generic target) ----------
class Share(models.Model):
    # what is being shared
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveBigIntegerField()
    target = GenericForeignKey("content_type", "object_id")

    # who is sharing
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    # single recipient per row (so we have ONE table only)
    to_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True, blank=True, on_delete=models.CASCADE,
        related_name="received_share_rows",
    )
    to_group = models.ForeignKey(
        "groups.Group",
        null=True, blank=True, on_delete=models.CASCADE,
        related_name="received_share_rows",
    )

    note = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["content_type", "object_id", "created_at"]),
            models.Index(fields=["to_user"]),
            models.Index(fields=["to_group"]),
        ]
        constraints = [
            # Exactly one of to_user / to_group must be set
            models.CheckConstraint(
                check=(
                    (Q(to_user__isnull=False) & Q(to_group__isnull=True)) |
                    (Q(to_user__isnull=True) & Q(to_group__isnull=False))
                ),
                name="share_exactly_one_recipient",
            ),
            # Prevent duplicate rows from the same sharer to the same recipient for the same target
            models.UniqueConstraint(
                fields=["user", "content_type", "object_id", "to_user"],
                name="uniq_share_to_user_per_target",
                condition=Q(to_user__isnull=False),
            ),
            models.UniqueConstraint(
                fields=["user", "content_type", "object_id", "to_group"],
                name="uniq_share_to_group_per_target",
                condition=Q(to_group__isnull=False),
            ),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        r = f"user:{self.to_user_id}" if self.to_user_id else f"group:{self.to_group_id}"
        return f"Share({self.id}) by {self.user_id} → {r}"
