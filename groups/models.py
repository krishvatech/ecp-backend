# groups/models.py
from django.conf import settings
from django.db import models
from django.utils.text import slugify
from django.db.models import Q

class Group(models.Model):
    VISIBILITY_PUBLIC = 'public'
    VISIBILITY_PRIVATE = 'private'
    VISIBILITY_CHOICES = [
        (VISIBILITY_PUBLIC, 'Public'),
        (VISIBILITY_PRIVATE, 'Private'),
    ]

    JOIN_OPEN = 'open'
    JOIN_INVITE = 'invite'
    JOIN_APPROVAL = 'approval'
    JOIN_POLICY_CHOICES = [
        (JOIN_OPEN, 'Open'),
        (JOIN_INVITE, 'Invite-only'),
        (JOIN_APPROVAL, 'Request approval'),
    ]

    MSG_MODE_ALL = "all"
    MSG_MODE_ADMINS = "admins_only"
    MSG_MODE_CHOICES = [
        (MSG_MODE_ALL, "All members"),
        (MSG_MODE_ADMINS, "Only admins/moderators"),
    ]

    community = models.ForeignKey(
        'community.Community',
        on_delete=models.CASCADE,
        related_name='groups',
        null=True, blank=True,
    )

    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=220, unique=True, db_index=True)
    description = models.TextField(blank=True)
    visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default=VISIBILITY_PUBLIC)
    join_policy = models.CharField(max_length=10, choices=JOIN_POLICY_CHOICES, default=JOIN_OPEN)
    cover_image = models.ImageField(upload_to='group_covers/', blank=True, null=True)
    message_mode = models.CharField(max_length=20, choices=MSG_MODE_CHOICES, default=MSG_MODE_ALL, db_index=True)

    # owner can exist, but owner/admin logic is out of this moderator scope
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='groups_owned',
        null=True, blank=True,
    )

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='groups_created'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['community', 'slug']),
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug and self.name:
            base = slugify(self.name)
            slug = base
            i = 2
            while Group.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base}-{i}"
                i += 1
            self.slug = slug

        if not self.pk and self.owner_id is None and self.created_by_id:
            self.owner_id = self.created_by_id

        if self.cover_image and hasattr(self.cover_image, "size") and self.cover_image.size > 50 * 1024 * 1024:
            from django.core.exceptions import ValidationError
            raise ValidationError("Cover image must be ≤ 50MB.")
        super().save(*args, **kwargs)


class GroupMembership(models.Model):
    ROLE_ADMIN = 'admin'
    ROLE_MODERATOR = 'moderator'
    ROLE_MEMBER = 'member'
    ROLE_CHOICES = [
        (ROLE_ADMIN, 'Admin'),
        (ROLE_MODERATOR, 'Moderator'),
        (ROLE_MEMBER, 'Member'),
    ]

    STATUS_ACTIVE = 'active'
    STATUS_PENDING = 'pending'
    STATUS_BANNED = 'banned'
    STATUS_CHOICES = [
        (STATUS_ACTIVE, 'Active'),
        (STATUS_PENDING, 'Pending'),
        (STATUS_BANNED, 'Banned'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='group_memberships')
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='memberships')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default=ROLE_MEMBER)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='group_invitations_sent'
    )
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'group')
        indexes = [
            models.Index(fields=['group', 'user']),
            models.Index(fields=['group', 'status']),
            models.Index(fields=['group', 'role']),
        ]

    def __str__(self):
        return f"{self.user} → {self.group} ({self.role}, {self.status})"


class PromotionRequest(models.Model):
    """Member/Moderator can request promotion; review is handled elsewhere."""
    ROLE_CHOICES = GroupMembership.ROLE_CHOICES
    STATUS_PENDING = 'pending'
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_REJECTED, 'Rejected'),
    ]

    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='promotion_requests')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='promotion_requests')
    role_requested = models.CharField(max_length=10, choices=ROLE_CHOICES)
    reason = models.CharField(max_length=500, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PENDING)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='promotion_reviews'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('group', 'user', 'role_requested')
        indexes = [models.Index(fields=['group', 'status'])]

    def __str__(self):
        return f"{self.user} → {self.group} ({self.role_requested}, {self.status})"

# ---- Pin a messaging.Message inside a group ----
class GroupPinnedMessage(models.Model):
    group = models.ForeignKey("groups.Group", on_delete=models.CASCADE, related_name="pinned_messages")
    message = models.ForeignKey("messaging.Message", on_delete=models.CASCADE, related_name="group_pins")
    pinned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="pinned_group_messages"
    )
    pinned_at = models.DateTimeField(auto_now_add=True)
    is_global = models.BooleanField(default=False, db_index=True)
    user = models.ForeignKey(  # only used for personal pins
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True, related_name="personal_group_pins"
    )
    class Meta:
        constraints = [
            # Only one global pin per (group, message)
            models.UniqueConstraint(
                fields=["group", "message"],
                condition=Q(is_global=True),
                name="uniq_global_pin_per_group_message",
            ),
            # Only one personal pin per (group, message, user)
            models.UniqueConstraint(
                fields=["group", "message", "user"],
                condition=Q(is_global=False),
                name="uniq_personal_pin_per_user",
            ),
        ]
        indexes = [models.Index(fields=["group", "pinned_at"])]

    def __str__(self):
        scope = "GLOBAL" if self.is_global else f"PERSONAL:{self.user_id}"
        return f"Pin[{scope}] g={self.group_id} msg={self.message_id}"


# ---- Polls ----
class GroupPoll(models.Model):
    group = models.ForeignKey("groups.Group", on_delete=models.CASCADE, related_name="polls")
    question = models.CharField(max_length=500)
    allows_multiple = models.BooleanField(default=False)
    is_anonymous = models.BooleanField(default=False)  # store votes; hide voter identity in API
    is_closed = models.BooleanField(default=False)
    ends_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="group_polls")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["group", "is_closed"]),
            models.Index(fields=["group", "created_at"]),
        ]

    def __str__(self):
        return f"Poll[{self.id}] {self.question[:40]}"


class GroupPollOption(models.Model):
    poll = models.ForeignKey(GroupPoll, on_delete=models.CASCADE, related_name="options")
    text = models.CharField(max_length=300)
    index = models.IntegerField(default=0)

    class Meta:
        unique_together = ("poll", "index")
        indexes = [models.Index(fields=["poll", "index"])]

    def __str__(self):
        return f"PollOption[{self.poll_id}#{self.index}] {self.text[:30]}"


class GroupPollVote(models.Model):
    poll = models.ForeignKey(GroupPoll, on_delete=models.CASCADE, related_name="votes")
    option = models.ForeignKey(GroupPollOption, on_delete=models.CASCADE, related_name="votes")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="group_poll_votes")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("poll", "user", "option")
        indexes = [
            models.Index(fields=["poll", "user"]),
            models.Index(fields=["option"]),
        ]

    def __str__(self):
        return f"Vote[poll={self.poll_id}, user={self.user_id}, option={self.option_id}]"