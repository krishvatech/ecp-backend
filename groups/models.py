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
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="subgroups",
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
            models.Index(fields=['parent']),
            models.Index(fields=['parent', 'community']),
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
        
    @property
    def is_subgroup(self) -> bool:
        return bool(self.parent_id)



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



class GroupNotification(models.Model):
    KIND_JOIN_REQUEST = "join_request"
    KIND_MEMBER_JOINED = "member_joined"
    KIND_MEMBER_ADDED = "member_added"
    KIND_GROUP_CREATED = "group_created"

    KIND_CHOICES = [
        (KIND_JOIN_REQUEST, "Join Request"),
        (KIND_MEMBER_JOINED, "Member Joined"),
        (KIND_MEMBER_ADDED, "Member Added"),
        (KIND_GROUP_CREATED, "Group Created"),
    ]

    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="group_notifications",
        on_delete=models.CASCADE,
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="group_notifications_as_actor",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    group = models.ForeignKey(
        Group,
        related_name="notifications",
        on_delete=models.CASCADE,
    )
    kind = models.CharField(max_length=32, choices=KIND_CHOICES)
    title = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True, default="")
    # for join requests etc: "pending", "approved", "rejected"…
    state = models.CharField(max_length=16, blank=True)
    data = models.JSONField(default=dict, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["recipient", "is_read", "created_at"]),
            models.Index(fields=["group", "kind"]),
        ]

    def __str__(self):
        return (
            f"GroupNotification(group={self.group_id}, "
            f"to={self.recipient_id}, kind={self.kind}, state={self.state})"
        )
