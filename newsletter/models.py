"""Newsletter preference and Mautic synchronization models.

ECP PostgreSQL is the source of truth for newsletter consent/preferences.
Mautic is an external delivery/marketing system synchronized from durable
NewsletterSyncEvent records.
"""

import uuid

from django.conf import settings
from django.db import models


class NewsletterCategory(models.Model):
    name = models.CharField(max_length=120, unique=True)
    slug = models.SlugField(max_length=140, unique=True)
    description = models.TextField(blank=True, default="")
    is_active = models.BooleanField(default=True, db_index=True)
    mautic_segment_id = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="External Mautic segment ID. Unused until Mautic sync is enabled.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class NewsletterAudience(models.Model):
    """ECP-owned audience definition for future newsletter targeting."""

    class AudienceType(models.TextChoices):
        STATIC = "static", "Static"
        DYNAMIC = "dynamic", "Dynamic"

    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"
        ACTIVE = "active", "Active"
        ARCHIVED = "archived", "Archived"

    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=180)
    description = models.TextField(blank=True, default="")
    audience_type = models.CharField(
        max_length=16,
        choices=AudienceType.choices,
        default=AudienceType.STATIC,
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.DRAFT,
    )
    rule_definition = models.JSONField(blank=True, default=dict)
    estimated_count = models.IntegerField(null=True, blank=True)
    mautic_segment_id = models.CharField(max_length=64, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_newsletter_audiences",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(
                fields=["status"],
                name="newsletter_audience_status_idx",
            ),
            models.Index(
                fields=["is_active"],
                name="newsletter_audience_active_idx",
            ),
            models.Index(
                fields=["created_at"],
                name="newsletter_aud_created_idx",
            ),
        ]

    def __str__(self):
        return self.name


class NewsletterSubscription(models.Model):
    class Source(models.TextChoices):
        USER = "user", "User"
        ADMIN = "admin", "Admin"
        IMPORT = "import", "Import"
        MAUTIC = "mautic", "Mautic"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="newsletter_subscriptions",
    )
    category = models.ForeignKey(
        NewsletterCategory,
        on_delete=models.PROTECT,
        related_name="subscriptions",
    )
    is_subscribed = models.BooleanField(default=False, db_index=True)
    subscribed_at = models.DateTimeField(null=True, blank=True)
    unsubscribed_at = models.DateTimeField(null=True, blank=True)
    source = models.CharField(
        max_length=16,
        choices=Source.choices,
        default=Source.USER,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["user_id", "category_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "category"],
                name="newsletter_unique_user_category",
            ),
        ]
        indexes = [
            models.Index(
                fields=["user", "is_subscribed"],
                name="newsletter_user_state_idx",
            ),
        ]

    def __str__(self):
        state = "subscribed" if self.is_subscribed else "unsubscribed"
        return f"{self.user_id}:{self.category.slug} ({state})"


class NewsletterCampaign(models.Model):
    """Admin-authored newsletter broadcast draft owned by ECP."""

    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"
        SCHEDULED = "scheduled", "Scheduled"
        SENDING = "sending", "Sending"
        SENT = "sent", "Sent"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=180)
    subject = models.CharField(max_length=190, blank=True, default="")
    preview_text = models.CharField(max_length=255, blank=True, default="")
    from_name = models.CharField(max_length=120, blank=True, default="")
    from_email = models.EmailField(blank=True, default="")
    html_content = models.TextField(blank=True, default="")
    plain_text = models.TextField(blank=True, default="")
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.DRAFT,
        db_index=True,
    )
    audiences = models.ManyToManyField(
        NewsletterCategory,
        blank=True,
        related_name="campaigns",
    )
    scheduled_at = models.DateTimeField(null=True, blank=True, db_index=True)
    send_started_at = models.DateTimeField(null=True, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    mautic_email_id = models.CharField(max_length=64, blank=True, default="")
    last_synced_to_mautic_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True, default="")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_newsletter_campaigns",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="updated_newsletter_campaigns",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return self.name


class NewsletterCampaignSendEvent(models.Model):
    """One durable, single-use send request for a newsletter campaign.

    A campaign may have only one send event for its lifetime. This is stricter
    than preference synchronization because a broadcast must never be blindly
    retried after an ambiguous provider response.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PROCESSING = "processing", "Processing"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    event_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    idempotency_key = models.CharField(max_length=255, unique=True)
    campaign = models.OneToOneField(
        NewsletterCampaign,
        on_delete=models.PROTECT,
        related_name="send_event",
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="requested_newsletter_campaign_sends",
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    attempt_count = models.PositiveIntegerField(default=0)
    processing_started_at = models.DateTimeField(null=True, blank=True)
    provider_send_started_at = models.DateTimeField(null=True, blank=True)
    provider_sent_count = models.PositiveIntegerField(default=0)
    provider_failed_count = models.PositiveIntegerField(default=0)
    provider_failed_recipients = models.JSONField(blank=True, default=list)
    completed_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(
                fields=["status", "created_at"],
                name="newsletter_send_queue_idx",
            ),
        ]

    def __str__(self):
        return f"campaign:{self.campaign_id} [{self.status}]"


class NewsletterCampaignTrackingEvent(models.Model):
    """Append-only provider tracking event for newsletter analytics."""

    class EventType(models.TextChoices):
        DELIVERED = "delivered", "Delivered"
        OPENED = "opened", "Opened"
        CLICKED = "clicked", "Clicked"
        UNSUBSCRIBED = "unsubscribed", "Unsubscribed"
        BOUNCED = "bounced", "Bounced"
        FAILED = "failed", "Failed"

    event_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    campaign = models.ForeignKey(
        NewsletterCampaign,
        on_delete=models.PROTECT,
        related_name="tracking_events",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    mautic_contact_id = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
    )
    recipient_email = models.EmailField(blank=True, default="", db_index=True)
    event_type = models.CharField(max_length=16, choices=EventType.choices)
    source = models.CharField(max_length=32, default="mautic", db_index=True)
    provider_event_id = models.CharField(max_length=255, blank=True, default="")
    url = models.URLField(blank=True, default="")
    payload = models.JSONField(blank=True, default=dict)
    occurred_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["occurred_at", "created_at", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["source", "provider_event_id"],
                condition=~models.Q(provider_event_id=""),
                name="newsletter_tracking_provider_event_uniq",
            ),
        ]
        indexes = [
            models.Index(
                fields=["campaign", "event_type", "occurred_at"],
                name="newsletter_tracking_rollup_idx",
            ),
        ]

    def __str__(self):
        return f"campaign:{self.campaign_id} [{self.event_type}]"


class MauticContactMapping(models.Model):
    """Stable mapping between one ECP user and one Mautic contact."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="mautic_contact_mapping",
    )
    mautic_contact_id = models.CharField(max_length=64, unique=True)
    last_synced_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["user_id"]

    def __str__(self):
        return f"user:{self.user_id} -> mautic:{self.mautic_contact_id}"


class NewsletterSyncEvent(models.Model):
    """Durable desired-state event for ECP -> Mautic synchronization.

    user_id is stored as text rather than a ForeignKey so an event remains
    inspectable/recoverable even if the local user is later deleted.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PROCESSING = "processing", "Processing"
        SUCCEEDED = "succeeded", "Succeeded"
        RETRYING = "retrying", "Retrying"
        FAILED = "failed", "Failed"
        SKIPPED = "skipped", "Skipped"

    event_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    idempotency_key = models.CharField(max_length=255, unique=True)
    user_id = models.CharField(max_length=128, db_index=True)
    category = models.ForeignKey(
        NewsletterCategory,
        on_delete=models.PROTECT,
        related_name="sync_events",
    )
    desired_subscribed = models.BooleanField()
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    attempt_count = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True, default="")
    next_retry_at = models.DateTimeField(null=True, blank=True, db_index=True)
    processing_started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(
                fields=["status", "created_at"],
                name="newsletter_sync_queue_idx",
            ),
            models.Index(
                fields=["user_id", "category"],
                name="newsletter_sync_target_idx",
            ),
        ]

    def __str__(self):
        desired = "subscribed" if self.desired_subscribed else "unsubscribed"
        return (
            f"user:{self.user_id} category:{self.category.slug} "
            f"{desired} [{self.status}]"
        )
