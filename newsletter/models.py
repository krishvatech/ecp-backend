"""Newsletter preference models.

ECP PostgreSQL is the source of truth for newsletter consent/preferences.
External marketing providers (for example Mautic) synchronize from this state
in later phases.
"""

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
