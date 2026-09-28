"""
Models for the standalone ECP blog.

``BlogPost`` holds long-form articles written by platform superusers. The
schema also carries WordPress source fields so a later import can preserve
original slugs, dates and authorship; no import behaviour lives here.

Slugs are generated once, on first save, when none is supplied. They are never
regenerated on title changes so published URLs (including imported WordPress
URLs) stay stable.
"""
import os
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Lower
from django.utils import timezone
from django.utils.text import slugify

# Slugs that would collide with fixed routes under /api/blogs/.
RESERVED_SLUGS = frozenset({"admin"})


def unique_slug(model, value, fallback, max_length, exclude_pk=None):
    """Return a slug derived from ``value`` that no ``model`` row uses yet.

    Collisions get a numeric suffix (``m-a-market-update-2``). Comparison is
    case-insensitive so an explicit ``Foo`` slug still blocks ``foo``.
    """
    # "&" separates words ("M&A" -> "m-a"); slugify would otherwise drop it.
    base = slugify((value or "").replace("&", " "))[: max_length - 10].strip("-") or fallback
    slug = base
    i = 2
    while slug in RESERVED_SLUGS or (
        model.objects.filter(slug__iexact=slug).exclude(pk=exclude_pk).exists()
    ):
        slug = f"{base}-{i}"
        i += 1
    return slug


def blog_featured_image_upload_to(instance, filename):
    name, ext = os.path.splitext(filename or "")
    base = slugify(name)[:60] or "featured"
    return f"blogs/featured/{base}-{uuid.uuid4().hex[:8]}{ext.lower()}"


class BlogTerm(models.Model):
    """Shared shape for flat blog taxonomies (categories and tags)."""

    slug_fallback = "term"

    name = models.CharField(max_length=120)
    slug = models.SlugField(max_length=140, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        ordering = ["name"]

    def __str__(self):
        return self.name

    def clean(self):
        self.name = (self.name or "").strip()
        if not self.name:
            raise ValidationError({"name": "Name cannot be blank."})

    def save(self, *args, **kwargs):
        self.name = (self.name or "").strip()
        if not self.slug:
            self.slug = unique_slug(
                type(self), self.name, self.slug_fallback,
                self._meta.get_field("slug").max_length, exclude_pk=self.pk,
            )
        super().save(*args, **kwargs)


class BlogCategory(BlogTerm):
    slug_fallback = "category"

    class Meta(BlogTerm.Meta):
        verbose_name = "blog category"
        verbose_name_plural = "blog categories"
        constraints = [
            models.UniqueConstraint(Lower("name"), name="uniq_blog_category_name_ci"),
        ]


class BlogTag(BlogTerm):
    slug_fallback = "tag"

    class Meta(BlogTerm.Meta):
        verbose_name = "blog tag"
        constraints = [
            models.UniqueConstraint(Lower("name"), name="uniq_blog_tag_name_ci"),
        ]


class PublishedBlogPostManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(status=BlogPost.STATUS_PUBLISHED)


class BlogPost(models.Model):
    STATUS_DRAFT = "draft"
    STATUS_PUBLISHED = "published"
    STATUS_CHOICES = [
        (STATUS_DRAFT, "Draft"),
        (STATUS_PUBLISHED, "Published"),
    ]

    # Core content
    title = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True)
    excerpt = models.TextField(blank=True, default="")
    # Article HTML stored as-is. Only superusers can write it. The backend has
    # no HTML sanitiser yet, so the WordPress import / rendering layer must
    # sanitise before content from less trusted sources is accepted.
    content_html = models.TextField(blank=True, default="")
    featured_image = models.ImageField(
        upload_to=blog_featured_image_upload_to,
        blank=True,
        null=True,
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="blog_posts_authored",
        help_text="ECP user who wrote the article, when one exists",
    )
    legacy_author_name = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Display name for historical authors without an ECP account",
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default=STATUS_DRAFT, db_index=True
    )
    published_at = models.DateTimeField(null=True, blank=True, db_index=True)

    # Relationships
    categories = models.ManyToManyField(BlogCategory, blank=True, related_name="posts")
    tags = models.ManyToManyField(BlogTag, blank=True, related_name="posts")

    # SEO
    seo_title = models.CharField(max_length=255, blank=True, default="")
    seo_description = models.TextField(blank=True, default="")
    canonical_url = models.URLField(max_length=500, blank=True, default="")

    # WordPress source (populated by the future importer only)
    wp_post_id = models.PositiveBigIntegerField(null=True, blank=True, unique=True)
    wp_source_url = models.URLField(max_length=500, blank=True, default="")
    wp_author_id = models.PositiveBigIntegerField(null=True, blank=True)
    wp_modified_at = models.DateTimeField(null=True, blank=True)
    imported_from_wordpress = models.BooleanField(default=False)
    # Hash of the normalized WordPress content (before ECP media/link
    # rewriting), so re-imports compare source with source.
    wp_content_hash = models.CharField(max_length=64, blank=True, default="")
    # WordPress media ID whose image the importer attached. Lets a re-import
    # tell an imported featured image from one an ECP admin replaced/removed.
    wp_featured_media_id = models.PositiveBigIntegerField(null=True, blank=True)

    # Audit
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="blog_posts_created",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="blog_posts_updated",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = models.Manager()
    published = PublishedBlogPostManager()

    class Meta:
        ordering = ["-updated_at", "-id"]
        indexes = [
            models.Index(fields=["status", "-published_at"], name="blog_post_status_pub_idx"),
        ]

    def __str__(self):
        return self.title

    @property
    def is_published(self):
        return self.status == self.STATUS_PUBLISHED

    def publishability_errors(self):
        errors = {}
        if not (self.title or "").strip():
            errors["title"] = "A published blog requires a title."
        if not (self.content_html or "").strip():
            errors["content_html"] = "A published blog requires article content."
        return errors

    def clean(self):
        self.title = (self.title or "").strip()
        if not self.title:
            raise ValidationError({"title": "Title cannot be blank."})
        if self.slug in RESERVED_SLUGS:
            raise ValidationError({"slug": "This slug is reserved."})
        if self.is_published:
            errors = self.publishability_errors()
            if errors:
                raise ValidationError(errors)

    def save(self, *args, **kwargs):
        self.title = (self.title or "").strip()
        if not self.slug:
            self.slug = unique_slug(
                BlogPost, self.title, "post",
                self._meta.get_field("slug").max_length, exclude_pk=self.pk,
            )
        super().save(*args, **kwargs)

    def publish(self, user=None):
        """Publish the post, keeping any historical ``published_at``."""
        errors = self.publishability_errors()
        if errors:
            raise ValidationError(errors)
        self.status = self.STATUS_PUBLISHED
        if self.published_at is None:
            self.published_at = timezone.now()
        if user is not None:
            self.updated_by = user
        self.save(update_fields=["status", "published_at", "updated_by", "updated_at"])

    def unpublish(self, user=None):
        """Return the post to draft; ``published_at`` is kept for republishing."""
        self.status = self.STATUS_DRAFT
        if user is not None:
            self.updated_by = user
        self.save(update_fields=["status", "updated_by", "updated_at"])


class BlogImportRun(models.Model):
    """Durable record of one WordPress Blog import (progress, counts, report)."""

    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_SUCCEEDED = "succeeded"
    STATUS_PARTIAL = "partial"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCEEDED, "Succeeded"),
        (STATUS_PARTIAL, "Completed with warnings"),
        (STATUS_FAILED, "Failed"),
    ]
    ACTIVE_STATUSES = (STATUS_QUEUED, STATUS_RUNNING)
    TERMINAL_STATUSES = (STATUS_SUCCEEDED, STATUS_PARTIAL, STATUS_FAILED)

    SOURCE_WORDPRESS = "wordpress"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.CharField(max_length=40, default=SOURCE_WORDPRESS)
    source_url = models.URLField(max_length=500, blank=True, default="")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_QUEUED, db_index=True)
    current_step = models.CharField(max_length=40, default="queued")
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="blog_import_runs"
    )
    celery_task_id = models.CharField(max_length=255, blank=True, default="")

    total_discovered = models.PositiveIntegerField(default=0)
    total_importable = models.PositiveIntegerField(default=0)
    processed_count = models.PositiveIntegerField(default=0)
    created_count = models.PositiveIntegerField(default=0)
    updated_count = models.PositiveIntegerField(default=0)
    skipped_count = models.PositiveIntegerField(default=0)
    restricted_count = models.PositiveIntegerField(default=0)
    failed_count = models.PositiveIntegerField(default=0)

    media_found_count = models.PositiveIntegerField(default=0)
    media_processed_count = models.PositiveIntegerField(default=0)
    media_migrated_count = models.PositiveIntegerField(default=0)
    media_reused_count = models.PositiveIntegerField(default=0)
    media_skipped_count = models.PositiveIntegerField(default=0)
    media_failed_count = models.PositiveIntegerField(default=0)
    links_rewritten_count = models.PositiveIntegerField(default=0)

    report_json = models.JSONField(default=dict, blank=True)
    error_message = models.CharField(max_length=500, blank=True, default="")

    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  # doubles as the heartbeat

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            # At most one queued/running import per source: the lock.
            models.UniqueConstraint(
                fields=["source"],
                condition=models.Q(status__in=["queued", "running"]),
                name="uniq_active_blog_import_run",
            ),
        ]

    def __str__(self):
        return f"{self.source} import {self.id} ({self.status})"

    @property
    def is_active(self):
        return self.status in self.ACTIVE_STATUSES


class BlogMediaAsset(models.Model):
    """Ledger of WordPress media migrated into ECP storage (one row per source URL).

    Makes media migration idempotent: a source URL already migrated is reused
    without downloading or uploading again.
    """

    source_url = models.TextField()
    source_url_hash = models.CharField(max_length=64, unique=True)
    storage_name = models.CharField(max_length=500)
    sha256 = models.CharField(max_length=64)
    image_format = models.CharField(max_length=10)
    width = models.PositiveIntegerField()
    height = models.PositiveIntegerField()
    size_bytes = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.storage_name
