from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models


class Report(models.Model):
    # Content report reasons
    REASON_SPAM = "spam"
    REASON_HARASSMENT = "harassment"
    REASON_HATE_SPEECH = "hate_speech"
    REASON_FALSE_INFO = "false_info"
    REASON_VIOLENCE = "violence"
    REASON_SEXUAL = "sexual_content"
    REASON_OTHER = "other"

    # Profile report reasons
    REASON_PROFILE_INAPPROPRIATE = "profile_inappropriate"
    REASON_PROFILE_DECEASED = "profile_deceased"
    REASON_PROFILE_IMPERSONATION = "profile_impersonation"
    REASON_PROFILE_FAKE = "profile_fake"
    REASON_PROFILE_CORRECTION = "profile_correction"
    REASON_PROFILE_ILLEGAL = "profile_illegal"

    REASON_CHOICES = [
        # Content reasons
        (REASON_SPAM, "Spam"),
        (REASON_HARASSMENT, "Harassment"),
        (REASON_HATE_SPEECH, "Hate speech"),
        (REASON_FALSE_INFO, "False information"),
        (REASON_VIOLENCE, "Violence"),
        (REASON_SEXUAL, "Sexual content"),
        (REASON_OTHER, "Other"),
        # Profile reasons
        (REASON_PROFILE_INAPPROPRIATE, "Inappropriate profile content"),
        (REASON_PROFILE_DECEASED, "Person is deceased"),
        (REASON_PROFILE_IMPERSONATION, "Impersonation"),
        (REASON_PROFILE_FAKE, "Not a real person"),
        (REASON_PROFILE_CORRECTION, "Profile needs correction"),
        (REASON_PROFILE_ILLEGAL, "Illegal content on profile"),
    ]

    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="reports_filed",
    )
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveBigIntegerField()
    target = GenericForeignKey("content_type", "object_id")
    reason = models.CharField(max_length=32, choices=REASON_CHOICES)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            # Removed unique_report_per_user_target to allow re-reporting after clearing
        ]
        indexes = [
            models.Index(fields=["content_type", "object_id", "created_at"]),
            models.Index(fields=["reason", "created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Report({self.id}) {self.content_type_id}:{self.object_id} by {self.reporter_id}"


class ModerationAction(models.Model):
    ACTION_APPROVE = "approve"
    ACTION_SOFT_DELETE = "soft_delete"
    ACTION_EDIT = "edit"
    ACTION_AUTO_UNDER_REVIEW = "auto_under_review"

    ACTION_CHOICES = [
        (ACTION_APPROVE, "Approve"),
        (ACTION_SOFT_DELETE, "Soft delete"),
        (ACTION_EDIT, "Edit"),
        (ACTION_AUTO_UNDER_REVIEW, "Auto under review"),
    ]

    performed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="moderation_actions",
    )
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveBigIntegerField()
    target = GenericForeignKey("content_type", "object_id")
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)
    note = models.TextField(blank=True)
    meta = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["content_type", "object_id", "created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"ModerationAction({self.action}) {self.content_type_id}:{self.object_id}"


class ProfileReportMetadata(models.Model):
    """
    Additional metadata for profile reports.
    Linked to Report model for extended information.
    """
    report = models.OneToOneField(
        Report,
        on_delete=models.CASCADE,
        related_name="profile_metadata"
    )

    # For deceased reports
    relationship_to_deceased = models.CharField(
        max_length=100,
        blank=True,
        help_text="Relationship to the deceased person"
    )
    death_date = models.DateField(
        null=True,
        blank=True,
        help_text="Date of death if known"
    )
    obituary_url = models.URLField(
        blank=True,
        help_text="Link to obituary or death certificate"
    )

    # For impersonation reports
    impersonated_person_name = models.CharField(
        max_length=255,
        blank=True,
        help_text="Real name of person being impersonated"
    )
    proof_urls = models.JSONField(
        default=list,
        blank=True,
        help_text="URLs to evidence of impersonation"
    )

    # For correction requests
    correction_fields = models.JSONField(
        default=dict,
        blank=True,
        help_text="Fields that need correction: {field: correct_value}"
    )
    correction_reason = models.TextField(
        blank=True,
        help_text="Why these corrections are needed"
    )

    # For illegal content
    illegal_content_description = models.TextField(
        blank=True,
        help_text="Description of illegal content"
    )
    illegal_content_location = models.CharField(
        max_length=255,
        blank=True,
        help_text="Where on profile (bio, about, etc.)"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Profile Report Metadata"
        verbose_name_plural = "Profile Report Metadata"

    def __str__(self) -> str:
        return f"ProfileReportMetadata for Report#{self.report_id}"
