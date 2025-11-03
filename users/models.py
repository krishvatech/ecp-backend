"""
Models for the users app.

A `UserProfile` model extends the built-in `auth.User` with additional
fields.  A `OneToOneField` links each profile to its user.  The
`UserProfile` is created automatically via signals when a new user
instance is saved.
"""
from django.conf import settings
from django.db import models
from django.db.models import Q, F
from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField

class UserProfile(models.Model):
    """Extension of Django's built-in User model."""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    full_name = models.CharField(max_length=255, blank=True)
    timezone = models.CharField(max_length=64, default="Asia/Kolkata")
    bio = models.TextField(blank=True)
    # new networking fields
    job_title = models.CharField(max_length=255, blank=True)
    company = models.CharField(max_length=255, blank=True)
    location = models.CharField(max_length=255, blank=True)
    headline = models.CharField(max_length=255, blank=True)
    skills = ArrayField(
        models.CharField(max_length=50),
        default=list,
        blank=True,
        help_text="List of user skills",
    )
    links = models.JSONField(default=dict, blank=True, help_text="External profile links")

    def __str__(self) -> str:
        return f"Profile<{self.user.username}>"

    class Meta:
        indexes = [
            models.Index(fields=["company"]),
            models.Index(fields=["location"]),
        ]
    
    
class LinkedInAccount(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="linkedin")
    linkedin_id = models.CharField(max_length=64, unique=True)
    access_token = models.TextField()
    refresh_token = models.TextField(blank=True, default="")  # LinkedIn may issue or not; handle nulls
    expires_at = models.DateTimeField(null=True, blank=True)
    raw_profile_json = models.JSONField(default=dict, blank=True)
    email = models.EmailField(blank=True, default="")
    headline = models.CharField(max_length=255, blank=True, default="")
    picture_url = models.URLField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Education(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="educations"
    )
    school = models.CharField(max_length=255)
    degree = models.CharField(max_length=255)
    field_of_study = models.CharField(max_length=255, blank=True, default="")
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    grade = models.CharField(max_length=64, blank=True, default="")
    description = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-end_date", "-start_date", "-id"]
        indexes = [
            models.Index(fields=["school"]),
            models.Index(fields=["degree"]),
            models.Index(fields=["field_of_study"]),
        ]
        constraints = [
            # If both dates present, end_date must be >= start_date
            models.CheckConstraint(
                check=Q(end_date__isnull=True) | Q(start_date__isnull=True) | Q(end_date__gte=F("start_date")),
                name="edu_end_after_start",
            ),
        ]

    def __str__(self):
        return f"{self.school} — {self.degree}"


class Experience(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="experiences"
    )
    # If you want to tie to your community table, uncomment the FK and keep the text fallback.
    # community = models.ForeignKey(Community, null=True, blank=True, on_delete=models.SET_NULL, related_name="experiences")
    community_name = models.CharField(max_length=255)
    position = models.CharField(max_length=255)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    currently_work_here = models.BooleanField(default=False)
    location = models.CharField(max_length=255, blank=True, default="")
    description = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-currently_work_here", "-end_date", "-start_date", "-id"]
        indexes = [
            models.Index(fields=["community_name"]),
            models.Index(fields=["position"]),
            models.Index(fields=["currently_work_here"]),
        ]
        constraints = [
            # If not current, allow null or >= start; if current, end_date must be null
            models.CheckConstraint(
                check=Q(currently_work_here=True, end_date__isnull=True) |
                      Q(currently_work_here=False) & (Q(end_date__isnull=True) | Q(end_date__gte=F("start_date"))),
                name="exp_dates_valid",
            ),
        ]

    def __str__(self):
        return f"{self.community_name} — {self.position}"