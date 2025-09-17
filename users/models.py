"""
Models for the users app.

A `UserProfile` model extends the built-in `auth.User` with additional
fields.  A `OneToOneField` links each profile to its user.  The
`UserProfile` is created automatically via signals when a new user
instance is saved.
"""
from django.conf import settings
from django.db import models
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