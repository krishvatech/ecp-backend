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
from django.utils.text import slugify
from django.contrib.postgres.fields import ArrayField
from django.utils import timezone
from datetime import timedelta
import os, uuid

def user_profile_image(instance, filename):
    """
    Save preview images directly under:
      media_previews/event/<file>
    (No tmp/, no <id>/, no preview/ subfolder)
    """
    name, ext = os.path.splitext(filename or "")
    base = slugify(name) or "avatar"
    return f"avatars/{base}-{uuid.uuid4().hex[:8]}{ext.lower()}"

class UserProfile(models.Model):
    """Extension of Django's built-in User model."""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    full_name = models.CharField(max_length=255, blank=True)
    middle_name = models.CharField(max_length=150, blank=True, default="")
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
    user_image = models.ImageField(
        upload_to=user_profile_image,
        blank=True,
        null=True,
    )
    last_activity_at = models.DateTimeField(null=True, blank=True)
    # Online if active within last N minutes (tweak as you like)
    ONLINE_THRESHOLD = timedelta(minutes=2)

    @property
    def is_online(self):
        """
        True if user was active within the last ONLINE_THRESHOLD.
        """
        if not self.last_activity_at:
            return False
        return timezone.now() - self.last_activity_at <= self.ONLINE_THRESHOLD

    def __str__(self) -> str:
        return f"Profile<{self.user.username}>"

    class Meta:
        indexes = [
            models.Index(fields=["company"]),
            models.Index(fields=["location"]),
            models.Index(fields=["last_activity_at"]),
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
    exit_reason = models.TextField(blank=True, default="")
    sector = models.CharField(max_length=128, blank=True, default="")
    industry = models.CharField(max_length=128, blank=True, default="")
    number_of_employees = models.CharField(max_length=64, blank=True, default="")

    # ---------- NEW LINKEDIN-STYLE META FIELDS ----------
    EMPLOYMENT_TYPE_CHOICES = [
        ("full_time", "Full-time"),
        ("part_time", "Part-time"),
        ("self_employed", "Self-employment"),
        ("freelance", "Freelance"),
    ]
    WORK_SCHEDULE_CHOICES = [
        ("", "—"),
        ("full_time", "Full-time"),
        ("part_time", "Part-time"),
        ("internship", "Internship"),
    ]
    REL_TO_ORG_CHOICES = [
        ("", "—"),
        ("employee", "Employee (on payroll)"),
        ("independent", "Independent (self-employed / contractor / freelance)"),
        ("third_party", "Third-party (Agency/Consultancy/Temp)"),
    ]
    CAREER_STAGE_CHOICES = [
        ("", "—"),
        ("internship", "Internship"),
        ("apprenticeship", "Apprenticeship"),
        ("trainee", "Trainee / Entry program"),
        ("entry", "Entry level"),
        ("mid", "Mid level"),
        ("senior", "Senior level"),
    ]
    WORK_ARRANGEMENT_CHOICES = [
        ("", "—"),
        ("onsite", "On-site"),
        ("hybrid", "Hybrid"),
        ("remote", "Remote"),
    ]

    # One compulsory with a safe default:
    employment_type = models.CharField(
        max_length=32, choices=EMPLOYMENT_TYPE_CHOICES, default="full_time"
    )
    # All others optional (store "" when not chosen):
    work_schedule = models.CharField(
        max_length=32, choices=WORK_SCHEDULE_CHOICES, blank=True, default=""
    )
    relationship_to_org = models.CharField(
        max_length=32, choices=REL_TO_ORG_CHOICES, blank=True, default=""
    )
    career_stage = models.CharField(
        max_length=32, choices=CAREER_STAGE_CHOICES, blank=True, default=""
    )
    work_arrangement = models.CharField(
        max_length=32, choices=WORK_ARRANGEMENT_CHOICES, blank=True, default=""
    )
    # ----------------------------------------------------

    class Meta:
        ordering = ["-currently_work_here", "-end_date", "-start_date", "-id"]
        indexes = [
            models.Index(fields=["community_name"]),
            models.Index(fields=["position"]),
            models.Index(fields=["currently_work_here"]),
            # helpful when filtering by type:
            models.Index(fields=["employment_type"]),
        ]
        constraints = [
            # If not current, allow null or >= start; if current, end_date must be null
            models.CheckConstraint(
                check=(
                    Q(currently_work_here=True, end_date__isnull=True)
                    | (Q(currently_work_here=False) & (Q(end_date__isnull=True) | Q(end_date__gte=F("start_date"))))
                ),
                name="exp_dates_valid",
            ),
        ]

    def __str__(self):
        return f"{self.community_name} — {self.position}"
    
class NameChangeRequest(models.Model):
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"

    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="name_change_requests",
    )

    # current legal names (snapshot at time of request)
    old_first_name = models.CharField(max_length=150, blank=True, default="")
    old_middle_name = models.CharField(max_length=150, blank=True, default="")
    old_last_name = models.CharField(max_length=150, blank=True, default="")

    # requested new legal names
    new_first_name = models.CharField(max_length=150)
    new_middle_name = models.CharField(max_length=150, blank=True, default="")  # optional
    new_last_name = models.CharField(max_length=150)

    # reason: Marriage / Divorce / etc.
    reason = models.TextField()

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="processed_name_change_requests",
    )
    admin_note = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "status"]),
        ]

    def __str__(self) -> str:
        return f"NameChangeRequest<{self.user_id} {self.old_first_name} → {self.new_first_name}>"
