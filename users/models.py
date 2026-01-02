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

    KYC_STATUS_NOT_STARTED = "not_started"
    KYC_STATUS_PENDING = "pending"
    KYC_STATUS_APPROVED = "approved"
    KYC_STATUS_DECLINED = "declined"
    KYC_STATUS_REVIEW = "review"

    KYC_STATUS_CHOICES = [
        (KYC_STATUS_NOT_STARTED, "Not started"),
        (KYC_STATUS_PENDING, "Pending"),
        (KYC_STATUS_APPROVED, "Approved"),
        (KYC_STATUS_DECLINED, "Declined"),
        (KYC_STATUS_REVIEW, "In review"),
    ]

    KYC_DECLINE_REASON_NAME_MISMATCH = "name_mismatch"
    KYC_DECLINE_REASON_OTHER = "other"

    KYC_DECLINE_REASON_CHOICES = [
        (KYC_DECLINE_REASON_NAME_MISMATCH, "Name on document does not match sign-up name"),
        (KYC_DECLINE_REASON_OTHER, "Other"),
    ]

    kyc_status = models.CharField(
        max_length=20,
        choices=KYC_STATUS_CHOICES,
        default=KYC_STATUS_NOT_STARTED,
    )
    kyc_decline_reason = models.CharField(
        max_length=32,
        choices=KYC_DECLINE_REASON_CHOICES,
        blank=True,
        null=True,
    )
    kyc_last_session_id = models.CharField(max_length=128, blank=True, default="")
    legal_name_locked = models.BooleanField(default=False)
    legal_name_verified_at = models.DateTimeField(null=True, blank=True)

        # --- Didit payload storage (Initial KYC webhook) ---
    kyc_didit_raw_payload = models.JSONField(default=dict, blank=True)
    kyc_didit_last_webhook_at = models.DateTimeField(null=True, blank=True)


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
    
class EscoSkill(models.Model):
    """
    Local cache of an ESCO skill concept.
    We store the ESCO URI as the primary key so it never changes.
    """
    uri = models.CharField(max_length=255, primary_key=True)
    preferred_label = models.CharField(max_length=255)
    alt_labels = ArrayField(
        models.CharField(max_length=255),
        default=list,
        blank=True,
        help_text="Alternative labels from ESCO",
    )
    description = models.TextField(blank=True, default="")
    skill_type = models.CharField(
        max_length=32,
        blank=True,
        default="",
        help_text="K, S, L, T or similar ESCO classification",
    )
    esco_version = models.CharField(
        max_length=20,
        blank=True,
        default="",
        help_text="ESCO version string, e.g. v1.2.0",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["preferred_label"]),
        ]

    def __str__(self) -> str:
        return f"{self.preferred_label} ({self.uri})"

class UserSkill(models.Model):
    """
    Structured user skill linked to ESCO.
    This is the 'new' skills system.
    """
    ASSESSMENT_SELF = "self"
    ASSESSMENT_VERIFIED = "verified"
    ASSESSMENT_TEST = "test"

    ASSESSMENT_CHOICES = [
        (ASSESSMENT_SELF, "Self-assessed"),
        (ASSESSMENT_VERIFIED, "Verified (manual/admin)"),
        (ASSESSMENT_TEST, "Verified via test"),
    ]

    # If you prefer: use settings.AUTH_USER_MODEL
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="user_skills",
    )
    skill = models.ForeignKey(
        EscoSkill,
        on_delete=models.CASCADE,
        related_name="user_skills",
    )

    # 1–5 internal scale (Beginner → Expert)
    proficiency_level = models.PositiveSmallIntegerField(
        default=1,
        help_text="1=Beginner, 2=Basic, 3=Intermediate, 4=Advanced, 5=Expert",
    )
    assessment_type = models.CharField(
        max_length=16,
        choices=ASSESSMENT_CHOICES,
        default=ASSESSMENT_SELF,
    )
    notes = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "skill")
        ordering = ["-proficiency_level", "-updated_at"]
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["proficiency_level"]),
        ]

    def __str__(self):
        return f"{self.user_id} – {self.skill.preferred_label} (L{self.proficiency_level})"


def language_certificate_path(instance, filename):
    import os, uuid
    from django.utils.text import slugify
    name, ext = os.path.splitext(filename or "")
    base = slugify(name) or "certificate"
    # keep it simple & consistent with your media style
    return f"language_certificates/{base}-{uuid.uuid4().hex[:8]}{ext.lower()}"

class IsoLanguage(models.Model):
    """
    Local cache of ISO language master.
    Mirrors EscoSkill idea but for ISO codes.
    """
    iso_639_1 = models.CharField(max_length=2, primary_key=True)
    iso_639_3 = models.CharField(max_length=3, blank=True, default="")
    english_name = models.CharField(max_length=255)
    native_name = models.CharField(max_length=255, blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["english_name"]),
            models.Index(fields=["native_name"]),
        ]

    def __str__(self):
        return f"{self.english_name} ({self.iso_639_1})"

class GeoCity(models.Model):
    """
    Offline GeoNames city master (from cities15000.txt).
    We keep it separate so Profile/Experience can still store location as string.
    """
    geoname_id = models.BigIntegerField(primary_key=True)
    name = models.CharField(max_length=255)
    ascii_name = models.CharField(max_length=255, blank=True, default="")

    country_code = models.CharField(max_length=2, db_index=True)
    admin1_code = models.CharField(max_length=20, blank=True, default="", db_index=True)
    admin2_code = models.CharField(max_length=80, blank=True, default="")

    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)

    feature_class = models.CharField(max_length=1, blank=True, default="")
    feature_code = models.CharField(max_length=10, blank=True, default="")

    population = models.BigIntegerField(default=0, db_index=True)
    timezone = models.CharField(max_length=64, blank=True, default="")
    modified_at = models.DateField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["ascii_name"]),
            models.Index(fields=["country_code", "population"]),
        ]

    def __str__(self):
        return f"{self.name}, {self.country_code}"

class GeoCountry(models.Model):
    iso2 = models.CharField(max_length=2, unique=True, db_index=True)  # e.g. IN
    iso3 = models.CharField(max_length=3, blank=True, default="")      # e.g. IND
    name = models.CharField(max_length=200)                            # e.g. India

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.iso2})"

class UserLanguage(models.Model):
    """
    Structured user language linked to ISO master.
    """

    # Assessment same style as UserSkill
    ASSESSMENT_SELF = "self"
    ASSESSMENT_VERIFIED = "verified"
    ASSESSMENT_TEST = "test"
    ASSESSMENT_CHOICES = [
        (ASSESSMENT_SELF, "Self-assessed"),
        (ASSESSMENT_VERIFIED, "Verified (manual/admin)"),
        (ASSESSMENT_TEST, "Verified via test"),
    ]

    # CEFR
    CEFR_A1 = "A1"
    CEFR_A2 = "A2"
    CEFR_B1 = "B1"
    CEFR_B2 = "B2"
    CEFR_C1 = "C1"
    CEFR_C2 = "C2"
    CEFR_CHOICES = [
        (CEFR_A1, "Beginner Proficiency (A1)"),
        (CEFR_A2, "Elementary Proficiency (A2)"),
        (CEFR_B1, "Limited Working Proficiency (B1)"),
        (CEFR_B2, "Professional Working Proficiency (B2)"),
        (CEFR_C1, "Full Professional Proficiency (C1)"),
        (CEFR_C2, "Native or Bilingual Proficiency (C2)"),
    ]

    # Acquisition Context (from PPT)
    ACQ_MOTHER = "mother_tongue"
    ACQ_FORMAL = "formal_education"
    ACQ_PRO = "professional_immersion"
    ACQ_SELF = "self_taught"
    ACQ_CHOICES = [
        (ACQ_MOTHER, "Mother Tongue"),
        (ACQ_FORMAL, "Formal Education"),
        (ACQ_PRO, "Professional Immersion"),
        (ACQ_SELF, "Self-Taught"),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="user_languages",
    )
    language = models.ForeignKey(
        IsoLanguage,
        on_delete=models.CASCADE,
        related_name="user_languages",
    )

    # "Primary Dialect" - keep flexible
    primary_dialect = models.CharField(
        max_length=32,
        blank=True,
        default="",
        help_text="Optional dialect/variant (e.g., ISO 639-3 or BCP-47 tag).",
    )

    proficiency_cefr = models.CharField(max_length=2, choices=CEFR_CHOICES)
    acquisition_context = models.CharField(
        max_length=32, choices=ACQ_CHOICES, blank=True, default=""
    )

    assessment_type = models.CharField(
        max_length=16,
        choices=ASSESSMENT_CHOICES,
        default=ASSESSMENT_SELF,
    )
    notes = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "language", "primary_dialect")
        ordering = ["-proficiency_cefr", "-updated_at"]
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["proficiency_cefr"]),
        ]

    def __str__(self):
        return f"{self.user_id} – {self.language.english_name} ({self.proficiency_cefr})"


class LanguageCertificate(models.Model):
    """
    Certificates or test results for a user language.
    """
    user_language = models.ForeignKey(
        UserLanguage,
        on_delete=models.CASCADE,
        related_name="certificates",
    )
    file = models.FileField(upload_to=language_certificate_path)
    filename = models.CharField(max_length=255, blank=True, default="")

    test_name = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="IELTS/TOEFL/DEGREE/OTHER etc.",
    )
    score = models.CharField(max_length=64, blank=True, default="")
    verified = models.BooleanField(default=False)

    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["uploaded_at"]),
        ]

    def save(self, *args, **kwargs):
        if self.file and not self.filename:
            try:
                self.filename = self.file.name
            except Exception:
                pass
        super().save(*args, **kwargs)
    
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

    DIDIT_STATUS_NOT_STARTED = "not_started"
    DIDIT_STATUS_PENDING = "pending"
    DIDIT_STATUS_APPROVED = "approved"
    DIDIT_STATUS_DECLINED = "declined"
    DIDIT_STATUS_REVIEW = "review"

    DIDIT_STATUS_CHOICES = [
        (DIDIT_STATUS_NOT_STARTED, "Not started"),
        (DIDIT_STATUS_PENDING, "Pending"),
        (DIDIT_STATUS_APPROVED, "Approved"),
        (DIDIT_STATUS_DECLINED, "Declined"),
        (DIDIT_STATUS_REVIEW, "In review"),
    ]

    didit_session_id = models.CharField(max_length=128, blank=True, default="")
    didit_status = models.CharField(
        max_length=20,
        choices=DIDIT_STATUS_CHOICES,
        default=DIDIT_STATUS_NOT_STARTED,
    )
    didit_raw_payload = models.JSONField(default=dict, blank=True)
    # --- extracted names from Didit document (for admin review) ---
    doc_full_name = models.CharField(max_length=255, blank=True, default="")
    doc_first_name = models.CharField(max_length=150, blank=True, default="")
    doc_last_name = models.CharField(max_length=150, blank=True, default="")

    # --- auto-approval + debug ---
    name_match_passed = models.BooleanField(default=False)
    name_match_debug = models.JSONField(default=dict, blank=True)
    auto_approved = models.BooleanField(default=False)



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


def education_document_path(instance, filename):
    name, ext = os.path.splitext(filename)
    # Upload to: education_docs/user_<id>/<random_id>.<ext>
    return f"education_docs/user_{instance.education.user.id}/{uuid.uuid4().hex[:8]}{ext}"

class EducationDocument(models.Model):
    education = models.ForeignKey(
        Education, on_delete=models.CASCADE, related_name="documents"
    )
    file = models.FileField(upload_to=education_document_path)
    filename = models.CharField(max_length=255, blank=True) # To store original filename
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Auto-save original filename if not set
        if self.file and not self.filename:
            self.filename = os.path.basename(self.file.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Doc for {self.education}: {self.filename}"
    

# --- NEW: Profile Sections (Trainings, Certifications, Memberships) ---

class ProfileTraining(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="trainings"
    )

    program_title = models.CharField(max_length=255)
    provider = models.CharField(max_length=255)

    start_date = models.DateField(null=True, blank=True)  # store as YYYY-MM-01
    end_date = models.DateField(null=True, blank=True)    # store as YYYY-MM-01
    currently_ongoing = models.BooleanField(default=False)

    description = models.TextField(blank=True, default="")
    credential_url = models.URLField(blank=True, default="")

    class Meta:
        ordering = ["-currently_ongoing", "-end_date", "-start_date", "-id"]
        indexes = [
            models.Index(fields=["provider"]),
            models.Index(fields=["program_title"]),
            models.Index(fields=["start_date"]),
            models.Index(fields=["end_date"]),
        ]
        constraints = [
            models.CheckConstraint(
                check=Q(end_date__isnull=True) | Q(start_date__isnull=True) | Q(end_date__gte=F("start_date")),
                name="training_end_after_start",
            ),
            models.CheckConstraint(
                check=Q(currently_ongoing=False) | Q(end_date__isnull=True),
                name="training_end_null_when_ongoing",
            ),
        ]

    def __str__(self):
        return f"{self.program_title} — {self.provider}"


class ProfileCertification(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="certifications"
    )

    certification_name = models.CharField(max_length=255)
    issuing_organization = models.CharField(max_length=255)

    issue_date = models.DateField(null=True, blank=True)         # YYYY-MM-01
    expiration_date = models.DateField(null=True, blank=True)    # YYYY-MM-01
    no_expiration = models.BooleanField(default=False)

    credential_id = models.CharField(max_length=128, blank=True, default="")
    credential_url = models.URLField(blank=True, default="")

    class Meta:
        ordering = ["-issue_date", "-id"]
        indexes = [
            models.Index(fields=["issuing_organization"]),
            models.Index(fields=["certification_name"]),
            models.Index(fields=["issue_date"]),
        ]
        constraints = [
            models.CheckConstraint(
                check=Q(no_expiration=False) | Q(expiration_date__isnull=True),
                name="cert_exp_null_when_no_expiration",
            ),
            models.CheckConstraint(
                check=Q(expiration_date__isnull=True) | Q(issue_date__isnull=True) | Q(expiration_date__gte=F("issue_date")),
                name="cert_exp_after_issue",
            ),
        ]

    def __str__(self):
        return f"{self.certification_name} — {self.issuing_organization}"


class ProfileMembership(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships"
    )

    organization_name = models.CharField(max_length=255)
    role_type = models.CharField(max_length=100, blank=True, default="")  # Member/Admin/Volunteer/Fellow

    start_date = models.DateField(null=True, blank=True)  # YYYY-MM-01
    end_date = models.DateField(null=True, blank=True)    # YYYY-MM-01
    ongoing = models.BooleanField(default=False)

    membership_url = models.URLField(blank=True, default="")

    class Meta:
        ordering = ["-ongoing", "-end_date", "-start_date", "-id"]
        indexes = [
            models.Index(fields=["organization_name"]),
            models.Index(fields=["start_date"]),
            models.Index(fields=["end_date"]),
        ]
        constraints = [
            models.CheckConstraint(
                check=Q(end_date__isnull=True) | Q(start_date__isnull=True) | Q(end_date__gte=F("start_date")),
                name="membership_end_after_start",
            ),
            models.CheckConstraint(
                check=Q(ongoing=False) | Q(end_date__isnull=True),
                name="membership_end_null_when_ongoing",
            ),
        ]

    def __str__(self):
        return f"{self.organization_name} ({self.role_type})"

class CognitoIdentity(models.Model):
    """
    Maps Cognito 'sub' -> a single Django User.
    This prevents duplicates when Cognito username changes by provider (Google_xxx / LinkedIn_xxx).
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="cognito_identities")

    cognito_sub = models.CharField(max_length=128, unique=True, db_index=True)

    email = models.EmailField(blank=True, default="")
    email_verified = models.BooleanField(default=False)

    provider = models.CharField(max_length=32, blank=True, default="cognito")  # optional

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.provider}:{self.cognito_sub} -> user_id={self.user_id}"