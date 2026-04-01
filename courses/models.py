"""
Courses app models — caches Moodle LMS data locally.

MoodleCategory   → course categories synced from Moodle/EB
MoodleCourse     → course catalogue synced from Moodle/EB
MoodleEnrollment → per-user enrollment + progress, synced from EB
CourseSection    → course sections (weeks/topics) synced from Moodle REST API
CourseModule     → individual activities/resources inside a section
ModuleCompletion → per-user per-module completion status
"""
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class MoodleCategory(models.Model):
    moodle_id = models.IntegerField(unique=True)
    name = models.CharField(max_length=500)
    parent_moodle_id = models.IntegerField(null=True, blank=True)
    course_count = models.IntegerField(default=0)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "Moodle Category"
        verbose_name_plural = "Moodle Categories"

    def __str__(self):
        return self.name


class MoodleCourse(models.Model):
    moodle_id = models.IntegerField(unique=True)
    short_name = models.CharField(max_length=255)
    full_name = models.CharField(max_length=500)
    summary = models.TextField(blank=True)
    category = models.ForeignKey(
        MoodleCategory,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="courses",
    )
    image_url = models.URLField(max_length=1000, blank=True)
    enrolled_user_count = models.IntegerField(default=0)
    completion_enabled = models.BooleanField(default=False)
    is_visible = models.BooleanField(default=True)
    moodle_url = models.URLField(max_length=1000, blank=True)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["full_name"]
        verbose_name = "Moodle Course"
        verbose_name_plural = "Moodle Courses"

    def __str__(self):
        return self.full_name



class MoodleEnrollment(models.Model):
    """Tracks a single user's enrollment + progress in one Moodle course."""

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="moodle_enrollments",
    )
    course = models.ForeignKey(
        MoodleCourse,
        on_delete=models.CASCADE,
        related_name="enrollments",
    )
    moodle_user_id = models.IntegerField()
    progress = models.FloatField(default=0.0, help_text="Completion percentage 0–100")
    completed = models.BooleanField(default=False)
    last_access = models.DateTimeField(null=True, blank=True)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "course")
        ordering = ["-synced_at"]
        verbose_name = "Moodle Enrollment"
        verbose_name_plural = "Moodle Enrollments"

    def __str__(self):
        return f"{self.user.email} → {self.course.full_name} ({self.progress:.0f}%)"


# ---------------------------------------------------------------------------
# Course content models (synced from Moodle REST API)
# ---------------------------------------------------------------------------

class CourseSection(models.Model):
    """
    A section (week/topic/chapter) inside a Moodle course.
    Moodle organises courses into sections; each section contains modules.
    """
    course = models.ForeignKey(
        MoodleCourse,
        on_delete=models.CASCADE,
        related_name="sections",
    )
    moodle_section_id = models.IntegerField()          # Moodle section.id
    position = models.IntegerField(default=0)          # section number (0-based)
    name = models.CharField(max_length=500, blank=True)
    summary = models.TextField(blank=True)
    visible = models.BooleanField(default=True)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("course", "moodle_section_id")
        ordering = ["position"]
        verbose_name = "Course Section"
        verbose_name_plural = "Course Sections"

    def __str__(self):
        return f"{self.course.full_name} / {self.name or f'Section {self.position}'}"


class CourseModule(models.Model):
    """
    A single activity or resource inside a course section.
    modtype maps to Moodle's modname: resource, url, page, quiz, hvp, label, assign, folder.
    """
    MODULE_TYPES = [
        ("resource", "File/Resource"),
        ("url", "URL"),
        ("page", "Page"),
        ("quiz", "Quiz"),
        ("hvp", "H5P Interactive"),
        ("label", "Label/Text"),
        ("assign", "Assignment"),
        ("folder", "Folder"),
        ("forum", "Forum"),
        ("other", "Other"),
    ]

    section = models.ForeignKey(
        CourseSection,
        on_delete=models.CASCADE,
        related_name="modules",
    )
    moodle_module_id = models.IntegerField(unique=True)   # Moodle cmid (course module id)
    name = models.CharField(max_length=500)
    modtype = models.CharField(max_length=50, choices=MODULE_TYPES, default="other")
    position = models.IntegerField(default=0)
    visible = models.BooleanField(default=True)

    # The URL to access this module on the Moodle site
    module_url = models.URLField(max_length=2000, blank=True)

    # For video/file resources: direct download/stream URL (requires token)
    content_url = models.URLField(max_length=2000, blank=True)
    content_filename = models.CharField(max_length=500, blank=True)
    content_mimetype = models.CharField(max_length=200, blank=True)
    content_filesize = models.BigIntegerField(null=True, blank=True)

    # Completion tracking type: 0=none, 1=manual, 2=automatic
    completion = models.IntegerField(default=0)

    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["position"]
        verbose_name = "Course Module"
        verbose_name_plural = "Course Modules"

    def __str__(self):
        return f"{self.section} / {self.name} ({self.modtype})"

    @property
    def is_video(self):
        return self.content_mimetype.startswith("video/") if self.content_mimetype else False

    @property
    def is_pdf(self):
        return self.content_mimetype == "application/pdf" if self.content_mimetype else False


class ModuleCompletion(models.Model):
    """Per-user per-module completion status, synced from Moodle."""
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="module_completions",
    )
    module = models.ForeignKey(
        CourseModule,
        on_delete=models.CASCADE,
        related_name="completions",
    )
    completed = models.BooleanField(default=False)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "module")
        verbose_name = "Module Completion"
        verbose_name_plural = "Module Completions"

    def __str__(self):
        status = "✓" if self.completed else "○"
        return f"{status} {self.user.email} — {self.module.name}"
