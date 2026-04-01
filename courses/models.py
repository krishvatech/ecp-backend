"""
Courses app models — caches Moodle LMS data locally.

MoodleCategory   → course categories synced from Moodle
MoodleCourse     → course catalogue synced from Moodle
MoodleEnrollment → per-user enrollment + progress, synced from Moodle
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
