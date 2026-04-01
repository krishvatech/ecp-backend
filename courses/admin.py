from django.contrib import admin
from .models import MoodleCategory, MoodleCourse, MoodleEnrollment


@admin.register(MoodleCategory)
class MoodleCategoryAdmin(admin.ModelAdmin):
    list_display = ["name", "moodle_id", "parent_moodle_id", "course_count", "synced_at"]
    search_fields = ["name"]
    ordering = ["name"]
    readonly_fields = ["synced_at"]


@admin.register(MoodleCourse)
class MoodleCourseAdmin(admin.ModelAdmin):
    list_display = [
        "full_name", "short_name", "moodle_id", "category",
        "enrolled_user_count", "completion_enabled", "is_visible", "synced_at",
    ]
    list_filter = ["is_visible", "completion_enabled", "category"]
    search_fields = ["full_name", "short_name"]
    readonly_fields = ["synced_at", "moodle_url"]
    ordering = ["full_name"]


@admin.register(MoodleEnrollment)
class MoodleEnrollmentAdmin(admin.ModelAdmin):
    list_display = [
        "user", "course", "progress", "completed", "last_access", "synced_at",
    ]
    list_filter = ["completed", "course__category"]
    search_fields = ["user__email", "course__full_name"]
    readonly_fields = ["synced_at"]
    raw_id_fields = ["user", "course"]
