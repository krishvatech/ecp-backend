from rest_framework import serializers
from .models import MoodleCategory, MoodleCourse, MoodleEnrollment, CourseSection, CourseModule, ModuleCompletion


class MoodleCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = MoodleCategory
        fields = ["id", "moodle_id", "name", "parent_moodle_id", "course_count"]


class MoodleCourseSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source="category.name", read_only=True, default=None)
    course_url = serializers.SerializerMethodField()

    class Meta:
        model = MoodleCourse
        fields = [
            "id",
            "moodle_id",
            "short_name",
            "full_name",
            "summary",
            "category",
            "category_name",
            "image_url",
            "enrolled_user_count",
            "completion_enabled",
            "is_visible",
            "course_url",
            "synced_at",
        ]

    def get_course_url(self, obj):
        return obj.moodle_url


class MoodleEnrollmentSerializer(serializers.ModelSerializer):
    course = MoodleCourseSerializer(read_only=True)

    class Meta:
        model = MoodleEnrollment
        fields = [
            "id",
            "course",
            "moodle_user_id",
            "progress",
            "completed",
            "last_access",
            "synced_at",
        ]


class MoodleEnrollmentListSerializer(serializers.ModelSerializer):
    """Lighter serializer for list views — avoids heavy nested course data."""
    course_id = serializers.IntegerField(source="course.id")
    moodle_course_id = serializers.IntegerField(source="course.moodle_id")
    full_name = serializers.CharField(source="course.full_name")
    short_name = serializers.CharField(source="course.short_name")
    image_url = serializers.CharField(source="course.image_url")
    course_url = serializers.SerializerMethodField()
    category_name = serializers.CharField(source="course.category.name", default=None)

    class Meta:
        model = MoodleEnrollment
        fields = [
            "id",
            "course_id",
            "moodle_course_id",
            "full_name",
            "short_name",
            "image_url",
            "course_url",
            "category_name",
            "progress",
            "completed",
            "last_access",
            "synced_at",
        ]

    def get_course_url(self, obj):
        return obj.course.moodle_url


# ---------------------------------------------------------------------------
# Course content serializers
# ---------------------------------------------------------------------------

class CourseModuleSerializer(serializers.ModelSerializer):
    is_video = serializers.BooleanField(read_only=True)
    is_pdf = serializers.BooleanField(read_only=True)
    # completed is injected per-request (not stored in this serializer)
    completed = serializers.SerializerMethodField()

    class Meta:
        model = CourseModule
        fields = [
            "id",
            "moodle_module_id",
            "name",
            "modtype",
            "position",
            "visible",
            "module_url",
            "content_url",
            "content_filename",
            "content_mimetype",
            "content_filesize",
            "completion",
            "is_video",
            "is_pdf",
            "completed",
        ]

    def get_completed(self, obj):
        # completion_map is injected into context by the view
        completion_map = self.context.get("completion_map", {})
        return completion_map.get(obj.moodle_module_id, False)


class CourseSectionSerializer(serializers.ModelSerializer):
    modules = CourseModuleSerializer(many=True, read_only=True)

    class Meta:
        model = CourseSection
        fields = [
            "id",
            "moodle_section_id",
            "position",
            "name",
            "summary",
            "visible",
            "modules",
        ]

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        # Include all modules (locked ones shown with lock icon in frontend)
        # Only exclude pure label/text modules with no content
        modules_qs = instance.modules.exclude(modtype="label")
        ret["modules"] = CourseModuleSerializer(
            modules_qs, many=True, context=self.context
        ).data
        return ret
