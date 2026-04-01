from rest_framework import serializers
from .models import MoodleCategory, MoodleCourse, MoodleEnrollment


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
