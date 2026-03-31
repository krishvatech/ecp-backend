"""
Courses API views.

Endpoints:
  GET  /api/courses/                     — Browse all synced Moodle courses
  GET  /api/courses/{id}/                — Course detail
  GET  /api/courses/categories/          — All categories
  GET  /api/courses/my-courses/          — Authenticated user's enrollments
  POST /api/courses/my-courses/refresh/  — Trigger enrollment re-sync for current user
  POST /api/courses/admin/sync/          — Admin: trigger full course + category sync
"""
import logging

from django.conf import settings
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.viewsets import ReadOnlyModelViewSet, ViewSet

from .models import MoodleCategory, MoodleCourse, MoodleEnrollment
from .serializers import (
    MoodleCategorySerializer,
    MoodleCourseSerializer,
    MoodleEnrollmentListSerializer,
    MoodleEnrollmentSerializer,
)
from .tasks import sync_moodle_courses_and_categories, sync_single_user_moodle_enrollments

logger = logging.getLogger(__name__)


class MoodleCourseViewSet(ReadOnlyModelViewSet):
    """Browse courses synced from Moodle LMS."""

    permission_classes = [IsAuthenticated]
    serializer_class = MoodleCourseSerializer

    def get_queryset(self):
        qs = MoodleCourse.objects.filter(is_visible=True).select_related("category")
        category = self.request.query_params.get("category")
        search = self.request.query_params.get("search")
        if category:
            qs = qs.filter(category__moodle_id=category)
        if search:
            qs = qs.filter(full_name__icontains=search)
        return qs

    @action(detail=False, methods=["get"], url_path="categories")
    def categories(self, request):
        """List all Moodle course categories."""
        cats = MoodleCategory.objects.all()
        serializer = MoodleCategorySerializer(cats, many=True)
        return Response(serializer.data)

    @action(
        detail=False,
        methods=["get"],
        url_path="my-courses",
        permission_classes=[IsAuthenticated],
    )
    def my_courses(self, request):
        """Return the authenticated user's Moodle enrollments."""
        enrollments = (
            MoodleEnrollment.objects.filter(user=request.user)
            .select_related("course", "course__category")
            .order_by("-synced_at")
        )
        serializer = MoodleEnrollmentListSerializer(enrollments, many=True)
        return Response(serializer.data)

    @action(
        detail=False,
        methods=["post"],
        url_path="my-courses/refresh",
        permission_classes=[IsAuthenticated],
    )
    def refresh_my_courses(self, request):
        """
        Trigger a Moodle enrollment sync for the current user.
        Queued as a Celery task — returns immediately.
        """
        sync_single_user_moodle_enrollments.delay(request.user.id)
        return Response(
            {"detail": "Enrollment sync queued. Refresh in a few seconds."},
            status=status.HTTP_202_ACCEPTED,
        )

    @action(
        detail=True,
        methods=["get"],
        url_path="launch",
        permission_classes=[IsAuthenticated],
    )
    def launch(self, request, pk=None):
        """
        Returns the direct LMS URL for a course.

        For users authenticated via WordPress/Edwiser Bridge, Moodle's
        WordPress SSO will auto-log them in when they follow this URL.
        For others, Moodle will show its login page first.
        """
        course = self.get_object()
        return Response({"url": course.course_url})

    @action(
        detail=False,
        methods=["post"],
        url_path="admin/sync",
        permission_classes=[IsAdminUser],
    )
    def admin_sync(self, request):
        """Admin-only: trigger a full Moodle course + category sync."""
        sync_moodle_courses_and_categories.delay()
        return Response(
            {"detail": "Full Moodle course sync queued."},
            status=status.HTTP_202_ACCEPTED,
        )
