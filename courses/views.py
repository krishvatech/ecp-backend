"""
Courses API views.

Every endpoint hits the Edwiser Bridge API (imaa-institute.org/wp-json) live on
each request. If the API is unavailable or returns no data, the response falls
back to the locally cached database (kept warm by background Celery tasks).

Endpoints:
  GET  /api/courses/                     — All visible courses
  GET  /api/courses/{id}/                — Course detail
  GET  /api/courses/categories/          — All categories
  GET  /api/courses/my-courses/          — Authenticated user's enrollments
  POST /api/courses/my-courses/refresh/  — Trigger background enrollment re-sync
  GET  /api/courses/{id}/launch          — Direct LMS URL for a course
  POST /api/courses/admin/sync/          — Admin: trigger full background sync
"""
import logging
from html import unescape

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.viewsets import ReadOnlyModelViewSet

from .edwiser_api import get_edwiser_client
from .models import MoodleCategory, MoodleCourse, MoodleEnrollment
from .serializers import (
    MoodleCategorySerializer,
    MoodleCourseSerializer,
    MoodleEnrollmentListSerializer,
)
from .tasks import sync_moodle_courses_and_categories, sync_single_user_moodle_enrollments

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers: map raw Edwiser Bridge API dicts → serializer-compatible dicts
# ---------------------------------------------------------------------------

def _eb_course_to_dict(course: dict) -> dict:
    """Map an EB API course object to the MoodleCourseSerializer output shape."""
    cats = course.get("categories") or []
    return {
        "id": None,
        "moodle_id": course.get("id"),
        "short_name": unescape(course.get("title") or ""),
        "full_name": unescape(course.get("title") or ""),
        "summary": unescape(course.get("excerpt") or ""),
        "category": cats[0].get("id") if cats else None,
        "category_name": unescape(cats[0].get("name") or "") if cats else None,
        "image_url": course.get("thumbnail") or "",
        "enrolled_user_count": 0,
        "completion_enabled": False,
        "is_visible": not bool(course.get("suspended", False)),
        "course_url": course.get("link") or "",
        "synced_at": None,
        "source": "live",
    }


def _eb_category_to_dict(cat: dict) -> dict:
    """Map an EB API category object to the MoodleCategorySerializer output shape."""
    return {
        "id": None,
        "moodle_id": cat.get("id"),
        "name": unescape(cat.get("name") or ""),
        "parent_moodle_id": None,
        "course_count": cat.get("count") or 0,
        "source": "live",
    }


def _eb_enrollment_to_dict(ec: dict) -> dict:
    """Map an EB API enrolled-course object to the MoodleEnrollmentListSerializer output shape."""
    progress_data = ec.get("progress") or {}
    cats = ec.get("categories") or []
    percentage = float(progress_data.get("percentage") or 0.0)
    return {
        "id": None,
        "course_id": None,
        "moodle_course_id": ec.get("id"),
        "full_name": unescape(ec.get("title") or ""),
        "short_name": unescape(ec.get("title") or ""),
        "image_url": ec.get("thumbnail") or "",
        "course_url": ec.get("link") or progress_data.get("course_url") or "",
        "category_name": unescape(cats[0].get("name") or "") if cats else None,
        "progress": percentage,
        "completed": bool(progress_data.get("completed") or percentage >= 100.0),
        "last_access": None,
        "synced_at": None,
        "source": "live",
    }


# ---------------------------------------------------------------------------
# ViewSet
# ---------------------------------------------------------------------------

class MoodleCourseViewSet(ReadOnlyModelViewSet):
    """
    All reads attempt a live call to the Edwiser Bridge API.
    DB is used as fallback when the API is unavailable.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = MoodleCourseSerializer

    def get_queryset(self):
        """DB fallback queryset — used only when the live API is unavailable."""
        qs = MoodleCourse.objects.filter(is_visible=True).select_related("category")
        category = self.request.query_params.get("category")
        search = self.request.query_params.get("search")
        if category:
            qs = qs.filter(category__moodle_id=category)
        if search:
            qs = qs.filter(full_name__icontains=search)
        return qs

    # ------------------------------------------------------------------
    # Course list  —  GET /api/courses/
    # ------------------------------------------------------------------

    def list(self, request, *args, **kwargs):
        category = request.query_params.get("category")
        search = request.query_params.get("search")

        try:
            client = get_edwiser_client()
            data = client.get_all_courses()
            courses = data.get("courses") or []
        except Exception as exc:
            logger.warning("EB API unavailable for course list: %s", exc)
            courses = []

        if courses:
            # DEBUG — print raw first course to see all field names from EB API
            import json
            print("[DEBUG] RAW first course from EB API:")
            print(json.dumps(courses[0], indent=2, default=str))
            logger.debug("[DEBUG] RAW first course from EB API: %s", json.dumps(courses[0], default=str))

            # Filter visible courses
            courses = [c for c in courses if not c.get("suspended", False)]

            if category:
                try:
                    cat_id = int(category)
                    courses = [
                        c for c in courses
                        if any(cat.get("id") == cat_id for cat in (c.get("categories") or []))
                    ]
                except (ValueError, TypeError):
                    pass

            if search:
                q = search.lower()
                courses = [c for c in courses if q in (c.get("title") or "").lower()]

            return Response([_eb_course_to_dict(c) for c in courses])

        # Fallback — DB cache
        logger.warning("Falling back to DB for course list (EB API returned no data)")
        qs = self.get_queryset()
        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)

    # ------------------------------------------------------------------
    # Course detail  —  GET /api/courses/{id}/
    # ------------------------------------------------------------------

    def retrieve(self, request, *args, **kwargs):
        # Always fetch from DB first to resolve moodle_id and enforce permissions
        instance = self.get_object()

        try:
            client = get_edwiser_client()
            course = client.get_course(instance.moodle_id)
        except Exception as exc:
            logger.warning("EB API unavailable for course %s: %s", instance.moodle_id, exc)
            course = None

        if course:
            return Response(_eb_course_to_dict(course))

        # Fallback — DB cache
        logger.warning("Falling back to DB for course %s", instance.moodle_id)
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    # ------------------------------------------------------------------
    # Categories  —  GET /api/courses/categories/
    # ------------------------------------------------------------------

    @action(detail=False, methods=["get"], url_path="categories")
    def categories(self, request):
        try:
            client = get_edwiser_client()
            data = client.get_all_courses()
            cats = data.get("categories") or []
        except Exception as exc:
            logger.warning("EB API unavailable for categories: %s", exc)
            cats = []

        if cats:
            return Response([_eb_category_to_dict(c) for c in cats])

        # Fallback — DB cache
        logger.warning("Falling back to DB for categories (EB API returned no data)")
        serializer = MoodleCategorySerializer(MoodleCategory.objects.all(), many=True)
        return Response(serializer.data)

    # ------------------------------------------------------------------
    # My courses  —  GET /api/courses/my-courses/
    # ------------------------------------------------------------------

    @action(
        detail=False,
        methods=["get"],
        url_path="my-courses",
        permission_classes=[IsAuthenticated],
    )
    def my_courses(self, request):
        user = request.user

        # Get cached EB WordPress user ID
        eb_wp_user_id = None
        try:
            eb_wp_user_id = user.profile.moodle_user_id
        except Exception:
            pass

        try:
            client = get_edwiser_client()

            # Look up the user on imaa-institute.org if not cached
            if not eb_wp_user_id:
                eb_wp_user_id = client.get_user_id_by_email(user.email)
                if eb_wp_user_id:
                    try:
                        user.profile.moodle_user_id = eb_wp_user_id
                        user.profile.save(update_fields=["moodle_user_id"])
                    except Exception:
                        pass

            if eb_wp_user_id:
                eb_enrollments = client.get_user_courses(eb_wp_user_id)

                # DEBUG — print raw first enrollment to see all field names from EB API
                if eb_enrollments:
                    import json
                    print("[DEBUG] RAW first enrolled course from EB API:")
                    print(json.dumps(eb_enrollments[0], indent=2, default=str))
                    logger.debug("[DEBUG] RAW first enrolled course from EB API: %s", json.dumps(eb_enrollments[0], default=str))

                return Response([_eb_enrollment_to_dict(e) for e in eb_enrollments])

        except Exception as exc:
            logger.warning("EB API unavailable for my-courses (user %s): %s", user.email, exc)

        # Fallback — DB cache
        logger.warning("Falling back to DB for my-courses (user %s)", user.email)
        enrollments = (
            MoodleEnrollment.objects.filter(user=user)
            .select_related("course", "course__category")
            .order_by("-synced_at")
        )
        serializer = MoodleEnrollmentListSerializer(enrollments, many=True)
        return Response(serializer.data)

    # ------------------------------------------------------------------
    # Refresh enrollments  —  POST /api/courses/my-courses/refresh/
    # ------------------------------------------------------------------

    @action(
        detail=False,
        methods=["post"],
        url_path="my-courses/refresh",
        permission_classes=[IsAuthenticated],
    )
    def refresh_my_courses(self, request):
        """Queue a background enrollment sync for the current user."""
        sync_single_user_moodle_enrollments.delay(request.user.id)
        return Response(
            {"detail": "Enrollment sync queued. Refresh in a few seconds."},
            status=status.HTTP_202_ACCEPTED,
        )

    # ------------------------------------------------------------------
    # Launch  —  GET /api/courses/{id}/launch
    # ------------------------------------------------------------------

    @action(
        detail=True,
        methods=["get"],
        url_path="launch",
        permission_classes=[IsAuthenticated],
    )
    def launch(self, request, pk=None):
        """
        Returns the direct LMS URL for a course.
        WordPress SSO will auto-log users in when they follow this URL.
        """
        course = self.get_object()
        return Response({"url": course.moodle_url})

    # ------------------------------------------------------------------
    # Admin sync  —  POST /api/courses/admin/sync/
    # ------------------------------------------------------------------

    @action(
        detail=False,
        methods=["post"],
        url_path="admin/sync",
        permission_classes=[IsAdminUser],
    )
    def admin_sync(self, request):
        """Admin-only: trigger a full course + category sync in the background."""
        sync_moodle_courses_and_categories.delay()
        return Response(
            {"detail": "Full course sync queued."},
            status=status.HTTP_202_ACCEPTED,
        )
