"""
Courses API views.

Strategy: stale-while-revalidate
  1. Serve DB data immediately (fast response)
  2. Trigger background Celery sync so next request gets fresher data
  3. DB is kept warm by scheduled tasks (every 6h courses, every 30min enrollments)

Endpoints:
  GET  /api/courses/                     — All visible courses
  GET  /api/courses/{id}/                — Course detail
  GET  /api/courses/categories/          — All categories
  GET  /api/courses/my-courses/          — Authenticated user's enrollments
  POST /api/courses/my-courses/refresh/  — Trigger background enrollment re-sync
  GET  /api/courses/{id}/launch          — Direct LMS URL for a course
  POST /api/courses/admin/sync/          — Admin: trigger full background sync
  GET  /api/courses/image-proxy/         — Proxy IMAA images (bypasses hotlink protection)
"""
import logging
from datetime import timedelta
from urllib.parse import urlparse, urlencode

import requests as http_requests
from django.http import HttpResponse, Http404
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import action, api_view, permission_classes, authentication_classes
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
from .tasks import sync_moodle_courses_and_categories, sync_single_user_moodle_enrollments, _sync_user_enrollments

logger = logging.getLogger(__name__)

# Trigger a background course sync if DB data is older than this
COURSE_STALE_AFTER = timedelta(minutes=15)


# ---------------------------------------------------------------------------
# Image proxy — bypasses imaa-institute.org hotlink protection
# ---------------------------------------------------------------------------

ALLOWED_IMAGE_HOSTS = {"imaa-institute.org", "www.imaa-institute.org"}


def _proxy_image_url(request, url: str) -> str:
    """Rewrite an IMAA image URL to go through our backend proxy."""
    if not url:
        return url
    try:
        host = urlparse(url).netloc
        if host in ALLOWED_IMAGE_HOSTS:
            return request.build_absolute_uri(
                "/api/courses/image-proxy/?" + urlencode({"url": url})
            )
    except Exception:
        pass
    return url


def _proxy_image_urls_in_list(request, data: list, key: str = "image_url") -> list:
    """Rewrite image_url fields in a list of dicts through the proxy."""
    result = []
    for item in data:
        d = dict(item)
        d[key] = _proxy_image_url(request, d.get(key) or "")
        result.append(d)
    return result


@api_view(["GET"])
@authentication_classes([])
@permission_classes([])
def image_proxy(request):
    """
    Proxy images from imaa-institute.org to bypass hotlink protection.
    Browser requests carry a Referer header → 403 from IMAA.
    Server-side fetch has no Referer → 200 OK.
    """
    url = request.query_params.get("url", "")
    if not url:
        raise Http404

    try:
        host = urlparse(url).netloc
    except Exception:
        raise Http404

    if host not in ALLOWED_IMAGE_HOSTS:
        return HttpResponse("Forbidden", status=403)

    try:
        resp = http_requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},  # no Referer — that's the fix
            stream=True,
        )
        if resp.status_code != 200:
            return HttpResponse(status=resp.status_code)

        content_type = resp.headers.get("Content-Type", "image/jpeg")
        django_resp = HttpResponse(resp.content, content_type=content_type)
        django_resp["Cache-Control"] = "public, max-age=86400"  # cache 1 day in browser
        return django_resp

    except Exception as exc:
        logger.warning("Image proxy failed for %s: %s", url, exc)
        return HttpResponse("Failed to fetch image", status=502)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_course_data_stale() -> bool:
    """Return True if the DB course data is older than COURSE_STALE_AFTER."""
    try:
        latest = MoodleCourse.objects.latest("synced_at")
        return (timezone.now() - latest.synced_at) > COURSE_STALE_AFTER
    except MoodleCourse.DoesNotExist:
        return True


# ---------------------------------------------------------------------------
# ViewSet
# ---------------------------------------------------------------------------

class MoodleCourseViewSet(ReadOnlyModelViewSet):
    """
    Serves DB data immediately for fast responses.
    Triggers background EB API sync so data stays fresh for subsequent requests.
    """
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

    # ------------------------------------------------------------------
    # Course list  —  GET /api/courses/
    # ------------------------------------------------------------------

    def list(self, request, *args, **kwargs):
        # Serve from DB immediately
        qs = self.get_queryset()
        serializer = self.get_serializer(qs, many=True)
        result = _proxy_image_urls_in_list(request, serializer.data)

        # Trigger background refresh if data is stale
        if _is_course_data_stale():
            sync_moodle_courses_and_categories.delay()
            logger.info("Course data is stale — background sync triggered")

        return Response(result)

    # ------------------------------------------------------------------
    # Course detail  —  GET /api/courses/{id}/
    # ------------------------------------------------------------------

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        d = dict(serializer.data)
        d["image_url"] = _proxy_image_url(request, d.get("image_url") or "")
        return Response(d)

    # ------------------------------------------------------------------
    # Categories  —  GET /api/courses/categories/
    # ------------------------------------------------------------------

    @action(detail=False, methods=["get"], url_path="categories")
    def categories(self, request):
        # Serve from DB immediately
        serializer = MoodleCategorySerializer(MoodleCategory.objects.all(), many=True)

        # Trigger background refresh if stale (same task as courses)
        if _is_course_data_stale():
            sync_moodle_courses_and_categories.delay()

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

        # Serve from DB immediately
        enrollments = (
            MoodleEnrollment.objects.filter(user=user)
            .select_related("course", "course__category")
            .order_by("-synced_at")
        )
        serializer = MoodleEnrollmentListSerializer(enrollments, many=True)
        result = _proxy_image_urls_in_list(request, serializer.data)

        # Always trigger background enrollment refresh (non-blocking, user-specific)
        sync_single_user_moodle_enrollments.delay(user.id)
        logger.info("Background enrollment sync triggered for user %s", user.email)

        return Response(result)

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
        """
        Synchronously fetch fresh enrollments from EB API, update DB,
        then return the updated list immediately.
        This ensures unenrolled courses are removed right away.
        """
        user = request.user
        try:
            client = get_edwiser_client()
            _sync_user_enrollments(client, user)
        except Exception as exc:
            logger.warning("Sync failed during refresh for user %s: %s", user.email, exc)

        # Return fresh data from DB after sync
        enrollments = (
            MoodleEnrollment.objects.filter(user=user)
            .select_related("course", "course__category")
            .order_by("-synced_at")
        )
        serializer = MoodleEnrollmentListSerializer(enrollments, many=True)
        result = _proxy_image_urls_in_list(request, serializer.data)
        return Response(result)

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
        """Returns the direct LMS URL for a course."""
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
