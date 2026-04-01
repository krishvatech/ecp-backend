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
from .models import MoodleCategory, MoodleCourse, MoodleEnrollment, CourseSection, CourseModule, ModuleCompletion
from .serializers import (
    MoodleCategorySerializer,
    MoodleCourseSerializer,
    MoodleEnrollmentListSerializer,
    CourseSectionSerializer,
)
from .tasks import (
    sync_moodle_courses_and_categories,
    sync_single_user_moodle_enrollments,
    _sync_user_enrollments,
    sync_course_content,
    sync_user_module_completions,
    _sync_course_content,
)

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

        logger.debug(
            "[DEBUG] my_courses | user=%s | enrolled_count=%d | courses=%s",
            user.email,
            len(result),
            [{"course_id": e["course_id"], "full_name": e["full_name"], "progress": e["progress"]} for e in result],
        )

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

    # ------------------------------------------------------------------
    # Raw EB API response (Phase 1 discovery)
    # GET /api/courses/{id}/raw/
    # ------------------------------------------------------------------

    @action(detail=True, methods=["get"], url_path="raw", permission_classes=[IsAdminUser])
    def raw(self, request, pk=None):
        """
        Admin-only: return the raw Edwiser Bridge API response for a course.
        Used to discover what fields EB exposes (sections, videos, quizzes, etc.)
        """
        instance = self.get_object()
        try:
            client = get_edwiser_client()
            data = client.get_course_raw(instance.moodle_id)
        except Exception as exc:
            return Response({"error": str(exc)}, status=status.HTTP_502_BAD_GATEWAY)
        return Response(data)

    # ------------------------------------------------------------------
    # Course detail for player  —  GET /api/courses/{id}/detail/
    # ------------------------------------------------------------------

    @action(detail=True, methods=["get"], url_path="detail", permission_classes=[IsAuthenticated])
    def course_detail(self, request, pk=None):
        """
        Returns full course metadata + current user's progress.
        Used by the in-platform course player page.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        course_data = dict(serializer.data)
        course_data["image_url"] = _proxy_image_url(request, course_data.get("image_url") or "")

        # Attach user progress
        progress_data = {"progress": 0, "completed": False}
        try:
            enrollment = MoodleEnrollment.objects.get(user=request.user, course=instance)
            progress_data = {
                "progress": enrollment.progress,
                "completed": enrollment.completed,
                "last_access": enrollment.last_access,
            }
        except MoodleEnrollment.DoesNotExist:
            pass

        logger.debug(
            "[DEBUG] course_detail | user=%s | course_id=%s | moodle_id=%s | full_name=%s | progress=%s | completed=%s",
            request.user.email,
            instance.pk,
            instance.moodle_id,
            instance.full_name,
            progress_data.get("progress"),
            progress_data.get("completed"),
        )

        return Response({**course_data, **progress_data})

    # ------------------------------------------------------------------
    # SSO Launch URL  —  GET /api/courses/{id}/launch-url/
    # ------------------------------------------------------------------

    @action(detail=True, methods=["get"], url_path="launch-url", permission_classes=[IsAuthenticated])
    def launch_url(self, request, pk=None):
        """
        Returns a URL to load the course in the in-platform iframe player.
        Attempts to generate an SSO auto-login URL so the user is authenticated
        inside the iframe automatically. Falls back to the plain course URL.
        """
        instance = self.get_object()
        course_url = instance.moodle_url

        # Try SSO auto-login URL
        sso_url = None
        try:
            eb_wp_user_id = request.user.profile.moodle_user_id
            if eb_wp_user_id:
                client = get_edwiser_client()
                sso_url = client.get_sso_login_url(eb_wp_user_id, course_url)
        except Exception as exc:
            logger.debug("SSO URL generation skipped: %s", exc)

        return Response({
            "url": sso_url or course_url,
            "sso": sso_url is not None,
            "course_url": course_url,
        })

    # ------------------------------------------------------------------
    # Course content (sections + modules)  —  GET /api/courses/{id}/content/
    # ------------------------------------------------------------------

    @action(detail=True, methods=["get"], url_path="content", permission_classes=[IsAuthenticated])
    def course_content(self, request, pk=None):
        """
        Returns sections and modules for a course, with per-user completion status.
        Triggers background syncs for content and completion if not yet cached.

        Response shape:
          {
            "course_id": N,
            "moodle_course_id": N,
            "sections": [
              {
                "id": N, "name": "...", "position": N,
                "modules": [
                  {
                    "id": N, "name": "...", "modtype": "resource|url|quiz|...",
                    "content_url": "...", "content_mimetype": "...",
                    "module_url": "...", "completed": true/false, ...
                  }
                ]
              }
            ],
            "syncing": true/false   ← true means background sync was triggered
          }
        """
        instance = self.get_object()
        syncing = False

        # Sync content if not yet cached
        sections_qs = CourseSection.objects.filter(course=instance)
        if not sections_qs.exists():
            # Synchronously sync content so we can return data right away
            try:
                from .moodle_rest_api import get_moodle_client
                client = get_moodle_client()
                _sync_course_content(client, instance)
                sections_qs = CourseSection.objects.filter(course=instance)
                syncing = False
            except Exception as exc:
                logger.warning("Inline content sync failed for course %d: %s", instance.pk, exc)
                # Queue background sync for next request
                sync_course_content.delay(instance.pk)
                syncing = True
        else:
            # Refresh in background
            sync_course_content.delay(instance.pk)
            syncing = True

        # Build completion map for this user
        completion_map = {}
        module_completions = ModuleCompletion.objects.filter(
            user=request.user,
            module__section__course=instance,
        ).values_list("module__moodle_module_id", "completed")
        for cmid, completed in module_completions:
            completion_map[cmid] = completed

        # Trigger background completion sync
        sync_user_module_completions.delay(instance.pk, request.user.pk)

        # Include all sections — frontend filters by content (modules or summary)
        sections = sections_qs.prefetch_related("modules")
        serializer = CourseSectionSerializer(
            sections,
            many=True,
            context={"request": request, "completion_map": completion_map},
        )

        section_summary = [
            {
                "section": s["name"] or f"Section {s['position']}",
                "modules": [
                    {"name": m["name"], "modtype": m["modtype"], "visible": m["visible"], "completed": m["completed"]}
                    for m in (s.get("modules") or [])
                ],
            }
            for s in serializer.data
        ]
        logger.debug(
            "[DEBUG] course_content | user=%s | course_id=%s | sections=%s | syncing=%s | content=%s",
            request.user.email,
            instance.pk,
            serializer.data,
            syncing,
            section_summary,
        )

        return Response({
            "course_id": instance.pk,
            "moodle_course_id": instance.moodle_id,
            "sections": serializer.data,
            "syncing": syncing,
        })

    # ------------------------------------------------------------------
    # Module native detail  —  GET /api/courses/{id}/modules/{cmid}/detail/
    # ------------------------------------------------------------------

    @action(
        detail=True,
        methods=["get"],
        url_path="modules/(?P<cmid>[0-9]+)/detail",
        permission_classes=[IsAuthenticated],
    )
    def module_detail(self, request, pk=None, cmid=None):
        """
        Returns native content for a module (assignment intro HTML, quiz info, etc.)
        so it can be rendered inside the platform without an iframe.
        """
        from .moodle_rest_api import get_moodle_client
        instance = self.get_object()
        cmid = int(cmid)

        try:
            module = CourseModule.objects.get(moodle_module_id=cmid, section__course=instance)
        except CourseModule.DoesNotExist:
            return Response({"detail": "Module not found."}, status=status.HTTP_404_NOT_FOUND)

        result = {
            "cmid": cmid,
            "name": module.name,
            "modtype": module.modtype,
            "module_url": module.module_url,
            "completion": module.completion,
        }

        try:
            client = get_moodle_client()

            if module.modtype == "assign":
                data = client.get_assignment_detail(instance.moodle_id, cmid)
                if data:
                    raw_intro = data.get("intro", "")
                    introfiles = data.get("introfiles") or []

                    logger.debug(
                        "[DEBUG] module_detail assign | cmid=%s | introfiles=%s | intro_snippet=%s",
                        cmid,
                        [{"filename": f.get("filename"), "fileurl": f.get("fileurl"), "mimetype": f.get("mimetype")} for f in introfiles],
                        raw_intro[:300],
                    )

                    # Append token to all pluginfile.php image URLs inside the intro HTML
                    import re
                    def _add_token(m):
                        url = m.group(1)
                        sep = "&amp;" if "&amp;" in m.group(0) else "&" if "?" in url else "?"
                        if "token=" not in url:
                            url = f"{url}{'&' if '?' in url else '?'}token={client.token}"
                        return f'src="{url}"'
                    intro_with_token = re.sub(r'src="(https?://[^"]*pluginfile\.php[^"]*)"', _add_token, raw_intro)

                    result.update({
                        "intro": intro_with_token,
                        "introformat": data.get("introformat", 1),
                        "introfiles": [
                            {
                                "filename": f.get("filename"),
                                "fileurl": f"{f.get('fileurl', '')}?token={client.token}" if f.get("fileurl") else "",
                                "mimetype": f.get("mimetype", ""),
                                "filesize": f.get("filesize", 0),
                            }
                            for f in introfiles
                        ],
                        "duedate": data.get("duedate"),
                        "allowsubmissionsfromdate": data.get("allowsubmissionsfromdate"),
                        "nosubmissions": data.get("nosubmissions", 0),
                    })

            elif module.modtype == "quiz":
                data = client.get_quiz_detail(instance.moodle_id, cmid)
                if data:
                    result.update({
                        "intro": data.get("intro", ""),
                        "timelimit": data.get("timelimit", 0),
                        "attempts": data.get("attempts", 0),
                        "grademethod": data.get("grademethod"),
                        "timeopen": data.get("timeopen"),
                        "timeclose": data.get("timeclose"),
                    })

        except Exception as exc:
            logger.warning("module_detail: failed to fetch native content for cmid %s: %s", cmid, exc)

        return Response(result)

    # ------------------------------------------------------------------
    # Module launch URL  —  GET /api/courses/{id}/modules/{cmid}/launch-url/
    # ------------------------------------------------------------------

    @action(
        detail=True,
        methods=["get"],
        url_path="modules/(?P<cmid>[0-9]+)/launch-url",
        permission_classes=[IsAuthenticated],
    )
    def module_launch_url(self, request, pk=None, cmid=None):
        """
        Returns a URL to load a module (assignment/quiz/etc.) inside the platform iframe.
        Attempts to generate an SSO auto-login URL; falls back to the plain module URL.
        """
        instance = self.get_object()
        try:
            module = CourseModule.objects.get(
                moodle_module_id=cmid,
                section__course=instance,
            )
        except CourseModule.DoesNotExist:
            return Response({"detail": "Module not found."}, status=status.HTTP_404_NOT_FOUND)

        module_url = module.module_url
        if not module_url:
            return Response({"detail": "Module URL not available."}, status=status.HTTP_400_BAD_REQUEST)

        # Try SSO auto-login URL
        sso_url = None
        try:
            eb_wp_user_id = request.user.profile.moodle_user_id
            if eb_wp_user_id:
                client = get_edwiser_client()
                sso_url = client.get_sso_login_url(eb_wp_user_id, module_url)
        except Exception as exc:
            logger.debug("Module SSO URL generation skipped: %s", exc)

        return Response({
            "url": sso_url or module_url,
            "sso": sso_url is not None,
            "module_url": module_url,
        })

    # ------------------------------------------------------------------
    # Mark module complete  —  POST /api/courses/{id}/modules/{cmid}/complete/
    # ------------------------------------------------------------------

    @action(
        detail=True,
        methods=["post"],
        url_path="modules/(?P<cmid>[0-9]+)/complete",
        permission_classes=[IsAuthenticated],
    )
    def mark_module_complete(self, request, pk=None, cmid=None):
        """
        Mark a module as manually complete for the requesting user.
        Calls Moodle REST API and updates local ModuleCompletion record.
        """
        from .moodle_rest_api import get_moodle_client
        from .models import CourseModule

        try:
            module = CourseModule.objects.get(moodle_module_id=cmid)
        except CourseModule.DoesNotExist:
            return Response({"detail": "Module not found."}, status=status.HTTP_404_NOT_FOUND)

        if module.completion != 1:
            return Response({"detail": "This module does not support manual completion."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            client = get_moodle_client()
            client.mark_activity_complete(int(cmid))
        except Exception as exc:
            logger.warning("Moodle mark_complete failed for cmid %s: %s", cmid, exc)

        # Update local record regardless of Moodle result
        ModuleCompletion.objects.update_or_create(
            user=request.user,
            module=module,
            defaults={"completed": True},
        )

        return Response({"detail": "Marked as complete.", "cmid": cmid})
