"""
A failed WordPress (Edwiser Bridge) or Moodle request must never delete a
user's course enrollments.

Before this fix, a 503, 401, timeout or HTML error page was read as "this user
has no courses" and every enrollment was deleted: My Courses went empty, the
course page showed 0% and Mergers.AI answered "Not enrolled in this course"
until a later sync succeeded. A real unenrollment (the service answers, with
no courses) must still remove courses.

Nothing here reaches WordPress, Moodle, Cognito, email or Redis: `requests`
is replaced with canned replies, and Cognito, email and cache settings are
local.
"""
import json
from unittest import mock

import requests
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from courses import tasks
from courses.edwiser_api import EdwiserBridgeAPIClient
from courses.models import MoodleCourse, MoodleEnrollment
from courses.moodle_rest_api import MoodleRestClient, MoodleUnavailable
from users.models import UserProfile

User = get_user_model()

MAINTENANCE_HTML = "<html><body>Briefly unavailable for scheduled maintenance.</body></html>"


def reply(status=200, body=None, html=None):
    """A real requests.Response, so raise_for_status() and json() behave as in prod."""
    resp = requests.Response()
    resp.status_code = status
    resp.url = "https://service.example.test/"
    resp.encoding = "utf-8"
    resp._content = (json.dumps(body) if html is None else html).encode()
    return resp


# Every way a request can fail. Each one used to look like "no courses".
FAILURES = {
    "maintenance 503": reply(503, html=MAINTENANCE_HTML),
    "revoked password 401": reply(401, {"code": "rest_forbidden"}),
    "HTML page with 200": reply(200, html=MAINTENANCE_HTML),
    "connection refused": requests.ConnectionError("connection refused"),
    "timeout": requests.Timeout("read timed out"),
}
MOODLE_ERROR_REPLY = reply(200, {"exception": "moodle_exception", "errorcode": "invalidtoken", "message": "Invalid token"})


def _raise_or_return(outcome):
    if isinstance(outcome, Exception):
        raise outcome
    return outcome


def eb_courses_reply(percentage):
    return reply(200, {
        "enrolled_courses": [{
            "id": 5988,
            "title": "M&A Foundations",
            "progress": {
                "percentage": percentage,
                "completed": False,
                "course_url": "https://imaa-institute.example.test?mdl_course_id=7",
            },
        }],
    })


@override_settings(
    COGNITO_USER_POOL_ID="",
    COGNITO_REGION="",
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    EB_WP_API_URL="https://eb.example.test/wp-json",
    EB_WP_AUTH_TYPE="basic",
    EB_WP_API_USER="test",
    EB_WP_API_PASSWORD="test",
    MOODLE_URL="https://moodle.example.test",
    MOODLE_TOKEN="test-token",
)
class EnrollmentSyncFailureTests(TestCase):
    def setUp(self):
        self.course = MoodleCourse.objects.create(moodle_id=7, short_name="MAF", full_name="M&A Foundations")

    def _student(self, name, wordpress_id=101, progress=60.0):
        user = User.objects.create_user(username=f"test-user-{name}", email=f"test-user-{name}@example.test")
        UserProfile.objects.update_or_create(user=user, defaults={"wordpress_id": wordpress_id})
        MoodleEnrollment.objects.create(user=user, course=self.course, moodle_user_id=wordpress_id, progress=progress)
        return user

    def _progress(self, user):
        return list(MoodleEnrollment.objects.filter(user=user).values_list("progress", flat=True))

    # ------------------------------------------------------------------
    # WordPress / Edwiser Bridge client
    # ------------------------------------------------------------------

    def test_eb_client_returns_none_when_wordpress_does_not_answer(self):
        client = EdwiserBridgeAPIClient()
        for label, outcome in FAILURES.items():
            with self.subTest(label), mock.patch("courses.edwiser_api.requests.get", side_effect=lambda *a, o=outcome, **k: _raise_or_return(o)):
                self.assertIsNone(client.get_user_courses(wp_user_id=101))

    def test_eb_client_returns_the_answer_when_wordpress_answers(self):
        client = EdwiserBridgeAPIClient()
        with mock.patch("courses.edwiser_api.requests.get", return_value=reply(200, {"enrolled_courses": []})):
            self.assertEqual(client.get_user_courses(wp_user_id=101), [])
        with mock.patch("courses.edwiser_api.requests.get", return_value=eb_courses_reply(75)):
            self.assertEqual(len(client.get_user_courses(wp_user_id=101)), 1)

    # ------------------------------------------------------------------
    # The 30-minute WordPress sync (story 1)
    # ------------------------------------------------------------------

    def test_eb_sync_keeps_enrollments_when_wordpress_does_not_answer(self):
        student = self._student("eb-kept")
        client = EdwiserBridgeAPIClient()
        for label, outcome in FAILURES.items():
            with self.subTest(label), mock.patch("courses.edwiser_api.requests.get", side_effect=lambda *a, o=outcome, **k: _raise_or_return(o)):
                self.assertIsNone(tasks._sync_user_enrollments(client, student))
                self.assertEqual(self._progress(student), [60.0])

    def test_eb_sync_still_removes_a_real_unenrollment(self):
        student = self._student("eb-unenrolled")
        with mock.patch("courses.edwiser_api.requests.get", return_value=reply(200, {"enrolled_courses": []})):
            self.assertEqual(tasks._sync_user_enrollments(EdwiserBridgeAPIClient(), student), 0)
        self.assertEqual(self._progress(student), [])

    def test_eb_sync_still_updates_progress_when_wordpress_answers(self):
        student = self._student("eb-updated")
        with mock.patch("courses.edwiser_api.requests.get", return_value=eb_courses_reply(75)):
            self.assertEqual(tasks._sync_user_enrollments(EdwiserBridgeAPIClient(), student), 1)
        self.assertEqual(self._progress(student), [75.0])

    def test_maintenance_during_the_sync_deletes_nothing_and_is_counted(self):
        students = [self._student(f"maint-{i}", wordpress_id=200 + i) for i in range(3)]
        wordpress_down = mock.patch("courses.edwiser_api.requests.get", return_value=reply(503, html=MAINTENANCE_HTML))
        with mock.patch.object(tasks, "get_edwiser_client", return_value=EdwiserBridgeAPIClient()), wordpress_down:
            result = tasks.sync_user_moodle_enrollments_chunk([s.id for s in students], 1, 1)

        self.assertEqual(result, {"chunk": 1, "chunks": 1, "users": 0, "enrollments": 0, "failed": 3})
        self.assertEqual(MoodleEnrollment.objects.filter(user__in=students).count(), 3)

    def test_one_failed_user_does_not_affect_the_others_in_a_chunk(self):
        failed = self._student("chunk-failed", wordpress_id=301)
        answered = self._student("chunk-answered", wordpress_id=302)

        def wordpress(url, params=None, **kwargs):
            if params.get("user_id") == 301:
                raise requests.Timeout("read timed out")
            return eb_courses_reply(90)

        with mock.patch.object(tasks, "get_edwiser_client", return_value=EdwiserBridgeAPIClient()), \
                mock.patch("courses.edwiser_api.requests.get", side_effect=wordpress):
            result = tasks.sync_user_moodle_enrollments_chunk([failed.id, answered.id], 1, 1)

        self.assertEqual(result, {"chunk": 1, "chunks": 1, "users": 1, "enrollments": 1, "failed": 1})
        self.assertEqual(self._progress(failed), [60.0])
        self.assertEqual(self._progress(answered), [90.0])

    # ------------------------------------------------------------------
    # Moodle client
    # ------------------------------------------------------------------

    def test_moodle_client_raises_when_moodle_does_not_answer(self):
        client = MoodleRestClient()
        failures = dict(FAILURES, **{"Moodle error reply": MOODLE_ERROR_REPLY})
        for label, outcome in failures.items():
            with self.subTest(label), mock.patch("courses.moodle_rest_api.requests.post", side_effect=lambda *a, o=outcome, **k: _raise_or_return(o)):
                with self.assertRaises(MoodleUnavailable):
                    client.get_user_id_by_email("test-user@example.test")
                with self.assertRaises(MoodleUnavailable):
                    client.get_user_enrolled_courses(42)

    def test_moodle_client_tells_not_found_and_no_courses_apart_from_failure(self):
        client = MoodleRestClient()
        with mock.patch("courses.moodle_rest_api.requests.post", return_value=reply(200, [])):
            self.assertIsNone(client.get_user_id_by_email("test-user@example.test"))
            self.assertEqual(client.get_user_enrolled_courses(42), [])
        with mock.patch("courses.moodle_rest_api.requests.post", return_value=reply(200, [{"id": 42}])):
            self.assertEqual(client.get_user_id_by_email("test-user@example.test"), 42)

    # ------------------------------------------------------------------
    # The Moodle sync behind My Courses and Refresh (story 2)
    # ------------------------------------------------------------------

    def _moodle(self, lookup, courses):
        """Patch Moodle: `lookup` answers the email lookup, `courses` the course list."""
        def post(url, data=None, **kwargs):
            outcome = lookup if data["wsfunction"] == "core_user_get_users_by_field" else courses
            return _raise_or_return(outcome)

        return mock.patch("courses.moodle_rest_api.requests.post", side_effect=post)

    def test_moodle_sync_keeps_enrollments_when_moodle_does_not_answer(self):
        student = self._student("moodle-kept")
        found = reply(200, [{"id": 42}])
        cases = {
            "lookup: Moodle restarting": (requests.ConnectionError("refused"), None),
            "lookup: token rejected": (MOODLE_ERROR_REPLY, None),
            "course list: 503": (found, reply(503, html=MAINTENANCE_HTML)),
            "course list: timeout": (found, requests.Timeout("read timed out")),
        }
        with mock.patch.object(tasks, "get_moodle_client", return_value=MoodleRestClient()):
            for label, (lookup, courses) in cases.items():
                with self.subTest(label), self._moodle(lookup, courses):
                    self.assertIsNone(tasks._sync_user_enrollments_via_moodle(student))
                    self.assertEqual(self._progress(student), [60.0])

    def test_moodle_sync_still_removes_courses_when_moodle_answers_none(self):
        not_found = self._student("moodle-not-found")
        no_courses = self._student("moodle-no-courses")
        with mock.patch.object(tasks, "get_moodle_client", return_value=MoodleRestClient()):
            with self._moodle(reply(200, []), None):
                self.assertEqual(tasks._sync_user_enrollments_via_moodle(not_found), 0)
            with self._moodle(reply(200, [{"id": 42}]), reply(200, [])):
                self.assertEqual(tasks._sync_user_enrollments_via_moodle(no_courses), 0)
        self.assertEqual(self._progress(not_found), [])
        self.assertEqual(self._progress(no_courses), [])

    def test_refresh_button_keeps_the_list_while_moodle_restarts(self):
        student = self._student("refresh")
        api = APIClient()
        api.force_authenticate(student)

        with mock.patch.object(tasks, "get_moodle_client", return_value=MoodleRestClient()), \
                self._moodle(requests.ConnectionError("refused"), None):
            response = api.post("/api/courses/my-courses/refresh/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual([(c["full_name"], c["progress"]) for c in response.data], [("M&A Foundations", 60.0)])

    def test_module_completion_sync_skips_when_moodle_does_not_answer(self):
        student = self._student("completions")
        with mock.patch.object(tasks, "get_moodle_client", return_value=MoodleRestClient()), \
                self._moodle(requests.ConnectionError("refused"), None):
            self.assertEqual(tasks.sync_user_module_completions(self.course.pk, student.pk), {"skipped": True})
