"""
A 429 Too Many Requests from WordPress must stop the enrollment sync instead
of being asked again for every remaining user (Sentry ECP-BACKEND-8).

On prod, once imaa-institute.org started rate-limiting, every remaining user
in the run got a fast 429 and one Sentry error each (303 in a week). The old
code also deleted each of those users' courses; the failure tests cover that.
These tests pin what a 429 does now: the chunk stops, users not reached keep
their enrollments, one warning is logged (no error, so no Sentry event), and
the sync pauses, so the chunks still queued and the next Beat run leave
WordPress alone until the pause ends.

Nothing here reaches WordPress, Cognito, email, Redis or the Celery broker:
`requests` gets canned replies, the cache is local memory and `chain` is
replaced when the Beat task queues chunks.
"""
import json
from datetime import datetime, timedelta, timezone as dt_timezone
from email.utils import format_datetime
from unittest import mock

import requests
from celery import chain as real_chain
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings

from courses import tasks
from courses.edwiser_api import EdwiserBridgeAPIClient, EdwiserRateLimited, _retry_after_seconds
from courses.models import MoodleCourse, MoodleEnrollment
from users.models import UserProfile

User = get_user_model()

CLOUDFLARE_1015 = "error code: 1015"


def reply(status=200, body=None, text=None, headers=None):
    """A real requests.Response, so raise_for_status() and json() behave as in prod."""
    resp = requests.Response()
    resp.status_code = status
    resp.url = "https://eb.example.test/wp-json/eb/api/v1/my-courses"
    resp.encoding = "utf-8"
    resp._content = (json.dumps(body) if text is None else text).encode()
    resp.headers.update(headers or {})
    return resp


def courses_reply():
    return reply(200, {
        "enrolled_courses": [{
            "id": 5988,
            "title": "M&A Foundations",
            "progress": {
                "percentage": 90,
                "completed": False,
                "course_url": "https://imaa-institute.example.test?mdl_course_id=7",
            },
        }],
    })


def too_many_requests(retry_after=None):
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    return reply(429, text=CLOUDFLARE_1015, headers=headers)


class RateLimitingWordPress:
    """
    Answers `answers_before_limit` /my-courses requests, then only 429s,
    as imaa-institute.org did on prod. Records which WP user ids were asked.
    """

    def __init__(self, answers_before_limit=0, retry_after=None):
        self.answers_before_limit = answers_before_limit
        self.retry_after = retry_after
        self.asked = []

    def get(self, url, params=None, **kwargs):
        self.asked.append(params.get("user_id"))
        if len(self.asked) <= self.answers_before_limit:
            return courses_reply()
        return too_many_requests(self.retry_after)


@override_settings(
    COGNITO_USER_POOL_ID="",
    COGNITO_REGION="",
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    EB_WP_API_URL="https://eb.example.test/wp-json",
    EB_WP_AUTH_TYPE="basic",
    EB_WP_API_USER="test",
    EB_WP_API_PASSWORD="test",
)
class EnrollmentSyncRateLimitTests(TestCase):
    def setUp(self):
        # Only this key, never cache.clear(): never wipe a shared cache.
        cache.delete(tasks.EB_RATE_LIMIT_PAUSE_KEY)
        self.addCleanup(cache.delete, tasks.EB_RATE_LIMIT_PAUSE_KEY)
        self.course = MoodleCourse.objects.create(moodle_id=7, short_name="MAF", full_name="M&A Foundations")
        patcher = mock.patch.object(tasks, "get_edwiser_client", return_value=EdwiserBridgeAPIClient())
        patcher.start()
        self.addCleanup(patcher.stop)

    def _students(self, count, first_wp_id=101):
        students = []
        for i in range(count):
            user = User.objects.create_user(
                username=f"test-user-rl-{first_wp_id + i}",
                email=f"test-user-rl-{first_wp_id + i}@example.test",
            )
            UserProfile.objects.update_or_create(user=user, defaults={"wordpress_id": first_wp_id + i})
            MoodleEnrollment.objects.create(user=user, course=self.course, moodle_user_id=first_wp_id + i, progress=60.0)
            students.append(user)
        return students

    def _progress(self, users):
        return [
            list(MoodleEnrollment.objects.filter(user=u).values_list("progress", flat=True))
            for u in users
        ]

    def _wordpress(self, wordpress):
        return mock.patch("courses.edwiser_api.requests.get", side_effect=wordpress.get)

    def _dispatch(self):
        """Run the Beat task; return (result, chunk signatures, chain mock)."""
        captured = {}

        def fake_chain(*signatures):
            captured["signatures"] = list(signatures)
            return mock.Mock()

        with mock.patch.object(tasks, "chain", side_effect=fake_chain) as chain_mock:
            result = tasks.sync_all_user_moodle_enrollments()
        return result, captured.get("signatures", []), chain_mock

    # ------------------------------------------------------------------
    # WordPress client
    # ------------------------------------------------------------------

    def test_retry_after_is_read_as_seconds_or_as_a_date(self):
        in_five_minutes = datetime.now(dt_timezone.utc) + timedelta(minutes=5)
        an_hour_ago = datetime.now(dt_timezone.utc) - timedelta(hours=1)

        self.assertEqual(_retry_after_seconds("120"), 120)
        self.assertEqual(_retry_after_seconds(" 60 "), 60)
        self.assertIn(_retry_after_seconds(format_datetime(in_five_minutes, usegmt=True)), range(295, 301))
        self.assertEqual(_retry_after_seconds(format_datetime(an_hour_ago, usegmt=True)), 0)
        for missing_or_bad in (None, "", "soon", "-5"):
            with self.subTest(missing_or_bad):
                self.assertIsNone(_retry_after_seconds(missing_or_bad))

    def test_my_courses_429_raises_with_retry_after_and_reply_and_logs_no_error(self):
        client = EdwiserBridgeAPIClient()
        with mock.patch("courses.edwiser_api.requests.get", return_value=too_many_requests("120")), \
                self.assertNoLogs("courses", level="ERROR"):
            with self.assertRaises(EdwiserRateLimited) as raised:
                client.get_user_courses(wp_user_id=101)

        self.assertEqual(raised.exception.retry_after, 120)
        self.assertEqual(raised.exception.reply, CLOUDFLARE_1015)

    def test_other_wordpress_calls_still_answer_none_on_429(self):
        # Only /my-courses (the per-user sync) raises; the catalogue calls are unchanged.
        client = EdwiserBridgeAPIClient()
        with mock.patch("courses.edwiser_api.requests.get", return_value=too_many_requests()):
            self.assertIsNone(client.get_course(5988))

    # ------------------------------------------------------------------
    # The 30-minute sync
    # ------------------------------------------------------------------

    def test_429_stops_the_chunk_keeps_enrollments_and_logs_one_warning(self):
        students = self._students(5)
        wordpress = RateLimitingWordPress(answers_before_limit=2)

        with self._wordpress(wordpress), self.assertLogs("courses", level="WARNING") as logs:
            result = tasks.sync_user_moodle_enrollments_chunk([s.id for s in students], 1, 1)

        self.assertEqual(result, {
            "chunk": 1, "chunks": 1, "users": 2, "enrollments": 2, "failed": 0,
            "rate_limited": True, "not_synced": 3, "paused_until": mock.ANY,
        })
        # Stopped at the first 429: users 4 and 5 were never asked.
        self.assertEqual(wordpress.asked, [101, 102, 103])
        self.assertEqual(self._progress(students), [[90.0], [90.0], [60.0], [60.0], [60.0]])
        # One warning (a Sentry breadcrumb), no error (a Sentry event).
        self.assertEqual([r.levelname for r in logs.records], ["WARNING"])
        self.assertIn("429 Too Many Requests", logs.output[0])
        self.assertIn(CLOUDFLARE_1015, logs.output[0])
        self.assertEqual(tasks._eb_sync_paused_until(), result["paused_until"])

    def test_while_paused_the_next_chunk_and_the_next_run_leave_wordpress_alone(self):
        students = self._students(2)
        paused_until = tasks._pause_eb_sync(None)
        wordpress = RateLimitingWordPress(answers_before_limit=99)

        with self._wordpress(wordpress):
            chunk_result = tasks.sync_user_moodle_enrollments_chunk([s.id for s in students], 2, 9)
            run_result, signatures, chain_mock = self._dispatch()

        self.assertEqual(chunk_result, {"chunk": 2, "chunks": 9, "skipped": "rate_limited", "paused_until": paused_until})
        self.assertEqual(run_result, {"skipped": "rate_limited", "paused_until": paused_until})
        chain_mock.assert_not_called()
        self.assertEqual(signatures, [])
        self.assertEqual(wordpress.asked, [])
        self.assertEqual(self._progress(students), [[60.0], [60.0]])

    def test_whole_run_stops_after_the_first_429(self):
        students = self._students(5)
        wordpress = RateLimitingWordPress(answers_before_limit=2)

        with mock.patch.object(tasks, "ENROLLMENT_SYNC_CHUNK_SIZE", 2):
            _, signatures, _ = self._dispatch()
        with self._wordpress(wordpress):
            last = real_chain(*signatures).apply()  # runs each chunk in-process, in order

        # Chunk 1 synced users 1-2, chunk 2 stopped at user 3, chunk 3 skipped.
        self.assertEqual(wordpress.asked, [101, 102, 103])
        self.assertEqual(last.get(), {"chunk": 3, "chunks": 3, "skipped": "rate_limited", "paused_until": mock.ANY})
        self.assertEqual(self._progress(students), [[90.0], [90.0], [60.0], [60.0], [60.0]])

    def test_pause_follows_retry_after_within_bounds(self):
        self.assertEqual(tasks._eb_pause_seconds(None), 10 * 60)
        self.assertEqual(tasks._eb_pause_seconds(30), 10 * 60)
        self.assertEqual(tasks._eb_pause_seconds(45 * 60), 45 * 60)
        self.assertEqual(tasks._eb_pause_seconds(10 ** 6), 2 * 60 * 60)

        with mock.patch.object(tasks, "cache") as fake_cache:
            tasks._pause_eb_sync(45 * 60)
        fake_cache.set.assert_called_once_with(tasks.EB_RATE_LIMIT_PAUSE_KEY, mock.ANY, timeout=45 * 60)

    def test_sync_still_runs_and_stops_on_429_when_the_cache_is_down(self):
        students = self._students(3)
        wordpress = RateLimitingWordPress(answers_before_limit=1)
        broken_cache = mock.Mock()
        broken_cache.get.side_effect = ConnectionError("redis down")
        broken_cache.set.side_effect = ConnectionError("redis down")

        with mock.patch.object(tasks, "cache", broken_cache), self._wordpress(wordpress):
            result = tasks.sync_user_moodle_enrollments_chunk([s.id for s in students], 1, 1)

        self.assertEqual(result["users"], 1)
        self.assertEqual(result["not_synced"], 2)
        self.assertEqual(wordpress.asked, [101, 102])
        self.assertEqual(self._progress(students), [[90.0], [60.0], [60.0]])

    def test_single_user_sync_on_429_keeps_enrollments_and_pauses(self):
        (student,) = self._students(1)
        wordpress = RateLimitingWordPress(answers_before_limit=0, retry_after="900")

        with self._wordpress(wordpress), self.assertNoLogs("courses", level="ERROR"):
            result = tasks.sync_single_user_moodle_enrollments(student.id)

        self.assertEqual(result, {"user_id": student.id, "skipped": "rate_limited", "paused_until": mock.ANY})
        self.assertEqual(self._progress([student]), [[60.0]])
        self.assertIsNotNone(tasks._eb_sync_paused_until())
