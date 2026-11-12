"""
The Edwiser Bridge enrollment sync runs as a chain of small chunk tasks.

Syncing every linked user in one task took 236-240 s on prod and kept hitting
the 240 s soft time limit (Sentry ECP-BACKEND-6). These tests pin the chunked
behaviour: who is queued, in which order, that each chunk syncs only its own
users, and that a failed chunk stops the rest of the chain.

Nothing here reaches WordPress, Cognito, email or the Celery broker: the
Edwiser client and `chain` are replaced, and Cognito/email settings are blank.
"""
from unittest import mock

from celery import chain as real_chain
from celery.exceptions import SoftTimeLimitExceeded
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from courses import tasks
from courses.models import MoodleEnrollment
from users.models import UserProfile

User = get_user_model()

CHUNK_TASK_NAME = "courses.tasks.sync_user_moodle_enrollments_chunk"


class FakeEdwiserClient:
    """Answers /my-courses with one course per user; records who was asked."""

    def __init__(self):
        self.requested_wp_ids = []

    def get_user_courses(self, wp_user_id=None, email=None):
        self.requested_wp_ids.append(wp_user_id)
        return [
            {
                "id": 5988,
                "title": "M&A Foundations",
                "progress": {
                    "percentage": 50,
                    "completed": False,
                    "course_url": "https://imaa-institute.example.test?mdl_course_id=7",
                },
            }
        ]


@override_settings(
    COGNITO_USER_POOL_ID="",
    COGNITO_REGION="",
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
)
class EnrollmentSyncChunkTests(TestCase):
    def setUp(self):
        self.client_fake = FakeEdwiserClient()
        patcher = mock.patch.object(tasks, "get_edwiser_client", return_value=self.client_fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _user(self, name, *, wordpress_id=None, is_active=True):
        user = User.objects.create_user(
            username=f"test-user-{name}",
            email=f"test-user-{name}@example.test",
            is_active=is_active,
        )
        UserProfile.objects.update_or_create(user=user, defaults={"wordpress_id": wordpress_id})
        return user

    def _dispatch(self):
        """Run the Beat task; return (result, chunk signatures, apply_async mock)."""
        captured = {}
        queued = mock.Mock()

        def fake_chain(*signatures):
            captured["signatures"] = list(signatures)
            return mock.Mock(apply_async=queued)

        with mock.patch.object(tasks, "chain", side_effect=fake_chain):
            result = tasks.sync_all_user_moodle_enrollments()
        return result, captured.get("signatures", []), queued

    def test_chunk_size_keeps_each_task_far_under_the_soft_limit(self):
        # About 1.05 s per WordPress call on prod: 25 users is about 30 s, against 240 s.
        self.assertEqual(tasks.ENROLLMENT_SYNC_CHUNK_SIZE, 25)

    def test_queues_linked_active_users_in_id_order_as_one_chain(self):
        linked = [self._user(f"linked-{i}", wordpress_id=100 + i) for i in range(5)]
        self._user("inactive", wordpress_id=200, is_active=False)
        self._user("unlinked", wordpress_id=None)
        User.objects.create_user(username="test-user-no-profile", email="test-user-no-profile@example.test")

        with mock.patch.object(tasks, "ENROLLMENT_SYNC_CHUNK_SIZE", 2):
            result, signatures, queued = self._dispatch()

        ids = sorted(u.id for u in linked)
        self.assertEqual(result, {"users": 5, "chunks": 3})
        self.assertEqual([s.task for s in signatures], [CHUNK_TASK_NAME] * 3)
        self.assertEqual(
            [s.args for s in signatures],
            [(ids[0:2], 1, 3), (ids[2:4], 2, 3), (ids[4:5], 3, 3)],
        )
        # Immutable, so one chunk's return value is not passed into the next chunk.
        self.assertTrue(all(s.immutable for s in signatures))
        queued.assert_called_once_with()
        # Queueing makes no WordPress calls; the chunks do.
        self.assertEqual(self.client_fake.requested_wp_ids, [])

    def test_no_linked_users_queues_nothing(self):
        self._user("unlinked", wordpress_id=None)

        result, signatures, queued = self._dispatch()

        self.assertEqual(result, {"users": 0, "chunks": 0})
        self.assertEqual(signatures, [])
        queued.assert_not_called()

    def test_unconfigured_edwiser_skips_without_queueing(self):
        self._user("linked", wordpress_id=101)

        with mock.patch.object(tasks, "get_edwiser_client", side_effect=ValueError("EB_WP_API_URL is not configured")):
            result, signatures, queued = self._dispatch()

        self.assertEqual(result, {"skipped": True})
        self.assertEqual(signatures, [])
        queued.assert_not_called()

    def test_chunk_syncs_only_its_users_and_skips_users_changed_since_queueing(self):
        first = self._user("first", wordpress_id=101)
        second = self._user("second", wordpress_id=102)
        deactivated = self._user("deactivated", wordpress_id=103)
        unlinked = self._user("unlinked-later", wordpress_id=104)
        outside_chunk = self._user("outside", wordpress_id=105)
        User.objects.filter(pk=deactivated.pk).update(is_active=False)
        UserProfile.objects.filter(user=unlinked).update(wordpress_id=None)

        result = tasks.sync_user_moodle_enrollments_chunk(
            [second.id, first.id, deactivated.id, unlinked.id], 2, 9
        )

        self.assertEqual(result, {"chunk": 2, "chunks": 9, "users": 2, "enrollments": 2, "failed": 0})
        self.assertEqual(self.client_fake.requested_wp_ids, [101, 102])
        self.assertEqual(
            set(MoodleEnrollment.objects.values_list("user_id", flat=True)),
            {first.id, second.id},
        )
        self.assertFalse(MoodleEnrollment.objects.filter(user=outside_chunk).exists())

    def test_full_chain_syncs_every_linked_user(self):
        users = [self._user(f"linked-{i}", wordpress_id=300 + i) for i in range(5)]

        with mock.patch.object(tasks, "ENROLLMENT_SYNC_CHUNK_SIZE", 2):
            _, signatures, _ = self._dispatch()
        last = real_chain(*signatures).apply()  # runs each chunk in-process, in order

        self.assertEqual(last.get(), {"chunk": 3, "chunks": 3, "users": 1, "enrollments": 1, "failed": 0})
        self.assertEqual(self.client_fake.requested_wp_ids, [300, 301, 302, 303, 304])
        enrolled = MoodleEnrollment.objects.filter(course__moodle_id=7)
        self.assertEqual(set(enrolled.values_list("user_id", flat=True)), {u.id for u in users})
        self.assertEqual(set(enrolled.values_list("progress", flat=True)), {50.0})

    def test_failed_chunk_stops_the_rest_of_the_chain(self):
        users = [self._user(f"linked-{i}", wordpress_id=400 + i) for i in range(5)]
        ids = sorted(u.id for u in users)
        synced = []

        def sync_or_time_out(client, user):
            if user.id == ids[2]:  # first user of chunk 2
                raise SoftTimeLimitExceeded()
            synced.append(user.id)
            return 0

        with mock.patch.object(tasks, "ENROLLMENT_SYNC_CHUNK_SIZE", 2):
            _, signatures, _ = self._dispatch()
        with mock.patch.object(tasks, "_sync_user_enrollments", side_effect=sync_or_time_out):
            with self.assertRaises(SoftTimeLimitExceeded):
                real_chain(*signatures).apply()

        # Chunk 1 ran; chunk 2 stopped at its first user; chunk 3 never started.
        self.assertEqual(synced, ids[0:2])
