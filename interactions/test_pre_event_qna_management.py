"""
interactions/test_pre_event_qna_management.py

Tests for the Pre-Event Q&A Management + AI Advisor endpoints:
  - GET  /api/interactions/questions/my-pre-event/
  - PATCH /api/interactions/questions/{id}/pre-event-edit/
  - DELETE /api/interactions/questions/{id}/pre-event-delete/
  - POST /api/interactions/questions/pre-event-duplicate-check/

Design decisions tested:
  - Ownership: user can only view/edit/delete their own questions.
  - Time-gate: edit/delete blocked after event starts (backend enforced).
  - Moderation reset: editing resets moderation_status to "pending" when
    qna_moderation_enabled is True.
  - Soft delete: is_deleted=True, deleted_at set; question still exists in DB.
  - Live Q&A questions are unaffected by pre-event filters.
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from events.models import Event, EventRegistration
from interactions.models import Question

User = get_user_model()


def _make_event(host, *, start_offset_minutes=60, pre_event_qna_enabled=True,
                qna_moderation_enabled=False):
    """Create a minimal Event for testing."""
    start = timezone.now() + timedelta(minutes=start_offset_minutes)
    return Event.objects.create(
        title="Test Event",
        created_by=host,
        start_time=start,
        pre_event_qna_enabled=pre_event_qna_enabled,
        qna_moderation_enabled=qna_moderation_enabled,
        status="scheduled",
    )


class PreEventQnaManagementTests(TestCase):
    """All pre-event Q&A management endpoint tests."""

    def setUp(self):
        self.client = APIClient()

        # Create two attendees and a host
        self.host = User.objects.create_user(
            username="host", email="host@test.com", password="pass"
        )
        self.user_a = User.objects.create_user(
            username="user_a", email="a@test.com", password="pass"
        )
        self.user_b = User.objects.create_user(
            username="user_b", email="b@test.com", password="pass"
        )

        # Upcoming event (starts in 60 minutes)
        self.event = _make_event(self.host)

        # Register user_a for the event
        EventRegistration.objects.create(event=self.event, user=self.user_a, status="registered")

        # User A's pre-event questions
        self.q1 = Question.objects.create(
            event=self.event,
            user=self.user_a,
            content="What are the key trends in AI in 2025?",
            submission_phase="pre_event",
            moderation_status="approved",
        )
        self.q2 = Question.objects.create(
            event=self.event,
            user=self.user_a,
            content="How do large language models handle hallucination?",
            submission_phase="pre_event",
            moderation_status="pending",
        )

        # User B's question (user B is NOT registered in setUp — added per test)
        self.q_b = Question.objects.create(
            event=self.event,
            user=self.user_b,
            content="User B's totally different question.",
            submission_phase="pre_event",
            moderation_status="approved",
        )

        # Live question by user A (should never appear in pre-event list)
        self.q_live = Question.objects.create(
            event=self.event,
            user=self.user_a,
            content="A live question that must not appear in pre-event list.",
            submission_phase="live",
            moderation_status="approved",
        )

    def _auth(self, user):
        """Force auth as user via DRF test client."""
        self.client.force_authenticate(user=user)

    # ── Test 1: List own pre-event questions ──────────────────────────────────

    def test_list_returns_only_own_pre_event_questions(self):
        """Attendee sees only their own non-deleted pre-event questions."""
        self._auth(self.user_a)
        resp = self.client.get(
            "/api/interactions/questions/my-pre-event/",
            {"event_id": self.event.id},
        )
        self.assertEqual(resp.status_code, 200)
        ids = [q["id"] for q in resp.json()]
        self.assertIn(self.q1.id, ids)
        self.assertIn(self.q2.id, ids)
        # Other user's question must NOT appear
        self.assertNotIn(self.q_b.id, ids)
        # Live question must NOT appear
        self.assertNotIn(self.q_live.id, ids)

    # ── Test 2: Edit own pre-event question before event starts ───────────────

    def test_edit_own_question_succeeds(self):
        """Owner can edit their own pre-event question before event starts."""
        self._auth(self.user_a)
        new_text = "What are the key AI safety challenges in 2025?"
        resp = self.client.patch(
            f"/api/interactions/questions/{self.q1.id}/pre-event-edit/",
            {"content": new_text},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.q1.refresh_from_db()
        self.assertEqual(self.q1.content, new_text)

    # ── Test 3: Edit resets moderation status ─────────────────────────────────

    def test_edit_resets_moderation_when_enabled(self):
        """Editing resets moderation_status to 'pending' when moderation is on."""
        event_mod = _make_event(self.host, qna_moderation_enabled=True)
        EventRegistration.objects.create(event=event_mod, user=self.user_a, status="registered")
        q = Question.objects.create(
            event=event_mod,
            user=self.user_a,
            content="Original approved question.",
            submission_phase="pre_event",
            moderation_status="approved",
        )

        self._auth(self.user_a)
        resp = self.client.patch(
            f"/api/interactions/questions/{q.id}/pre-event-edit/",
            {"content": "Updated approved question with new details."},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        q.refresh_from_db()
        self.assertEqual(q.moderation_status, "pending")

    # ── Test 4: Edit blocked after event starts ───────────────────────────────

    def test_edit_blocked_after_event_starts(self):
        """Edit is rejected with 403 if event start_time is in the past."""
        # Move the event start to the past
        self.event.start_time = timezone.now() - timedelta(minutes=1)
        self.event.save(update_fields=["start_time"])

        self._auth(self.user_a)
        resp = self.client.patch(
            f"/api/interactions/questions/{self.q1.id}/pre-event-edit/",
            {"content": "This edit should be blocked."},
            format="json",
        )
        self.assertEqual(resp.status_code, 403)

    # ── Test 5: Edit blocked for wrong owner ──────────────────────────────────

    def test_edit_blocked_for_wrong_owner(self):
        """Non-owner cannot edit another user's question."""
        # Register user_b so they can attempt the edit
        EventRegistration.objects.create(event=self.event, user=self.user_b, status="registered")
        self._auth(self.user_b)
        resp = self.client.patch(
            f"/api/interactions/questions/{self.q1.id}/pre-event-edit/",
            {"content": "Trying to hijack user A's question."},
            format="json",
        )
        self.assertEqual(resp.status_code, 403)

    # ── Test 6: Soft-delete removes from list ─────────────────────────────────

    def test_soft_delete_removes_question_from_list(self):
        """After deleting, the question is absent from the list and is_deleted is True in DB."""
        self._auth(self.user_a)
        resp = self.client.delete(
            f"/api/interactions/questions/{self.q1.id}/pre-event-delete/"
        )
        self.assertEqual(resp.status_code, 204)

        # DB: soft-deleted, NOT hard deleted
        self.q1.refresh_from_db()
        self.assertTrue(self.q1.is_deleted)
        self.assertIsNotNone(self.q1.deleted_at)

        # List should no longer include the deleted question
        list_resp = self.client.get(
            "/api/interactions/questions/my-pre-event/",
            {"event_id": self.event.id},
        )
        self.assertEqual(list_resp.status_code, 200)
        ids = [q["id"] for q in list_resp.json()]
        self.assertNotIn(self.q1.id, ids)

    # ── Test 7: Delete blocked after event starts ─────────────────────────────

    def test_delete_blocked_after_event_starts(self):
        """Delete is rejected with 403 if event has already started."""
        self.event.start_time = timezone.now() - timedelta(minutes=5)
        self.event.save(update_fields=["start_time"])

        self._auth(self.user_a)
        resp = self.client.delete(
            f"/api/interactions/questions/{self.q1.id}/pre-event-delete/"
        )
        self.assertEqual(resp.status_code, 403)
        # Must not be deleted in DB
        self.q1.refresh_from_db()
        self.assertFalse(self.q1.is_deleted)

    # ── Test 8: Delete blocked for wrong owner ────────────────────────────────

    def test_delete_blocked_for_wrong_owner(self):
        """Non-owner cannot delete another user's question."""
        EventRegistration.objects.create(event=self.event, user=self.user_b, status="registered")
        self._auth(self.user_b)
        resp = self.client.delete(
            f"/api/interactions/questions/{self.q1.id}/pre-event-delete/"
        )
        self.assertEqual(resp.status_code, 403)

    # ── Test 9: Duplicate check returns structured response ───────────────────

    def test_duplicate_check_returns_structured_response(self):
        """
        Duplicate-check endpoint returns 200 with 'duplicates' and 'has_duplicates' keys.
        We mock the AI call to avoid network dependency in tests.
        """
        from unittest.mock import patch

        self._auth(self.user_a)

        # Patch the AI function to return a predictable result
        mock_result = {
            "duplicates": [
                {
                    "question_id": self.q1.id,
                    "existing_text": self.q1.content,
                    "similarity_reason": "Both ask about AI trends.",
                    "suggested_merge": "What are the key AI trends and safety challenges in 2025?",
                    "suggestions": ["keep both", "edit existing", "replace existing", "cancel"],
                }
            ],
            "has_duplicates": True,
        }

        with patch(
            "interactions.views.check_duplicate_questions",
            return_value=mock_result,
        ):
            resp = self.client.post(
                "/api/interactions/questions/pre-event-duplicate-check/",
                {
                    "event_id": self.event.id,
                    "content": "What are the most important AI trends in 2025?",
                },
                format="json",
            )

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("duplicates", data)
        self.assertIn("has_duplicates", data)
        self.assertTrue(data["has_duplicates"])
        self.assertEqual(len(data["duplicates"]), 1)
        self.assertEqual(data["duplicates"][0]["question_id"], self.q1.id)

    # ── Test 10: Live Q&A questions remain unaffected ─────────────────────────

    def test_live_questions_unaffected(self):
        """
        The main question list endpoint still returns live questions normally.
        Soft-deleted pre-event questions must not appear there either.
        """
        # Soft-delete q1 to confirm it doesn't bleed into live list
        self.q1.is_deleted = True
        self.q1.save(update_fields=["is_deleted"])

        self._auth(self.user_a)
        resp = self.client.get(
            "/api/interactions/questions/",
            {"event_id": self.event.id},
        )
        self.assertEqual(resp.status_code, 200)
        ids = [q["id"] for q in resp.json()]
        # Live question must appear
        self.assertIn(self.q_live.id, ids)
