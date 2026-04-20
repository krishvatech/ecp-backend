"""Tests for post-event Q&A answer feature."""

from django.test import TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

from events.models import Event, EventRegistration
from .models import Question, QuestionUpvote
from .services.post_event_qna_service import (
    publish_post_event_answer,
    resolve_notification_recipients,
)
from friends.models import Notification

User = get_user_model()


class PostEventQnAServiceTests(TestCase):
    """Test the post-event Q&A service functions."""

    def setUp(self):
        # Create users
        self.host = User.objects.create_user(username="host", email="host@example.com", password="pass123")
        self.author = User.objects.create_user(username="author", email="author@example.com", password="pass123")
        self.upvoter1 = User.objects.create_user(username="upvoter1", email="upvoter1@example.com", password="pass123")
        self.upvoter2 = User.objects.create_user(username="upvoter2", email="upvoter2@example.com", password="pass123")
        self.participant = User.objects.create_user(username="participant", email="participant@example.com", password="pass123")

        # Create ended event
        self.event = Event.objects.create(
            title="Test Event",
            slug="test-event",
            created_by=self.host,
            status="ended",
            start_time=timezone.now() - timezone.timedelta(hours=2),
            end_time=timezone.now() - timezone.timedelta(hours=1),
        )

        # Create event registrations
        for user in [self.host, self.author, self.upvoter1, self.upvoter2, self.participant]:
            EventRegistration.objects.create(event=self.event, user=user, status="registered")

        # Create question
        self.question = Question.objects.create(
            event=self.event,
            user=self.author,
            content="How do I implement feature X?",
            is_answered=False,
        )

        # Add upvotes
        QuestionUpvote.objects.create(question=self.question, user=self.upvoter1)
        QuestionUpvote.objects.create(question=self.question, user=self.upvoter2)

    def test_publish_post_event_answer_sets_fields(self):
        """Publishing an answer sets all required fields."""
        answer_text = "Here's how to implement feature X..."
        publish_post_event_answer(self.question, answer_text, self.host)

        # Refresh from DB
        question = Question.objects.get(id=self.question.id)

        # Assert all fields are set correctly
        self.assertEqual(question.answer_text, answer_text)
        self.assertTrue(question.is_answered)
        self.assertEqual(question.answered_by, self.host)
        self.assertEqual(question.answered_phase, "post_event")
        self.assertIsNotNone(question.answered_at)

    def test_resolve_recipients_notify_author_only(self):
        """Resolving recipients with only author notification."""
        recipient_ids = resolve_notification_recipients(
            question=self.question,
            notify_author=True,
            notify_interested=False,
            notify_all_participants=False,
            answering_user=self.host,
        )

        self.assertEqual(set(recipient_ids), {self.author.id})

    def test_resolve_recipients_notify_interested(self):
        """Resolving recipients includes upvoters."""
        recipient_ids = resolve_notification_recipients(
            question=self.question,
            notify_author=True,
            notify_interested=True,
            notify_all_participants=False,
            answering_user=self.host,
        )

        # Should have author + 2 upvoters
        self.assertEqual(
            set(recipient_ids),
            {self.author.id, self.upvoter1.id, self.upvoter2.id}
        )

    def test_resolve_recipients_notify_all(self):
        """Resolving recipients with all participants."""
        recipient_ids = resolve_notification_recipients(
            question=self.question,
            notify_author=True,
            notify_interested=True,
            notify_all_participants=True,
            answering_user=self.host,
        )

        # Should have author + 2 upvoters + participant (4 total, minus host who answered)
        self.assertEqual(
            set(recipient_ids),
            {self.author.id, self.upvoter1.id, self.upvoter2.id, self.participant.id}
        )

    def test_resolve_recipients_deduplicates(self):
        """Resolving recipients deduplicates when author is also upvoter."""
        # Make author also an upvoter
        QuestionUpvote.objects.create(question=self.question, user=self.author)

        recipient_ids = resolve_notification_recipients(
            question=self.question,
            notify_author=True,
            notify_interested=True,
            notify_all_participants=False,
            answering_user=self.host,
        )

        # Should still only have 3 unique recipients (no duplicates)
        self.assertEqual(
            set(recipient_ids),
            {self.author.id, self.upvoter1.id, self.upvoter2.id}
        )

    def test_resolve_recipients_excludes_answering_user(self):
        """Resolving recipients excludes the answering user."""
        # Make host an upvoter
        QuestionUpvote.objects.create(question=self.question, user=self.host)

        recipient_ids = resolve_notification_recipients(
            question=self.question,
            notify_author=True,
            notify_interested=True,
            notify_all_participants=True,
            answering_user=self.host,
        )

        # Host should not be in recipients even though they're a participant and upvoter
        self.assertNotIn(self.host.id, set(recipient_ids))


class PostEventQnAAPITests(TestCase):
    """Test the post-event Q&A API endpoints."""

    def setUp(self):
        self.client = APIClient()

        # Create users
        self.host = User.objects.create_user(username="host", email="host@example.com", password="pass123")
        self.staff = User.objects.create_user(username="staff", email="staff@example.com", password="pass123", is_staff=True)
        self.attendee = User.objects.create_user(username="attendee", email="attendee@example.com", password="pass123")

        # Create events
        self.live_event = Event.objects.create(
            title="Live Event",
            slug="live-event",
            created_by=self.host,
            status="live",
            start_time=timezone.now() - timezone.timedelta(hours=1),
            end_time=timezone.now() + timezone.timedelta(hours=1),
        )

        self.ended_event = Event.objects.create(
            title="Ended Event",
            slug="ended-event",
            created_by=self.host,
            status="ended",
            start_time=timezone.now() - timezone.timedelta(hours=2),
            end_time=timezone.now() - timezone.timedelta(hours=1),
        )

        # Create registrations
        for event in [self.live_event, self.ended_event]:
            for user in [self.host, self.staff, self.attendee]:
                EventRegistration.objects.create(event=event, user=user, status="registered")

        # Create questions
        self.live_question = Question.objects.create(
            event=self.live_event,
            user=self.attendee,
            content="Live event question",
            is_answered=False,
        )

        self.unanswered_question = Question.objects.create(
            event=self.ended_event,
            user=self.attendee,
            content="What's the answer?",
            is_answered=False,
        )

        self.answered_live_question = Question.objects.create(
            event=self.ended_event,
            user=self.attendee,
            content="Already answered live",
            is_answered=True,
            answered_phase="live",
            answered_by=self.host,
            answered_at=timezone.now() - timezone.timedelta(hours=1),
        )

    def test_post_event_answer_blocked_before_event_ends(self):
        """POST /post_event_answer should block if event not ended."""
        self.client.force_authenticate(user=self.host)

        url = f"/api/interactions/questions/{self.live_question.id}/post_event_answer/"
        response = self.client.post(url, {
            "answer_text": "This is an answer",
            "notify_author": True,
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Event must be ended", str(response.data))

    def test_post_event_answer_unauthorized(self):
        """POST /post_event_answer should reject unauthorized users."""
        self.client.force_authenticate(user=self.attendee)

        url = f"/api/interactions/questions/{self.unanswered_question.id}/post_event_answer/"
        response = self.client.post(url, {
            "answer_text": "This is an answer",
            "notify_author": True,
        })

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_post_event_answer_already_answered_live(self):
        """POST /post_event_answer should block if already answered live."""
        self.client.force_authenticate(user=self.host)

        url = f"/api/interactions/questions/{self.answered_live_question.id}/post_event_answer/"
        response = self.client.post(url, {
            "answer_text": "New answer",
            "notify_author": True,
        })

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertIn("already answered during the live event", str(response.data))

    def test_post_event_answer_success(self):
        """POST /post_event_answer should successfully publish answer."""
        self.client.force_authenticate(user=self.host)

        url = f"/api/interactions/questions/{self.unanswered_question.id}/post_event_answer/"
        response = self.client.post(url, {
            "answer_text": "Here's the answer!",
            "notify_author": True,
            "notify_interested_participants": False,
            "notify_all_participants": False,
        })

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify question was updated
        question = Question.objects.get(id=self.unanswered_question.id)
        self.assertTrue(question.is_answered)
        self.assertEqual(question.answer_text, "Here's the answer!")
        self.assertEqual(question.answered_phase, "post_event")
        self.assertEqual(question.answered_by, self.host)

        # Verify notification was created
        notifications = Notification.objects.filter(
            recipient=self.attendee,
            kind="event",
        )
        self.assertEqual(notifications.count(), 1)

    def test_unanswered_endpoint(self):
        """GET /unanswered should list unanswered questions."""
        self.client.force_authenticate(user=self.host)

        response = self.client.get(f"/api/interactions/questions/unanswered/?event_id={self.ended_event.id}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(len(data), 1)  # Only the unanswered question
        self.assertEqual(data[0]["id"], self.unanswered_question.id)

    def test_unanswered_endpoint_unauthorized(self):
        """GET /unanswered should reject unauthorized users."""
        self.client.force_authenticate(user=self.attendee)

        response = self.client.get(f"/api/interactions/questions/unanswered/?event_id={self.ended_event.id}")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_post_event_answered_endpoint(self):
        """GET /post_event_answered should list post-event answered questions."""
        # First answer a question post-event
        publish_post_event_answer(self.unanswered_question, "The answer", self.host)

        self.client.force_authenticate(user=self.host)
        response = self.client.get(f"/api/interactions/questions/post_event_answered/?event_id={self.ended_event.id}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], self.unanswered_question.id)
        self.assertEqual(data[0]["answered_phase"], "post_event")
