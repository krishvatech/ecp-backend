"""Editing a Participant Information form that was already submitted.

Sentry ECP-BACKEND-M (2026-11-09): POST /api/post-acceptance-form-assignments/<pk>/submit/
allows an attendee to edit a completed form until ``editable_until`` (or, when that is
empty, until the event starts). The view saved the new answers, then always called
``mark_assignment_completed()``, which refuses a form that is already completed. The
request returned a 500 and the transaction rolled the edit back, so every edit was lost.

transaction.on_commit callbacks (form emails, form triggers) do not run inside
TestCase, so nothing is sent during these tests.
"""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from community.models import Community
from events.models import (
    Event, EventRegistration, PostAcceptanceFormAnswer,
    PostAcceptanceFormAssignment, PostAcceptanceFormTemplate,
)

# A valid in-person Participant Information submission (the Sentry request had 9 answers).
FIRST_ANSWERS = {
    "accessibility_support_needs": "no",
    "emergency_contact_name": "Test Contact",
    "emergency_contact_phone": "+1 555 0100",
    "emergency_contact_relationship": "friend",
    "share_contact_details": "yes",
    "photo_video_consent": "yes",
    "food_allergies": ["none"],
    "dietary_restrictions": ["none"],
    "visa_support": "not_required",
}


class EditSubmittedParticipantFormTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user(username="pafe-owner", password="pass")
        self.attendee = User.objects.create_user(username="pafe-attendee", email="pafe-attendee@example.com")
        self.community = Community.objects.create(name="pafe community", owner=self.owner)

        self.event = Event(
            title="Form edit summit", community=self.community, created_by=self.owner,
            format="in_person", status="published", timezone="UTC",
            start_time=timezone.now() + timedelta(days=1),
            end_time=timezone.now() + timedelta(days=1, hours=8),
        )
        self.event.skip_saleor_sync = True
        self.event.save()

        # In-person events auto-create this template with the real schema (events/signals.py).
        self.template, _ = PostAcceptanceFormTemplate.objects.get_or_create(
            event=self.event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            defaults={"question_schema": {"sections": []}},
        )
        self.registration = EventRegistration.objects.create(event=self.event, user=self.attendee)
        self.assignment = PostAcceptanceFormAssignment.objects.create(
            event=self.event,
            form_template=self.template,
            event_registration=self.registration,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            deadline=timezone.now() + timedelta(days=7),
        )

        self.client = APIClient()
        self.client.force_authenticate(self.attendee)

    # ---- helpers ----

    def submit(self, answers):
        return self.client.post(
            f"/api/post-acceptance-form-assignments/{self.assignment.id}/submit/",
            {"answers": answers}, format="json",
        )

    def submit_first_time(self):
        res = self.submit(FIRST_ANSWERS)
        self.assertEqual(res.status_code, 201, res.content)
        self.assignment.refresh_from_db()
        self.assertEqual(self.assignment.status, PostAcceptanceFormAssignment.STATUS_COMPLETED)
        return self.assignment.completed_at

    def answer(self, key):
        return PostAcceptanceFormAnswer.objects.get(
            submission__assignment=self.assignment, question_key=key,
        ).answer_text

    # ---- tests ----

    def test_template_uses_real_participant_schema(self):
        # Guard: the edit tests below validate against the real auto-created schema.
        self.assertTrue(self.template.question_schema.get("sections"))

    def test_first_submission_completes_form(self):
        completed_at = self.submit_first_time()
        self.assertIsNotNone(completed_at)
        self.assertEqual(self.answer("photo_video_consent"), "yes")
        self.registration.refresh_from_db()
        self.assertEqual(self.registration.photo_video_consent, "full")
        self.assertTrue(self.registration.directory_visibility)

    def test_edit_before_event_start_saves_changes(self):
        """The ECP-BACKEND-M case: completed form, editable_until empty, event not started."""
        completed_at = self.submit_first_time()
        answers_before = PostAcceptanceFormAnswer.objects.filter(
            submission__assignment=self.assignment).count()

        edited = {**FIRST_ANSWERS, "photo_video_consent": "no", "share_contact_details": "no"}
        res = self.submit(edited)

        self.assertEqual(res.status_code, 201, res.content)
        self.assertEqual(self.answer("photo_video_consent"), "no")
        self.assertEqual(self.answer("share_contact_details"), "no")
        # Answers are updated in place, not duplicated.
        self.assertEqual(
            PostAcceptanceFormAnswer.objects.filter(submission__assignment=self.assignment).count(),
            answers_before,
        )
        # The form stays completed and keeps its first completion time.
        self.assignment.refresh_from_db()
        self.assertEqual(self.assignment.status, PostAcceptanceFormAssignment.STATUS_COMPLETED)
        self.assertEqual(self.assignment.completed_at, completed_at)
        # The edit reaches the registration (writeback runs again).
        self.registration.refresh_from_db()
        self.assertEqual(self.registration.photo_video_consent, "no")
        self.assertFalse(self.registration.directory_visibility)

    def test_edit_can_be_repeated(self):
        self.submit_first_time()
        for consent in ("no", "yes", "no"):
            res = self.submit({**FIRST_ANSWERS, "photo_video_consent": consent})
            self.assertEqual(res.status_code, 201, res.content)
            self.assertEqual(self.answer("photo_video_consent"), consent)

    def test_edit_within_editable_until_saves_changes(self):
        self.submit_first_time()
        PostAcceptanceFormAssignment.objects.filter(pk=self.assignment.pk).update(
            editable_until=timezone.now() + timedelta(hours=2))

        res = self.submit({**FIRST_ANSWERS, "visa_support": "required",
                           "visa_support_details": "Invitation letter"})

        self.assertEqual(res.status_code, 201, res.content)
        self.assertEqual(self.answer("visa_support"), "required")
        self.registration.refresh_from_db()
        self.assertTrue(self.registration.visa_support_requested)

    def test_edit_after_editable_until_is_refused(self):
        self.submit_first_time()
        PostAcceptanceFormAssignment.objects.filter(pk=self.assignment.pk).update(
            editable_until=timezone.now() - timedelta(minutes=1))

        res = self.submit({**FIRST_ANSWERS, "photo_video_consent": "no"})

        self.assertEqual(res.status_code, 400)
        self.assertIn("Cannot submit form", res.json()["error"])
        self.assertEqual(self.answer("photo_video_consent"), "yes")

    def test_edit_after_event_start_is_refused(self):
        self.submit_first_time()
        Event.objects.filter(pk=self.event.pk).update(start_time=timezone.now() - timedelta(minutes=1))

        res = self.submit({**FIRST_ANSWERS, "photo_video_consent": "no"})

        self.assertEqual(res.status_code, 400)
        self.assertIn("Cannot submit form", res.json()["error"])
        self.assertEqual(self.answer("photo_video_consent"), "yes")

    def test_invalid_edit_keeps_previous_answers(self):
        self.submit_first_time()

        res = self.submit({**FIRST_ANSWERS, "photo_video_consent": ""})

        self.assertEqual(res.status_code, 400)
        self.assertIn("photo_video_consent", res.json()["errors"])
        self.assertEqual(self.answer("photo_video_consent"), "yes")
        self.assignment.refresh_from_db()
        self.assertEqual(self.assignment.status, PostAcceptanceFormAssignment.STATUS_COMPLETED)

    def test_other_users_cannot_edit(self):
        self.submit_first_time()
        other = get_user_model().objects.create_user(username="pafe-other")
        client = APIClient()
        client.force_authenticate(other)

        res = client.post(
            f"/api/post-acceptance-form-assignments/{self.assignment.id}/submit/",
            {"answers": {**FIRST_ANSWERS, "photo_video_consent": "no"}}, format="json",
        )

        self.assertEqual(res.status_code, 404)
        self.assertEqual(self.answer("photo_video_consent"), "yes")
