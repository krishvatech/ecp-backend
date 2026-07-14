from datetime import timedelta

from django.contrib.auth.models import User
from django.utils import timezone
from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework import status

from community.models import Community
from events.models import (
    Event,
    EventSession,
    EventSessionBookmark,
    SessionAttendance,
    SessionBreak,
    SessionParticipant,
)
from events.views import EventSessionViewSet, SessionBreakViewSet


class EventSessionSoftDeleteTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.admin = User.objects.create_superuser(
            username="session-admin",
            email="session-admin@example.com",
            password="pass1234",
        )
        self.attendee = User.objects.create_user(
            username="session-attendee",
            email="session-attendee@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(name="Session Test Community", owner=self.admin)
        now = timezone.now()
        self.event = Event.objects.create(
            community=self.community,
            title="Session Soft Delete Event",
            slug="session-soft-delete-event",
            created_by=self.admin,
            status="published",
            start_time=now,
            end_time=now + timedelta(hours=4),
        )
        self.session = EventSession.objects.create(
            event=self.event,
            title="Preserved Session",
            description="History must remain",
            start_time=now + timedelta(minutes=15),
            end_time=now + timedelta(hours=1),
            recording_url="https://example.com/recording.mp4",
            rtk_meeting_id="meeting-session-1",
        )
        self.break_obj = SessionBreak.objects.create(
            session=self.session,
            label="Coffee",
            break_type="coffee",
            duration_minutes=10,
        )
        self.participant = SessionParticipant.objects.create(
            session=self.session,
            participant_type="guest",
            role="speaker",
            guest_name="Guest Speaker",
        )
        self.attendance = SessionAttendance.objects.create(
            session=self.session,
            user=self.attendee,
            is_online=False,
        )
        self.bookmark = EventSessionBookmark.objects.create(
            event=self.event,
            session=self.session,
            user=self.attendee,
        )

    def test_delete_soft_deletes_session_and_preserves_history(self):
        view = EventSessionViewSet.as_view({"delete": "destroy"})
        request = self.factory.delete(
            "/api/events/%s/sessions/%s/" % (self.event.id, self.session.id),
            {"reason": "Removed from programme"},
            format="json",
        )
        force_authenticate(request, user=self.admin)
        response = view(request, event_id=self.event.id, pk=self.session.id)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["code"] == "session_soft_deleted"
        assert not EventSession.objects.filter(id=self.session.id).exists()

        stored = EventSession.all_objects.get(id=self.session.id)
        assert stored.is_deleted is True
        assert stored.deletion_reason == "Removed from programme"
        assert stored.rtk_meeting_id == "meeting-session-1"
        assert stored.recording_url == "https://example.com/recording.mp4"
        assert SessionParticipant.objects.filter(id=self.participant.id).exists()
        assert SessionAttendance.objects.filter(id=self.attendance.id).exists()
        assert EventSessionBookmark.objects.filter(id=self.bookmark.id).exists()

        stored_break = SessionBreak.all_objects.get(id=self.break_obj.id)
        assert stored_break.is_deleted is True
        assert stored_break.deleted_with_session is True

    def test_live_session_cannot_be_deleted(self):
        self.session.is_live = True
        self.session.save(update_fields=["is_live"])

        view = EventSessionViewSet.as_view({"delete": "destroy"})
        request = self.factory.delete(
            "/api/events/%s/sessions/%s/" % (self.event.id, self.session.id),
            {},
            format="json",
        )
        force_authenticate(request, user=self.admin)
        response = view(request, event_id=self.event.id, pk=self.session.id)

        assert response.status_code == status.HTTP_409_CONFLICT
        assert response.data["code"] == "session_is_live"
        assert EventSession.objects.filter(id=self.session.id).exists()

    def test_break_delete_keeps_database_row(self):
        view = SessionBreakViewSet.as_view({"delete": "destroy"})
        request = self.factory.delete(
            "/api/events/%s/sessions/%s/breaks/%s/"
            % (self.event.id, self.session.id, self.break_obj.id),
            {"reason": "Programme updated"},
            format="json",
        )
        force_authenticate(request, user=self.admin)
        response = view(
            request,
            event_id=self.event.id,
            session_pk=self.session.id,
            pk=self.break_obj.id,
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data["code"] == "session_break_soft_deleted"
        assert not SessionBreak.objects.filter(id=self.break_obj.id).exists()
        stored = SessionBreak.all_objects.get(id=self.break_obj.id)
        assert stored.is_deleted is True
        assert stored.deleted_with_session is False
