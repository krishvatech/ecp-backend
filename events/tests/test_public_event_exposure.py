"""
Regression tests for anonymous exposure of event data.

Production verification found the public event endpoints returning speaker
email addresses, and shipping the external-streaming password and host link in
list, detail and public payloads (empty at the time, but a leak as soon as an
organizer fills them in).

Covered here:
- the anonymous event list carries no streaming credentials;
- anonymous event detail and the public landing payload carry no participant
  email, no streaming credentials and no room identifiers;
- event managers still receive everything their management screens need;
- the anonymous application lookup answers with a status only.
"""

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient
from django.test import TestCase

from community.models import Community
from events.models import (
    Event,
    EventApplication,
    EventParticipant,
    EventPlatform,
    EventPublication,
    EventRegistration,
    EventSession,
    SessionParticipant,
)


User = get_user_model()

SECRET_PASSWORD = "streaming-pass-should-never-be-public"  # noqa: S105 - test fixture
HOST_LINK = "https://zoom.example.com/host/secret-link"
MEETING_ID = "meeting-id-987654321"
SPEAKER_EMAIL = "guest-speaker@example.com"


class PublicEventExposureTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.owner = User.objects.create_user(
            username="event-owner",
            email="event-owner@example.com",
            password="pass1234",
        )
        self.outsider = User.objects.create_user(
            username="event-outsider",
            email="event-outsider@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(
            name="Event Exposure Community",
            owner=self.owner,
        )
        self.platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect",
            defaults={"name": "IMAA Connect", "is_active": True},
        )

        self.event = self._make_event()
        self.session = EventSession.objects.create(
            event=self.event,
            title="Opening session",
            session_date=timezone.now().date(),
            start_time=timezone.now() + timezone.timedelta(days=1),
            end_time=timezone.now() + timezone.timedelta(days=1, hours=1),
        )
        EventParticipant.objects.create(
            event=self.event,
            participant_type=EventParticipant.PARTICIPANT_TYPE_GUEST,
            guest_name="Guest Speaker",
            guest_email=SPEAKER_EMAIL,
            role="speaker",
        )
        SessionParticipant.objects.create(
            session=self.session,
            participant_type=EventParticipant.PARTICIPANT_TYPE_GUEST,
            guest_name="Guest Speaker",
            guest_email=SPEAKER_EMAIL,
            role="speaker",
        )

    def _make_event(self):
        event = Event(
            community=self.community,
            created_by=self.owner,
            title="Public Exposure Event",
            slug="public-exposure-event",
            description="Regression test event",
            status="published",
            start_time=timezone.now() + timezone.timedelta(days=1),
            end_time=timezone.now() + timezone.timedelta(days=1, hours=2),
            is_free=True,
            format="virtual",
            use_external_streaming=True,
            external_streaming_platform="zoom",
            external_streaming_url="https://zoom.example.com/j/123",
            external_streaming_meeting_id=MEETING_ID,
            external_streaming_password=SECRET_PASSWORD,
            external_streaming_host_link=HOST_LINK,
            rtk_meeting_id="rtk-meeting-abc123",
        )
        event.skip_saleor_sync = True
        event.save()
        EventPublication.objects.get_or_create(
            event=event,
            platform=self.platform,
            defaults={"is_enabled": True},
        )
        return event

    @staticmethod
    def _body_text(resp) -> str:
        return resp.content.decode()

    # ---------------- list ----------------

    def test_anonymous_event_list_has_no_streaming_credentials(self):
        """No credentials and no meeting identifier in the anonymous list."""
        resp = self.client.get("/api/events/?limit=50")
        self.assertEqual(resp.status_code, 200)

        body = resp.json()
        rows = body["results"] if isinstance(body, dict) else body
        row = next(r for r in rows if r["id"] == self.event.id)

        for field in (
            "external_streaming_password",
            "external_streaming_host_link",
            "external_streaming_meeting_id",
        ):
            self.assertNotIn(field, row, f"{field} must not be in the public event list")

        text = self._body_text(resp)
        self.assertNotIn(SECRET_PASSWORD, text)
        self.assertNotIn(HOST_LINK, text)
        self.assertNotIn(MEETING_ID, text)

    # ---------------- detail ----------------

    def test_anonymous_event_detail_hides_participant_email(self):
        resp = self.client.get(f"/api/events/{self.event.id}/")
        self.assertEqual(resp.status_code, 200)

        body = resp.json()
        speakers = body["event_participants"]["speakers"]
        self.assertTrue(speakers, "speaker should still be listed")
        self.assertIsNone(speakers[0]["email"])
        self.assertEqual(speakers[0]["name"], "Guest Speaker")
        self.assertNotIn(SPEAKER_EMAIL, self._body_text(resp))

    def test_anonymous_event_detail_hides_session_participant_email(self):
        resp = self.client.get(f"/api/events/{self.event.id}/")
        self.assertEqual(resp.status_code, 200)

        sessions = resp.json()["sessions"]
        listed = [
            participant
            for session in sessions
            for group in session["session_participants"].values()
            for participant in group
        ]
        self.assertTrue(listed, "session speaker should still be listed")
        for participant in listed:
            self.assertIsNone(participant["email"])

    def test_anonymous_event_detail_hides_streaming_credentials_and_room_ids(self):
        resp = self.client.get(f"/api/events/{self.event.id}/")
        body = resp.json()

        self.assertNotIn("external_streaming_password", body)
        self.assertNotIn("external_streaming_host_link", body)
        self.assertNotIn("rtk_meeting_id", body)
        self.assertNotIn(SECRET_PASSWORD, self._body_text(resp))
        self.assertNotIn(HOST_LINK, self._body_text(resp))

    def test_anonymous_event_detail_keeps_public_platform_metadata_only(self):
        """
        The platform is advertised publicly ("this event runs on Zoom"), but the
        join URL is joining material and follows the /streaming-link/ rule.
        """
        body = self.client.get(f"/api/events/{self.event.id}/").json()

        self.assertTrue(body["use_external_streaming"])
        self.assertEqual(body["external_streaming_platform"], "zoom")
        self.assertNotIn("external_streaming_url", body)
        self.assertNotIn("external_streaming_meeting_id", body)

    def test_authenticated_outsider_is_treated_as_public(self):
        self.client.force_authenticate(self.outsider)
        resp = self.client.get(f"/api/events/{self.event.id}/")

        self.assertNotIn(SECRET_PASSWORD, self._body_text(resp))
        self.assertNotIn(SPEAKER_EMAIL, self._body_text(resp))

    def test_event_manager_still_receives_management_fields(self):
        self.client.force_authenticate(self.owner)
        resp = self.client.get(f"/api/events/{self.event.id}/")
        body = resp.json()

        self.assertEqual(body["external_streaming_password"], SECRET_PASSWORD)
        self.assertEqual(body["external_streaming_host_link"], HOST_LINK)
        self.assertEqual(body["rtk_meeting_id"], "rtk-meeting-abc123")
        self.assertEqual(
            body["event_participants"]["speakers"][0]["email"],
            SPEAKER_EMAIL,
        )

    def test_staff_still_receives_management_fields(self):
        staff = User.objects.create_user(
            username="event-staff",
            email="event-staff@example.com",
            password="pass1234",
            is_staff=True,
        )
        self.client.force_authenticate(staff)
        body = self.client.get(f"/api/events/{self.event.id}/").json()

        self.assertEqual(body["external_streaming_password"], SECRET_PASSWORD)
        self.assertEqual(
            body["event_participants"]["speakers"][0]["email"],
            SPEAKER_EMAIL,
        )

    # ---------------- public landing payload ----------------

    def test_public_event_endpoint_has_no_credentials_or_email(self):
        resp = self.client.get(f"/api/events/public/{self.event.slug}/")
        self.assertEqual(resp.status_code, 200)

        body = resp.json()
        self.assertEqual(body["slug"], self.event.slug)
        self.assertNotIn("external_streaming_password", body)
        self.assertNotIn("external_streaming_host_link", body)
        self.assertNotIn("external_streaming_meeting_id", body)
        self.assertNotIn("rtk_meeting_id", body)
        self.assertNotIn(SECRET_PASSWORD, self._body_text(resp))
        self.assertNotIn(HOST_LINK, self._body_text(resp))
        self.assertNotIn(SPEAKER_EMAIL, self._body_text(resp))

    def test_public_event_endpoint_still_lists_speakers(self):
        body = self.client.get(f"/api/events/public/{self.event.slug}/").json()

        self.assertTrue(body["speakers"])
        self.assertEqual(body["speakers"][0]["name"], "Guest Speaker")


class AttendeeEventListExposureTests(TestCase):
    """
    /api/events/mine/ serves an attendee's own events through
    MyEventCardSerializer (?view=card) and EventLiteSerializer. Both are behind
    IsAuthenticated, but a plain attendee is not a manager, so neither may carry
    the streaming password or host link.
    """

    def setUp(self):
        self.client = APIClient()
        self.owner = User.objects.create_user(
            username="mine-owner",
            email="mine-owner@example.com",
            password="pass1234",
        )
        self.attendee = User.objects.create_user(
            username="mine-attendee",
            email="mine-attendee@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(name="Mine Community", owner=self.owner)
        self.platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect",
            defaults={"name": "IMAA Connect", "is_active": True},
        )

        event = Event(
            community=self.community,
            created_by=self.owner,
            title="Mine Exposure Event",
            slug="mine-exposure-event",
            status="published",
            start_time=timezone.now() + timezone.timedelta(days=1),
            end_time=timezone.now() + timezone.timedelta(days=1, hours=2),
            is_free=True,
            format="virtual",
            use_external_streaming=True,
            external_streaming_platform="zoom",
            external_streaming_url="https://zoom.example.com/j/123",
            external_streaming_meeting_id=MEETING_ID,
            external_streaming_password=SECRET_PASSWORD,
            external_streaming_host_link=HOST_LINK,
        )
        event.skip_saleor_sync = True
        event.save()
        EventPublication.objects.get_or_create(
            event=event,
            platform=self.platform,
            defaults={"is_enabled": True},
        )
        self.event = event

        EventRegistration.objects.create(
            event=event,
            user=self.attendee,
            status="registered",
            attendee_status="confirmed",
        )

    def _rows(self, resp):
        body = resp.json()
        rows = body["results"] if isinstance(body, dict) else body
        return [r for r in rows if r.get("id") == self.event.id]

    def test_attendee_card_view_has_no_streaming_credentials(self):
        self.client.force_authenticate(self.attendee)
        resp = self.client.get("/api/events/mine/?view=card")
        self.assertEqual(resp.status_code, 200)

        rows = self._rows(resp)
        self.assertTrue(rows, "attendee should still see their registered event")
        self.assertNotIn("external_streaming_password", rows[0])
        self.assertNotIn("external_streaming_host_link", rows[0])
        self.assertNotIn(SECRET_PASSWORD, resp.content.decode())
        self.assertNotIn(HOST_LINK, resp.content.decode())

    def test_attendee_lite_view_has_no_streaming_credentials(self):
        self.client.force_authenticate(self.attendee)
        resp = self.client.get("/api/events/mine/")
        self.assertEqual(resp.status_code, 200)

        rows = self._rows(resp)
        self.assertTrue(rows, "attendee should still see their registered event")
        self.assertNotIn("external_streaming_password", rows[0])
        self.assertNotIn("external_streaming_host_link", rows[0])
        self.assertNotIn(SECRET_PASSWORD, resp.content.decode())
        self.assertNotIn(HOST_LINK, resp.content.decode())

    def test_attendee_keeps_the_join_details_they_need(self):
        self.client.force_authenticate(self.attendee)
        rows = self._rows(self.client.get("/api/events/mine/?view=card"))

        self.assertEqual(rows[0]["external_streaming_url"], "https://zoom.example.com/j/123")
        self.assertEqual(rows[0]["external_streaming_meeting_id"], MEETING_ID)

    def test_event_owner_still_receives_streaming_credentials(self):
        self.client.force_authenticate(self.owner)
        EventRegistration.objects.create(
            event=self.event,
            user=self.owner,
            status="registered",
            attendee_status="confirmed",
        )

        rows = self._rows(self.client.get("/api/events/mine/?view=card"))
        self.assertTrue(rows, "owner should see the event they run")
        self.assertEqual(rows[0]["external_streaming_password"], SECRET_PASSWORD)
        self.assertEqual(rows[0]["external_streaming_host_link"], HOST_LINK)

    def test_anonymous_cannot_reach_the_endpoint_at_all(self):
        resp = self.client.get("/api/events/mine/?view=card")
        self.assertIn(resp.status_code, (401, 403))


class JoinInformationBoundaryTests(TestCase):
    """
    Joining material must not be obtainable from the serializers when
    /streaming-link/ itself would refuse it (K5), and the per-session fields
    must follow their event-level rules (K1, K2).
    """

    JOIN_URL = "https://zoom.example.com/j/boundary-123"
    SESSION_RTK = "session-rtk-meeting-id-xyz"
    SESSION_RECORDING = "https://recordings.example.com/session-private.mp4"

    def setUp(self):
        # The event list endpoint caches responses per user+query for 45s, so a
        # payload cached by another test class would otherwise be served here.
        cache.clear()

        self.client = APIClient()
        self.owner = User.objects.create_user(
            username="jb-owner", email="jb-owner@example.com", password="pass1234",
        )
        self.attendee = User.objects.create_user(
            username="jb-attendee", email="jb-attendee@example.com", password="pass1234",
        )
        self.outsider = User.objects.create_user(
            username="jb-outsider", email="jb-outsider@example.com", password="pass1234",
        )
        self.host_participant = User.objects.create_user(
            username="jb-host", email="jb-host@example.com", password="pass1234",
        )
        self.community = Community.objects.create(name="Join Boundary Community", owner=self.owner)
        self.platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect", defaults={"name": "IMAA Connect", "is_active": True},
        )

        event = Event(
            community=self.community,
            created_by=self.owner,
            title="Join Boundary Event",
            slug="join-boundary-event",
            status="published",
            start_time=timezone.now() + timezone.timedelta(days=1),
            end_time=timezone.now() + timezone.timedelta(days=1, hours=2),
            is_free=True,
            format="virtual",
            use_external_streaming=True,
            external_streaming_platform="zoom",
            external_streaming_url=self.JOIN_URL,
            external_streaming_meeting_id=MEETING_ID,
            rtk_meeting_id="event-rtk-meeting-id",
            # No event-level recording here: an event that has one while
            # replay_visible_to_participants is False is hidden from plain
            # attendees by EventViewSet.get_queryset (pre-existing rule). The
            # replay tests below set it explicitly.
            replay_visible_to_participants=False,
        )
        event.skip_saleor_sync = True
        event.save()
        EventPublication.objects.get_or_create(
            event=event, platform=self.platform, defaults={"is_enabled": True},
        )
        self.event = event

        self.session = EventSession.objects.create(
            event=event,
            title="Boundary session",
            session_date=timezone.now().date(),
            start_time=timezone.now() + timezone.timedelta(days=1),
            end_time=timezone.now() + timezone.timedelta(days=1, hours=1),
            rtk_meeting_id=self.SESSION_RTK,
            recording_url=self.SESSION_RECORDING,
        )

        EventRegistration.objects.create(
            event=event, user=self.attendee, status="registered", attendee_status="confirmed",
        )
        EventParticipant.objects.create(
            event=event,
            participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
            user=self.host_participant,
            role="host",
        )

    # ---------------- helpers ----------------

    def _detail(self):
        return self.client.get(f"/api/events/{self.event.id}/")

    def _sessions_of(self, body):
        return body.get("sessions") or []

    def _assert_no_join_material(self, resp):
        text = resp.content.decode()
        for secret in (self.JOIN_URL, MEETING_ID, self.SESSION_RTK, self.SESSION_RECORDING):
            self.assertNotIn(secret, text)

    # ---------------- 1, 2, 5, 6: anonymous event detail ----------------

    def test_anonymous_event_detail_has_no_join_url_or_meeting_id(self):
        resp = self._detail()
        self.assertEqual(resp.status_code, 200)

        body = resp.json()
        self.assertNotIn("external_streaming_url", body)
        self.assertNotIn("external_streaming_meeting_id", body)
        self.assertNotIn(self.JOIN_URL, resp.content.decode())
        self.assertNotIn(MEETING_ID, resp.content.decode())

    def test_anonymous_session_output_has_no_rtk_meeting_id_or_recording_url(self):
        body = self._detail().json()
        sessions = self._sessions_of(body)

        self.assertTrue(sessions, "sessions must still be listed publicly")
        for session in sessions:
            self.assertNotIn("rtk_meeting_id", session)
            self.assertNotIn("recording_url", session)
        self._assert_no_join_material(self._detail())

    def test_anonymous_session_keeps_schedule_fields(self):
        session = self._sessions_of(self._detail().json())[0]

        self.assertEqual(session["title"], "Boundary session")
        self.assertIn("start_time", session)
        self.assertIn("end_time", session)
        self.assertIn("session_type", session)

    # ---------------- 3, 4: public endpoint and list ----------------

    def test_anonymous_public_event_response_has_no_join_url(self):
        resp = self.client.get(f"/api/events/public/{self.event.slug}/")
        self.assertEqual(resp.status_code, 200)

        body = resp.json()
        self.assertNotIn("external_streaming_url", body)
        self._assert_no_join_material(resp)

    def test_anonymous_event_list_has_no_join_url(self):
        resp = self.client.get("/api/events/?limit=50")
        self.assertEqual(resp.status_code, 200)

        rows = resp.json().get("results", [])
        row = next(r for r in rows if r["id"] == self.event.id)
        self.assertNotIn("external_streaming_url", row)
        self._assert_no_join_material(resp)

    # ---------------- 7: unrelated authenticated user ----------------

    def test_unrelated_authenticated_user_gets_no_join_material(self):
        self.client.force_authenticate(self.outsider)

        for resp in (
            self._detail(),
            self.client.get(f"/api/events/public/{self.event.slug}/"),
            self.client.get("/api/events/?limit=50"),
        ):
            self.assertEqual(resp.status_code, 200)
            self._assert_no_join_material(resp)

    # ---------------- 8: registered attendee ----------------

    def test_registered_attendee_receives_join_fields(self):
        self.client.force_authenticate(self.attendee)
        body = self._detail().json()

        self.assertEqual(body["external_streaming_url"], self.JOIN_URL)
        self.assertEqual(body["external_streaming_meeting_id"], MEETING_ID)
        self.assertEqual(self._sessions_of(body)[0]["rtk_meeting_id"], self.SESSION_RTK)

    def test_registered_attendee_still_has_no_private_session_recording(self):
        """replay_visible_to_participants is off, so the replay stays hidden."""
        self.client.force_authenticate(self.attendee)
        resp = self._detail()
        body = resp.json()

        self.assertNotIn("recording_url", self._sessions_of(body)[0])
        self.assertIsNone(body.get("recording_url"))
        self.assertNotIn(self.SESSION_RECORDING, resp.content.decode())

    def test_registered_attendee_sees_join_url_in_the_list(self):
        self.client.force_authenticate(self.attendee)
        rows = self.client.get("/api/events/?limit=50").json()["results"]
        row = next(r for r in rows if r["id"] == self.event.id)

        self.assertEqual(row["external_streaming_url"], self.JOIN_URL)

    # ---------------- 9: host and manager ----------------

    def test_assigned_host_receives_join_and_session_material(self):
        self.client.force_authenticate(self.host_participant)
        body = self._detail().json()

        self.assertEqual(body["external_streaming_url"], self.JOIN_URL)
        self.assertEqual(body["external_streaming_meeting_id"], MEETING_ID)
        self.assertEqual(self._sessions_of(body)[0]["rtk_meeting_id"], self.SESSION_RTK)

    def test_manager_receives_everything_including_recordings(self):
        self.client.force_authenticate(self.owner)
        body = self._detail().json()

        self.assertEqual(body["external_streaming_url"], self.JOIN_URL)
        self.assertEqual(body["external_streaming_meeting_id"], MEETING_ID)
        session = self._sessions_of(body)[0]
        self.assertEqual(session["rtk_meeting_id"], self.SESSION_RTK)
        self.assertEqual(session["recording_url"], self.SESSION_RECORDING)
        self.assertEqual(body["rtk_meeting_id"], "event-rtk-meeting-id")

    # ---------------- 10: legitimate replay access ----------------

    def _publish_replay(self):
        self.event.recording_url = "https://recordings.example.com/event.mp4"
        self.event.replay_visible_to_participants = True
        self.event.skip_saleor_sync = True
        self.event.save()

    def test_attendee_sees_recordings_once_replay_is_published(self):
        self._publish_replay()

        self.client.force_authenticate(self.attendee)
        body = self._detail().json()

        self.assertEqual(body["recording_url"], "https://recordings.example.com/event.mp4")
        self.assertEqual(self._sessions_of(body)[0]["recording_url"], self.SESSION_RECORDING)

    def test_anonymous_never_sees_recordings_even_when_published(self):
        self._publish_replay()

        resp = self._detail()
        body = resp.json()
        self.assertIsNone(body.get("recording_url"))
        self.assertNotIn("recording_url", self._sessions_of(body)[0])
        self.assertNotIn(self.SESSION_RECORDING, resp.content.decode())

    # ---------------- native branch ----------------

    def test_native_event_sessions_follow_the_same_boundary(self):
        self.event.use_external_streaming = False
        self.event.skip_saleor_sync = True
        self.event.save()

        anon = self._detail().json()
        self.assertNotIn("rtk_meeting_id", self._sessions_of(anon)[0])
        self.assertNotIn("rtk_meeting_id", anon)

        self.client.force_authenticate(self.attendee)
        registered = self._detail().json()
        self.assertEqual(self._sessions_of(registered)[0]["rtk_meeting_id"], self.SESSION_RTK)


class StreamingLinkAccessTests(TestCase):
    """
    GET /api/events/<id>/streaming-link/ hands out joining details.

    It used to be AllowAny and returned the host link to every caller,
    including anonymous ones. It now requires a login, limits the host link to
    people who actually run the event, and keeps the password with managers.
    """

    def setUp(self):
        self.client = APIClient()
        self.owner = User.objects.create_user(
            username="sl-owner",
            email="sl-owner@example.com",
            password="pass1234",
        )
        self.attendee = User.objects.create_user(
            username="sl-attendee",
            email="sl-attendee@example.com",
            password="pass1234",
        )
        self.outsider = User.objects.create_user(
            username="sl-outsider",
            email="sl-outsider@example.com",
            password="pass1234",
        )
        self.host_participant = User.objects.create_user(
            username="sl-host",
            email="sl-host@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(name="Streaming Community", owner=self.owner)
        self.platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect",
            defaults={"name": "IMAA Connect", "is_active": True},
        )

        event = Event(
            community=self.community,
            created_by=self.owner,
            title="Streaming Link Event",
            slug="streaming-link-event",
            status="published",
            start_time=timezone.now() + timezone.timedelta(days=1),
            end_time=timezone.now() + timezone.timedelta(days=1, hours=2),
            is_free=True,
            format="virtual",
            use_external_streaming=True,
            external_streaming_platform="zoom",
            external_streaming_url="https://zoom.example.com/j/123",
            external_streaming_meeting_id=MEETING_ID,
            external_streaming_password=SECRET_PASSWORD,
            external_streaming_host_link=HOST_LINK,
        )
        event.skip_saleor_sync = True
        event.save()
        EventPublication.objects.get_or_create(
            event=event,
            platform=self.platform,
            defaults={"is_enabled": True},
        )
        self.event = event
        self.url = f"/api/events/{event.id}/streaming-link/"

        EventRegistration.objects.create(
            event=event,
            user=self.attendee,
            status="registered",
            attendee_status="confirmed",
        )
        EventParticipant.objects.create(
            event=event,
            participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
            user=self.host_participant,
            role="host",
        )

    # ---------------- anonymous ----------------

    def test_anonymous_caller_is_rejected(self):
        resp = self.client.get(self.url)
        self.assertIn(resp.status_code, (401, 403))

    def test_anonymous_caller_receives_no_host_link_or_password(self):
        text = self.client.get(self.url).content.decode()

        self.assertNotIn(HOST_LINK, text)
        self.assertNotIn(SECRET_PASSWORD, text)

    # ---------------- guest principal ----------------

    def _guest_principal(self, email):
        from events.guest_auth import GuestPrincipal
        from events.models import GuestAttendee

        guest = GuestAttendee.objects.create(
            event=self.event,
            email=email,
            first_name="Gwen",
            last_name="Guest",
            email_verified=True,
        )
        return GuestPrincipal(guest)

    def test_guest_principal_gets_join_details_but_no_credentials(self):
        self.client.force_authenticate(self._guest_principal("sl-guest@example.com"))
        resp = self.client.get(self.url)

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["join_url"], "https://zoom.example.com/j/123")
        self.assertIsNone(body["host_link"])
        self.assertIsNone(body["password"])

    def test_guest_of_another_event_is_denied(self):
        """A valid guest token is access to its own event, not to every event."""
        from events.guest_auth import GuestPrincipal
        from events.models import GuestAttendee

        other_event = Event(
            community=self.community,
            created_by=self.owner,
            title="Other Event",
            slug="streaming-link-other-event",
            status="published",
            start_time=timezone.now() + timezone.timedelta(days=2),
            end_time=timezone.now() + timezone.timedelta(days=2, hours=1),
            is_free=True,
            format="virtual",
        )
        other_event.skip_saleor_sync = True
        other_event.save()
        foreign_guest = GuestAttendee.objects.create(
            event=other_event,
            email="sl-foreign-guest@example.com",
            first_name="Fern",
            last_name="Foreign",
            email_verified=True,
        )

        self.client.force_authenticate(GuestPrincipal(foreign_guest))
        resp = self.client.get(self.url)

        # The viewset queryset already scopes a guest to the event their token
        # was issued for, so this is refused as 404 before the access gate is
        # reached; the gate returns 403 for any guest that slips past it.
        self.assertIn(resp.status_code, (403, 404))
        text = resp.content.decode()
        self.assertNotIn("https://zoom.example.com/j/123", text)
        self.assertNotIn(MEETING_ID, text)
        self.assertNotIn(HOST_LINK, text)
        self.assertNotIn(SECRET_PASSWORD, text)

    def test_guest_assigned_as_host_receives_the_host_link(self):
        """A guest speaker holding the host role is a legitimate host."""
        EventParticipant.objects.create(
            event=self.event,
            participant_type=EventParticipant.PARTICIPANT_TYPE_GUEST,
            guest_name="Gwen Guest",
            guest_email="sl-guest-host@example.com",
            role="host",
        )
        self.client.force_authenticate(self._guest_principal("sl-guest-host@example.com"))

        body = self.client.get(self.url).json()
        self.assertEqual(body["host_link"], HOST_LINK)
        self.assertIsNone(body["password"], "a host is not automatically a manager")

    # ---------------- attendees and outsiders ----------------

    def test_registered_attendee_receives_only_join_information(self):
        self.client.force_authenticate(self.attendee)
        resp = self.client.get(self.url)

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["join_url"], "https://zoom.example.com/j/123")
        self.assertEqual(body["meeting_id"], MEETING_ID)
        self.assertIsNone(body["host_link"])
        self.assertIsNone(body["password"])
        self.assertNotIn(HOST_LINK, resp.content.decode())
        self.assertNotIn(SECRET_PASSWORD, resp.content.decode())

    def test_unrelated_authenticated_user_is_denied_entirely(self):
        """Holding an account is not a relationship with this event."""
        self.client.force_authenticate(self.outsider)
        resp = self.client.get(self.url)

        self.assertEqual(resp.status_code, 403)
        text = resp.content.decode()
        self.assertNotIn("https://zoom.example.com/j/123", text)
        self.assertNotIn(MEETING_ID, text)
        self.assertNotIn(HOST_LINK, text)
        self.assertNotIn(SECRET_PASSWORD, text)

    def test_cancelled_registration_is_denied(self):
        cancelled_user = User.objects.create_user(
            username="sl-cancelled",
            email="sl-cancelled@example.com",
            password="pass1234",
        )
        EventRegistration.objects.create(
            event=self.event,
            user=cancelled_user,
            status="cancelled",
            attendee_status="confirmed",
        )
        self.client.force_authenticate(cancelled_user)

        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn("https://zoom.example.com/j/123", resp.content.decode())

    def test_banned_registration_is_denied(self):
        banned_user = User.objects.create_user(
            username="sl-banned",
            email="sl-banned@example.com",
            password="pass1234",
        )
        EventRegistration.objects.create(
            event=self.event,
            user=banned_user,
            status="registered",
            attendee_status="confirmed",
            is_banned=True,
        )
        self.client.force_authenticate(banned_user)

        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn("https://zoom.example.com/j/123", resp.content.decode())

    # ---------------- hosts and managers ----------------

    def test_assigned_host_receives_the_host_link_but_not_the_password(self):
        self.client.force_authenticate(self.host_participant)
        body = self.client.get(self.url).json()

        self.assertEqual(body["host_link"], HOST_LINK)
        self.assertIsNone(body["password"])

    def test_event_manager_receives_host_link_and_password(self):
        self.client.force_authenticate(self.owner)
        body = self.client.get(self.url).json()

        self.assertEqual(body["host_link"], HOST_LINK)
        self.assertEqual(body["password"], SECRET_PASSWORD)

    def test_platform_staff_receives_host_link_and_password(self):
        staff = User.objects.create_user(
            username="sl-staff",
            email="sl-staff@example.com",
            password="pass1234",
            is_staff=True,
        )
        self.client.force_authenticate(staff)
        body = self.client.get(self.url).json()

        self.assertEqual(body["host_link"], HOST_LINK)
        self.assertEqual(body["password"], SECRET_PASSWORD)

    # ---------------- native branch still works ----------------

    def _switch_to_native(self):
        self.event.use_external_streaming = False
        self.event.rtk_meeting_id = "rtk-meeting-abc123"
        self.event.skip_saleor_sync = True
        self.event.save()

    def test_native_streaming_branch_unchanged_for_attendee(self):
        self._switch_to_native()

        self.client.force_authenticate(self.attendee)
        body = self.client.get(self.url).json()

        self.assertEqual(body["type"], "native")
        self.assertEqual(body["platform_name"], "Our Platform (RTK)")
        self.assertEqual(body["meeting_id"], "rtk-meeting-abc123")

    def test_native_streaming_branch_applies_the_same_access_boundary(self):
        """The RTK meeting id is joining material too."""
        self._switch_to_native()

        self.client.force_authenticate(self.outsider)
        resp = self.client.get(self.url)

        self.assertEqual(resp.status_code, 403)
        self.assertNotIn("rtk-meeting-abc123", resp.content.decode())

    def test_native_streaming_branch_denies_a_guest_of_another_event(self):
        from events.guest_auth import GuestPrincipal
        from events.models import GuestAttendee

        self._switch_to_native()
        other_event = Event(
            community=self.community,
            created_by=self.owner,
            title="Other Native Event",
            slug="streaming-link-other-native",
            status="published",
            start_time=timezone.now() + timezone.timedelta(days=2),
            end_time=timezone.now() + timezone.timedelta(days=2, hours=1),
            is_free=True,
            format="virtual",
        )
        other_event.skip_saleor_sync = True
        other_event.save()
        foreign_guest = GuestAttendee.objects.create(
            event=other_event,
            email="sl-native-foreign@example.com",
            first_name="Fern",
            last_name="Foreign",
            email_verified=True,
        )

        self.client.force_authenticate(GuestPrincipal(foreign_guest))
        resp = self.client.get(self.url)

        # 404 from the queryset scoping, 403 from the access gate: either way
        # no joining material is returned.
        self.assertIn(resp.status_code, (403, 404))
        self.assertNotIn("rtk-meeting-abc123", resp.content.decode())


class AnonymousApplicationLookupTests(TestCase):
    """GET /api/events/<id>/apply/?email= must answer with a status only."""

    def setUp(self):
        self.client = APIClient()
        self.owner = User.objects.create_user(
            username="apply-owner",
            email="apply-owner@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(
            name="Apply Exposure Community",
            owner=self.owner,
        )
        self.platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect",
            defaults={"name": "IMAA Connect", "is_active": True},
        )

        event = Event(
            community=self.community,
            created_by=self.owner,
            title="Apply Exposure Event",
            slug="apply-exposure-event",
            status="published",
            start_time=timezone.now() + timezone.timedelta(days=1),
            end_time=timezone.now() + timezone.timedelta(days=1, hours=2),
            is_free=True,
            registration_type="apply",
        )
        event.skip_saleor_sync = True
        event.save()
        EventPublication.objects.get_or_create(
            event=event,
            platform=self.platform,
            defaults={"is_enabled": True},
        )
        self.event = event

        self.applicant_email = "applicant@example.com"
        self.application = EventApplication.objects.create(
            event=event,
            first_name="Ada",
            last_name="Applicant",
            email=self.applicant_email,
            phone="+10000000001",
            linkedin_url="https://linkedin.example.com/in/ada",
            company_name="Applicant Corp",
            location="Berlin",
            comments="Please let me in, here is my private note.",
            status="pending",
        )

    def test_anonymous_lookup_returns_status_only(self):
        resp = self.client.get(
            f"/api/events/{self.event.id}/apply/?email={self.applicant_email}"
        )
        self.assertEqual(resp.status_code, 200)

        body = resp.json()
        self.assertEqual(set(body.keys()), {"status", "application_status"})
        self.assertEqual(body["status"], "pending")

    def test_anonymous_lookup_returns_no_applicant_pii(self):
        resp = self.client.get(
            f"/api/events/{self.event.id}/apply/?email={self.applicant_email}"
        )
        text = resp.content.decode()

        for leaked in (
            self.applicant_email,
            "+10000000001",
            "linkedin.example.com",
            "Applicant Corp",
            "private note",
            "Ada",
        ):
            self.assertNotIn(leaked, text)

    def test_unknown_email_reports_none(self):
        resp = self.client.get(
            f"/api/events/{self.event.id}/apply/?email=nobody@example.com"
        )
        self.assertEqual(resp.json(), {"status": "none"})

    def test_authenticated_applicant_still_receives_their_application(self):
        applicant = User.objects.create_user(
            username="apply-user",
            email="apply-user@example.com",
            password="pass1234",
        )
        EventApplication.objects.create(
            event=self.event,
            user=applicant,
            first_name="Uri",
            last_name="User",
            email=applicant.email,
            phone="+10000000002",
            status="pending",
        )
        self.client.force_authenticate(applicant)

        body = self.client.get(f"/api/events/{self.event.id}/apply/").json()
        self.assertEqual(body["email"], applicant.email)
        self.assertEqual(body["phone"], "+10000000002")
