"""No guest OTP email for in-person events or for already-registered members."""
from unittest.mock import patch

from rest_framework import status

from events.models import EventRegistration, GuestAttendee
from events.tests.test_participant_email_rules import OTP_SENT, ParticipantEmailRulesBase, User


class GuestOtpBlockTests(ParticipantEmailRulesBase):
    def setUp(self):
        super().setUp()
        self.payload = {"first_name": "Guest", "last_name": "Person", "email": "guest@example.com"}

    def post(self, path, payload):
        with patch("events.guest_views.send_guest_otp", return_value=OTP_SENT) as send:
            response = self.client.post(f"/api/events/{self.event.id}/{path}/", payload, format="json")
        return response, send

    def register_member(self, email):
        member = User.objects.create_user(username="member", email=email, password="test-pass-123")
        EventRegistration.objects.create(event=self.event, user=member, status="registered")

    def test_in_person_event_refuses_guest_join_without_otp(self):
        self.event.format = "in_person"
        self.event.save(update_fields=["format"])

        response, send = self.post("guest-join", self.payload)

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.data["error"], "in_person_event")
        send.assert_not_called()
        self.assertFalse(GuestAttendee.objects.filter(event=self.event).exists())

    def test_in_person_event_refuses_otp_resend(self):
        self.event.format = "in_person"
        self.event.save(update_fields=["format"])

        response, send = self.post("guest-resend-otp", {"email": "guest@example.com"})

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.data["error"], "in_person_event")
        send.assert_not_called()

    def test_registered_member_email_refuses_guest_join(self):
        self.register_member("Guest@Example.com")

        response, send = self.post("guest-join", self.payload)

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.data["error"], "account_exists")
        send.assert_not_called()
        self.assertFalse(GuestAttendee.objects.filter(event=self.event).exists())

    def test_registered_member_email_refuses_otp_resend(self):
        self.register_member("guest@example.com")

        response, send = self.post("guest-resend-otp", {"email": "guest@example.com"})

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        send.assert_not_called()

    def test_cancelled_registration_does_not_block_guest_join(self):
        self.register_member("guest@example.com")
        EventRegistration.objects.filter(event=self.event).update(status="cancelled")

        response, send = self.post("guest-join", self.payload)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        send.assert_called_once()

    def test_hybrid_event_still_sends_guest_otp(self):
        self.event.format = "hybrid"
        self.event.save(update_fields=["format"])

        response, send = self.post("guest-join", self.payload)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        send.assert_called_once()
