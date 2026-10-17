"""Guest join and event applications use the same email rules as signup."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase

from community.models import Community
from events.models import (
    IMAA_CONNECT_PLATFORM_SLUG,
    Event,
    EventApplication,
    EventApplicationTrack,
    EventPlatform,
    EventPublication,
    GuestAttendee,
)
from users.disposable_email import DISPOSABLE_EMAIL_CODE, DISPOSABLE_EMAIL_MESSAGE, INVALID_EMAIL_CODE


User = get_user_model()

OTP_SENT = {"success": True, "otp_required": True, "message": "Verification code sent"}


class ParticipantEmailRulesBase(APITestCase):
    registration_type = "open"

    def setUp(self):
        self.owner = User.objects.create_user(
            username="email-rules-owner",
            email="owner@example.com",
            password="test-pass-123",
        )
        self.community = Community.objects.create(
            name="Email Rules Community",
            slug="email-rules-community",
            owner=self.owner,
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Email Rules Event",
            slug="email-rules-event",
            registration_type=self.registration_type,
            status="published",
            created_by=self.owner,
        )
        # Event lookups only see events published on IMAA Connect.
        platform, _ = EventPlatform.objects.get_or_create(
            slug=IMAA_CONNECT_PLATFORM_SLUG, defaults={"name": "IMAA Connect"}
        )
        EventPublication.objects.create(event=self.event, platform=platform, is_enabled=True)


class GuestJoinEmailRulesTests(ParticipantEmailRulesBase):
    def setUp(self):
        super().setUp()
        self.url = f"/api/events/{self.event.id}/guest-join/"
        self.payload = {"first_name": "Guest", "last_name": "Person", "email": "guest@example.com"}

    def post(self, email):
        with patch("events.guest_views.send_guest_otp", return_value=OTP_SENT) as send:
            response = self.client.post(self.url, {**self.payload, "email": email}, format="json")
        return response, send

    def test_regular_email_is_accepted(self):
        response, send = self.post("guest@example.com")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        send.assert_called_once()
        self.assertTrue(GuestAttendee.objects.filter(event=self.event, email="guest@example.com").exists())

    def test_disposable_email_is_refused_before_otp(self):
        response, send = self.post("someone@mailinator.com")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["code"], DISPOSABLE_EMAIL_CODE)
        self.assertEqual(response.data["error"], DISPOSABLE_EMAIL_MESSAGE)
        send.assert_not_called()
        self.assertFalse(GuestAttendee.objects.filter(event=self.event).exists())

    def test_disposable_subdomain_is_refused(self):
        response, send = self.post("someone@inbox.mailinator.com")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["code"], DISPOSABLE_EMAIL_CODE)
        send.assert_not_called()

    def test_malformed_email_is_refused(self):
        for email in ("sifoka", "a@b", "guest@exa_mple.com"):
            with self.subTest(email=email):
                response, send = self.post(email)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertEqual(response.data["code"], INVALID_EMAIL_CODE)
                send.assert_not_called()

    def test_lookalike_domain_is_not_refused(self):
        response, _ = self.post("guest@mailinator.company")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_existing_user_with_listed_domain_is_not_refused(self):
        User.objects.create_user(username="legacy", email="legacy@mailinator.com", password="x-pass-123")

        response, send = self.post("Legacy@Mailinator.com")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        send.assert_called_once()

    @override_settings(DISPOSABLE_EMAIL_VALIDATION_ENABLED=False)
    def test_kill_switch_allows_disposable_but_not_malformed(self):
        response, _ = self.post("someone@mailinator.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response, _ = self.post("sifoka")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ApplicationEmailRulesTests(ParticipantEmailRulesBase):
    registration_type = "apply"

    def setUp(self):
        super().setUp()
        EventApplicationTrack.objects.create(
            event=self.event,
            key="participant",
            label="Participant",
            enabled_submission_modes=["self_submission"],
            status="open",
            is_active=True,
        )
        self.url = f"/api/events/{self.event.id}/apply/"
        self.payload = {
            "first_name": "Guest",
            "last_name": "Applicant",
            "email": "guest@example.com",
            "job_title": "Director",
            "company_name": "Example Ltd",
        }

    def post(self, email):
        return self.client.post(self.url, {**self.payload, "email": email}, format="json")

    def test_regular_email_is_accepted(self):
        response = self.post("guest@example.com")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_disposable_guest_application_is_refused(self):
        response = self.post("someone@mailinator.com")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["code"], DISPOSABLE_EMAIL_CODE)
        self.assertEqual(response.data["detail"], DISPOSABLE_EMAIL_MESSAGE)
        self.assertEqual(response.data["email"], [DISPOSABLE_EMAIL_MESSAGE])
        self.assertFalse(EventApplication.objects.filter(event=self.event).exists())

    def test_strictly_malformed_email_is_refused(self):
        response = self.post("guest@exa_mple.com")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)
        self.assertFalse(EventApplication.objects.filter(event=self.event).exists())

    def test_signed_in_user_cannot_apply_with_a_new_disposable_email(self):
        member = User.objects.create_user(username="member", email="member@example.com", password="x-pass-123")
        self.client.force_authenticate(user=member)

        with patch("events.views.EventViewSet._get_missing_lead_gen_fields", return_value=(True, {})):
            response = self.post("other@mailinator.com")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["code"], DISPOSABLE_EMAIL_CODE)

    def test_existing_account_with_listed_domain_can_still_apply(self):
        legacy = User.objects.create_user(username="legacy", email="legacy@mailinator.com", password="x-pass-123")
        self.client.force_authenticate(user=legacy)

        with patch("events.views.EventViewSet._get_missing_lead_gen_fields", return_value=(True, {})):
            response = self.post(legacy.email)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
