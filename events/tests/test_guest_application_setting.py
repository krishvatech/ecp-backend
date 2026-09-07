from django.contrib.auth import get_user_model
from rest_framework import status
from unittest.mock import patch
from rest_framework.test import APITestCase

from community.models import Community
from events.models import Event, EventApplication, EventApplicationTrack


User = get_user_model()


class GuestApplicationSettingTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="guest-app-owner",
            email="owner@example.com",
            password="test-pass-123",
        )
        self.community = Community.objects.create(
            name="Guest Application Test Community",
            slug="guest-application-test-community",
            owner=self.owner,
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Application Event",
            slug="application-event",
            registration_type="apply",
            status="published",
            created_by=self.owner,
        )
        self.track = EventApplicationTrack.objects.create(
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
            "location": "United Kingdom",
            "phone": "+44 20 0000 0000",
        }

    def test_guest_applications_are_enabled_by_default(self):
        self.assertTrue(self.event.allow_guest_applications)

        response = self.client.post(self.url, self.payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        application = EventApplication.objects.get(event=self.event, email="guest@example.com")
        self.assertIsNone(application.user_id)
        self.assertEqual(application.status, "pending")
        self.assertEqual(application.location, "United Kingdom")
        self.assertEqual(application.phone, "+44 20 0000 0000")

    def test_guest_application_is_blocked_when_setting_is_disabled(self):
        self.event.allow_guest_applications = False
        self.event.save(update_fields=["allow_guest_applications"])

        response = self.client.post(self.url, self.payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data.get("code"), "authentication_required")
        self.assertFalse(EventApplication.objects.filter(event=self.event, email="guest@example.com").exists())

    def test_authenticated_application_still_works_when_guest_setting_is_disabled(self):
        self.event.allow_guest_applications = False
        self.event.save(update_fields=["allow_guest_applications"])
        applicant = User.objects.create_user(
            username="signed-in-applicant",
            email="member@example.com",
            password="test-pass-123",
            first_name="Signed",
            last_name="Applicant",
        )
        self.client.force_authenticate(user=applicant)

        with patch(
            "events.views.EventViewSet._get_missing_lead_gen_fields",
            return_value=(True, {}),
        ):
            response = self.client.post(
                self.url,
                {**self.payload, "email": applicant.email},
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        application = EventApplication.objects.get(event=self.event, email=applicant.email)
        self.assertEqual(application.user_id, applicant.id)
