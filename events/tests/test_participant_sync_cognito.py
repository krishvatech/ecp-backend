from django.contrib.auth.models import User
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APITestCase

from community.models import Community
from users.models import CognitoIdentity

from events.models import (
    Event,
    EventPlatform,
    EventPublication,
    EventRegistration,
    ExternalParticipantMapping,
    MANDA_PLATFORM_SLUG,
    PlatformSyncJob,
)
from events.participant_sync import enqueue_participant_cancel, enqueue_participant_upsert


@override_settings(
    MANDA_INTEGRATION_SECRET="test-secret",
    EVENT_PLATFORM_SYNC_TRIGGER_ON_COMMIT=False,
)
class ImaaParticipantSyncCognitoTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner@example.com", "owner@example.com", "pass")
        self.member = User.objects.create_user("member@example.com", "member@example.com", "pass")
        self.community = Community.objects.create(name="Sync Community", slug="sync-community", owner=self.owner)
        self.event = Event.objects.create(
            title="Shared Event",
            community=self.community,
            status="published",
            start_time=timezone.now() + timezone.timedelta(days=7),
        )
        self.manda_platform = EventPlatform.objects.create(slug=MANDA_PLATFORM_SLUG, name="MANDA", is_active=True)
        EventPublication.objects.create(event=self.event, platform=self.manda_platform, is_enabled=True)

    def _payload_from_manda(self, cognito_sub="sub-123", source_id="att-101"):
        return {
            "source_platform": "manda",
            "source_attendee_id": source_id,
            "source_event_id": "55",
            "canonical_event_id": str(self.event.canonical_event_id),
            "cognito_sub": cognito_sub,
            "email": "member@example.com",
            "name": "Member Name",
            "status": "confirmed",
        }

    def test_local_registration_with_cognito_creates_manda_participant_upsert_job(self):
        CognitoIdentity.objects.create(
            user=self.member,
            cognito_sub="sub-123",
            email=self.member.email,
            email_verified=True,
        )
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.member,
            status="registered",
            attendee_status="confirmed",
        )

        created_jobs = enqueue_participant_upsert(registration)

        self.assertEqual(len(created_jobs), 1)
        job = created_jobs[0]
        self.assertEqual(job.platform.slug, MANDA_PLATFORM_SLUG)
        self.assertEqual(job.job_type, PlatformSyncJob.JobType.PARTICIPANT_UPSERT)
        self.assertEqual(job.payload["canonical_event_id"], str(self.event.canonical_event_id))
        self.assertEqual(job.payload["cognito_sub"], "sub-123")
        self.assertEqual(job.payload["source_registration_id"], str(registration.id))

    def test_local_registration_without_cognito_does_not_sync(self):
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.member,
            status="registered",
            attendee_status="confirmed",
        )

        created_jobs = enqueue_participant_upsert(registration)

        self.assertEqual(created_jobs, [])
        self.assertEqual(PlatformSyncJob.objects.count(), 0)

    def test_cancelled_registration_creates_manda_participant_cancel_job(self):
        CognitoIdentity.objects.create(user=self.member, cognito_sub="sub-123", email=self.member.email)
        registration = EventRegistration.objects.create(event=self.event, user=self.member)

        created_jobs = enqueue_participant_cancel(registration)

        self.assertEqual(len(created_jobs), 1)
        self.assertEqual(created_jobs[0].job_type, PlatformSyncJob.JobType.PARTICIPANT_CANCEL)
        self.assertEqual(created_jobs[0].payload["status"], "cancelled")

    def test_inbound_manda_upsert_is_idempotent_and_cancel_marks_registration_cancelled(self):
        CognitoIdentity.objects.create(user=self.member, cognito_sub="sub-123", email=self.member.email)
        headers = {"HTTP_X_MANDA_INTEGRATION_SECRET": "test-secret"}
        payload = self._payload_from_manda()

        first = self.client.post("/api/integrations/manda/participants/upsert/", payload, format="json", **headers)
        second = self.client.post("/api/integrations/manda/participants/upsert/", payload, format="json", **headers)

        self.assertEqual(first.status_code, 201, first.content)
        self.assertEqual(second.status_code, 200, second.content)
        self.assertEqual(EventRegistration.objects.filter(event=self.event, user=self.member).count(), 1)
        registration = EventRegistration.objects.get(event=self.event, user=self.member)
        self.assertEqual(registration.status, "registered")
        self.assertEqual(registration.attendee_status, "confirmed")
        mapping = ExternalParticipantMapping.objects.get(source_participant_id="att-101")
        self.assertEqual(mapping.local_registration, registration)
        self.assertTrue(mapping.is_active)

        cancel = self.client.post(
            "/api/integrations/manda/participants/cancel/",
            {
                "source_platform": "manda",
                "source_attendee_id": "att-101",
                "canonical_event_id": str(self.event.canonical_event_id),
                "cognito_sub": "sub-123",
                "status": "cancelled",
            },
            format="json",
            **headers,
        )

        self.assertEqual(cancel.status_code, 200, cancel.content)
        registration.refresh_from_db()
        mapping.refresh_from_db()
        self.assertEqual(registration.status, "cancelled")
        self.assertEqual(registration.attendee_status, "cancelled")
        self.assertFalse(mapping.is_active)

    def test_inbound_manda_upsert_rejects_missing_cognito_user(self):
        headers = {"HTTP_X_MANDA_INTEGRATION_SECRET": "test-secret"}
        response = self.client.post(
            "/api/integrations/manda/participants/upsert/",
            self._payload_from_manda(cognito_sub="unknown-sub"),
            format="json",
            **headers,
        )

        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(EventRegistration.objects.filter(event=self.event).count(), 0)
