"""
Per-track pre-approval code tracking: the exact code used is stored on the
track application and surfaced in the review queue API and CSV export.
"""
import csv
import io
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.management import call_command
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase

from community.models import Community
from events.models import (
    Event,
    EventApplication,
    EventApplicationTrack,
    EventApplicationTrackApplication,
    EventPlatform,
    EventPreApprovalAllowlist,
    EventPreApprovalCode,
    EventPublication,
    IMAA_CONNECT_PLATFORM_SLUG,
)


class PreApprovalCodeTrackingTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.owner = User.objects.create_user(
            username="tracking-owner", email="tracking-owner@example.com", password="Password123!"
        )
        self.community = Community.objects.create(name="Tracking Community", slug="tracking-community", owner=self.owner)
        self.event = Event.objects.create(
            community=self.community,
            title="Tracking Event",
            slug="tracking-event",
            created_by=self.owner,
            registration_type="apply",
            status="published",
            preapproval_code_enabled=True,
            preapproval_allowlist_enabled=True,
        )
        # Event lookups only see events published on IMAA Connect.
        platform, _ = EventPlatform.objects.get_or_create(
            slug=IMAA_CONNECT_PLATFORM_SLUG, defaults={"name": "IMAA Connect"}
        )
        EventPublication.objects.create(event=self.event, platform=platform, is_enabled=True)
        self.sponsor_track = EventApplicationTrack.objects.create(
            event=self.event,
            key="sponsors",
            label="Sponsors Registration",
            status="open",
            is_active=True,
            enabled_submission_modes=["self_submission", "confirmed"],
        )
        self.code = EventPreApprovalCode.objects.create(
            event=self.event,
            track=self.sponsor_track,
            submission_mode="confirmed",
            code="TEST-SPONSOR-001",
            created_by=self.owner,
        )

    def _apply(self, email, mode="confirmed", code=None):
        track_payload = {"track_id": self.sponsor_track.id, "submission_mode": mode}
        if mode == "confirmed":
            track_payload["sponsor_organization"] = "Dummy Sponsor Ltd"
        if code:
            track_payload["pre_approval_code"] = code
        return self.client.post(
            f"/api/events/{self.event.id}/apply/",
            {
                "first_name": "Test",
                "last_name": "Applicant",
                "email": email,
                "job_title": "Test Manager",
                "company_name": "Dummy Company Ltd",
                "track_applications": [track_payload],
            },
            format="json",
        )

    def _review_queue_row(self, email):
        self.client.force_authenticate(self.owner)
        response = self.client.get(f"/api/events/{self.event.id}/review-queue/")
        self.client.force_authenticate(None)
        self.assertEqual(response.status_code, 200, response.data)
        rows = response.data["results"] if isinstance(response.data, dict) else response.data
        return next(row for row in rows if row["applicant_email"] == email)

    def _export_rows(self):
        self.client.force_authenticate(self.owner)
        response = self.client.get(
            f"/api/events/{self.event.id}/review-queue/export/?export_format=csv"
        )
        self.client.force_authenticate(None)
        self.assertEqual(response.status_code, 200)
        return list(csv.DictReader(io.StringIO(response.content.decode())))

    def test_guest_code_is_stored_on_track_application_and_exposed(self):
        response = self._apply("guest.sponsor@example.com", code="TEST-SPONSOR-001")
        self.assertEqual(response.status_code, 201, response.data)

        track_app = EventApplicationTrackApplication.objects.get(application__email="guest.sponsor@example.com")
        self.assertEqual(track_app.preapproval_code, self.code)
        self.assertEqual(track_app.preapproval_source, EventApplication.PREAPPROVAL_SOURCE_CODE)
        self.code.refresh_from_db()
        self.assertEqual(self.code.status, EventPreApprovalCode.STATUS_USED)

        row = self._review_queue_row("guest.sponsor@example.com")
        self.assertIs(row["is_preapproved"], True)
        self.assertEqual(row["preapproval_source"], "code")
        self.assertEqual(row["preapproval_code"], "TEST-SPONSOR-001")

    def test_registered_user_code_is_stored(self):
        user = User.objects.create_user(username="sponsor-staff", email="staff@example.com")
        self.client.force_authenticate(user)
        # Profile completeness and the auto-accept side effects (registration,
        # commerce, emails) are out of scope; only code storage is asserted.
        with patch(
            "events.views.EventViewSet._get_missing_lead_gen_fields", return_value=(True, {})
        ), patch("events.services.application_decisions.accept_track_application") as accept:
            response = self._apply("staff@example.com", code="TEST-SPONSOR-001")
        self.client.force_authenticate(None)
        accept.assert_called_once()
        self.assertEqual(response.status_code, 201, response.data)

        track_app = EventApplicationTrackApplication.objects.get(application__email="staff@example.com")
        self.assertEqual(track_app.preapproval_code, self.code)
        self.assertEqual(self._review_queue_row("staff@example.com")["preapproval_code"], "TEST-SPONSOR-001")

    def test_allowlist_preapproval_has_source_email_and_no_code(self):
        EventPreApprovalAllowlist.objects.create(
            event=self.event,
            track=self.sponsor_track,
            submission_mode="confirmed",
            first_name="Allow",
            last_name="Listed",
            email="allowlisbackfill.guest@example.com",
        )
        response = self._apply("allowlisbackfill.guest@example.com")
        self.assertEqual(response.status_code, 201, response.data)

        row = self._review_queue_row("allowlisbackfill.guest@example.com")
        self.assertIs(row["is_preapproved"], True)
        self.assertEqual(row["preapproval_source"], "email")
        self.assertIsNone(row["preapproval_code"])

    def test_self_submission_is_not_preapproved(self):
        response = self._apply("self@example.com", mode="self_submission")
        self.assertEqual(response.status_code, 201, response.data)

        row = self._review_queue_row("self@example.com")
        # Real boolean (was the string "False", which the UI treated as truthy).
        self.assertIs(row["is_preapproved"], False)
        self.assertEqual(row["preapproval_source"], "none")
        self.assertIsNone(row["preapproval_code"])

    def test_parent_invite_flag_alone_is_not_code_preapproval(self):
        app = EventApplication.objects.create(
            event=self.event,
            first_name="Invited",
            last_name="User",
            email="invibackfill.guest@example.com",
            status="approved",
            is_preapproved=True,
        )
        EventApplicationTrackApplication.objects.create(
            application=app, track=self.sponsor_track, submission_mode="self_submission", status="accepted"
        )
        row = self._review_queue_row("invibackfill.guest@example.com")
        self.assertIs(row["is_preapproved"], False)

    def test_legacy_parent_code_used_as_fallback_for_its_track(self):
        app = EventApplication.objects.create(
            event=self.event,
            first_name="Legacy",
            last_name="Row",
            email="legacy@example.com",
            application_track=self.sponsor_track,
            is_preapproved=True,
            preapproval_source=EventApplication.PREAPPROVAL_SOURCE_CODE,
            preapproval_code=self.code,
        )
        EventApplicationTrackApplication.objects.create(
            application=app, track=self.sponsor_track, submission_mode="confirmed", status="accepted"
        )
        self.assertEqual(self._review_queue_row("legacy@example.com")["preapproval_code"], "TEST-SPONSOR-001")

    def test_csv_export_includes_source_and_code_columns(self):
        self._apply("guest.sponsor@example.com", code="TEST-SPONSOR-001")
        self._apply("self@example.com", mode="self_submission")

        rows = {row["Applicant Email"]: row for row in self._export_rows()}
        self.assertEqual(rows["guest.sponsor@example.com"]["Pre-approved"], "Yes")
        self.assertEqual(rows["guest.sponsor@example.com"]["Pre-approval Source"], "Code")
        self.assertEqual(rows["guest.sponsor@example.com"]["Pre-approved Code"], "TEST-SPONSOR-001")
        self.assertEqual(rows["self@example.com"]["Pre-approved"], "No")
        self.assertEqual(rows["self@example.com"]["Pre-approval Source"], "")
        self.assertEqual(rows["self@example.com"]["Pre-approved Code"], "")

    def test_csv_existing_columns_keep_their_positions(self):
        self._apply("guest.sponsor@example.com", code="TEST-SPONSOR-001")
        self.client.force_authenticate(self.owner)
        response = self.client.get(f"/api/events/{self.event.id}/review-queue/export/?export_format=csv")
        header = next(csv.reader(io.StringIO(response.content.decode())))
        self.assertEqual(header[:14], [
            "ID", "Applicant Email", "Applicant Name", "Track", "Submission Mode",
            "Status", "Tier Preference", "Accepted Tier", "Company", "Job Title",
            "Reviewed By", "Reviewed At", "Created At", "Pre-approved",
        ])
        self.assertEqual(header[14:], ["Pre-approval Source", "Pre-approved Code"])


class BackfillTrackPreApprovalCodesTests(APITestCase):
    def setUp(self):
        owner = User.objects.create_user(username="backfill-owner", email="backfill-owner@example.com")
        community = Community.objects.create(name="Backfill Community", slug="backfill-community", owner=owner)
        self.event = Event.objects.create(
            community=community, title="Backfill Event", slug="backfill-event",
            created_by=owner, registration_type="apply",
        )
        self.sponsor_track = EventApplicationTrack.objects.create(
            event=self.event, key="sponsors", label="Sponsors", status="open",
            is_active=True, enabled_submission_modes=["self_submission", "confirmed"],
        )
        self.end_user_track = EventApplicationTrack.objects.create(
            event=self.event, key="end-user", label="End User", status="open",
            is_active=True, enabled_submission_modes=["self_submission", "confirmed"],
        )

    def _historical(self, email, track, mode, code_value, code_track, used_at):
        app = EventApplication.objects.create(
            event=self.event, first_name="H", last_name="R", email=email
        )
        row = EventApplicationTrackApplication.objects.create(
            application=app, track=track, submission_mode=mode, status="accepted"
        )
        code = EventPreApprovalCode.objects.create(
            event=self.event, track=code_track, submission_mode="confirmed", code=code_value,
            status=EventPreApprovalCode.STATUS_USED, used_by_application=app,
            used_by_email=email, used_at=used_at,
        )
        return row, code

    def _run(self, *args):
        out = StringIO()
        call_command("backfill_track_preapproval_codes", "--event", str(self.event.id), *args, stdout=out)
        return out.getvalue()

    def test_dry_run_changes_nothing_and_apply_links(self):
        row, code = self._historical(
            "backfill.guest@example.com", self.sponsor_track, "confirmed", "TEST-SPONSOR-002", self.sponsor_track, timezone.now()
        )
        before = EventApplicationTrackApplication.objects.get(id=row.id).updated_at

        output = self._run()
        self.assertIn("Would link: 1", output)
        row.refresh_from_db()
        self.assertIsNone(row.preapproval_code_id)

        output = self._run("--apply")
        self.assertIn("Linked: 1", output)
        row.refresh_from_db()
        self.assertEqual(row.preapproval_code, code)
        self.assertEqual(row.preapproval_source, EventApplication.PREAPPROVAL_SOURCE_CODE)
        self.assertEqual(row.updated_at, before)

        # Idempotent: second run links nothing.
        self.assertIn("Linked: 0", self._run("--apply"))

    def test_code_from_deleted_earlier_attempt_is_not_attached_to_current_row(self):
        # Reapply case: the code was used for a Sponsors row that was later
        # hard-deleted; the application now holds an unrelated End User row.
        row, _ = self._historical(
            "reapply@example.com", self.end_user_track, "self_submission", "TEST-SPONSOR-003",
            self.sponsor_track, timezone.now() - timedelta(days=16),
        )
        output = self._run("--apply")
        self.assertIn("Linked: 0", output)
        self.assertIn("SKIP", output)
        row.refresh_from_db()
        self.assertIsNone(row.preapproval_code_id)
