"""Bulk attendee import: CSV/XLSX preview + apply for open and application events.

Cognito is mocked; emails use the test (locmem) backend. Dummy data only.
"""
import csv
import io
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APITestCase

from community.models import Community
from events.models import (
    Event,
    EventApplication,
    EventApplicationTrack,
    EventApplicationTrackApplication,
    EventBadgeLabel,
    EventRegistration,
    TrackPricingTier,
)
from events.services import attendee_import
from users.models import UserProfile

User = get_user_model()

HEADER = ["email", "first_name", "last_name", "type", "job_title", "company", "country", "payment_reference"]

LOCMEM_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "attendee-import-tests"}}


def csv_upload(rows, header=HEADER, name="attendees.csv"):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for row in rows:
        writer.writerow(row)
    return SimpleUploadedFile(name, buffer.getvalue().encode("utf-8"), content_type="text/csv")


def xlsx_upload(rows, header=HEADER, name="attendees.xlsx"):
    from openpyxl import Workbook

    workbook = Workbook()
    sheet = workbook.active
    sheet.append(header)
    for row in rows:
        sheet.append(row)
    buffer = io.BytesIO()
    workbook.save(buffer)
    return SimpleUploadedFile(
        name, buffer.getvalue(),
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


def client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "AdminCreateUser")


@override_settings(CACHES=LOCMEM_CACHE, FRONTEND_URL="https://connect.example.test")
class AttendeeImportBase(APITestCase):
    registration_type = "open"

    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser(
            username="import-admin", email="import-admin@example.com", password="test-pass-123"
        )
        self.community = Community.objects.create(
            name="Import Community", slug="import-community", owner=self.admin
        )
        self.addCleanup(patch.stopall)
        # No test may reach real AWS (Cognito, SES, S3).
        patch(
            "botocore.client.BaseClient._make_api_call",
            side_effect=AssertionError("unexpected real AWS call"),
        ).start()

        start = timezone.now() + timedelta(days=30)
        self.event = Event.objects.create(
            community=self.community,
            title="Import Test Event",
            slug="import-test-event",
            registration_type=self.registration_type,
            status="published",
            is_free=True,
            start_time=start,
            end_time=start + timedelta(hours=8),
            created_by=self.admin,
        )
        self.client.force_authenticate(self.admin)

        self.cognito = MagicMock()
        patch.object(attendee_import, "_cognito_client", return_value=(self.cognito, "pool-test")).start()
        self.delete_cognito = patch("users.email_utils.delete_cognito_user", return_value=True).start()
        # Run the Celery job inline.
        self.delay = patch(
            "events.tasks.run_attendee_import_task.delay", side_effect=attendee_import.run_job
        ).start()

    # -- helpers --
    def url(self, suffix):
        return f"/api/events/{self.event.id}/attendee-import/{suffix}/"

    def preview(self, upload, track=None):
        data = {"file": upload}
        if track is not None:
            data["track_id"] = track.id
        return self.client.post(self.url("preview"), data, format="multipart")

    def run_import(self, upload, track=None):
        preview = self.preview(upload, track)
        self.assertEqual(preview.status_code, 200, preview.data)
        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            applied = self.client.post(self.url("apply"), {"plan_id": preview.data["plan_id"]}, format="json")
        self.assertEqual(applied.status_code, 202, applied.data)
        status_response = self.client.get(self.url(f"status/{applied.data['job_id']}"))
        self.assertEqual(status_response.status_code, 200)
        self.assertEqual(status_response.data["status"], "done", status_response.data)
        return preview.data, status_response.data

    def result_for(self, job, email):
        return next(item for item in job["results"] if item["email"] == email)

    def make_user(self, email, first="Existing", last="Member"):
        user = User.objects.create_user(username=email.split("@")[0], email=email, first_name=first, last_name=last)
        # The ensure_profile signal creates it on commit, which TestCase never reaches.
        UserProfile.objects.get_or_create(user=user)
        return user

    def subjects_to(self, email):
        return [message.subject for message in mail.outbox if email in message.to]


class ParsingTests(AttendeeImportBase):
    def test_csv_headers_are_case_insensitive_and_aliased(self):
        upload = csv_upload(
            [["NEW.Person@Example.com", "New", "Person", "paid attendee", "CFO", "Acme", "India", "INV-1"]],
            header=["Email Address", "First Name", "Last Name", "Type", "Title", "Company Name", "Location", "Payment Reference"],
        )
        rows = attendee_import.parse_file(upload)
        self.assertEqual(rows[0]["email"], "new.person@example.com")
        self.assertEqual(rows[0]["type"], attendee_import.TYPE_PAID_ATTENDEE)
        self.assertEqual(rows[0]["job_title"], "CFO")
        self.assertEqual(rows[0]["company"], "Acme")
        self.assertEqual(rows[0]["country"], "India")
        self.assertEqual(rows[0]["payment_reference"], "INV-1")
        self.assertEqual(rows[0]["row"], 2)

    def test_xlsx_is_parsed(self):
        rows = attendee_import.parse_file(xlsx_upload([["x@example.com", "X", "Y", "Sponsor", None, None, None, None]]))
        self.assertEqual(rows[0]["email"], "x@example.com")
        self.assertEqual(rows[0]["type"], attendee_import.TYPE_SPONSOR)
        self.assertEqual(rows[0]["company"], "")

    def test_missing_required_column_is_refused(self):
        response = self.preview(csv_upload([["a@example.com", "A"]], header=["email", "first_name"]))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "missing_columns")

    def test_unsupported_file_type_is_refused(self):
        response = self.preview(SimpleUploadedFile("people.txt", b"email\n", content_type="text/plain"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "unsupported_file_type")

    def test_too_many_rows_is_refused(self):
        with patch.object(attendee_import, "MAX_ROWS", 2):
            response = self.preview(csv_upload([[f"p{i}@example.com", "P", "Q", "Attendee"] for i in range(3)]))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "too_many_rows")

    def test_row_errors(self):
        response = self.preview(csv_upload([
            ["not-an-email", "A", "B", "Attendee"],
            ["temp@mailinator.com", "A", "B", "Attendee"],
            ["noname@example.com", "", "B", "Attendee"],
            ["badtype@example.com", "A", "B", "Speaker"],
            ["dup@example.com", "A", "B", "Attendee"],
            ["DUP@example.com", "A", "B", "Sponsor"],
        ]))
        self.assertEqual(response.status_code, 200)
        reasons = [row["reason"] for row in response.data["rows"]]
        self.assertEqual(reasons, [
            "invalid_email", "", "missing_first_name", "invalid_type", "", "duplicate_email_in_file:row_6",
        ])
        # Disposable domains are allowed for staff imports, flagged as a warning
        self.assertEqual(response.data["rows"][1]["action"], "register")
        self.assertEqual(response.data["rows"][1]["warnings"], ["disposable_email"])
        self.assertEqual(response.data["summary"]["error"], 4)


class PermissionTests(AttendeeImportBase):
    def test_non_superuser_is_refused(self):
        staff = User.objects.create_user(username="staff-only", email="staff-only@example.com", is_staff=True)
        self.client.force_authenticate(staff)
        self.assertEqual(self.client.get(self.url("template")).status_code, 403)
        self.assertEqual(self.preview(csv_upload([["a@example.com", "A", "B", "Attendee"]])).status_code, 403)
        self.assertEqual(self.client.post(self.url("apply"), {"plan_id": "x"}, format="json").status_code, 403)
        self.assertEqual(self.client.get(self.url(f"status/{'a' * 32}")).status_code, 403)

    def test_template_download(self):
        response = self.client.get(self.url("template"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        self.assertTrue(response.content.decode().startswith(",".join(attendee_import.TEMPLATE_HEADER)))

    def test_plan_is_single_use_and_owned(self):
        preview = self.preview(csv_upload([["a@example.com", "A", "B", "Attendee"]]))
        other_admin = User.objects.create_superuser(username="other-admin", email="other-admin@example.com", password="x")
        self.client.force_authenticate(other_admin)
        response = self.client.post(self.url("apply"), {"plan_id": preview.data["plan_id"]}, format="json")
        self.assertEqual(response.data["code"], "plan_not_owned")

        self.client.force_authenticate(self.admin)
        with self.captureOnCommitCallbacks(execute=True):
            first = self.client.post(self.url("apply"), {"plan_id": preview.data["plan_id"]}, format="json")
        self.assertEqual(first.status_code, 202)
        second = self.client.post(self.url("apply"), {"plan_id": preview.data["plan_id"]}, format="json")
        self.assertEqual(second.status_code, 400)
        self.assertEqual(second.data["code"], "plan_expired")

    def test_cancelled_event_is_refused(self):
        Event.objects.filter(pk=self.event.pk).update(status="cancelled")
        response = self.preview(csv_upload([["a@example.com", "A", "B", "Attendee"]]))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "event_cancelled")


class OpenEventImportTests(AttendeeImportBase):
    def test_preview_plans_without_writing(self):
        existing = self.make_user("existing@example.com")
        registered = self.make_user("registered@example.com")
        EventRegistration.objects.create(event=self.event, user=registered, status="registered")

        response = self.preview(csv_upload([
            ["new@example.com", "New", "Person", "Attendee"],
            ["existing@example.com", "Existing", "Member", "Sponsor"],
            ["registered@example.com", "Reg", "Istered", "Attendee"],
        ]))

        self.assertEqual(response.status_code, 200)
        actions = [(row["action"], row["account"], row["reason"]) for row in response.data["rows"]]
        self.assertEqual(actions, [
            ("register", "create", ""),
            ("register", "existing", ""),
            ("skip", "existing", "already_registered"),
        ])
        self.assertEqual(response.data["summary"]["create_account"], 1)
        self.assertFalse(User.objects.filter(email="new@example.com").exists())
        self.assertFalse(EventRegistration.objects.filter(event=self.event, user=existing).exists())
        self.cognito.admin_create_user.assert_not_called()

    def test_new_account_is_created_registered_and_emailed(self):
        _, job = self.run_import(csv_upload([
            ["New.Person@Example.com", "New", "Person", "Attendee", "Head of M&A", "Acme", "Singapore", ""],
        ]))

        result = self.result_for(job, "new.person@example.com")
        self.assertEqual(result["status"], "register")
        self.assertEqual(result["emails"], {"credentials": True, "registration_confirmation": True})

        create_kwargs = self.cognito.admin_create_user.call_args.kwargs
        self.assertEqual(create_kwargs["Username"], "new.person")
        self.assertEqual(create_kwargs["MessageAction"], "SUPPRESS")
        self.assertIn({"Name": "email_verified", "Value": "true"}, create_kwargs["UserAttributes"])
        self.assertTrue(self.cognito.admin_set_user_password.call_args.kwargs["Permanent"])

        user = User.objects.get(email="new.person@example.com")
        self.assertEqual(user.username, "new.person")
        self.assertTrue(user.check_password(create_kwargs["TemporaryPassword"]))
        profile = UserProfile.objects.get(user=user)
        self.assertEqual((profile.full_name, profile.job_title, profile.company, profile.location),
                         ("New Person", "Head of M&A", "Acme", "Singapore"))

        registration = EventRegistration.objects.get(event=self.event, user=user)
        self.assertEqual(registration.status, "registered")
        self.assertEqual(set(registration.badge_labels.values_list("name", flat=True)), {"Participant", "Attendee"})
        self.assertEqual(registration.roles.count(), 0)

        # New accounts also get the platform's normal welcome email (ensure_profile signal).
        self.assertEqual(sorted(self.subjects_to("new.person@example.com")), [
            "Registration Confirmed: Import Test Event", "Welcome to IMAA Connect!", "Your IMAA Connect account",
        ])
        credentials = next(m for m in mail.outbox if m.subject == "Your IMAA Connect account")
        self.assertIn(create_kwargs["TemporaryPassword"], credentials.body)

    def test_login_email_uses_its_own_editable_template(self):
        from cms.models import EmailTemplate

        # A DB "Admin Credentials" template (as on prod) must not reach attendees.
        EmailTemplate.objects.create(
            template_key="admin_credentials", subject="Welcome - Your Admin Credentials",
            html_body="<p>admin</p>", text_body="admin", is_active=True,
        )
        self.run_import(csv_upload([["first@example.com", "First", "Person", "Attendee"]]))
        login = next(m for m in mail.outbox if "first@example.com" in m.to and "account" in m.subject.lower())
        self.assertEqual(login.subject, "Your IMAA Connect account")
        self.assertIn("as part of your registration for Import Test Event", login.body)
        self.assertNotIn("Admin", login.subject)

        # Staff can edit the import email separately.
        EmailTemplate.objects.create(
            template_key="attendee_account_credentials", subject="Your login for {{ event_title }}",
            html_body="<p>{{ temporary_password }}</p>", text_body="{{ first_name }} {{ temporary_password }}",
            is_active=True,
        )
        self.run_import(csv_upload([["second@example.com", "Second", "Person", "Attendee"]]))
        subjects = self.subjects_to("second@example.com")
        self.assertIn("Your login for Import Test Event", subjects)

    def test_existing_account_is_registered_without_overwriting_profile(self):
        user = self.make_user("existing@example.com", first="Keep", last="Name")
        UserProfile.objects.filter(user=user).update(company="Old Co", job_title="")

        _, job = self.run_import(csv_upload([
            ["existing@example.com", "Other", "Name", "Sponsor", "Partner", "New Co", "", ""],
        ]))

        self.assertEqual(self.result_for(job, "existing@example.com")["emails"], {"registration_confirmation": True})
        self.cognito.admin_create_user.assert_not_called()
        user.refresh_from_db()
        profile = UserProfile.objects.get(user=user)
        self.assertEqual((user.first_name, profile.company, profile.job_title), ("Keep", "Old Co", "Partner"))
        registration = EventRegistration.objects.get(event=self.event, user=user)
        self.assertIn("Sponsor", registration.badge_labels.values_list("name", flat=True))
        self.assertEqual(self.subjects_to("existing@example.com"), ["Registration Confirmed: Import Test Event"])

    def test_already_registered_is_skipped_without_email(self):
        user = self.make_user("registered@example.com")
        EventRegistration.objects.create(event=self.event, user=user, status="registered")

        _, job = self.run_import(csv_upload([["registered@example.com", "R", "S", "Attendee"]]))

        result = self.result_for(job, "registered@example.com")
        self.assertEqual((result["status"], result["reason"]), ("skip", "already_registered"))
        self.assertEqual(self.subjects_to("registered@example.com"), [])
        self.assertEqual(job["summary"]["skipped"], 1)

    def test_cancelled_registration_is_reactivated(self):
        user = self.make_user("cancelled@example.com")
        EventRegistration.objects.create(event=self.event, user=user, status="cancelled")

        preview, job = self.run_import(csv_upload([["cancelled@example.com", "C", "D", "Attendee"]]))

        self.assertEqual(preview["rows"][0]["warnings"], ["reactivates_cancelled_registration"])
        self.assertEqual(EventRegistration.objects.get(event=self.event, user=user).status, "registered")

    def test_paid_attendee_is_marked_paid(self):
        self.run_import(csv_upload([["paid@example.com", "Paid", "Person", "Paid Attendee", "", "", "", "INV-2026-01"]]))

        registration = EventRegistration.objects.get(event=self.event, user__email="paid@example.com")
        self.assertIsNotNone(registration.marked_paid_at)
        self.assertEqual(registration.marked_paid_by, self.admin)
        self.assertEqual(registration.payment_reference, "INV-2026-01")
        self.assertIn("Paid Attendee", registration.badge_labels.values_list("name", flat=True))

    def test_sponsored_guest_gets_label_and_is_not_marked_paid(self):
        preview, job = self.run_import(csv_upload([["guest@example.com", "Guest", "Person", "Sponsored Guest"]]))

        self.assertEqual(preview["rows"][0]["type_label"], "Sponsored Guest")
        self.assertEqual(job["summary"]["errors"], 0)
        registration = EventRegistration.objects.get(event=self.event, user__email="guest@example.com")
        self.assertIsNone(registration.marked_paid_at)
        self.assertIn("Sponsored Guest", registration.badge_labels.values_list("name", flat=True))

    def test_event_badge_label_is_accepted_as_type(self):
        label = EventBadgeLabel.objects.create(event=self.event, name="Media Partner", color="#123456")
        preview, job = self.run_import(csv_upload([["media@example.com", "Me", "Dia", "  media   PARTNER "]]))

        self.assertEqual(preview["rows"][0]["type_label"], "Media Partner")
        self.assertIn("Media Partner", preview["type_options"])
        self.assertEqual(job["summary"]["errors"], 0)
        registration = EventRegistration.objects.get(event=self.event, user__email="media@example.com")
        self.assertIn(label.id, registration.badge_labels.values_list("id", flat=True))
        self.assertIsNone(registration.marked_paid_at)
        self.assertEqual(EventBadgeLabel.objects.filter(event=self.event, name__iexact="Media Partner").count(), 1)

    def test_inactive_or_other_event_label_is_not_a_type(self):
        EventBadgeLabel.objects.create(event=self.event, name="Retired Label", is_active=False)
        other = Event.objects.create(
            community=self.community, title="Other", slug="other-event", status="published",
            start_time=self.event.start_time, end_time=self.event.end_time, created_by=self.admin,
        )
        EventBadgeLabel.objects.create(event=other, name="Other Event Label")
        response = self.preview(csv_upload([
            ["a@example.com", "A", "B", "Retired Label"],
            ["b@example.com", "A", "B", "Other Event Label"],
        ]))
        self.assertEqual([row["reason"] for row in response.data["rows"]], ["invalid_type", "invalid_type"])
        self.assertNotIn("Retired Label", response.data["type_options"])
        self.assertNotIn("Other Event Label", response.data["type_options"])

    def test_import_may_exceed_max_participants(self):
        Event.objects.filter(pk=self.event.pk).update(max_participants=1)
        preview, job = self.run_import(csv_upload([
            ["one@example.com", "One", "A", "Attendee"],
            ["two@example.com", "Two", "B", "Attendee"],
        ]))
        self.assertEqual(preview["capacity_warning"], {"max_participants": 1, "current": 0, "after_import": 2})
        self.assertEqual(job["summary"]["registered"], 2)
        self.assertEqual(self.event.registrations.filter(status="registered").count(), 2)

    def test_inactive_type_label_is_reactivated(self):
        label = EventBadgeLabel.objects.create(event=self.event, name="Sponsor", is_active=False)
        self.run_import(csv_upload([["s@example.com", "S", "T", "Sponsor"]]))
        label.refresh_from_db()
        self.assertTrue(label.is_active)
        self.assertEqual(EventBadgeLabel.objects.filter(event=self.event, name="Sponsor").count(), 1)

    def test_taken_cognito_username_gets_a_new_one(self):
        self.cognito.admin_create_user.side_effect = [client_error("UsernameExistsException"), {}]
        self.run_import(csv_upload([["jane@example.com", "Jane", "Doe", "Attendee"]]))
        usernames = [call.kwargs["Username"] for call in self.cognito.admin_create_user.call_args_list]
        self.assertEqual(usernames, ["jane", "jane1"])
        self.assertEqual(User.objects.get(email="jane@example.com").username, "jane1")
        # Never resets the password of the existing Cognito user
        self.assertEqual(self.cognito.admin_set_user_password.call_args.kwargs["Username"], "jane1")

    def test_cognito_failure_errors_the_row_and_continues(self):
        self.cognito.admin_create_user.side_effect = [client_error("AliasExistsException"), {}]
        _, job = self.run_import(csv_upload([
            ["taken@example.com", "T", "K", "Attendee"],
            ["fine@example.com", "F", "N", "Attendee"],
        ]))
        failed = self.result_for(job, "taken@example.com")
        self.assertEqual((failed["status"], failed["reason"]), ("error", "email_exists_in_login_system"))
        self.assertFalse(User.objects.filter(email="taken@example.com").exists())
        self.assertEqual(self.result_for(job, "fine@example.com")["status"], "register")
        self.assertEqual(job["summary"], {
            "total": 2, "registered": 1, "accounts_created": 1, "skipped": 0, "errors": 1, "emails_failed": 0,
        })

    def test_db_failure_removes_the_cognito_user(self):
        with patch.object(attendee_import, "_fill_profile", side_effect=RuntimeError("boom")):
            _, job = self.run_import(csv_upload([["boom@example.com", "B", "M", "Attendee"]]))
        self.assertEqual(self.result_for(job, "boom@example.com")["reason"], "unexpected_error")
        self.delete_cognito.assert_called_once_with("boom")
        self.assertFalse(User.objects.filter(email="boom@example.com").exists())

    def test_disposable_email_account_is_created(self):
        preview, job = self.run_import(csv_upload([["temp.user@mailinator.com", "Temp", "User", "Attendee"]]))
        self.assertEqual(preview["rows"][0]["warnings"], ["disposable_email"])
        self.assertEqual(self.result_for(job, "temp.user@mailinator.com")["status"], "register")
        self.assertTrue(EventRegistration.objects.filter(event=self.event, user__email="temp.user@mailinator.com").exists())

    def test_reimport_skips_everyone(self):
        rows = [["again@example.com", "A", "G", "Attendee"]]
        self.run_import(csv_upload(rows))
        _, job = self.run_import(csv_upload(rows))
        self.assertEqual(job["summary"]["skipped"], 1)
        self.assertEqual(mail.outbox, [])


class ApplicationEventImportTests(AttendeeImportBase):
    registration_type = "apply"

    def setUp(self):
        super().setUp()
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key="import-delegates",
            label="Import Delegates",
            status="open",
            enabled_submission_modes=["self_submission"],
            role_mappings_on_acceptance=["attendee", "sponsor"],
        )
        self.tier = TrackPricingTier.objects.create(
            track=self.track, key="free", label="Free", price=Decimal("0"), is_active=True, is_default=True,
        )
        self.acceptance_email = patch("events.tasks.send_application_acceptance_email_task.delay").start()

    def roles(self, registration):
        return set(registration.roles.values_list("key", flat=True))

    def test_track_is_required_and_must_be_valid(self):
        upload = lambda: csv_upload([["a@example.com", "A", "B", "Attendee"]])
        self.assertEqual(self.preview(upload()).data["code"], "track_required")
        self.track.status = "closed"
        self.track.save(update_fields=["status"])
        self.assertEqual(self.preview(upload(), self.track).data["code"], "track_not_open")

    def test_new_person_gets_an_accepted_application(self):
        preview, job = self.run_import(
            csv_upload([["delegate@example.com", "Dele", "Gate", "Sponsor", "CEO", "Gate Co", "Japan", ""]]),
            self.track,
        )

        self.assertEqual(preview["event"]["track"], {"id": self.track.id, "label": "Import Delegates", "roles": ["attendee", "sponsor"]})
        self.assertEqual((preview["rows"][0]["action"], preview["rows"][0]["application"]), ("accept_application", "new"))

        user = User.objects.get(email="delegate@example.com")
        application = EventApplication.objects.get(event=self.event, email="delegate@example.com")
        self.assertEqual((application.user, application.status, application.is_preapproved), (user, "approved", True))
        self.assertEqual((application.job_title, application.company_name, application.location), ("CEO", "Gate Co", "Japan"))
        self.assertIn("Imported by import-admin@example.com", application.comments)
        track_application = application.track_applications.get(track=self.track)
        self.assertEqual(track_application.status, EventApplicationTrackApplication.STATUS_ACCEPTED)
        self.assertEqual(track_application.accepted_tier, self.tier)

        registration = EventRegistration.objects.get(event=self.event, user=user)
        self.assertEqual((registration.status, registration.attendee_status), ("registered", "confirmed"))
        self.assertEqual(self.roles(registration), {"attendee", "sponsor"})
        self.assertEqual(registration.origins.filter(track=self.track).count(), 2)
        self.assertIn("Sponsor", registration.badge_labels.values_list("name", flat=True))

        self.acceptance_email.assert_not_called()
        # Same as any accepted applicant: the post-acceptance form request is sent
        # (no DB template in tests, hence the placeholder subject).
        self.assertEqual(
            sorted(self.subjects_to("delegate@example.com")),
            [
                "Registration Confirmed: Import Test Event",
                "Welcome to IMAA Connect!",
                "Your IMAA Connect account",
                "[post_acceptance_form_sent]",
            ],
        )
        self.assertEqual(self.result_for(job, "delegate@example.com")["status"], "accept_application")

    def make_application(self, user, status):
        application = EventApplication.objects.create(
            event=self.event, user=user, email=user.email, first_name="App", last_name="Licant",
            status="declined" if status == "declined" else "pending",
        )
        EventApplicationTrackApplication.objects.create(application=application, track=self.track, status=status)
        return application

    def test_pending_application_is_accepted_without_duplicate(self):
        user = self.make_user("pending@example.com")
        application = self.make_application(user, EventApplicationTrackApplication.STATUS_PENDING)

        preview, _ = self.run_import(csv_upload([["pending@example.com", "P", "N", "Attendee"]]), self.track)

        self.assertEqual(preview["rows"][0]["application"], "existing")
        self.assertEqual(EventApplication.objects.filter(event=self.event).count(), 1)
        self.assertEqual(application.track_applications.count(), 1)
        self.assertEqual(application.track_applications.get().status, EventApplicationTrackApplication.STATUS_ACCEPTED)
        application.refresh_from_db()
        self.assertEqual(application.status, "approved")

    def test_declined_application_is_accepted_with_warning(self):
        user = self.make_user("declined@example.com")
        self.make_application(user, EventApplicationTrackApplication.STATUS_DECLINED)

        preview, _ = self.run_import(csv_upload([["declined@example.com", "D", "C", "Attendee"]]), self.track)

        self.assertEqual(preview["rows"][0]["warnings"], ["was_declined"])
        self.assertEqual(EventRegistration.objects.get(event=self.event, user=user).status, "registered")

    def test_already_accepted_is_skipped(self):
        first = csv_upload([["twice@example.com", "T", "W", "Attendee"]])
        self.run_import(first, self.track)
        preview, job = self.run_import(csv_upload([["twice@example.com", "T", "W", "Attendee"]]), self.track)
        self.assertEqual(preview["rows"][0]["reason"], "already_accepted")
        self.assertEqual(job["summary"]["skipped"], 1)
        self.assertEqual(mail.outbox, [])

    def test_guest_application_is_linked_to_the_new_account(self):
        application = EventApplication.objects.create(
            event=self.event, email="guest@example.com", first_name="Gu", last_name="Est", status="pending",
        )
        self.run_import(csv_upload([["guest@example.com", "Gu", "Est", "Attendee"]]), self.track)
        application.refresh_from_db()
        self.assertEqual(application.user, User.objects.get(email="guest@example.com"))
        self.assertEqual(application.status, "approved")

    def test_paid_tier_paid_attendee_is_confirmed(self):
        self.tier.price = Decimal("500.00")
        self.tier.save(update_fields=["price"])

        self.run_import(csv_upload([
            ["paid@example.com", "Pa", "Id", "Paid Attendee", "", "", "", "INV-77"],
            ["unpaid@example.com", "Un", "Paid", "Attendee"],
        ]), self.track)

        paid = EventRegistration.objects.get(event=self.event, user__email="paid@example.com")
        self.assertEqual(paid.attendee_status, "confirmed")
        self.assertEqual(paid.payment_reference, "INV-77")
        self.assertFalse(paid.origins.filter(origin_status="payment_pending").exists())
        self.assertEqual(set(paid.origins.values_list("payment_reference", flat=True)), {"INV-77"})

        unpaid = EventRegistration.objects.get(event=self.event, user__email="unpaid@example.com")
        self.assertEqual(unpaid.attendee_status, "payment_pending")
        self.assertIsNone(unpaid.marked_paid_at)
