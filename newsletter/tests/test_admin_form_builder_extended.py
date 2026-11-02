"""Form builder parity: more field types, field/action removal, more submit
actions (with their consent rules) and the background submission export."""

import csv
import io
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from friends.models import Notification
from newsletter import form_submission_export_services as exports
from newsletter.form_actions import ActionPolicyError, action_matches, normalize_action, plan_action_update, plan_new_action
from newsletter.form_fields import (
    FieldPolicyError,
    field_type_catalogue,
    normalize_field,
    plan_field_removal,
    plan_field_update,
    plan_new_field,
    removal_problems,
)
from newsletter.mautic.client import MauticClient
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, FORM_ACTION_DELETE, FORM_FIELD_DELETE
from newsletter.models import MauticIdentityAuditLog
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_admin_forms_api import PER_USER_ON, native_form
from newsletter.tests.test_mautic_template_client import MAUTIC_SETTINGS, response

User = get_user_model()

EMAIL = {"id": 1, "label": "Email", "alias": "email", "type": "email", "order": 1}
NOTES = {"id": 2, "label": "Notes", "alias": "notes", "type": "textarea", "order": 2}
SUBMIT = {"id": 3, "label": "Submit", "alias": "submit", "type": "button", "order": 3}
REFS = {"users": {"6": "Ravi"}, "emails": {"40": "New lead alert"}, "assets": {"12": "Brochure"},
        "contactFields": {"city": "City", "company": "Company"}}


def form(fields=(EMAIL, NOTES, SUBMIT), **overrides):
    return native_form(fields=list(fields), **overrides)


class NewFieldTypeTests(SimpleTestCase):
    def test_new_types_store_their_native_settings(self):
        native, _ = plan_new_field({"type": "slider", "label": "Budget", "minValue": "0", "maxValue": 50, "step": "5"}, form(), {})
        self.assertEqual(native["properties"], {"min": "0", "max": "50", "step": "5"})
        native, _ = plan_new_field({"type": "file", "label": "CV", "isRequired": True, "allowedExtensions": [".PDF", "docx"]}, form(), {})
        self.assertEqual(native["properties"], {"allowed_file_extensions": ["pdf", "docx"], "allowed_file_size": "5",
                                                "public": "0", "profile_image": "0"})
        native, _ = plan_new_field({"type": "captcha", "label": "2 + 3?", "captchaAnswer": "5", "errorMessage": "Wrong"}, form(), {})
        self.assertEqual(native["properties"], {"placeholder": "", "captcha": "5", "errorMessage": "Wrong"})
        native, _ = plan_new_field({"type": "pagebreak", "label": "Page 2"}, form(), {})
        self.assertEqual(native["properties"], {"next_page_label": "Continue", "prev_page_label": "Back"})
        native, _ = plan_new_field({"type": "freehtml", "label": "Note", "content": '<p class="x">Hi <a href="https://imaa.org">IMAA</a></p>'}, form(), {})
        self.assertEqual(native["properties"]["text"], '<p class="x">Hi <a href="https://imaa.org">IMAA</a></p>')
        native, _ = plan_new_field({"type": "url", "label": "Site", "mappedField": "website"}, form(), {"website": "url"})
        self.assertEqual((native["mappedField"], native["properties"]), ("website", {"placeholder": ""}))

    def test_unsafe_or_invalid_settings_are_refused(self):
        cases = [
            ({"type": "freehtml", "label": "H", "content": "<script>alert(1)</script>"}, "form_field_active_content"),
            ({"type": "freetext", "label": "T", "content": '<img src=x onerror="alert(1)">'}, "form_field_active_content"),
            ({"type": "freetext", "label": "T", "content": '<a href="javascript:alert(1)">x</a>'}, "form_field_active_content"),
            ({"type": "file", "label": "F", "allowedExtensions": ["html"]}, "invalid_form_field"),
            ({"type": "file", "label": "F", "allowedExtensions": []}, "invalid_form_field"),
            ({"type": "file", "label": "F", "maxFileSize": 50}, "invalid_form_field"),
            ({"type": "file", "label": "F", "mappedField": "city"}, "unsupported_form_field_settings"),
            ({"type": "slider", "label": "S", "minValue": 10, "maxValue": 1}, "invalid_form_field"),
            ({"type": "slider", "label": "S", "step": 0}, "invalid_form_field"),
            ({"type": "captcha", "label": "C", "isRequired": True}, "unsupported_form_field_settings"),
            ({"type": "pagebreak", "label": "P", "minValue": 1}, "unsupported_form_field_settings"),
            ({"type": "url", "label": "U", "defaultValue": "not a url"}, "invalid_form_field"),
            ({"type": "password", "label": "P"}, "unsupported_form_field_type"),
        ]
        for data, code in cases:
            with self.subTest(data=data), self.assertRaises(FieldPolicyError) as raised:
                plan_new_field(data, form(), {"city": "text"})
            self.assertEqual(raised.exception.code, code)

    def test_saved_settings_round_trip_and_edits_send_only_changes(self):
        slider = {"id": 9, "type": "slider", "alias": "budget", "label": "Budget", "order": 4,
                  "properties": {"min": "0", "max": "100", "step": "1"}}
        normalized = normalize_field(slider)
        self.assertEqual((normalized["minValue"], normalized["maxValue"], normalized["step"], normalized["editable"]), ("0", "100", "1", True))
        self.assertEqual(plan_field_update({"maxValue": "200"}, slider, form([EMAIL, slider, SUBMIT]), {}), {"properties": {"max": "200"}})
        with self.assertRaises(FieldPolicyError):
            plan_field_update({"maxValue": "-1"}, slider, form([EMAIL, slider, SUBMIT]), {})

    def test_catalogue_describes_type_settings(self):
        catalogue = {entry["type"]: entry for entry in field_type_catalogue()}
        self.assertIn("file", catalogue)
        self.assertEqual([s["key"] for s in catalogue["file"]["settings"]], ["allowedExtensions", "maxFileSize"])
        self.assertIn("docx", catalogue["file"]["settings"][0]["choices"])
        self.assertFalse(catalogue["captcha"]["required"])
        self.assertFalse(catalogue["pagebreak"]["input"])


class FieldRemovalRuleTests(SimpleTestCase):
    def test_removal_rules(self):
        plan_field_removal(NOTES, form(isPublished=True), submissions=0, confirmed=False)
        with self.assertRaises(FieldPolicyError) as raised:
            plan_field_removal(NOTES, form(), submissions=4, confirmed=False)
        self.assertEqual(raised.exception.code, "form_field_removal_unconfirmed")
        plan_field_removal(NOTES, form(), submissions=4, confirmed=True)
        plan_field_removal(SUBMIT, form(), submissions=4, confirmed=False)  # a button holds no values
        for field, fields in ((SUBMIT, (EMAIL, NOTES, SUBMIT)), (EMAIL, (EMAIL, SUBMIT))):
            with self.subTest(field=field["alias"]), self.assertRaises(FieldPolicyError) as raised:
                plan_field_removal(field, form(fields, isPublished=True), submissions=0, confirmed=True)
            self.assertEqual(raised.exception.code, "form_field_removal_blocked")

    def test_read_back(self):
        self.assertEqual(removal_problems(form(), form([EMAIL, SUBMIT]), "2"), [])
        self.assertIn("the field is still on the Form", removal_problems(form(), form(), "2"))
        self.assertIn("field 1 changed", removal_problems(form(), form([{**EMAIL, "label": "x"}, SUBMIT]), "2"))
        self.assertIn("postAction changed", removal_problems(form(), form([EMAIL, SUBMIT], postAction="return"), "2"))


class NewActionTests(SimpleTestCase):
    def plan(self, data):
        return plan_new_action(data, form(), {}, REFS)[0]

    def test_new_actions_become_native_settings(self):
        self.assertEqual(self.plan({"type": "lead.scorecontactscompanies", "name": "Co", "score": "-5"})["properties"], {"score": -5})
        self.assertEqual(self.plan({"type": "lead.updatelead", "name": "U", "fieldValues": {"city": "Zurich"}})["properties"], {"city": "Zurich"})
        self.assertEqual(self.plan({"type": "lead.addutmtags", "name": "UTM"})["properties"], {})
        self.assertEqual(self.plan({"type": "asset.download", "name": "A", "assetId": "12"})["properties"], {"asset": "12", "category": ""})
        self.assertEqual(self.plan({"type": "email.send.user", "name": "Alert", "emailId": 40, "userIds": ["6", 6]})["properties"],
                         {"useremail": {"email": "40"}, "user_id": ["6"]})
        self.assertEqual(self.plan({"type": "form.email", "name": "N", "subject": "New lead", "message": "<p>{formfield=email}</p>",
                                    "to": "a@imaa.org, b@imaa.org", "emailToOwner": True})["properties"],
                         {"subject": "New lead", "message": "<p>{formfield=email}</p>", "to": "a@imaa.org, b@imaa.org", "cc": "",
                          "bcc": "", "email_to_owner": "1", "set_replyto": "1", "copy_lead": "0"})
        self.assertEqual(self.plan({"type": "form.repost", "name": "R", "postUrl": "https://hooks.example.com/in",
                                    "authorizationHeader": "Bearer abc"})["properties"],
                         {"post_url": "https://hooks.example.com/in", "failure_email": "", "authorization_header": "Bearer abc"})

    def test_consent_and_safety_refusals(self):
        cases = [
            # Mautic emails the CONTACT, ignoring DNC, when no user is set.
            {"type": "email.send.user", "name": "x", "emailId": "40", "userIds": []},
            {"type": "email.send.user", "name": "x", "emailId": "41", "userIds": ["6"]},
            {"type": "email.send.user", "name": "x", "emailId": "40", "userIds": ["99"]},
            {"type": "form.email", "name": "x", "subject": "s", "to": "{formfield=email}"},
            {"type": "form.email", "name": "x", "subject": "s", "to": ""},
            {"type": "form.email", "name": "x", "subject": "s", "to": "a@imaa.org", "copyToContact": True},
            {"type": "form.email", "name": "x", "subject": "s", "to": "a@imaa.org", "message": "<script>x</script>"},
            {"type": "lead.updatelead", "name": "x", "fieldValues": {"email": "x@y.z"}},
            {"type": "lead.updatelead", "name": "x", "fieldValues": {"ecp_newsletter_opt_in": "1"}},
            {"type": "lead.updatelead", "name": "x", "fieldValues": {"unknown_field": "1"}},
            {"type": "form.repost", "name": "x", "postUrl": "http://hooks.example.com"},
            {"type": "form.repost", "name": "x", "postUrl": "https://10.0.0.5/in"},
            {"type": "form.repost", "name": "x", "postUrl": "https://mautic.local/in"},
            {"type": "form.repost", "name": "x", "postUrl": "https://u:p@hooks.example.com/in"},
            {"type": "form.repost", "name": "x", "postUrl": "https://hooks.example.com:8443/in"},
            {"type": "form.repost", "name": "x", "postUrl": "https://hooks.example.com", "authorizationHeader": "a\r\nX: 1"},
            {"type": "asset.download", "name": "x", "assetId": "77"},
            {"type": "lead.scorecontactscompanies", "name": "x", "score": 0},
        ]
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ActionPolicyError):
                plan_new_action(data, form(), {}, REFS)

    def test_existing_risky_actions_are_locked_and_the_repost_header_is_never_returned(self):
        copy = normalize_action({"id": 1, "type": "form.email", "name": "C", "properties": {"subject": "s", "copy_lead": True}}, {})
        no_users = normalize_action({"id": 2, "type": "email.send.user", "name": "U", "properties": {"useremail": {"email": 4}, "user_id": []}}, {})
        self.assertTrue(copy["settingsLocked"] and no_users["settingsLocked"])
        self.assertTrue(copy["removable"])
        repost = {"id": 3, "type": "form.repost", "name": "R", "properties": {"post_url": "https://a.example.com", "failure_email": "",
                                                                                "authorization_header": "Bearer secret"}}
        normalized = normalize_action(repost, {})
        self.assertNotIn("Bearer secret", str(normalized))
        self.assertTrue(normalized["hasAuthorizationHeader"])
        # Changing only the address leaves the stored header to the bridge.
        self.assertEqual(plan_action_update({"postUrl": "https://b.example.com"}, repost, {}, REFS),
                         {"properties": {"post_url": "https://b.example.com", "failure_email": ""}})
        self.assertEqual(plan_action_update({"name": "R"}, repost, {}, REFS), {})
        # The stored header the bridge kept does not count as a mismatch.
        stored = {"type": "form.repost", "properties": {"post_url": "https://b.example.com", "failure_email": "", "authorization_header": "Bearer secret"}}
        self.assertTrue(action_matches(stored, {"type": "form.repost", "properties": {"post_url": "https://b.example.com", "failure_email": ""}}, {}))


@override_settings(**MAUTIC_SETTINGS)
class RemovalClientTests(SimpleTestCase):
    def test_removal_routes_and_operations(self):
        self.assertIn(FORM_FIELD_DELETE, ASSERTABLE_OPERATIONS)
        self.assertIn(FORM_ACTION_DELETE, ASSERTABLE_OPERATIONS)
        session = Mock()
        session.request.return_value = response(200, {"form": {"id": 31}, "submissions": []})
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)
        client.delete_form_field(31, 2, confirm=True)
        client.delete_form_action(31, 7)
        client.list_form_submissions(31, start=0, limit=200, newest_first=False)
        calls = session.request.call_args_list
        self.assertEqual([(c.args[0], c.args[1].split("/api/")[1]) for c in calls],
                         [("DELETE", "ecp/bridge/forms/31/fields/2/delete"), ("DELETE", "ecp/bridge/forms/31/actions/7/delete"),
                          ("GET", "forms/31/submissions")])
        self.assertEqual(calls[0].kwargs["json"], {"confirm": 1})
        self.assertEqual(calls[2].kwargs["params"]["orderByDir"], "ASC")
        self.assertEqual([c.args[0] for c in provider.call_args_list], [FORM_FIELD_DELETE, FORM_ACTION_DELETE])


class _ApiBase(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="builder-admin", email="builder-admin@example.test", password="x")
        grant_marketing_access(self.admin, mautic_user_id=6)
        self.api.force_authenticate(self.admin)
        self.service = Mock(name="service")
        self.service._uses_asserted_user.return_value = False
        self.service.list_tags.return_value = {"tags": []}
        self.service.list_users.return_value = {"users": [{"id": 6, "firstName": "Ravi", "lastName": "A", "isPublished": True}]}
        self.service.list_emails.return_value = {"total": 1, "emails": [{"id": 40, "name": "New lead alert", "isPublished": True}]}
        self.service.list_assets.return_value = {"total": 1, "assets": [{"id": 12, "title": "Brochure"}]}
        self.service.list_fields.return_value = {"fields": [{"alias": "city", "label": "City", "object": "lead", "type": "text"},
                                                           {"alias": "ecp_newsletter_opt_in", "label": "Opt-in", "object": "lead"}]}
        self.asserted = Mock(name="asserted")
        self.asserted._uses_asserted_user.return_value = True
        self.asserted.last_assertion_jti = "jti"

        def factory(*args, **kwargs):
            if kwargs.get("assertion_provider") is not None:
                self.asserted.execution_identity = kwargs["execution_identity"]
                return self.asserted
            return self.service

        for target in ("newsletter.form_views.MauticClient",):
            patcher = patch(target, side_effect=factory)
            patcher.start()
            self.addCleanup(patcher.stop)


@override_settings(**PER_USER_ON)
class FieldRemovalApiTests(_ApiBase):
    def setUp(self):
        super().setUp()
        self.url = reverse("newsletter-admin-form-field-detail", args=["31", "2"])

    def test_removal_with_submissions_needs_confirmation_then_is_verified_and_audited(self):
        self.service.get_form_usage.return_value = {"submissions": {"total": 4}}
        self.service.get_form.return_value = form()
        refused = self.api.delete(self.url)
        self.assertEqual((refused.status_code, refused.json()["code"], refused.json()["submissions"]),
                         (409, "form_field_removal_unconfirmed", 4))
        self.asserted.delete_form_field.assert_not_called()

        self.service.get_form.side_effect = [form(), form([EMAIL, SUBMIT])]
        self.asserted.delete_form_field.return_value = form([EMAIL, SUBMIT])
        removed = self.api.delete(self.url, {"confirm": True}, format="json")
        self.assertEqual(removed.status_code, 200, removed.json())
        self.asserted.delete_form_field.assert_called_once_with("31", "2", confirm=True)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual((entry.action, entry.resource_id, entry.status), (FORM_FIELD_DELETE, "31:2", "succeeded"))
        self.assertIn("4 stored submission", entry.detail)

    def test_published_form_keeps_its_button_and_mismatch_is_not_success(self):
        self.service.get_form_usage.return_value = {"submissions": {"total": 0}}
        self.service.get_form.return_value = form(isPublished=True)
        button = self.api.delete(reverse("newsletter-admin-form-field-detail", args=["31", "3"]))
        self.assertEqual((button.status_code, button.json()["code"]), (409, "form_field_removal_blocked"))

        self.service.get_form.side_effect = [form(), form()]
        self.asserted.delete_form_field.return_value = form()
        still = self.api.delete(self.url)
        self.assertEqual((still.status_code, still.json()["code"]), (409, "form_field_write_mismatch"))


@override_settings(**PER_USER_ON)
class ActionApiTests(_ApiBase):
    ALERT = {"id": 7, "name": "Alert", "type": "email.send.user", "order": 1,
             "properties": {"useremail": {"email": "40"}, "user_id": ["6"]}}

    def test_metadata_lists_new_actions_and_their_choices(self):
        body = self.api.get(reverse("newsletter-admin-form-action-metadata")).json()
        types = [t["type"] for t in body["actionTypes"]]
        for expected in ("form.email", "email.send.user", "asset.download", "form.repost", "lead.updatelead",
                         "lead.scorecontactscompanies", "lead.addutmtags"):
            self.assertIn(expected, types)
        self.assertEqual((body["users"][0]["id"], body["emails"][0]["id"], body["assets"][0]["id"]), ("6", "40", "12"))
        self.assertEqual([f["id"] for f in body["contactFields"]], ["city"])

    def test_add_user_email_checks_references_and_verifies(self):
        before = native_form(actions=[])
        after = native_form(actions=[self.ALERT])
        self.service.get_form.side_effect = [before, after]
        self.asserted.create_form_action.return_value = after
        created = self.api.post(reverse("newsletter-admin-form-action-list", args=["31"]),
                                {"type": "email.send.user", "name": "Alert", "emailId": "40", "userIds": ["6"]}, format="json")
        self.assertEqual(created.status_code, 201, created.json())
        self.asserted.create_form_action.assert_called_once_with(
            "31", {"type": "email.send.user", "name": "Alert", "description": "",
                   "properties": {"useremail": {"email": "40"}, "user_id": ["6"]}}, None, timeout=None)

    def test_repost_host_is_resolved_first_and_written_with_a_longer_timeout(self):
        url = reverse("newsletter-admin-form-action-list", args=["31"])
        body = {"type": "form.repost", "name": "CRM", "postUrl": "https://hooks.example.com/in"}
        self.service.get_form.return_value = native_form(actions=[])
        for addresses, expected in ((None, "could not be checked"), ([], "could not be found"), (["10.1.2.3"], "public website")):
            with self.subTest(addresses=addresses), patch("newsletter.form_views.resolve_host", return_value=addresses):
                refused = self.api.post(url, body, format="json")
                self.assertEqual(refused.status_code, 400)
                self.assertIn(expected, refused.json()["detail"])
        self.asserted.create_form_action.assert_not_called()

        saved = {"id": 7, "name": "CRM", "type": "form.repost", "order": 1,
                 "properties": {"post_url": "https://hooks.example.com/in", "failure_email": ""}}
        self.service.get_form.side_effect = [native_form(actions=[]), native_form(actions=[saved])]
        self.asserted.create_form_action.return_value = native_form(actions=[saved])
        with patch("newsletter.form_views.resolve_host", return_value=["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"]):
            created = self.api.post(url, body, format="json")
        self.assertEqual(created.status_code, 201, created.json())
        self.assertEqual(self.asserted.create_form_action.call_args.kwargs["timeout"], 30)

    def test_any_action_can_be_removed_and_removal_is_verified(self):
        unsafe = {"id": 9, "type": "lead.remove_do_not_contact", "name": "Undo", "order": 2}
        self.service.get_form.side_effect = [native_form(actions=[self.ALERT, unsafe]), native_form(actions=[self.ALERT])]
        self.asserted.delete_form_action.return_value = native_form(actions=[self.ALERT])
        removed = self.api.delete(reverse("newsletter-admin-form-action-detail", args=["31", "9"]))
        self.assertEqual(removed.status_code, 200, removed.json())
        self.asserted.delete_form_action.assert_called_once_with("31", "9")
        self.assertEqual(MauticIdentityAuditLog.objects.get().action, FORM_ACTION_DELETE)

        self.service.get_form.side_effect = [native_form(actions=[self.ALERT]), native_form(actions=[self.ALERT])]
        self.asserted.delete_form_action.return_value = native_form(actions=[self.ALERT])
        still = self.api.delete(reverse("newsletter-admin-form-action-detail", args=["31", "7"]))
        self.assertEqual((still.status_code, still.json()["code"]), (409, "form_action_write_mismatch"))


SUBMISSIONS = [
    {"id": 44, "dateSubmitted": "2026-10-20T10:00:00+00:00", "form": {"id": 31}, "lead": {"id": 501, "email": "dana@example.test"},
     "results": {"email": "dana@example.test", "secret": "hunter2", "notes": "=HYPERLINK(\"x\")", "old_field": "kept"}},
    {"id": 45, "dateSubmitted": "2026-10-21T10:00:00+00:00", "form": {"id": 31}, "lead": None,
     "results": {"email": "eve@example.test", "notes": "second"}},
    {"id": 46, "dateSubmitted": "2026-10-21T11:00:00+00:00", "form": {"id": 99}, "lead": None, "results": {"email": "other@x.test"}},
]
EXPORT_FORM = native_form(fields=[EMAIL, {"id": 5, "label": "Secret", "alias": "secret", "type": "password", "order": 2}, NOTES, SUBMIT])


class SubmissionExportTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="export-admin", email="export-admin@example.test", password="x")
        grant_marketing_access(self.admin, mautic_user_id=6)
        self.api.force_authenticate(self.admin)
        self.client_mock = Mock()
        self.client_mock.get_form.return_value = EXPORT_FORM
        self.client_mock.list_form_submissions.return_value = {"total": 3, "submissions": SUBMISSIONS}
        patcher = patch("newsletter.form_views.MauticClient", return_value=self.client_mock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def start(self, fmt="csv"):
        with patch("newsletter.tasks.run_form_submission_export.delay") as delay:
            created = self.api.post(reverse("newsletter-admin-form-submission-export-list", args=["31"]), {"format": fmt}, format="json")
        self.assertEqual(created.status_code, 202, created.json())
        delay.assert_called_once()
        return created.json()["id"]

    def test_export_builds_a_private_file_for_its_owner_only(self):
        job_id = self.start()
        with patch("newsletter.form_submission_export_services.default_storage") as storage:
            saved = {}
            storage.save.side_effect = lambda name, content: saved.setdefault(name, content.read()) and name
            job = exports.run_export(job_id, client=self.client_mock)
            self.assertEqual((job["status"], job["rows"]), ("done", 2), job.get("error"))
            self.assertNotIn(b"hunter2", next(iter(saved.values())))  # stored encrypted
            storage.open.return_value.__enter__.return_value.read.return_value = next(iter(saved.values()))
            download = self.api.get(reverse("newsletter-admin-form-submission-export-download", args=[job_id]))
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download["Cache-Control"], "no-store, private")
        rows = list(csv.reader(io.StringIO(download.content.decode("utf-8-sig"))))
        self.assertEqual(rows[0], ["Submission ID", "Date submitted", "Contact ID", "Contact email", "Email", "Notes", "old_field (removed field)"])
        self.assertEqual([row[0] for row in rows[1:]], ["45", "44"])  # newest first, other Forms' rows dropped
        self.assertNotIn("hunter2", download.content.decode())  # passwords never exported
        self.assertTrue(rows[2][5].startswith("'="))  # formula injection neutralised
        self.client_mock.list_form_submissions.assert_called_with("31", start=0, limit=200, timeout=60, newest_first=False)
        notification = Notification.objects.get(recipient=self.admin)
        self.assertEqual(notification.data["type"], "marketing_form_submission_export")
        self.assertEqual(
            set(MauticIdentityAuditLog.objects.values_list("action", flat=True)),
            {"form.submission.export.create", "form.submission.export.download"},
        )

        other = APIClient()
        intruder = User.objects.create_superuser(username="export-other", email="eo@example.test", password="x")
        grant_marketing_access(intruder, mautic_user_id=9)
        other.force_authenticate(intruder)
        self.assertEqual(other.get(reverse("newsletter-admin-form-submission-export-download", args=[job_id])).status_code, 404)

    def test_too_many_submissions_fail_the_job_clearly(self):
        job_id = self.start("xlsx")
        self.client_mock.list_form_submissions.return_value = {"total": 10, "submissions": SUBMISSIONS}
        with override_settings(NEWSLETTER_FORM_SUBMISSION_EXPORT_MAX_ROWS=5):
            job = exports.run_export(job_id, client=self.client_mock)
        self.assertEqual(job["status"], "failed")
        self.assertIn("at most 5", job["error"])

    def test_refused_to_non_marketing_users(self):
        other = APIClient()
        other.force_authenticate(User.objects.create_user(username="export-normal", email="en@example.test", password="x"))
        self.assertEqual(other.post(reverse("newsletter-admin-form-submission-export-list", args=["31"]), {"format": "csv"},
                                    format="json").status_code, 403)
