"""Batch 2 (5): contact note edit/delete and the single-contact data export."""

import io
import json
import zipfile
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, CONTACT_NOTE_DELETE, CONTACT_NOTE_UPDATE
from newsletter.models import MauticIdentityAuditLog
from newsletter.tests.marketing_actors import grant_marketing_access

User = get_user_model()


def note(note_id=9, lead=51, **extra):
    return {"id": note_id, "text": "Called about renewal", "type": "call", "lead": {"id": lead}, **extra}


@override_settings(ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False)
class ContactNoteApiTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="note-admin", email="note-admin@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api.force_authenticate(self.admin)
        self.client_mock = Mock()
        self.client_mock._uses_asserted_user.return_value = False
        self.client_mock.get_note.return_value = note()
        self.client_mock.update_note.return_value = note(text="Renewal confirmed", type="meeting")
        for target in ("newsletter.contact_services.MauticClient", "newsletter.mautic_identity_execution.MauticClient",
                       "newsletter.admin_views.MauticClient"):
            patcher = patch(target, return_value=self.client_mock)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.url = reverse("newsletter-admin-contact-note-detail", args=["51", "9"])

    def test_edit_sends_only_checked_changes(self):
        response = self.api.patch(self.url, {"text": "  Renewal confirmed ", "type": "meeting"}, format="json")
        self.assertEqual(response.status_code, 200, response.json())
        self.client_mock.update_note.assert_called_once_with("9", {"text": "Renewal confirmed", "type": "meeting"})
        self.assertEqual((response.json()["text"], response.json()["type"]), ("Renewal confirmed", "meeting"))
        self.assertTrue({CONTACT_NOTE_UPDATE, CONTACT_NOTE_DELETE} <= ASSERTABLE_OPERATIONS)

    def test_edit_refusals(self):
        for data in ({"text": "  "}, {"type": "sms"}, {}):
            with self.subTest(data=data):
                self.assertEqual(self.api.patch(self.url, data, format="json").status_code, 400)
        self.client_mock.update_note.assert_not_called()

    def test_a_note_of_another_contact_is_not_found(self):
        self.client_mock.get_note.return_value = note(lead=77)
        self.assertEqual(self.api.patch(self.url, {"text": "x"}, format="json").status_code, 404)
        self.assertEqual(self.api.delete(self.url).status_code, 404)
        self.client_mock.update_note.assert_not_called()
        self.client_mock.delete_note.assert_not_called()

    def test_delete(self):
        self.assertEqual(self.api.delete(self.url).status_code, 204)
        self.client_mock.delete_note.assert_called_once_with("9")

    def test_refused_to_non_marketing_users(self):
        other = APIClient()
        other.force_authenticate(User.objects.create_user(username="note-normal", email="nn@example.test", password="x"))
        self.assertEqual(other.delete(self.url).status_code, 403)
        self.assertEqual(other.get(reverse("newsletter-admin-contact-data-export", args=["51"])).status_code, 403)


class ContactDataExportTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="export-admin", email="export-admin@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api.force_authenticate(self.admin)
        client = Mock()
        client.get_contact.return_value = {
            "id": 51, "tags": [{"tag": "vip"}], "doNotContact": [{"channel": "email", "reason": 1}], "points": 12,
            "fields": {"core": {"email": {"label": "Email"}, "firstname": {"label": "First name"}},
                       "all": {"id": 51, "email": "dana@example.test", "firstname": "=HYPERLINK(1)"}},
        }
        client.list_contact_notes_detailed.return_value = {"total": 1, "notes": [
            note(dateAdded="2026-11-01T09:00:00+00:00", createdByUser="Ecp Admin", dateTime=None)]}
        client.list_contact_notes.return_value = {"total": 1, "notes": {"9": note()}}
        self.client = client
        client.get_contact_activity.return_value = {"events": [{"timestamp": "2026-11-01T10:00:00+00:00", "eventType": "Page hit",
                                                                "eventLabel": "Pricing"}], "maxPages": 1}
        client.list_contact_companies.return_value = {"companies": [{"company_id": 3, "companyname": "Acme", "is_primary": 1}]}
        client.get_contact_segments.return_value = [{"id": 4, "name": "Board"}]
        client.get_contact_campaigns.return_value = [{"id": 7, "name": "Welcome"}]
        patcher = patch("newsletter.contact_data_export.MauticClient", return_value=client)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_zip_holds_everything_and_is_audited(self):
        response = self.api.get(reverse("newsletter-admin-contact-data-export", args=["51"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/zip")
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertEqual(response["Cache-Control"], "no-store, private")
        bundle = zipfile.ZipFile(io.BytesIO(response.content))
        self.assertEqual(sorted(bundle.namelist()), ["activity.csv", "data.json", "notes.csv", "profile.csv"])
        data = json.loads(bundle.read("data.json"))
        self.assertEqual((data["tags"], data["segments"][0]["name"], data["campaigns"][0]["name"], data["companies"][0]["name"]),
                         (["vip"], "Board", "Welcome", "Acme"))
        self.assertEqual((len(data["notes"]), len(data["activity"]), data["truncated"]), (1, 1, {"notes": False, "activity": False}))
        profile = bundle.read("profile.csv").decode("utf-8-sig")
        self.assertIn("firstname,First name,'=HYPERLINK(1)", profile)  # formulas are neutralised
        notes = bundle.read("notes.csv").decode("utf-8-sig").splitlines()
        self.assertEqual(notes[0], "added,by,type,text,note_date,edited,edited_by")
        self.assertEqual(notes[1], "2026-11-01T09:00:00+00:00,Ecp Admin,call,Called about renewal,,,")
        self.client.list_contact_notes.assert_not_called()
        entry = MauticIdentityAuditLog.objects.get(action="contact.data.export")
        self.assertEqual((entry.resource_id, entry.status), ("51", "succeeded"))

    def test_without_the_plugin_reader_the_native_notes_are_used(self):
        self.client.list_contact_notes_detailed.side_effect = PermanentMauticError("Mautic contact notes failed: HTTP 404")
        response = self.api.get(reverse("newsletter-admin-contact-data-export", args=["51"]))
        self.assertEqual(response.status_code, 200)
        data = json.loads(zipfile.ZipFile(io.BytesIO(response.content)).read("data.json"))
        self.assertEqual([n["text"] for n in data["notes"]], ["Called about renewal"])
        self.client.list_contact_notes.assert_called_once()

    def test_other_reader_failures_are_not_hidden(self):
        self.client.list_contact_notes_detailed.side_effect = PermanentMauticError("Mautic contact notes failed: HTTP 500")
        self.assertEqual(self.api.get(reverse("newsletter-admin-contact-data-export", args=["51"])).status_code, 502)
        self.assertFalse(MauticIdentityAuditLog.objects.filter(action="contact.data.export").exists())

    def test_the_notes_list_shows_author_and_date(self):
        with patch("newsletter.contact_services.MauticClient", return_value=self.client):
            response = self.api.get(reverse("newsletter-admin-contact-notes", args=["51"]))
        self.assertEqual(response.status_code, 200, response.content[:300])
        row = response.json()["results"][0]
        self.assertEqual((row["createdByUser"], row["dateAdded"]), ("Ecp Admin", "2026-11-01T09:00:00+00:00"))
        self.client.list_contact_notes_detailed.assert_called_once_with("51", start=0, limit=25)

    def test_a_bad_id_is_not_found(self):
        self.assertEqual(self.api.get("/api/newsletter/admin/contacts/abc/data-export/").status_code, 404)
