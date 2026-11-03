"""Company CSV import (native Mautic queue) and company export."""

import csv
import io
import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from friends.models import Notification
from newsletter import company_export_services as exports
from newsletter.company_import_services import (
    CompanyImportError,
    check_rows,
    company_fields,
    parse_mapping,
    prepared_csv,
    read_csv,
    suggest_mapping,
)
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, COMPANY_IMPORT_CREATE
from newsletter.models import MauticIdentityAuditLog
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_admin_forms_api import PER_USER_ON

User = get_user_model()

FIELDS = [
    {"alias": "companyname", "label": "Company Name", "type": "text"},
    {"alias": "companyemail", "label": "Company Email", "type": "email"},
    {"alias": "companywebsite", "label": "Website", "type": "url"},
    {"alias": "companyzipcode", "label": "Zip Code", "type": "text"},
    {"alias": "companynumber_of_employees", "label": "Number of Employees", "type": "number"},
]
FIELD_ROWS = {"fields": [{**f, "object": "company", "isPublished": True} for f in FIELDS] + [{"alias": "email", "label": "Email", "object": "lead"}]}


def upload(text, name="companies.csv"):
    return SimpleUploadedFile(name, text.encode("utf-8"), content_type="text/csv")


class CompanyImportRuleTests(SimpleTestCase):
    def test_csv_reading_sniffs_the_delimiter_and_skips_blank_rows(self):
        parsed = read_csv(upload("﻿Company Name;Website;Postal Code\nAcme;acme.test;1000\n;;\n\"Beta; Inc\";beta.test;2000\n"))
        self.assertEqual(parsed["headers"], ["Company Name", "Website", "Postal Code"])
        self.assertEqual([row["Company Name"] for row in parsed["rows"]], ["Acme", "Beta; Inc"])
        for bad in ("", "Name,Name\nA,B\n", "Name,\nA,B\n", "Name\n"):
            with self.subTest(bad=bad), self.assertRaises(CompanyImportError):
                read_csv(upload(bad))
        with self.assertRaises(CompanyImportError):
            read_csv(SimpleUploadedFile("c.csv", "Name\nZürich\n".encode("latin-1")))

    def test_company_fields_put_the_name_first(self):
        rows = [{"alias": "companycity", "object": "company"}, {"alias": "companyname", "object": "company"},
                {"alias": "companyfax", "object": "company", "isPublished": False}, {"alias": "email", "object": "lead"}]
        self.assertEqual([field["alias"] for field in company_fields(rows)], ["companyname", "companycity"])

    def test_mapping_suggestions_and_rules(self):
        self.assertEqual(suggest_mapping(["Company Name", "Website", "Postal Code", "Email", "Notes"], FIELDS),
                         {"Company Name": "companyname", "Website": "companywebsite", "Postal Code": "companyzipcode", "Email": "companyemail"})
        headers = ["Name", "Site"]
        self.assertEqual(parse_mapping({"Name": "companyname", "Site": ""}, headers, FIELDS), {"Name": "companyname"})
        for raw in ({"Site": "companywebsite"}, {"Name": "email"}, {"Nope": "companyname"}, {"Name": "companyname", "Site": "companyname"}, None):
            with self.subTest(raw=raw), self.assertRaises(CompanyImportError):
                parse_mapping(raw, headers, FIELDS)

    def test_checks_report_rows_without_names_and_bad_values(self):
        rows = [{"Name": "Acme", "Mail": "info@acme.test", "Site": "acme.test", "Staff": "12"},
                {"Name": "", "Mail": "", "Site": "", "Staff": ""},
                {"Name": "acme", "Mail": "not-mail", "Site": "not a site", "Staff": "lots"}]
        result = check_rows(rows, {"Name": "companyname", "Mail": "companyemail", "Site": "companywebsite", "Staff": "companynumber_of_employees"}, FIELDS)
        self.assertEqual((result["rows"], result["without_name"], result["duplicate_names"]), (3, 1, 1))
        self.assertEqual([(issue["row"], issue["column"]) for issue in result["issues"]], [(2, "Name"), (3, "Mail"), (3, "Site"), (3, "Staff")])

    def test_prepared_csv_keeps_only_mapped_columns_as_rfc4180(self):
        rows = [{"Name": 'Acme, "the" Co', "Secret": "x", "Site": "acme.test"}, {"Name": "Beta\nGroup", "Secret": "", "Site": "NULL"}]
        content = prepared_csv(rows, {"Name": "companyname", "Site": "companywebsite"})
        # One physical line per row, no trailing newline, NULL never clears a field.
        self.assertEqual(content.decode(), 'companyname,companywebsite\n"Acme, ""the"" Co",acme.test\nBeta Group,')
        checks = check_rows(rows, {"Name": "companyname", "Site": "companywebsite"}, FIELDS)
        self.assertEqual((checks["line_breaks"], checks["null_literals"]), (1, 1))
        self.assertIn(COMPANY_IMPORT_CREATE, ASSERTABLE_OPERATIONS)


@override_settings(**PER_USER_ON)
class CompanyImportApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="coimport-admin", email="coimport-admin@example.test", password="x")
        grant_marketing_access(self.admin, mautic_user_id=6)
        self.api.force_authenticate(self.admin)
        self.service = Mock(name="service")
        self.service._uses_asserted_user.return_value = False
        self.service.list_fields.return_value = FIELD_ROWS
        self.asserted = Mock(name="asserted")
        self.asserted._uses_asserted_user.return_value = True
        self.asserted.last_assertion_jti = "jti"

        def factory(*args, **kwargs):
            if kwargs.get("assertion_provider") is not None:
                self.asserted.execution_identity = kwargs["execution_identity"]
                return self.asserted
            return self.service

        patcher = patch("newsletter.company_transfer_views.MauticClient", side_effect=factory)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.csv = "Company Name,Website,Internal\nAcme,acme.test,secret\nBeta,beta.test,secret\n"

    def test_preview_suggests_a_mapping_and_checks(self):
        result = self.api.post(reverse("newsletter-admin-company-import-preview"), {"file": upload(self.csv)}, format="multipart")
        self.assertEqual(result.status_code, 200, result.json())
        body = result.json()
        self.assertEqual(body["mapping"], {"Company Name": "companyname", "Website": "companywebsite"})
        self.assertEqual((body["rows"], body["checks"]["without_name"]), (2, 0))
        self.assertEqual([f["alias"] for f in body["fields"]][0], "companyname")
        self.assertRegex(body["attempt"], r"^[a-f0-9]{32}$")
        self.assertEqual(result["Cache-Control"], "no-store, private")

    def test_start_queues_only_mapped_columns_as_the_admin(self):
        self.asserted.create_company_import.return_value = ({"id": 7, "status_name": "queued"}, False)
        result = self.api.post(reverse("newsletter-admin-company-import-list"), {
            "file": upload(self.csv), "mode": "skip_existing", "mapping": json.dumps({"Company Name": "companyname", "Website": "companywebsite"}),
        }, format="multipart")
        self.assertEqual(result.status_code, 201, result.json())
        kwargs = self.asserted.create_company_import.call_args.kwargs
        self.assertEqual(kwargs["content"].decode(), "companyname,companywebsite\nAcme,acme.test\nBeta,beta.test")
        self.assertEqual((kwargs["config"]["mode"], kwargs["config"]["mapping"]), ("skip_existing", {"companyname": "companyname", "companywebsite": "companywebsite"}))
        self.assertEqual(len(kwargs["config"]["idempotency_key"]), 40)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual((entry.action, entry.resource_id, entry.status), (COMPANY_IMPORT_CREATE, "7", "succeeded"))

    def test_the_same_attempt_is_one_import_but_a_new_preview_can_import_again(self):
        self.asserted.create_company_import.return_value = ({"id": 7, "status_name": "imported"}, False)
        url = reverse("newsletter-admin-company-import-list")
        mapping = json.dumps({"Company Name": "companyname"})
        keys = []
        for attempt in ("a" * 32, "a" * 32, "b" * 32):
            response = self.api.post(url, {"file": upload(self.csv), "mode": "create_or_update", "mapping": mapping, "attempt": attempt},
                                     format="multipart")
            self.assertEqual(response.status_code, 201, response.json())
            keys.append(self.asserted.create_company_import.call_args.kwargs["config"]["idempotency_key"])
        self.assertEqual(keys[0], keys[1])
        self.assertNotEqual(keys[0], keys[2])
        bad = self.api.post(url, {"file": upload(self.csv), "mode": "create_or_update", "mapping": mapping, "attempt": "x"}, format="multipart")
        self.assertEqual(bad.status_code, 400)

    def test_start_refusals(self):
        url = reverse("newsletter-admin-company-import-list")
        cases = [
            ({"file": upload(self.csv), "mode": "replace", "mapping": json.dumps({"Company Name": "companyname"})}, "mode"),
            ({"file": upload(self.csv), "mode": "skip_existing", "mapping": json.dumps({"Website": "companywebsite"})}, "no name"),
            ({"file": upload("Company Name,Website\n,acme.test\n"), "mode": "skip_existing", "mapping": json.dumps({"Company Name": "companyname"})}, "all empty"),
        ]
        for data, name in cases:
            with self.subTest(name=name):
                self.assertEqual(self.api.post(url, data, format="multipart").status_code, 400)
        self.asserted.create_company_import.assert_not_called()

    def test_refused_to_non_marketing_users(self):
        other = APIClient()
        other.force_authenticate(User.objects.create_user(username="coimport-normal", email="cn@example.test", password="x"))
        self.assertEqual(other.get(reverse("newsletter-admin-company-import-list")).status_code, 403)
        self.assertEqual(other.post(reverse("newsletter-admin-company-export-list"), {"format": "csv"}, format="json").status_code, 403)


class CompanyExportTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="coexport-admin", email="coexport-admin@example.test", password="x")
        grant_marketing_access(self.admin, mautic_user_id=6)
        self.api.force_authenticate(self.admin)
        self.client_mock = Mock()
        self.client_mock.list_fields.return_value = FIELD_ROWS
        self.client_mock.list_companies.return_value = {"total": 2, "companies": {
            "1": {"id": 1, "dateAdded": "2026-11-01T10:00:00+00:00", "fields": {"all": {"companyname": "=Acme", "companywebsite": "acme.test"}}},
            "2": {"id": 2, "dateAdded": "2026-11-01T11:00:00+00:00", "fields": {"core": {"companyname": {"value": "Beta"}}}},
        }}

    def test_export_builds_a_private_file_for_its_owner_only(self):
        with patch("newsletter.tasks.run_company_export.delay") as delay:
            created = self.api.post(reverse("newsletter-admin-company-export-list"), {"format": "csv", "search": "a"}, format="json")
        self.assertEqual(created.status_code, 202, created.json())
        delay.assert_called_once()
        job_id = created.json()["id"]
        with patch("newsletter.company_export_services.default_storage") as storage:
            saved = {}
            storage.save.side_effect = lambda name, content: saved.setdefault(name, content.read()) and name
            job = exports.run_export(job_id, client=self.client_mock)
            self.assertEqual((job["status"], job["rows"]), ("done", 2), job.get("error"))
            storage.open.return_value.__enter__.return_value.read.return_value = next(iter(saved.values()))
            download = self.api.get(reverse("newsletter-admin-company-export-download", args=[job_id]))
        self.assertEqual(download.status_code, 200)
        rows = list(csv.reader(io.StringIO(download.content.decode("utf-8-sig"))))
        self.assertEqual(rows[0], ["Company ID", "Company Name", "Company Email", "Website", "Zip Code", "Number of Employees", "Date added"])
        self.assertEqual((rows[1][0], rows[1][1], rows[2][1]), ("1", "'=Acme", "Beta"))
        self.assertEqual(self.client_mock.list_companies.call_args.kwargs["search"], "a")
        self.assertEqual(Notification.objects.get(recipient=self.admin).data["type"], "marketing_company_export")
        other = APIClient()
        intruder = User.objects.create_superuser(username="coexport-other", email="co@example.test", password="x")
        grant_marketing_access(intruder, mautic_user_id=9)
        other.force_authenticate(intruder)
        self.assertEqual(other.get(reverse("newsletter-admin-company-export-download", args=[job_id])).status_code, 404)
