"""Marketing Hub CSV contact import.

Parsing, mapping and validation run against stubbed Mautic metadata. The
endpoint tests fake only the HTTP session: identity resolution, RS256
assertion signing, the client's bridge routing and the audit helper run for
real, so they prove the import is queued as the acting administrator's own
Mautic user and never through the service account.
"""

from __future__ import annotations

import csv
import io
import json
import time
from unittest.mock import Mock, patch

import jwt
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter import contact_import_services as services
from newsletter.contact_import_services import (
    ContactImportError,
    ImportOptions,
    build_prepared_csv,
    build_preview,
    idempotency_key,
    normalize_import,
    parse_csv,
    sign_validation,
    suggest_mapping,
    validate_import,
    verify_validation,
)
from newsletter.mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import ECP_IDENTITY_ASSERTION_HEADER
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, CONTACT_IMPORT_CREATE
from newsletter.models import MauticIdentityAuditLog, MauticUserConnection
from newsletter.tests.contact_import_fixtures import (
    HEADERS,
    contact_row,
    contacts_csv,
    edge_case_rows,
    to_csv,
)
from newsletter.tests.test_mautic_per_user_execution import PER_USER_OFF, PER_USER_ON
from newsletter.tests.test_mautic_user_identity import PUBLIC_KEY

User = get_user_model()

MAUTIC_USER_ID = 31
BASE = "https://mautic.example.test/api/"
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "contact-import-tests"}}
NO_CACHE = {"MARKETING_RESPONSE_CACHE_ENABLED": False, "CACHES": LOCMEM}

FIELDS = {
    "fields": {
        "1": {"alias": "email", "label": "Email", "type": "email", "group": "core", "isPublished": True, "isUniqueIdentifier": True},
        "2": {"alias": "firstname", "label": "First Name", "type": "text", "group": "core", "isPublished": True, "charLengthLimit": 64},
        "3": {"alias": "lastname", "label": "Last Name", "type": "text", "group": "core", "isPublished": True},
        "4": {"alias": "company", "label": "Company", "type": "text", "group": "core", "isPublished": True},
        "5": {"alias": "country", "label": "Country", "type": "country", "group": "core", "isPublished": True},
        "6": {"alias": "city", "label": "City", "type": "text", "group": "core", "isPublished": True},
        "7": {"alias": "phone", "label": "Phone", "type": "tel", "group": "core", "isPublished": True},
        "8": {"alias": "newsletter_opt_in", "label": "Newsletter Opt-In", "type": "boolean", "group": "professional", "isPublished": True, "properties": {"no": "No", "yes": "Yes"}},
        "9": {"alias": "promo_mailing", "label": "Promotional Mailing", "type": "boolean", "group": "professional", "isPublished": True},
        "10": {"alias": "points", "label": "Points", "type": "number", "group": "core", "isPublished": True},
        "11": {"alias": "renewal_date", "label": "Renewal Date", "type": "date", "group": "professional", "isPublished": True},
        "12": {"alias": "plan", "label": "Plan", "type": "select", "group": "professional", "isPublished": True, "properties": {"list": [{"label": "Gold", "value": "gold"}, {"label": "Silver", "value": "silver"}]}},
        "13": {"alias": "website", "label": "Website", "type": "url", "group": "core", "isPublished": True},
        "14": {"alias": "retired", "label": "Retired", "type": "text", "group": "core", "isPublished": False},
        "15": {"alias": "bio_html", "label": "Bio", "type": "html", "group": "professional", "isPublished": True},
    }
}
COUNTRIES = {"type": "country", "choices": [{"label": c, "value": c} for c in ("India", "Singapore", "United Kingdom")]}

FULL_MAPPING = {
    "Email": "email",
    "First Name": "firstname",
    "Last Name": "lastname",
    "Organization": "company",
    "Country": "country",
    "City": "city",
    "Phone Number": "phone",
    "Tags": "tags",
    "Newsletter Opt-In": "newsletter_opt_in",
    "Promotional Mailing": "promo_mailing",
    "Do Not Contact": "doNotEmail",
}


def _response(status_code=200, payload=None):
    response = Mock(status_code=status_code)
    response.json.return_value = payload if payload is not None else {}
    response.text = json.dumps(payload or {})
    response.headers = {}
    return response


class FakeMautic:
    """Answers the Mautic REST and bridge calls the import endpoints make."""

    def __init__(self, *, existing=None, imports=None, bridge_status=None, lookup_error=None):
        self.calls = []
        self.existing = {k.lower(): v for k, v in (existing or {}).items()}
        self.imports = imports or {}
        self.bridge_status = bridge_status
        self.lookup_error = lookup_error
        self.next_id = 700

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        path = url[len(BASE):]
        if method == "GET" and path == "fields/contact":
            return _response(payload=FIELDS)
        if method == "GET" and path == "ecp/fields/choices/country":
            return _response(payload=COUNTRIES)
        if method == "POST" and path == "ecp/contacts/email-lookup":
            if self.lookup_error:
                return _response(self.lookup_error, {"errors": [{"message": "unavailable"}]})
            emails = kwargs["json"]["emails"]
            assert len(emails) <= services.LOOKUP_BATCH_SIZE
            return _response(payload={"matches": {e: self.existing[e] for e in emails if e in self.existing}})
        if method == "POST" and path == "ecp/bridge/contacts/imports/new":
            if self.bridge_status:
                return _response(self.bridge_status, {"errors": [{"message": "Access denied."}]})
            config = json.loads(kwargs["data"]["config"])
            for existing in self.imports.values():
                if existing["ecp"]["idempotency_key"] == config["idempotency_key"]:
                    return _response(payload={"import": existing, "duplicate": True})
            self.next_id += 1
            record = _import_record(self.next_id, config)
            self.imports[self.next_id] = record
            return _response(201, {"import": record, "duplicate": False})
        if method == "GET" and path == "ecp/contacts/imports":
            created_by = kwargs["params"].get("created_by")
            items = [i for i in self.imports.values() if not created_by or i["created_by"] == created_by]
            return _response(payload={"total": len(items), "imports": items})
        if method == "GET" and path.startswith("ecp/contacts/imports/"):
            parts = path.split("/")
            record = self.imports.get(int(parts[3]))
            if record is None:
                return _response(404, {"errors": [{"message": "Import not found."}]})
            if len(parts) > 4 and parts[4] == "errors":
                return _response(
                    payload={
                        "total": 1,
                        "errors": [
                            {"line": 3, "source_row": 4, "category": "skipped_existing", "message": "A contact with this email already exists in Mautic, so the row was skipped."}
                        ],
                    }
                )
            return _response(payload={"import": record})
        return _response(500, {"errors": [{"message": f"unexpected {method} {path}"}]})

    def bridge_writes(self):
        return [c for c in self.calls if c["url"].startswith(f"{BASE}ecp/bridge/")]

    def native_writes(self):
        """Any write that is not the bridge import or the read-only lookup."""
        return [
            c
            for c in self.calls
            if c["method"] != "GET"
            and not c["url"].startswith(f"{BASE}ecp/bridge/contacts/imports/")
            and c["url"] != f"{BASE}ecp/contacts/email-lookup"
        ]


def _import_record(import_id, config, *, created_by=MAUTIC_USER_ID, **overrides):
    record = {
        "id": import_id,
        "status": 1,
        "status_name": "queued",
        "status_info": "",
        "original_file": config.get("original_filename", "contacts.csv"),
        "line_count": config.get("prepared_rows", 0),
        "processed": 0,
        "inserted": 0,
        "updated": 0,
        "ignored": 0,
        "skipped_existing": 0,
        "refused": 0,
        "date_added": "2026-10-09T10:00:00+00:00",
        "date_started": None,
        "date_ended": None,
        "created_by": created_by,
        "created_by_user": "Import Actor",
        "ecp": {
            "mode": config.get("mode", "skip_existing"),
            "prepared_rows": config.get("prepared_rows", 0),
            "summary": config.get("summary", {}),
            "idempotency_key": config.get("idempotency_key", ""),
        },
    }
    record.update(overrides)
    return record


def _targets():
    return services.mapping_targets(_StubClient())


class _StubClient:
    def __init__(self, existing=None, lookup_error=None):
        self.existing = {k.lower(): v for k, v in (existing or {}).items()}
        self.lookup_error = lookup_error
        self.lookups = 0

    def list_fields(self, field_object, **params):
        return FIELDS

    def get_field_type_choices(self, field_type):
        return COUNTRIES

    def lookup_contact_emails(self, emails):
        self.lookups += 1
        if self.lookup_error:
            raise self.lookup_error
        return {e: self.existing[e] for e in emails if e in self.existing}


def _parse(raw, name="contacts.csv"):
    return parse_csv(name, raw)


@override_settings(**NO_CACHE)
class CsvParsingTests(SimpleTestCase):
    def test_parses_headers_rows_and_row_numbers(self):
        parsed = _parse(contacts_csv(10))
        self.assertEqual(parsed.headers, HEADERS)
        self.assertEqual(len(parsed.rows), 10)
        self.assertEqual(parsed.rows[0][0], 2)
        self.assertEqual(parsed.delimiter, ",")
        self.assertEqual(len(parsed.sha256), 64)

    def test_utf8_bom_crlf_and_special_characters(self):
        rows = [contact_row(1, **{"First Name": "Zoë", "City": "São Paulo"})]
        parsed = _parse(to_csv(rows, bom=True, newline="\r\n"))
        self.assertEqual(parsed.headers[0], "Email")
        self.assertEqual(parsed.rows[0][1][1], "Zoë")
        self.assertEqual(parsed.rows[0][1][5], "São Paulo")

    def test_quoted_commas_and_embedded_newlines_stay_in_one_cell(self):
        rows = [contact_row(1, Organization='Acme, "Quoted" Inc', City="Line\nTwo")]
        parsed = _parse(to_csv(rows))
        self.assertEqual(parsed.rows[0][1][3], 'Acme, "Quoted" Inc')
        self.assertEqual(parsed.rows[0][1][5], "Line\nTwo")

    def test_semicolon_and_tab_files_are_detected(self):
        self.assertEqual(_parse(contacts_csv(3, delimiter=";")).delimiter, ";")
        self.assertEqual(_parse(contacts_csv(3, delimiter="\t")).delimiter, "\t")

    def test_ambiguous_delimiter_is_rejected(self):
        with self.assertRaises(ContactImportError) as ctx:
            _parse(b"Email;Name,Other;X,Y\na@example.test;b,c;d,e\n")
        self.assertEqual(ctx.exception.code, "ambiguous_delimiter")

    def _assert_code(self, raw, code, name="contacts.csv"):
        with self.assertRaises(ContactImportError) as ctx:
            parse_csv(name, raw)
        self.assertEqual(ctx.exception.code, code)

    def test_structural_rejections(self):
        self._assert_code(b"", "empty_file")
        self._assert_code(b"   \n", "empty_file")
        self._assert_code(b"Email\x00\n", "binary_file")
        self._assert_code("Email,Name\nä@example.test,Jörg\n".encode("latin-1"), "encoding")
        self._assert_code(b"Email,,Name\na@example.test,,A\n", "missing_headers")
        self._assert_code(b"Email,Name,email\na,b,c\n", "duplicate_headers")
        self._assert_code(b"Email,Name\n", "no_rows")
        self._assert_code(b'Email,Name\na@example.test,"unclosed\n', "malformed_csv")
        self._assert_code(b"Email,Name\na,b,c\nd,e,f\ng,h\n", "inconsistent_columns")

    def test_malformed_row_is_reported_by_its_spreadsheet_row_number(self):
        with self.assertRaises(ContactImportError) as ctx:
            parse_csv("contacts.csv", b'Email,Name\na@example.test,A\nb@example.test,"unclosed\n')
        self.assertIn("Row 3 ", str(ctx.exception))

    def test_too_many_columns(self):
        header = ",".join(f"C{i}" for i in range(services.MAX_COLUMNS + 1))
        self._assert_code(f"{header}\n".encode() + b"x" * 3 + b"\n", "too_many_columns")

    @override_settings(NEWSLETTER_CONTACT_IMPORT_MAX_ROWS=5)
    def test_row_limit(self):
        self._assert_code(contacts_csv(6), "too_many_rows")
        self.assertEqual(len(_parse(contacts_csv(5)).rows), 5)

    @override_settings(NEWSLETTER_CONTACT_IMPORT_MAX_BYTES=100)
    def test_upload_size_limit_and_type(self):
        with self.assertRaises(ContactImportError) as ctx:
            services.read_upload(SimpleUploadedFile("big.csv", b"x" * 101, content_type="text/csv"))
        self.assertEqual(ctx.exception.code, "file_too_large")
        with self.assertRaises(ContactImportError) as ctx:
            services.read_upload(SimpleUploadedFile("contacts.xlsx", b"Email\n", content_type="text/csv"))
        self.assertEqual(ctx.exception.code, "unsupported_type")
        name, _raw = services.read_upload(
            SimpleUploadedFile("../../etc/<evil>.csv", b"Email\n", content_type="application/octet-stream")
        )
        self.assertEqual(name, "_evil_.csv")

    def test_empty_rows_are_counted_not_imported(self):
        parsed = _parse(b"Email,Name\na@example.test,A\n,\nb@example.test,B\n")
        self.assertEqual(parsed.empty_rows, 1)


@override_settings(**NO_CACHE)
class MappingTests(SimpleTestCase):
    def test_targets_come_from_mautic_metadata(self):
        targets = {t["alias"]: t for t in _targets()}
        self.assertNotIn("retired", targets)  # unpublished
        self.assertFalse(targets["points"]["importable"])
        self.assertFalse(targets["bio_html"]["importable"])
        self.assertTrue(targets["email"]["required"])
        self.assertEqual(targets["firstname"]["max_length"], 64)
        self.assertTrue(targets["newsletter_opt_in"]["consent_like"])
        self.assertEqual(targets["plan"]["choices"][0], {"value": "gold", "label": "Gold"})
        self.assertTrue(targets["tags"]["special"] and targets["doNotEmail"]["special"])

    def test_suggestions_are_conservative(self):
        headers = HEADERS + ["ID", "Contact ID", "Email Address"]
        suggestions = suggest_mapping(headers, _targets())
        self.assertEqual(suggestions["Email"], "email")
        self.assertEqual(suggestions["Organization"], "company")
        self.assertEqual(suggestions["Newsletter Opt-In"], "newsletter_opt_in")
        self.assertEqual(suggestions["Do Not Contact"], "doNotEmail")
        self.assertEqual(suggestions["ID"], "")
        self.assertEqual(suggestions["Contact ID"], "")
        # The first column wins; a destination is never suggested twice.
        self.assertEqual(suggestions["Email Address"], "")

    def _mapping_errors(self, mapping):
        parsed = _parse(to_csv([contact_row(1, ID="17")], HEADERS + ["ID"]))
        with self.assertRaises(ContactImportError) as ctx:
            validate_import(parsed, mapping, ImportOptions(), client=_StubClient())
        return {e["code"] for e in ctx.exception.errors}

    def test_mapping_rejections(self):
        self.assertIn("blocked_target", self._mapping_errors({"Email": "email", "ID": "id"}))
        self.assertIn("blocked_target", self._mapping_errors({"Email": "email", "ID": "points"}))
        self.assertIn("unknown_target", self._mapping_errors({"Email": "email", "City": "nope"}))
        self.assertIn("unknown_target", self._mapping_errors({"Email": "email", "City": "retired"}))
        self.assertIn("unsupported_target", self._mapping_errors({"Email": "email", "City": "bio_html"}))
        self.assertIn("duplicate_target", self._mapping_errors({"Email": "email", "City": "city", "Country": "city"}))
        self.assertIn("email_required", self._mapping_errors({"City": "city"}))
        self.assertIn("unknown_column", self._mapping_errors({"Email": "email", "Nope": "city"}))


@override_settings(**NO_CACHE)
class ValidationTests(SimpleTestCase):
    def _validate(self, rows, mapping=None, options=None, client=None, headers=None):
        parsed = _parse(to_csv(rows, headers))
        return validate_import(
            parsed, mapping or FULL_MAPPING, options or ImportOptions(), client=client or _StubClient()
        )

    def _codes(self, result):
        return {(i["row"], i["code"]) for i in result.issues}

    def test_edge_cases_are_classified(self):
        result = self._validate(edge_case_rows())
        codes = self._codes(result)
        self.assertIn((3, "missing_email"), codes)
        self.assertIn((4, "invalid_email"), codes)
        self.assertIn((5, "duplicate_in_file"), codes)
        self.assertIn((11, "invalid_value"), codes)  # DNC "maybe"
        self.assertIn((12, "invalid_value"), codes)  # boolean "perhaps"
        self.assertIn((13, "invalid_value"), codes)  # "-Conference" tag
        imported = {row for row, _values, _key in result.rows}
        self.assertEqual(imported, {2, 6, 7, 8, 9, 10, 14, 15})

        summary = result.summary
        self.assertEqual(summary["total_rows"], 14)
        self.assertEqual(summary["invalid_rows"], 5)
        self.assertEqual(summary["duplicate_rows"], 1)
        self.assertEqual(summary["to_import"], 8)
        # Every row lands in exactly one bucket.
        self.assertEqual(
            summary["total_rows"],
            summary["to_import"] + summary["invalid_rows"] + summary["duplicate_rows"] + summary["to_skip"],
        )

    def test_values_are_normalized_without_inventing_data(self):
        result = self._validate(edge_case_rows())
        values = {row: v for row, v, _k in result.rows}
        self.assertEqual(values[8]["firstname"], "Zoë")
        self.assertEqual(values[9]["company"], 'Acme, "Quoted" Inc')
        self.assertEqual(values[10]["tags"], "Conference|Events")  # case-insensitive dedupe
        self.assertNotIn("city", values[14])  # "NULL" treated as empty
        self.assertEqual(values[15]["company"], "Line Break Org")
        self.assertNotIn("firstname", values[6])  # blanks are not set
        self.assertEqual(values[2]["newsletter_opt_in"], "1")
        self.assertEqual(values[7]["newsletter_opt_in"], "0")
        warnings = " ".join(result.warnings)
        self.assertIn("line breaks", warnings)
        self.assertIn("'NULL'", warnings)
        self.assertIn("Consent and preference columns", warnings)

    def test_do_not_contact_is_add_only(self):
        result = self._validate(
            [
                contact_row(1, **{"Do Not Contact": "true"}),
                contact_row(2, **{"Do Not Contact": "false"}),
                contact_row(3, **{"Do Not Contact": ""}),
            ]
        )
        values = {row: v for row, v, _k in result.rows}
        self.assertEqual(values[2].get("doNotEmail"), "1")
        self.assertNotIn("doNotEmail", values[3])
        self.assertNotIn("doNotEmail", values[4])
        self.assertEqual(result.summary["dnc_rows"], 1)
        content, _mapping = build_prepared_csv(result)
        rows = list(csv.DictReader(io.StringIO(content.decode())))
        self.assertEqual([r["donotemail"] for r in rows], ["1", "", ""])

    def test_type_validation(self):
        mapping = {"Email": "email", "First Name": "firstname", "Renewal": "renewal_date", "Plan": "plan", "Site": "website", "Phone Number": "phone", "Country": "country"}
        headers = ["Email", "First Name", "Renewal", "Plan", "Site", "Phone Number", "Country"]
        rows = [
            {"Email": "a1@example.test", "Renewal": "2026-12-31", "Plan": "GOLD", "Site": "https://example.test", "Phone Number": "+91 98765 43210", "Country": "india"},
            {"Email": "a2@example.test", "Renewal": "31/12/2026"},
            {"Email": "a3@example.test", "Plan": "Bronze"},
            {"Email": "a4@example.test", "Site": "example.test"},
            {"Email": "a5@example.test", "Phone Number": "call me"},
            {"Email": "a6@example.test", "Country": "Atlantis"},
            {"Email": "a7@example.test", "First Name": "x" * 65},
        ]
        result = self._validate(rows, mapping, headers=headers)
        values = {row: v for row, v, _k in result.rows}
        self.assertEqual(values[2]["plan"], "gold")
        self.assertEqual(values[2]["country"], "India")
        self.assertEqual(set(values), {2})
        self.assertEqual({row for row, code in self._codes(result)}, {3, 4, 5, 6, 7, 8})

    def test_tag_separators(self):
        rows = [contact_row(1, Tags="A, B ,a"), contact_row(2, Tags="A|B")]
        result = self._validate(rows, options=ImportOptions(tag_separator=","))
        values = {row: v for row, v, _k in result.rows}
        self.assertEqual(values[2]["tags"], "A|B")
        self.assertIn((3, "invalid_value"), self._codes(result))

    def test_existing_contacts_skip_mode(self):
        client = _StubClient(
            existing={
                "user00001@example.test": {"contact_ids": [5], "dnc_email": True, "dnc_reason": "unsubscribed"},
                "user00002@example.test": {"contact_ids": [6], "dnc_email": False, "dnc_reason": None},
            }
        )
        rows = [contact_row(1), contact_row(2, **{"Do Not Contact": "true"}), contact_row(3)]
        result = self._validate(rows, client=client)
        self.assertEqual([row for row, _v, _k in result.rows], [4])
        summary = result.summary
        self.assertTrue(summary["existing_checked"])
        self.assertEqual((summary["to_create"], summary["to_skip"], summary["to_update"]), (1, 2, 0))
        self.assertEqual(summary["existing_suppressed"], 1)
        self.assertEqual(summary["skipped_dnc_conflicts"], 1)
        self.assertIn("1 existing contact is marked Do Not Contact in the file but skipped", " ".join(result.warnings))

    def test_existing_contacts_fill_empty_mode(self):
        client = _StubClient(existing={"user00001@example.test": {"contact_ids": [5], "dnc_email": True}})
        result = self._validate([contact_row(1), contact_row(2)], client=client, options=ImportOptions(existing_mode="fill_empty"))
        self.assertEqual(len(result.rows), 2)
        self.assertEqual((result.summary["to_create"], result.summary["to_update"]), (1, 1))
        self.assertIn("only have empty fields filled", " ".join(result.warnings))

    def test_lookup_failure_reports_estimates(self):
        client = _StubClient(lookup_error=TemporaryMauticError("down"))
        result = self._validate([contact_row(1)], client=client)
        self.assertFalse(result.summary["existing_checked"])
        self.assertIn("estimates", " ".join(result.warnings))
        self.assertEqual(len(result.rows), 1)

    def test_lookup_is_batched(self):
        client = _StubClient()
        with patch.object(services, "LOOKUP_BATCH_SIZE", 4):
            self._validate([contact_row(i) for i in range(1, 11)], client=client)
        self.assertEqual(client.lookups, 3)

    def test_options_are_strict(self):
        with self.assertRaises(ContactImportError):
            services.parse_options({"existing_mode": "overwrite"})
        with self.assertRaises(ContactImportError):
            services.parse_options({"tag_separator": "/"})
        with self.assertRaises(ContactImportError):
            services.parse_options({"segment_id": 4})
        self.assertEqual(services.parse_options("").existing_mode, "skip_existing")

    def test_fifteen_thousand_rows_validate_quickly(self):
        raw = contacts_csv(15000)
        started = time.monotonic()
        parsed = _parse(raw)
        result = validate_import(parsed, FULL_MAPPING, ImportOptions(), client=_StubClient())
        elapsed = time.monotonic() - started
        self.assertEqual(result.summary["to_import"], 15000)
        self.assertLess(elapsed, 20)
        preview = build_preview(parsed, _targets())
        self.assertEqual(len(preview["sample_rows"]), services.PREVIEW_ROWS)
        self.assertLess(len(json.dumps(preview)), 50_000)
        self.assertLessEqual(len(result.issues), services.ISSUE_LIMIT)


@override_settings(**NO_CACHE)
class PreparedCsvTests(SimpleTestCase):
    def test_prepared_file_matches_the_bridge_contract(self):
        rows = [
            contact_row(1, Organization='Back\\slash, "q"', City="C:\\"),
            contact_row(2),
        ]
        result = validate_import(_parse(to_csv(rows)), FULL_MAPPING, ImportOptions(), client=_StubClient())
        content, mapping = build_prepared_csv(result)
        text = content.decode("utf-8")
        self.assertFalse(text.endswith("\n"))
        self.assertNotIn("\r", text)
        self.assertEqual(text.count("\n"), 2)  # header + 2 records, one line each
        header = text.split("\n", 1)[0].split(",")
        self.assertEqual(header[-1], "ecp_source_row")
        self.assertEqual(mapping["donotemail"], "doNotEmail")
        self.assertEqual(mapping["newsletter_opt_in"], "newsletter_opt_in")
        parsed = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(parsed[0]["company"], 'Back\\slash, "q"')
        self.assertEqual(parsed[0]["city"], "C:\\")
        self.assertEqual([r["ecp_source_row"] for r in parsed], ["2", "3"])


class TokenTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="token-user", password="x")
        self.other = User.objects.create_user(username="token-other", password="x")
        self.parsed = _parse(contacts_csv(3))
        self.options = ImportOptions()

    def test_round_trip_and_binding(self):
        token = sign_validation(self.user, self.parsed, FULL_MAPPING, self.options)
        claims = verify_validation(token, self.user, self.parsed, FULL_MAPPING, self.options)
        self.assertEqual(len(idempotency_key(claims)), 64)

        def code(**kwargs):
            args = {"token": token, "user": self.user, "parsed": self.parsed, "mapping": FULL_MAPPING, "options": self.options}
            args.update(kwargs)
            with self.assertRaises(ContactImportError) as ctx:
                verify_validation(args["token"], args["user"], args["parsed"], args["mapping"], args["options"])
            return ctx.exception.code

        self.assertEqual(code(token=token + "x"), "validation_required")
        self.assertEqual(code(token=""), "validation_required")
        self.assertEqual(code(user=self.other), "validation_required")
        self.assertEqual(code(parsed=_parse(contacts_csv(4))), "revalidation_required")
        self.assertEqual(code(mapping={**FULL_MAPPING, "City": ""}), "revalidation_required")
        self.assertEqual(code(options=ImportOptions(existing_mode="fill_empty")), "revalidation_required")

    def test_expiry(self):
        token = sign_validation(self.user, self.parsed, FULL_MAPPING, self.options)
        with patch.object(services, "TOKEN_MAX_AGE_SECONDS", -1):
            with self.assertRaises(ContactImportError) as ctx:
                verify_validation(token, self.user, self.parsed, FULL_MAPPING, self.options)
        self.assertEqual(ctx.exception.code, "validation_expired")

    def test_each_validation_gets_its_own_idempotency_key(self):
        first = verify_validation(sign_validation(self.user, self.parsed, FULL_MAPPING, self.options), self.user, self.parsed, FULL_MAPPING, self.options)
        second = verify_validation(sign_validation(self.user, self.parsed, FULL_MAPPING, self.options), self.user, self.parsed, FULL_MAPPING, self.options)
        self.assertNotEqual(idempotency_key(first), idempotency_key(second))


class NormalizeImportTests(SimpleTestCase):
    def _record(self, **overrides):
        return _import_record(9, {"prepared_rows": 10, "summary": {"total_rows": 14, "to_skip": 2, "invalid_rows": 1, "duplicate_rows": 1}}, **overrides)

    def test_states_and_counts(self):
        queued = normalize_import(self._record())
        self.assertEqual((queued["state"], queued["terminal"], queued["remaining"]), ("queued", False, 10))

        running = normalize_import(self._record(status_name="in_progress", inserted=4, ignored=1, skipped_existing=1))
        self.assertEqual(running["state"], "processing")
        self.assertEqual((running["processed"], running["progress_percentage"], running["remaining"]), (5, 50.0, 5))

        delayed = normalize_import(self._record(status_name="delayed", inserted=3))
        self.assertEqual(delayed["state"], "processing")

        done = normalize_import(self._record(status_name="imported", inserted=7, ignored=3, skipped_existing=3))
        self.assertEqual(done["state"], "completed")
        self.assertEqual((done["created"], done["failed"], done["skipped_existing"], done["excluded_invalid"]), (7, 0, 5, 2))

        partial = normalize_import(self._record(status_name="imported", inserted=8, ignored=2, skipped_existing=1))
        self.assertEqual((partial["state"], partial["failed"]), ("completed_with_errors", 1))

        unknown = normalize_import(self._record(status_name="imported", inserted=8, ignored=2, skipped_existing=None))
        self.assertEqual((unknown["state"], unknown["failed"], unknown["skipped_existing"]), ("completed_with_errors", None, None))

        self.assertFalse(running["stalled"])
        stale = normalize_import(self._record(status_name="in_progress", inserted=4, date_modified="2026-01-01T00:00:00+00:00"))
        self.assertTrue(stale["stalled"])
        fresh = normalize_import(self._record(status_name="in_progress", inserted=4, date_modified=timezone.now().isoformat()))
        self.assertFalse(fresh["stalled"])
        waiting = normalize_import(self._record(status_name="queued", date_modified="2026-01-01T00:00:00+00:00"))
        self.assertFalse(waiting["stalled"])

        failed = normalize_import(self._record(status_name="failed", status_info="ghost", inserted=2))
        self.assertEqual((failed["state"], failed["terminal"], failed["status_info"]), ("failed", True, "ghost"))
        self.assertEqual(failed["remaining"], 8)


class _EndpointFixtures:
    def setUp(self):
        self.api = APIClient()
        self.actor = User.objects.create_user(
            username="import-actor",
            email="import-actor@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        self.connection = MauticUserConnection.objects.create(
            user=self.actor,
            mautic_user_id=MAUTIC_USER_ID,
            status=MauticUserConnection.Status.ACTIVE,
            is_active=True,
        )
        self.api.force_authenticate(user=self.actor)
        self.mautic = FakeMautic()
        factory_patch = patch("newsletter.contact_import_services.MauticClient", side_effect=self._factory)
        factory_patch.start()
        self.addCleanup(factory_patch.stop)

    def _factory(self, *args, **kwargs):
        kwargs["session"] = self.mautic
        return MauticClient(*args, **kwargs)

    def _file(self, raw=None, name="contacts.csv"):
        return SimpleUploadedFile(name, raw if raw is not None else to_csv(edge_case_rows()), content_type="text/csv")

    def _post(self, name, data):
        return self.api.post(reverse(name), data, format="multipart")

    def _validate(self, raw=None, mapping=None, options=None):
        return self._post(
            "newsletter-admin-contact-import-validate",
            {"file": self._file(raw), "mapping": json.dumps(mapping or FULL_MAPPING), "options": json.dumps(options or {})},
        )

    def _start(self, token, raw=None, mapping=None, options=None, confirm="true"):
        return self._post(
            "newsletter-admin-contact-import-start",
            {
                "file": self._file(raw),
                "mapping": json.dumps(mapping or FULL_MAPPING),
                "options": json.dumps(options or {}),
                "validation_token": token,
                "confirm": confirm,
            },
        )


@override_settings(**PER_USER_ON, **NO_CACHE)
class ContactImportEndpointTests(_EndpointFixtures, TestCase):
    def test_operation_is_assertable(self):
        self.assertIn(CONTACT_IMPORT_CREATE, ASSERTABLE_OPERATIONS)

    def test_fields_endpoint(self):
        response = self.api.get(reverse("newsletter-admin-contact-import-fields"))
        self.assertEqual(response.status_code, 200)
        aliases = {t["alias"] for t in response.data["results"]}
        self.assertTrue({"email", "tags", "doNotEmail"} <= aliases)
        self.assertEqual(response.data["options"]["existing_modes"], ["skip_existing", "fill_empty"])

    def test_preview_is_read_only_and_capped(self):
        response = self._post("newsletter-admin-contact-import-preview", {"file": self._file(contacts_csv(60))})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["total_rows"], 60)
        self.assertEqual(len(response.data["sample_rows"]), services.PREVIEW_ROWS)
        self.assertEqual(response.data["detected_email_column"], "Email")
        self.assertEqual(self.mautic.native_writes(), [])
        self.assertEqual(self.mautic.bridge_writes(), [])

    def test_preview_rejects_bad_files(self):
        response = self._post("newsletter-admin-contact-import-preview", {"file": self._file(b"Email,email\na,b\n")})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "duplicate_headers")
        response = self._post("newsletter-admin-contact-import-preview", {})
        self.assertEqual(response.data["code"], "file_required")

    def test_validate_returns_summary_issues_and_token(self):
        response = self._validate()
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["summary"]["to_import"], 8)
        self.assertTrue(response.data["validation_token"])
        self.assertEqual(self.mautic.bridge_writes(), [])
        self.assertTrue(any(c["url"].endswith("ecp/contacts/email-lookup") for c in self.mautic.calls))
        # Issues never echo cell values back.
        self.assertNotIn("not-an-email", json.dumps(response.data["issues"]))

    def test_validate_reports_mapping_problems(self):
        response = self._validate(mapping={"Email": "email", "Last Name": "id"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "invalid_mapping")
        self.assertEqual(response.data["errors"][0]["code"], "blocked_target")

    def test_start_requires_confirmation_and_validation(self):
        response = self._start("token", confirm="")
        self.assertEqual((response.status_code, response.data["code"]), (400, "confirmation_required"))
        response = self._start("not-a-token")
        self.assertEqual((response.status_code, response.data["code"]), (400, "validation_required"))
        self.assertEqual(self.mautic.bridge_writes(), [])

    def test_start_rejects_a_changed_mapping(self):
        token = self._validate().data["validation_token"]
        response = self._start(token, mapping={**FULL_MAPPING, "City": ""})
        self.assertEqual((response.status_code, response.data["code"]), (400, "revalidation_required"))
        self.assertEqual(self.mautic.bridge_writes(), [])

    def test_start_queues_the_import_as_the_mapped_user(self):
        users_before = User.objects.count()
        token = self._validate().data["validation_token"]
        response = self._start(token)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(response.data["duplicate"])
        self.assertEqual(response.data["import"]["state"], "queued")
        self.assertEqual(response.data["import"]["rows_sent"], 8)

        writes = self.mautic.bridge_writes()
        self.assertEqual(len(writes), 1)
        call = writes[0]
        self.assertEqual((call["method"], call["url"]), ("POST", f"{BASE}ecp/bridge/contacts/imports/new"))
        claims = jwt.decode(call["headers"][ECP_IDENTITY_ASSERTION_HEADER], PUBLIC_KEY, algorithms=["RS256"], audience="ecp-mautic")
        self.assertEqual(claims["operation"], CONTACT_IMPORT_CREATE)
        self.assertEqual(claims["mautic_user_id"], MAUTIC_USER_ID)
        self.assertEqual(claims["sub"], str(self.actor.pk))

        config = json.loads(call["data"]["config"])
        self.assertEqual(config["mode"], "skip_existing")
        self.assertEqual(config["prepared_rows"], 8)
        self.assertEqual(config["summary"]["total_rows"], 14)
        _name, content, content_type = call["files"]["file"]
        self.assertEqual(content_type, "text/csv")
        self.assertEqual(len(config["expected_sha256"]), 64)
        self.assertNotIn("not-an-email", content.decode())  # invalid rows are never sent

        entry = MauticIdentityAuditLog.objects.latest("id")
        self.assertEqual((entry.action, entry.status, entry.auth_mode), (CONTACT_IMPORT_CREATE, "succeeded", "asserted_user"))
        self.assertEqual((entry.ecp_user, entry.mautic_user_id, entry.resource), (self.actor, MAUTIC_USER_ID, "contact_import"))

        # No ECP users, no emails, no native contact/segment/campaign writes.
        self.assertEqual(User.objects.count(), users_before)
        self.assertEqual(len(mail.outbox), 0)
        self.assertEqual(self.mautic.native_writes(), [])

    def test_repeated_start_never_queues_twice(self):
        token = self._validate().data["validation_token"]
        first = self._start(token)
        second = self._start(token)
        self.assertEqual((first.status_code, second.status_code), (201, 200))
        self.assertTrue(second.data["duplicate"])
        self.assertEqual(first.data["import"]["id"], second.data["import"]["id"])
        keys = {json.loads(c["data"]["config"])["idempotency_key"] for c in self.mautic.bridge_writes()}
        self.assertEqual(len(keys), 1)
        self.assertEqual(len(self.mautic.imports), 1)

    def test_concurrent_start_is_refused_while_one_is_in_flight(self):
        token = self._validate().data["validation_token"]
        claims = verify_validation(token, self.actor, _parse(to_csv(edge_case_rows())), FULL_MAPPING, ImportOptions())
        from django.core.cache import cache

        cache.add(f"newsletter:contact-import:start:{idempotency_key(claims)}", 1, 60)
        response = self._start(token)
        self.assertEqual((response.status_code, response.data["code"]), (409, "start_in_progress"))
        self.assertEqual(self.mautic.bridge_writes(), [])

    def test_existing_contacts_are_revalidated_at_start(self):
        token = self._validate(raw=contacts_csv(3)).data["validation_token"]
        self.mautic.existing = {"user00001@example.test": {"contact_ids": [1], "dnc_email": False}}
        response = self._start(token, raw=contacts_csv(3))
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["import"]["rows_sent"], 2)
        self.assertEqual(response.data["validation"]["summary"]["to_skip"], 1)

    def test_nothing_to_import(self):
        raw = to_csv([contact_row(1, Email="bad")])
        token = self._validate(raw=raw).data["validation_token"]
        response = self._start(token, raw=raw)
        self.assertEqual((response.status_code, response.data["code"]), (400, "nothing_to_import"))
        self.assertEqual(self.mautic.bridge_writes(), [])

    def test_bridge_refusal_is_an_identity_error_and_audited(self):
        token = self._validate().data["validation_token"]
        self.mautic.bridge_status = 403
        response = self._start(token)
        self.assertEqual(response.status_code, 403)
        entry = MauticIdentityAuditLog.objects.latest("id")
        self.assertEqual((entry.action, entry.status), (CONTACT_IMPORT_CREATE, "denied"))

    def test_unknown_outcome_is_reported_without_claiming_failure(self):
        token = self._validate().data["validation_token"]
        with patch.object(MauticClient, "create_contact_import", side_effect=TemporaryMauticError("timeout")):
            response = self._start(token)
        self.assertEqual((response.status_code, response.data["code"]), (502, "outcome_unknown"))
        self.assertIn("never queues the same import twice", response.data["detail"])

    def test_status_history_and_errors_are_owner_scoped(self):
        token = self._validate().data["validation_token"]
        import_id = self._start(token).data["import"]["id"]
        self.mautic.imports[999] = _import_record(999, {"prepared_rows": 1}, created_by=4242)

        detail = self.api.get(reverse("newsletter-admin-contact-import-detail", args=[import_id]))
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.data["id"], import_id)

        other = self.api.get(reverse("newsletter-admin-contact-import-detail", args=[999]))
        self.assertEqual(other.status_code, 404)
        missing = self.api.get(reverse("newsletter-admin-contact-import-detail", args=[12345]))
        self.assertEqual(missing.status_code, 404)
        other_errors = self.api.get(reverse("newsletter-admin-contact-import-errors", args=[999]))
        self.assertEqual(other_errors.status_code, 404)

        history = self.api.get(reverse("newsletter-admin-contact-import-list"))
        self.assertEqual([item["id"] for item in history.data["results"]], [import_id])
        list_call = [c for c in self.mautic.calls if c["url"] == f"{BASE}ecp/contacts/imports"][-1]
        self.assertEqual(list_call["params"]["created_by"], MAUTIC_USER_ID)

        errors = self.api.get(reverse("newsletter-admin-contact-import-errors", args=[import_id]))
        self.assertEqual(errors.status_code, 200)
        self.assertEqual(errors.data["results"][0], {"row": 4, "line": 3, "category": "skipped_existing", "message": "A contact with this email already exists in Mautic, so the row was skipped."})


@override_settings(**PER_USER_OFF, **NO_CACHE)
class ContactImportServiceAccountModeTests(_EndpointFixtures, TestCase):
    def test_start_refuses_without_per_user_execution(self):
        token = self._validate().data["validation_token"]
        response = self._start(token)
        self.assertEqual((response.status_code, response.data["code"]), (409, "per_user_execution_required"))
        self.assertEqual(self.mautic.bridge_writes(), [])
        self.assertEqual(self.mautic.native_writes(), [])

    def test_client_refuses_service_account_imports(self):
        with self.assertRaises(PermanentMauticError):
            MauticClient(session=self.mautic).create_contact_import(file_name="x.csv", content=b"email", config={})


@override_settings(**PER_USER_ON, **NO_CACHE)
class ContactImportPermissionTests(TestCase):
    URLS = [
        ("get", "newsletter-admin-contact-import-list", []),
        ("get", "newsletter-admin-contact-import-fields", []),
        ("post", "newsletter-admin-contact-import-preview", []),
        ("post", "newsletter-admin-contact-import-validate", []),
        ("post", "newsletter-admin-contact-import-start", []),
        ("get", "newsletter-admin-contact-import-detail", [1]),
        ("get", "newsletter-admin-contact-import-errors", [1]),
    ]

    def _statuses(self, user):
        api = APIClient()
        if user is not None:
            api.force_authenticate(user=user)
        with patch("newsletter.contact_import_services.MauticClient") as client:
            statuses = {getattr(api, method)(reverse(name, args=args)).status_code for method, name, args in self.URLS}
        client.assert_not_called()
        return statuses

    def test_anonymous_is_refused(self):
        self.assertTrue(self._statuses(None) <= {401, 403})

    def test_staff_without_superuser_is_refused(self):
        staff = User.objects.create_user(username="import-staff", password="x", is_staff=True)
        self.assertEqual(self._statuses(staff), {403})

    def test_superuser_without_mapping_is_refused(self):
        superuser = User.objects.create_user(username="import-super", password="x", is_staff=True, is_superuser=True)
        self.assertEqual(self._statuses(superuser), {403})
