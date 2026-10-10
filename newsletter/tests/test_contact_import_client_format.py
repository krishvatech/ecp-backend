"""CSV contact import against the client's 68-column export format.

Covers the client-specific behaviour: the Newsletter Opt-In and Promotional
Mailing destinations, Do Not Contact written as text, alternative (fallback)
columns, unmapped-column reporting, the Tags separator hint, and splitting
files over the row limit. All data is synthetic.
"""

from __future__ import annotations

import csv
import io
import json
import tempfile
from pathlib import Path

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings

from newsletter import contact_import_services as services
from newsletter.contact_import_batches import split_csv
from newsletter.contact_import_services import (
    ContactImportError,
    ImportOptions,
    build_prepared_csv,
    build_preview,
    parse_csv,
    sign_validation,
    validate_import,
    validation_payload,
    verify_validation,
)
from newsletter.tests.contact_import_fixtures import CLIENT_HEADERS, client_csv, client_row, to_csv
from newsletter.tests.test_contact_import import NO_CACHE

FIELDS = {
    "fields": {
        "1": {"alias": "email", "label": "Email", "type": "email", "group": "core", "isPublished": True},
        "2": {"alias": "firstname", "label": "First Name", "type": "text", "group": "core", "isPublished": True},
        "3": {"alias": "lastname", "label": "Last Name", "type": "text", "group": "core", "isPublished": True},
        "4": {"alias": "phone", "label": "Phone", "type": "tel", "group": "core", "isPublished": True},
        "5": {"alias": "company", "label": "Primary company", "type": "text", "group": "core", "isPublished": True},
        "6": {"alias": "position", "label": "Position", "type": "text", "group": "core", "isPublished": True},
        "7": {"alias": "country", "label": "Country", "type": "country", "group": "core", "isPublished": True},
        "8": {"alias": "state", "label": "State", "type": "region", "group": "core", "isPublished": True},
        "9": {"alias": "city", "label": "City", "type": "text", "group": "core", "isPublished": True},
        "10": {"alias": "ecp_newsletter_opt_in", "label": "Newsletter Opt-In", "type": "boolean", "group": "personal", "isPublished": True},
        "11": {"alias": "ecp_promotional_mailing", "label": "Promotional Mailing", "type": "boolean", "group": "personal", "isPublished": True},
        "12": {"alias": "points", "label": "Points", "type": "number", "group": "core", "isPublished": True},
    }
}
CHOICES = {
    "country": [{"label": "India", "value": "India"}],
    "region": [{"label": "Gujarat", "value": "Gujarat"}],
}


class StubClient:
    def __init__(self, existing=None, fields=FIELDS):
        self.existing = {k.lower(): v for k, v in (existing or {}).items()}
        self.fields = fields

    def list_fields(self, field_object, **params):
        return self.fields

    def get_field_type_choices(self, field_type):
        return {"choices": CHOICES.get(field_type, [])}

    def lookup_contact_emails(self, emails):
        return {e: self.existing[e] for e in emails if e in self.existing}


def _targets(client=None):
    return services.mapping_targets(client or StubClient())


def _suggested(parsed, targets=None):
    preview = build_preview(parsed, targets or _targets())
    mapping = {**preview["suggested_mapping"], **preview["suggested_fallbacks"]}
    options = ImportOptions(
        tag_separator=preview["tag_separator_hint"]["suggested"] or "|",
        fallback_columns=tuple(preview["suggested_fallbacks"]),
    )
    return preview, mapping, options


def _values(result):
    return {row: values for row, values, _key in result.rows}


@override_settings(**NO_CACHE)
class ClientMappingTests(SimpleTestCase):
    def test_all_68_headers_parse_and_get_conservative_suggestions(self):
        parsed = parse_csv("client.csv", client_csv([client_row(1)]))
        self.assertEqual(parsed.headers, CLIENT_HEADERS)
        preview, _mapping, _options = _suggested(parsed)
        mapped = {h: a for h, a in preview["suggested_mapping"].items() if a}
        self.assertEqual(
            mapped,
            {
                "Email": "email",
                "First Name": "firstname",
                "Last Name": "lastname",
                "Phone Number": "phone",
                "Organization": "company",
                "Job Title": "position",
                "*Country": "country",
                "*Region": "state",
                "*Do Not Contact": "doNotEmail",
                "*City": "city",
                "*News Letter Opt-In": "ecp_newsletter_opt_in",
                "*Promotional Mailing": "ecp_promotional_mailing",
                "Tags": "tags",
            },
        )
        self.assertEqual(
            preview["suggested_fallbacks"],
            {"*Phone Number": "phone", "*Company Name": "company", "*Job Title": "position"},
        )
        # System columns are never suggested.
        for header in ("ID", "Date Created", "IP Address", "*IP", "*Score 1"):
            self.assertEqual(preview["suggested_mapping"][header], "")

    def test_consent_fields_are_only_suggested_when_they_exist_in_mautic(self):
        fields = {"fields": {k: v for k, v in FIELDS["fields"].items() if not v["alias"].startswith("ecp_")}}
        parsed = parse_csv("client.csv", client_csv([client_row(1)]))
        preview, _m, _o = _suggested(parsed, _targets(StubClient(fields=fields)))
        self.assertEqual(preview["suggested_mapping"]["*News Letter Opt-In"], "")
        self.assertEqual(preview["suggested_mapping"]["*Promotional Mailing"], "")


@override_settings(**NO_CACHE)
class ConsentFieldTests(SimpleTestCase):
    def _validate(self, rows, existing=None, options=None):
        parsed = parse_csv("client.csv", client_csv(rows))
        _preview, mapping, suggested = _suggested(parsed)
        return validate_import(parsed, mapping, options or suggested, client=StubClient(existing))

    def test_true_false_and_blank_stay_distinct_and_separate(self):
        result = self._validate(
            [
                client_row(1, **{"*News Letter Opt-In": "true", "*Promotional Mailing": ""}),
                client_row(2, **{"*News Letter Opt-In": "false", "*Promotional Mailing": "TRUE"}),
                client_row(3, **{"*News Letter Opt-In": "", "*Promotional Mailing": "no"}),
            ]
        )
        values = _values(result)
        self.assertEqual(values[2].get("ecp_newsletter_opt_in"), "1")
        self.assertNotIn("ecp_promotional_mailing", values[2])
        self.assertEqual(values[3].get("ecp_newsletter_opt_in"), "0")
        self.assertEqual(values[3].get("ecp_promotional_mailing"), "1")
        self.assertNotIn("ecp_newsletter_opt_in", values[4])
        self.assertEqual(values[4].get("ecp_promotional_mailing"), "0")
        content, mapping = build_prepared_csv(result)
        rows = list(csv.DictReader(io.StringIO(content.decode())))
        self.assertEqual([r["ecp_newsletter_opt_in"] for r in rows], ["1", "0", ""])
        self.assertEqual([r["ecp_promotional_mailing"] for r in rows], ["", "1", "0"])
        self.assertEqual(mapping["ecp_newsletter_opt_in"], "ecp_newsletter_opt_in")

    def test_opt_in_never_overrides_do_not_contact(self):
        result = self._validate(
            [client_row(1, **{"*News Letter Opt-In": "true", "*Promotional Mailing": "true", "*Do Not Contact": "Do Not Contact"})]
        )
        values = _values(result)[2]
        self.assertEqual((values["doNotEmail"], values["ecp_newsletter_opt_in"]), ("1", "1"))
        self.assertIn("does not subscribe anyone", " ".join(result.warnings))

    def test_invalid_consent_value_is_an_error_not_false(self):
        result = self._validate([client_row(1, **{"*News Letter Opt-In": "Do Not Contact"})])
        self.assertEqual(result.summary["invalid_rows"], 1)
        self.assertEqual(result.issues[0]["column"], "*News Letter Opt-In")


@override_settings(**NO_CACHE)
class DoNotContactTextTests(SimpleTestCase):
    def _validate(self, rows, *, mapping=None, options=None, existing=None):
        parsed = parse_csv("client.csv", client_csv(rows))
        _preview, suggested_mapping, suggested_options = _suggested(parsed)
        return validate_import(
            parsed,
            mapping or suggested_mapping,
            options or suggested_options,
            client=StubClient(existing),
        )

    def test_textual_and_boolean_values(self):
        result = self._validate(
            [
                client_row(1, **{"*Do Not Contact": "Do Not Contact"}),
                client_row(2, **{"*Do Not Contact": "  do not   CONTACT "}),
                client_row(3, **{"*Do Not Contact": "true"}),
                client_row(4, **{"*Do Not Contact": "Yes"}),
                client_row(5, **{"*Do Not Contact": "false"}),
                client_row(6, **{"*Do Not Contact": "0"}),
                client_row(7, **{"*Do Not Contact": ""}),
                client_row(8, **{"*Do Not Contact": "unsubscribed"}),
            ]
        )
        values = _values(result)
        self.assertEqual([values[r].get("doNotEmail") for r in (2, 3, 4, 5)], ["1"] * 4)
        for row in (6, 7, 8):
            self.assertNotIn("doNotEmail", values[row])  # never sent as "false"
        self.assertEqual(result.summary["dnc_rows"], 4)
        self.assertEqual([(i["row"], i["code"]) for i in result.issues], [(9, "invalid_value")])

    def test_existing_contacts_keep_their_restrictions(self):
        existing = {
            "client-format-00001@example.test": {"dnc_email": True, "dnc_reason": "unsubscribed"},
            "client-format-00002@example.test": {"dnc_email": False},
        }
        rows = [
            client_row(1, **{"*Do Not Contact": "false", "*News Letter Opt-In": "true"}),
            client_row(2, **{"*Do Not Contact": "Do Not Contact"}),
        ]
        skip = self._validate(rows, existing=existing)
        self.assertEqual(skip.summary["to_skip"], 2)
        self.assertEqual(skip.summary["skipped_dnc_conflicts"], 1)
        self.assertEqual(skip.rows, [])

        parsed = parse_csv("client.csv", client_csv(rows))
        _p, mapping, options = _suggested(parsed)
        options.existing_mode = "fill_empty"
        fill = validate_import(parsed, mapping, options, client=StubClient(existing))
        values = _values(fill)
        self.assertNotIn("doNotEmail", values[2])  # false never removes the unsubscribe
        self.assertEqual(values[3]["doNotEmail"], "1")
        self.assertEqual(fill.summary["existing_suppressed"], 1)

    def test_unmapped_dnc_column_with_values_fails_closed(self):
        parsed = parse_csv("client.csv", client_csv([client_row(1, **{"*Do Not Contact": "true"})]))
        _p, mapping, options = _suggested(parsed)
        mapping["*Do Not Contact"] = ""
        with self.assertRaises(ContactImportError) as ctx:
            validate_import(parsed, mapping, options, client=StubClient())
        self.assertEqual([e["code"] for e in ctx.exception.errors], ["dnc_unmapped"])

        empty = parse_csv("client.csv", client_csv([client_row(1)]))
        _p, mapping, options = _suggested(empty)
        mapping["*Do Not Contact"] = ""
        self.assertEqual(len(validate_import(empty, mapping, options, client=StubClient()).rows), 1)

    def test_dnc_column_mapped_to_another_field_fails_closed(self):
        parsed = parse_csv("client.csv", client_csv([client_row(1, **{"*Do Not Contact": "Do Not Contact"})]))
        _p, mapping, options = _suggested(parsed)
        for target in ("city", "ecp_newsletter_opt_in"):
            with self.assertRaises(ContactImportError) as ctx:
                validate_import(parsed, {**mapping, "*Do Not Contact": target}, options, client=StubClient())
            self.assertIn("dnc_misdirected", {e["code"] for e in ctx.exception.errors})
        # An empty DNC column may be mapped anywhere or skipped.
        empty = parse_csv("client.csv", client_csv([client_row(1)]))
        _p, mapping, options = _suggested(empty)
        result = validate_import(empty, {**mapping, "*City": "", "*Do Not Contact": "city"}, options, client=StubClient())
        self.assertEqual(len(result.rows), 1)

    def test_any_true_dnc_column_adds_dnc(self):
        headers = ["Email", "Do Not Contact", "*Do Not Contact"]
        rows = [
            {"Email": "a@example.test", "Do Not Contact": "false", "*Do Not Contact": "Do Not Contact"},
            {"Email": "b@example.test", "Do Not Contact": "", "*Do Not Contact": "maybe"},
            {"Email": "c@example.test", "Do Not Contact": "", "*Do Not Contact": ""},
        ]
        parsed = parse_csv("dnc.csv", to_csv(rows, headers))
        mapping = {"Email": "email", "Do Not Contact": "doNotEmail", "*Do Not Contact": "doNotEmail"}
        result = validate_import(
            parsed, mapping, ImportOptions(fallback_columns=("*Do Not Contact",)), client=StubClient()
        )
        values = _values(result)
        self.assertEqual(values[2]["doNotEmail"], "1")
        self.assertNotIn("doNotEmail", values[4])
        self.assertEqual([(i["row"], i["column"]) for i in result.issues], [(3, "*Do Not Contact")])


@override_settings(**NO_CACHE)
class FallbackColumnTests(SimpleTestCase):
    def test_fallback_only_fills_an_empty_primary(self):
        rows = [
            client_row(1, Organization="Primary Org", **{"*Company Name": "Other Org"}),
            client_row(2, Organization="", **{"*Company Name": "Fallback Org", "*Phone Number": "+12025550100"}),
            client_row(3, Organization="Same Org", **{"*Company Name": "same org"}),
            client_row(4),
        ]
        parsed = parse_csv("client.csv", client_csv(rows))
        _p, mapping, options = _suggested(parsed)
        result = validate_import(parsed, mapping, options, client=StubClient())
        values = _values(result)
        self.assertEqual(values[2]["company"], "Primary Org")
        self.assertEqual(values[3]["company"], "Fallback Org")
        self.assertEqual(values[3]["phone"], "+12025550100")
        self.assertEqual(values[4]["company"], "Same Org")
        self.assertNotIn("company", values[5])
        self.assertEqual(result.summary["fallback_rows"], 1)
        self.assertEqual(result.summary["fallback_conflict_rows"], 1)  # case-only difference is not a conflict
        content, header_map = build_prepared_csv(result)
        self.assertEqual(list(header_map.values()).count("company"), 1)
        fallback_entries = [m for m in validation_payload(result)["mapping"] if m.get("fallback_for")]
        self.assertIn({"column": "*Company Name", "field": "company", "label": "Primary company", "type": "text", "fallback_for": "Organization"}, fallback_entries)

    def test_fallback_errors_are_reported_against_the_fallback_column(self):
        parsed = parse_csv("client.csv", client_csv([client_row(1, **{"Phone Number": "", "*Phone Number": "call me"})]))
        _p, mapping, options = _suggested(parsed)
        result = validate_import(parsed, mapping, options, client=StubClient())
        self.assertEqual(result.issues[0]["column"], "*Phone Number")

    def test_without_the_fallback_flag_two_columns_still_conflict(self):
        parsed = parse_csv("client.csv", client_csv([client_row(1)]))
        _p, mapping, _o = _suggested(parsed)
        with self.assertRaises(ContactImportError) as ctx:
            validate_import(parsed, mapping, ImportOptions(), client=StubClient())
        self.assertIn("duplicate_target", {e["code"] for e in ctx.exception.errors})

    def test_invalid_fallback_configurations(self):
        parsed = parse_csv("client.csv", client_csv([client_row(1)]))
        base = {"Email": "email"}

        def codes(mapping, fallbacks):
            with self.assertRaises(ContactImportError) as ctx:
                validate_import(parsed, mapping, ImportOptions(fallback_columns=fallbacks), client=StubClient())
            return {e["code"] for e in ctx.exception.errors}

        self.assertIn("fallback_without_primary", codes({**base, "*Company Name": "company"}, ("*Company Name",)))
        self.assertIn("fallback_not_allowed", codes({**base, "*Personal Email": "email"}, ("*Personal Email",)))
        self.assertIn("unknown_column", codes(base, ("Nope",)))

    def test_fallbacks_are_bound_into_the_validation_token(self):
        from django.contrib.auth import get_user_model

        user = get_user_model()(pk=5)
        parsed = parse_csv("client.csv", client_csv([client_row(1)]))
        _p, mapping, options = _suggested(parsed)
        token = sign_validation(user, parsed, mapping, options)
        verify_validation(token, user, parsed, mapping, options)
        with self.assertRaises(ContactImportError) as ctx:
            verify_validation(token, user, parsed, mapping, ImportOptions(tag_separator=options.tag_separator))
        self.assertEqual(ctx.exception.code, "revalidation_required")

    def test_options_validate_fallback_columns(self):
        self.assertEqual(services.parse_options({"fallback_columns": ["A", "A", "B"]}).fallback_columns, ("A", "B"))
        for bad in ("A", [1], {"A": 1}):
            with self.assertRaises(ContactImportError):
                services.parse_options({"fallback_columns": bad})


@override_settings(**NO_CACHE)
class UnmappedColumnTests(SimpleTestCase):
    def test_review_lists_unmapped_columns_and_warns_about_consent(self):
        rows = [client_row(1, **{"*Subscribe to Newsletter": "true", "*Industry": "Education"})]
        parsed = parse_csv("client.csv", client_csv(rows))
        _p, mapping, options = _suggested(parsed)
        result = validate_import(parsed, mapping, options, client=StubClient())
        summary = result.summary
        unmapped = {item["column"]: item["populated"] for item in summary["unmapped_columns"]}
        self.assertEqual(unmapped["*Industry"], 1)
        self.assertEqual(unmapped["*Subscribe to Newsletter"], 1)
        self.assertEqual(unmapped["*Opt-In 1"], 0)
        self.assertEqual(summary["mapped_columns"], 16)
        self.assertEqual(len(unmapped), 68 - 16)
        self.assertEqual(summary["skipped_consent_columns"], [{"column": "*Subscribe to Newsletter", "populated": 1}])
        self.assertIn("'*Subscribe to Newsletter' has 1 value but is not mapped", " ".join(result.warnings))

    def test_missing_consent_destination_is_reported(self):
        fields = {"fields": {k: v for k, v in FIELDS["fields"].items() if not v["alias"].startswith("ecp_")}}
        client = StubClient(fields=fields)
        parsed = parse_csv("client.csv", client_csv([client_row(1, **{"*News Letter Opt-In": "true", "*Promotional Mailing": "true"})]))
        preview = build_preview(parsed, _targets(client))
        mapping = {**preview["suggested_mapping"], **preview["suggested_fallbacks"]}
        options = ImportOptions(fallback_columns=tuple(preview["suggested_fallbacks"]))
        result = validate_import(parsed, mapping, options, client=client)
        skipped = {item["column"] for item in result.summary["skipped_consent_columns"]}
        self.assertEqual(skipped, {"*News Letter Opt-In", "*Promotional Mailing"})


@override_settings(**NO_CACHE)
class TagSeparatorTests(SimpleTestCase):
    def test_hint_detects_comma_and_validation_splits_with_it(self):
        rows = [
            client_row(1, Tags="demo-contact,local-import"),
            client_row(2, Tags=" a , b ,A,"),
            client_row(3, Tags="single"),
            client_row(4, Tags=""),
        ]
        parsed = parse_csv("client.csv", client_csv(rows))
        preview, mapping, options = _suggested(parsed)
        self.assertEqual(preview["tag_separator_hint"], {"column": "Tags", "suggested": ",", "counts": {"|": 0, ",": 2, ";": 0}, "values": 3})
        values = _values(validate_import(parsed, mapping, options, client=StubClient()))
        self.assertEqual(values[2]["tags"], "demo-contact|local-import")
        self.assertEqual(values[3]["tags"], "a|b")
        self.assertEqual(values[4]["tags"], "single")
        self.assertNotIn("tags", values[5])

    def test_pipe_keeps_its_semantics_but_warns(self):
        parsed = parse_csv("client.csv", client_csv([client_row(1, Tags="demo-contact,local-import")]))
        _p, mapping, options = _suggested(parsed)
        options.tag_separator = "|"
        result = validate_import(parsed, mapping, options, client=StubClient())
        self.assertEqual(_values(result)[2]["tags"], "demo-contact,local-import")
        self.assertEqual(result.summary["tag_separator_conflicts"], 1)
        self.assertIn("imported as a single tag", " ".join(result.warnings))

    def test_rejected_tag_values_are_not_reported_as_single_tags(self):
        parsed = parse_csv("client.csv", client_csv([client_row(1, Tags="a|b"), client_row(2, Tags="c,d")]))
        _p, mapping, options = _suggested(parsed)
        options.tag_separator = ","
        result = validate_import(parsed, mapping, options, client=StubClient())
        self.assertEqual(result.summary["tag_separator_conflicts"], 0)
        self.assertNotIn("single tag", " ".join(result.warnings))
        self.assertEqual([i["row"] for i in result.issues], [2])

    def test_mixed_separators_give_no_suggestion(self):
        parsed = parse_csv("client.csv", client_csv([client_row(1, Tags="a,b"), client_row(2, Tags="c|d")]))
        self.assertIsNone(build_preview(parsed, _targets())["tag_separator_hint"]["suggested"])

    def test_quoted_tag_values_survive_csv_parsing(self):
        raw = b'Email,Tags\na@example.test,"x, y, x"\n'
        parsed = parse_csv("t.csv", raw)
        result = validate_import(parsed, {"Email": "email", "Tags": "tags"}, ImportOptions(tag_separator=","), client=StubClient())
        self.assertEqual(_values(result)[2]["tags"], "x|y")


@override_settings(**NO_CACHE, NEWSLETTER_CONTACT_IMPORT_MAX_ROWS=20000)
class BatchSplitTests(SimpleTestCase):
    def _rows(self, count):
        return [client_row(i, **({"*Additional Comments": 'Line one\nline "two", three'} if i % 1000 == 0 else {})) for i in range(1, count + 1)]

    def test_large_client_file_splits_into_exact_batches(self):
        raw = client_csv(self._rows(34238))
        self.assertLessEqual(len(raw), 10 * 1024 * 1024)
        with self.assertRaises(ContactImportError) as ctx:
            parse_csv("client.csv", raw)
        self.assertEqual(ctx.exception.code, "too_many_rows")
        self.assertIn("split_contact_import_csv", str(ctx.exception))

        result = split_csv(raw)
        self.assertEqual([b.rows for b in result.batches], [20000, 14238])
        self.assertEqual(result.total_rows, 34238)
        self.assertEqual([(b.first_source_row, b.last_source_row) for b in result.batches], [(2, 20001), (20002, 34239)])

        source = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline="")))
        rebuilt = []
        for batch in result.batches:
            parsed = parse_csv("batch.csv", batch.content)  # each batch passes the importer's own limits
            self.assertEqual(parsed.headers, CLIENT_HEADERS)
            self.assertFalse(batch.content.startswith(b"\xef\xbb\xbf"))
            rebuilt.extend(cells for _n, cells in parsed.rows)
        self.assertEqual(rebuilt, source[1:])
        self.assertIn('Line one\nline "two", three', {row[CLIENT_HEADERS.index("*Additional Comments")] for row in rebuilt})

    def test_records_keep_their_exact_bytes_and_crlf(self):
        raw = b'Email,Note\r\na@example.test,"multi\r\nline, ""quoted"""\r\nb@example.test,plain\r\n\r\nc@example.test,x'
        result = split_csv(raw, batch_rows=2)
        self.assertEqual([b.rows for b in result.batches], [2, 1])
        self.assertEqual(
            result.batches[0].content,
            b'Email,Note\r\na@example.test,"multi\r\nline, ""quoted"""\r\nb@example.test,plain\r\n',
        )
        # The blank record travels with the next contact; only the final
        # record's missing line break is added.
        self.assertEqual(result.batches[1].content, b"Email,Note\r\n\r\nc@example.test,x\n")

    def test_duplicates_are_not_removed_and_byte_limit_is_respected(self):
        rows = [client_row(1)] * 3
        result = split_csv(client_csv(rows), batch_rows=2, batch_bytes=2000)
        self.assertEqual(sum(b.rows for b in result.batches), 3)
        self.assertTrue(all(len(b.content) <= 2000 for b in result.batches))

    def _same_records_as_the_wizard(self, raw, result):
        wizard = parse_csv("source.csv", raw)
        expected = [cells for _n, cells in wizard.rows if cells]
        rebuilt = []
        for batch in result.batches:
            parsed = parse_csv("batch.csv", batch.content)
            self.assertEqual(parsed.headers, wizard.headers)
            rebuilt.extend(cells for _n, cells in parsed.rows if cells)
        self.assertEqual(rebuilt, expected)
        self.assertEqual(result.total_rows, len(expected))

    def test_quoted_empty_record_is_blank_like_the_wizard(self):
        raw = b'Email,Name\na@example.test,A\n"",""\nb@example.test,B\n'
        result = split_csv(raw, batch_rows=1)
        self.assertEqual([b.rows for b in result.batches], [1, 1])
        self._same_records_as_the_wizard(raw, result)
        self.assertEqual(result.batches[1].content, b'Email,Name\n"",""\nb@example.test,B\n')

    def test_stray_quote_in_unquoted_value_stays_literal_like_the_wizard(self):
        raw = b'Email,Note\na@example.test,5" screen\nb@example.test,x\nc@example.test,"say ""hi"""\n'
        result = split_csv(raw, batch_rows=1)
        self.assertEqual([b.rows for b in result.batches], [1, 1, 1])
        self._same_records_as_the_wizard(raw, result)
        self.assertEqual(result.batches[0].content, b'Email,Note\na@example.test,5" screen\n')

    def test_semicolon_files_split_with_the_wizards_delimiter(self):
        raw = b'Email;Name\na@example.test;"A; B"\nb@example.test;C\n'
        result = split_csv(raw, batch_rows=1)
        self._same_records_as_the_wizard(raw, result)

    def test_limits_must_be_positive(self):
        for kwargs in ({"batch_rows": 0}, {"batch_rows": -1}, {"batch_bytes": 0}, {"batch_bytes": -5}):
            with self.assertRaises(ContactImportError) as ctx:
                split_csv(b"Email\na@example.test\n", **kwargs)
            self.assertEqual(ctx.exception.code, "invalid_batch_size")

    def test_blank_lines_count_toward_the_byte_limit(self):
        header = b"Email\n"
        row = b"a@example.test\n"
        raw = header + row + b"\n" * 10 + b"b@example.test\n" + b"\n" * 500
        limit = len(header) + len(row) + 20
        result = split_csv(raw, batch_bytes=limit)
        self.assertTrue(all(len(b.content) <= limit for b in result.batches))
        self.assertEqual((result.total_rows, [b.rows for b in result.batches]), (2, [1, 1]))
        self.assertEqual(result.batches[1].content, header + b"\n" * 10 + b"b@example.test\n")
        self.assertEqual(result.blank_records_dropped, 500)
        # 40 blank lines + the next contact exceed the limit together.
        with self.assertRaises(ContactImportError) as ctx:
            split_csv(header + row + b"\n" * 40 + b"b@example.test\n", batch_bytes=len(header) + 30)
        self.assertEqual(ctx.exception.code, "file_too_large")

    def test_trailing_blank_records_are_kept_when_they_fit_else_counted(self):
        kept = split_csv(b"Email\na@example.test\n\n\n")
        self.assertEqual((kept.batches[0].content, kept.blank_records_dropped), (b"Email\na@example.test\n\n\n", 0))
        dropped = split_csv(b"Email\na@example.test\n" + b"\n" * 50, batch_bytes=30)
        self.assertEqual((dropped.batches[0].content, dropped.blank_records_dropped), (b"Email\na@example.test\n", 50))

    def test_unsafe_inputs_are_refused(self):
        with self.assertRaises(ContactImportError):
            split_csv(b'Email,Note\na@example.test,"never closed\n')
        with self.assertRaises(ContactImportError):
            split_csv("Email\nä@example.test\n".encode("latin-1"))
        with self.assertRaises(ContactImportError):
            split_csv(b"Email\na@example.test\n", batch_rows=20001)

    def test_command_writes_batches_and_manifest_without_overwriting(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "contacts.csv"
            source.write_bytes(client_csv([client_row(i) for i in range(1, 6)]))
            out = Path(tmp) / "out"
            call_command("split_contact_import_csv", str(source), "--out-dir", str(out), "--rows", "2", stdout=io.StringIO())
            files = sorted(p.name for p in out.iterdir())
            self.assertEqual(
                files,
                ["contacts.manifest.json", "contacts.part-01-of-03.csv", "contacts.part-02-of-03.csv", "contacts.part-03-of-03.csv"],
            )
            manifest = json.loads((out / "contacts.manifest.json").read_text())
            self.assertEqual((manifest["total_rows"], [b["rows"] for b in manifest["batches"]]), (5, [2, 2, 1]))
            with self.assertRaises(CommandError):
                call_command("split_contact_import_csv", str(source), "--out-dir", str(out), "--rows", "2", stdout=io.StringIO())
            for args in (["--rows", "0"], ["--rows", "-3"], ["--max-bytes", "0"]):
                with self.assertRaises(CommandError):
                    call_command("split_contact_import_csv", str(source), "--out-dir", str(Path(tmp) / "x"), *args, stdout=io.StringIO())
            self.assertFalse((Path(tmp) / "x").exists())


class ClientFormatEndpointTests(TestCase):
    """The preview endpoint carries the new hints; existing payloads still work."""

    def test_preview_exposes_fallback_and_tag_hints(self):
        from unittest.mock import patch

        from django.contrib.auth import get_user_model
        from django.core.files.uploadedfile import SimpleUploadedFile
        from django.urls import reverse
        from rest_framework.test import APIClient

        from newsletter.tests.marketing_actors import grant_marketing_access

        user = get_user_model().objects.create_user(username="client-format-admin", password="x", is_superuser=True)
        grant_marketing_access(user)
        api = APIClient()
        api.force_authenticate(user=user)
        raw = client_csv([client_row(1, Tags="a,b")])
        with override_settings(**NO_CACHE), patch(
            "newsletter.contact_import_services.MauticClient", return_value=StubClient()
        ):
            response = api.post(
                reverse("newsletter-admin-contact-import-preview"),
                {"file": SimpleUploadedFile("client.csv", raw, content_type="text/csv")},
                format="multipart",
            )
            legacy = api.post(
                reverse("newsletter-admin-contact-import-validate"),
                {
                    "file": SimpleUploadedFile("client.csv", raw, content_type="text/csv"),
                    "mapping": json.dumps({"Email": "email"}),
                    "options": json.dumps({"existing_mode": "skip_existing", "tag_separator": "|"}),
                },
                format="multipart",
            )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["total_columns"], 68)
        self.assertEqual(response.data["tag_separator_hint"]["suggested"], ",")
        self.assertEqual(response.data["suggested_fallbacks"]["*Company Name"], "company")
        # A pre-existing payload (no fallback_columns) is still accepted.
        self.assertEqual(legacy.status_code, 200, legacy.data)
        self.assertEqual(legacy.data["options"]["fallback_columns"], [])
