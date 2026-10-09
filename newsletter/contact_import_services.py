"""CSV contact imports for the Marketing Hub.

ECP never stores the uploaded file. Each step (preview, validate, start)
receives the file again and parses it from scratch, bounded in size and rows.
Validation signs a short-lived token binding the file checksum, mapping and
options to the administrator; Start refuses anything else, revalidates the
whole file, and hands only the approved rows to Mautic's native import queue
through the ECP bridge.

Mautic owns the durable job: its ``imports`` row, per-batch progress, resume
point, counts and per-row errors. The bridge's row guard re-applies the safety
rules (Do Not Contact is add-only, existing contacts are skipped or only have
empty fields filled) while Mautic processes each row, so they hold even if
Mautic's data changes after validation.

Nothing here logs CSV contents.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from typing import Any

from django.conf import settings
from django.core import signing
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator, validate_email
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from . import marketing_cache
from .contact_services import _dict_values, _normalize_field
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_ROWS = 20000
MAX_COLUMNS = 100
FIELD_METADATA_LIMIT = 500
PREVIEW_ROWS = 25
ISSUE_LIMIT = 200
LOOKUP_BATCH_SIZE = 5000
TOKEN_MAX_AGE_SECONDS = 60 * 60
TOKEN_SALT = "newsletter.contact_import.validation"
# Mautic saves a running import once per batch; this long without a save
# means the worker most likely stopped (Mautic itself fails it after 2 hours).
STALL_MINUTES = 15
SOURCE_ROW_HEADER = "ecp_source_row"

MODE_SKIP_EXISTING = "skip_existing"
MODE_FILL_EMPTY = "fill_empty"
EXISTING_MODES = (MODE_SKIP_EXISTING, MODE_FILL_EMPTY)
TAG_SEPARATORS = ("|", ",", ";")

EMAIL_TARGET = "email"
TAGS_TARGET = "tags"
DNC_TARGET = "doNotEmail"

# Never writable from an import: the internal contact ID (a legacy CSV "ID"
# must not select or overwrite Mautic contacts), ownership/attribution and
# values Mautic derives itself. Mirrors the bridge's BLOCKED_TARGETS.
BLOCKED_TARGETS = frozenset(
    {
        "id",
        "points",
        "owner",
        "ownerusername",
        "createdbyuser",
        "modifiedbyuser",
        "dateadded",
        "datemodified",
        "dateidentified",
        "lastactive",
        "last_active",
        "attribution",
        "attribution_date",
        "ip",
        "stage",
    }
)

SUPPORTED_TYPES = frozenset(
    {
        "text",
        "textarea",
        "lookup",
        "email",
        "tel",
        "url",
        "number",
        "boolean",
        "date",
        "datetime",
        "time",
        "select",
        "multiselect",
        "country",
        "region",
        "locale",
        "timezone",
    }
)
REFERENCE_TYPES = frozenset({"country", "region", "locale", "timezone"})
MAX_TEXT_LENGTH = 191
MAX_TEXTAREA_LENGTH = 65535

TRUE_VALUES = frozenset({"1", "true", "yes", "y", "on", "t"})
FALSE_VALUES = frozenset({"0", "false", "no", "n", "off", "f"})

CONSENT_PATTERN = re.compile(
    r"(opt.?in|opt.?out|consent|subscri|newsletter|promo|marketing|gdpr|permission)",
    re.IGNORECASE,
)
PHONE_PATTERN = re.compile(r"^\+?[0-9 ().\-/]{3,40}(\s*(x|ext\.?)\s*[0-9]{1,6})?$", re.IGNORECASE)
NUMBER_PATTERN = re.compile(r"^[+-]?(\d+(\.\d+)?|\.\d+)$")
FORMULA_PREFIXES = ("=", "@")
LINE_BREAKS = re.compile(r"\r\n|\r|\n")
CANDIDATE_DELIMITERS = (",", ";", "\t")

# Normalized header -> suggested target. Only unambiguous synonyms; anything
# that looks like an identifier ("id", "contact id") is never suggested.
HEADER_SYNONYMS = {
    "email": "email",
    "emailaddress": "email",
    "mail": "email",
    "firstname": "firstname",
    "givenname": "firstname",
    "forename": "firstname",
    "lastname": "lastname",
    "surname": "lastname",
    "familyname": "lastname",
    "phone": "phone",
    "phonenumber": "phone",
    "telephone": "phone",
    "mobile": "mobile",
    "mobilephone": "mobile",
    "mobilenumber": "mobile",
    "cellphone": "mobile",
    "company": "company",
    "companyname": "company",
    "organization": "company",
    "organisation": "company",
    "position": "position",
    "jobtitle": "position",
    "city": "city",
    "town": "city",
    "state": "state",
    "province": "state",
    "country": "country",
    "zip": "zipcode",
    "zipcode": "zipcode",
    "postcode": "zipcode",
    "postalcode": "zipcode",
    "address": "address1",
    "address1": "address1",
    "address2": "address2",
    "website": "website",
    "tags": "tags",
    "tag": "tags",
    "donotcontact": DNC_TARGET,
    "donotemail": DNC_TARGET,
    "dnc": DNC_TARGET,
}
NEVER_SUGGEST = frozenset({"id", "contactid", "legacyid", "mauticid", "leadid", "recordid"})


def _count(count: int, singular: str, plural: str) -> str:
    """'1 row has' / '3 rows have': each phrase gives both forms in full."""
    return f"{count:,} {singular if count == 1 else plural}"


class ContactImportError(ValueError):
    """A request-level problem the administrator can fix (bad file, bad mapping)."""

    def __init__(self, message: str, *, code: str = "invalid", errors=None):
        super().__init__(message)
        self.code = code
        self.errors = list(errors or [])

    def as_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"detail": str(self), "code": self.code}
        if self.errors:
            payload["errors"] = self.errors
        return payload


class ContactImportUnavailable(Exception):
    """Execution is not possible in this deployment (e.g. no per-user identity)."""


def max_bytes() -> int:
    return int(getattr(settings, "NEWSLETTER_CONTACT_IMPORT_MAX_BYTES", DEFAULT_MAX_BYTES))


def max_rows() -> int:
    return int(getattr(settings, "NEWSLETTER_CONTACT_IMPORT_MAX_ROWS", DEFAULT_MAX_ROWS))


# ---------------------------------------------------------------------------
# Parsing


@dataclass
class ParsedCsv:
    filename: str
    size: int
    sha256: str
    delimiter: str
    headers: list[str]
    # (row number as a spreadsheet shows it, cells). The header is row 1.
    rows: list[tuple[int, list[str]]]
    malformed_rows: int = 0
    empty_rows: int = 0


def _normalize_header_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _safe_filename(name: str) -> str:
    name = str(name or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[^A-Za-z0-9 ._()\-]", "_", name).strip(" .")
    return (name or "contacts.csv")[:120]


def read_upload(uploaded_file) -> tuple[str, bytes]:
    """Read an uploaded file with a hard size bound. Never logs content."""
    if uploaded_file is None:
        raise ContactImportError("Choose a CSV file to upload.", code="file_required")

    filename = _safe_filename(getattr(uploaded_file, "name", ""))
    if not filename.lower().endswith(".csv"):
        raise ContactImportError("Only .csv files can be imported.", code="unsupported_type")

    limit = max_bytes()
    size = getattr(uploaded_file, "size", None)
    if size is not None and size > limit:
        raise ContactImportError(
            f"The file is larger than the {limit // (1024 * 1024)} MB limit.",
            code="file_too_large",
        )
    raw = uploaded_file.read(limit + 1)
    if len(raw) > limit:
        raise ContactImportError(
            f"The file is larger than the {limit // (1024 * 1024)} MB limit.",
            code="file_too_large",
        )
    return filename, raw


def _detect_delimiter(header_line: str) -> str:
    counts = {}
    for delimiter in CANDIDATE_DELIMITERS:
        try:
            cells = next(csv.reader([header_line], delimiter=delimiter, strict=True))
        except (csv.Error, StopIteration):
            continue
        counts[delimiter] = len(cells)

    best = max(counts.values(), default=1)
    if best <= 1:
        return ","
    winners = [delimiter for delimiter, count in counts.items() if count == best]
    if len(winners) > 1:
        names = {",": "comma", ";": "semicolon", "\t": "tab"}
        raise ContactImportError(
            "The column separator is ambiguous ("
            + " or ".join(names[d] for d in winners)
            + "). Save the file as a standard comma-separated CSV.",
            code="ambiguous_delimiter",
        )
    return winners[0]


def parse_csv(filename: str, raw: bytes) -> ParsedCsv:
    if not raw or not raw.strip():
        raise ContactImportError("The file is empty.", code="empty_file")
    if b"\x00" in raw:
        raise ContactImportError(
            "The file looks like a binary file, not a CSV.", code="binary_file"
        )
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ContactImportError(
            "The file is not valid UTF-8. Save it as 'CSV UTF-8' and upload it again.",
            code="encoding",
        ) from None

    first_line = text.lstrip("﻿").split("\n", 1)[0].rstrip("\r")
    delimiter = _detect_delimiter(first_line)

    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
    try:
        headers = next(reader)
    except StopIteration:
        raise ContactImportError("The file is empty.", code="empty_file") from None
    except csv.Error:
        raise ContactImportError(
            "The header row is not valid CSV.", code="malformed_csv"
        ) from None

    headers = [str(header or "").strip() for header in headers]
    if not any(headers):
        raise ContactImportError("The first row must contain column headers.", code="missing_headers")
    if any(not header for header in headers):
        raise ContactImportError(
            "Every column needs a header. Remove empty columns or name them.",
            code="missing_headers",
        )
    if len(headers) > MAX_COLUMNS:
        raise ContactImportError(
            f"The file has more than {MAX_COLUMNS} columns.", code="too_many_columns"
        )
    seen: dict[str, str] = {}
    duplicates = []
    for header in headers:
        key = header.casefold()
        if key in seen:
            duplicates.append(header)
        seen.setdefault(key, header)
    if duplicates:
        raise ContactImportError(
            "Column headers must be unique. Duplicated: "
            + ", ".join(sorted(set(duplicates), key=str.casefold))
            + ".",
            code="duplicate_headers",
        )

    rows: list[tuple[int, list[str]]] = []
    limit = max_rows()
    malformed = 0
    empty = 0
    row_number = 1
    try:
        for cells in reader:
            row_number += 1
            if not any(str(cell).strip() for cell in cells):
                empty += 1
                rows.append((row_number, []))
                continue
            if len(rows) - empty >= limit:
                raise ContactImportError(
                    f"The file has more than {limit:,} contact rows.", code="too_many_rows"
                )
            if len(cells) != len(headers):
                malformed += 1
            rows.append((row_number, cells))
    except csv.Error:
        # The reader fails while fetching the next record, before it is counted.
        raise ContactImportError(
            f"Row {row_number + 1} is not valid CSV (check for an unclosed quote).",
            code="malformed_csv",
        ) from None

    data_rows = len(rows) - empty
    if data_rows == 0:
        raise ContactImportError("The file has a header row but no contacts.", code="no_rows")
    if malformed and malformed * 10 > data_rows:
        raise ContactImportError(
            f"{malformed:,} of {data_rows:,} rows have a different number of columns "
            "than the header. Check the file's separator and quoting.",
            code="inconsistent_columns",
        )

    return ParsedCsv(
        filename=filename,
        size=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        delimiter=delimiter,
        headers=headers,
        rows=rows,
        malformed_rows=malformed,
        empty_rows=empty,
    )


# ---------------------------------------------------------------------------
# Mapping targets


def _choice_pairs(choices) -> list[tuple[str, str]]:
    pairs = []
    for choice in choices or []:
        if isinstance(choice, dict):
            value = str(choice.get("value", "") if choice.get("value") is not None else "")
            label = str(choice.get("label", "") or value)
        else:
            value = label = str(choice)
        if value != "" or label != "":
            pairs.append((value, label))
    return pairs


def _length_limit(raw: dict[str, Any], field_type: str) -> int:
    default = MAX_TEXTAREA_LENGTH if field_type == "textarea" else MAX_TEXT_LENGTH
    try:
        limit = int(raw.get("charLengthLimit") or 0)
    except (TypeError, ValueError):
        limit = 0
    return limit if 0 < limit <= default else default


def mapping_targets(client) -> list[dict[str, Any]]:
    """Mapping destinations from live Mautic field metadata plus Tags and DNC.

    Uses the full field API (publish state, required flag, select options and
    length limits), not the slimmer contacts/list/fields listing.
    """
    data = marketing_cache.fields(client, "contact", limit=FIELD_METADATA_LIMIT)
    raw_fields = _dict_values(data, "fields")

    targets = []
    for raw in raw_fields:
        item = _normalize_field(raw)
        alias = item["alias"]
        if not alias or not item["published"]:
            continue
        reason = ""
        if alias.lower() in BLOCKED_TARGETS:
            reason = "Set by Mautic; cannot be imported."
        elif not item["writable"]:
            reason = "Read-only in Mautic."
        elif item["type"] not in SUPPORTED_TYPES:
            reason = f"Field type '{item['type']}' is not supported by the importer."
        targets.append(
            {
                "alias": alias,
                "label": item["label"] or alias,
                "type": item["type"],
                "group": item["group"],
                "required": bool(item["required"]) or alias == EMAIL_TARGET,
                "max_length": _length_limit(raw, item["type"]),
                "importable": not reason,
                "reason": reason,
                "choices": [
                    {"value": value, "label": label}
                    for value, label in _choice_pairs(item["choices"])
                ],
                "consent_like": bool(
                    CONSENT_PATTERN.search(alias) or CONSENT_PATTERN.search(item["label"] or "")
                ),
                "special": False,
            }
        )

    targets.append(
        {
            "alias": TAGS_TARGET,
            "label": "Tags",
            "type": "tags",
            "group": "special",
            "required": False,
            "importable": True,
            "reason": "",
            "choices": [],
            "consent_like": False,
            "special": True,
        }
    )
    targets.append(
        {
            "alias": DNC_TARGET,
            "label": "Do Not Contact (email)",
            "type": "dnc",
            "group": "special",
            "required": False,
            "importable": True,
            "reason": "",
            "choices": [],
            "consent_like": False,
            "special": True,
        }
    )
    return targets


def suggest_mapping(headers: list[str], targets: list[dict[str, Any]]) -> dict[str, str]:
    importable = {t["alias"]: t for t in targets if t["importable"]}
    by_key: dict[str, str] = {}
    for alias, target in importable.items():
        by_key.setdefault(_normalize_header_key(alias), alias)
        by_key.setdefault(_normalize_header_key(target["label"]), alias)

    suggestions: dict[str, str] = {}
    used = set()
    for header in headers:
        key = _normalize_header_key(header)
        if not key or key in NEVER_SUGGEST:
            suggestions[header] = ""
            continue
        alias = by_key.get(key) or HEADER_SYNONYMS.get(key, "")
        if alias and alias in importable and alias not in used:
            suggestions[header] = alias
            used.add(alias)
        else:
            suggestions[header] = ""
    return suggestions


# ---------------------------------------------------------------------------
# Preview


def build_preview(parsed: ParsedCsv, targets: list[dict[str, Any]]) -> dict[str, Any]:
    data_rows = [(number, cells) for number, cells in parsed.rows if cells]
    suggestions = suggest_mapping(parsed.headers, targets)
    email_header = next((h for h, alias in suggestions.items() if alias == EMAIL_TARGET), "")
    email_index = parsed.headers.index(email_header) if email_header else None

    missing = [0] * len(parsed.headers)
    seen_emails: set[str] = set()
    duplicate_emails = 0
    missing_emails = 0
    for _number, cells in data_rows:
        for index in range(len(parsed.headers)):
            if index >= len(cells) or not str(cells[index]).strip():
                missing[index] += 1
        if email_index is not None:
            email = cells[email_index].strip().lower() if email_index < len(cells) else ""
            if not email:
                missing_emails += 1
            elif email in seen_emails:
                duplicate_emails += 1
            else:
                seen_emails.add(email)

    warnings = []
    if not email_header:
        warnings.append("No email column was detected. Map one in the next step; email is required.")
    if missing_emails:
        warnings.append(_count(missing_emails, "row has", "rows have") + " no email address.")
    if duplicate_emails:
        warnings.append(
            _count(duplicate_emails, "row repeats", "rows repeat")
            + " an email address that appears earlier in the file."
        )
    if parsed.malformed_rows:
        warnings.append(
            _count(parsed.malformed_rows, "row has", "rows have")
            + " a different number of columns than the header."
        )
    if parsed.empty_rows:
        warnings.append(_count(parsed.empty_rows, "empty row", "empty rows") + " will be ignored.")

    return {
        "file": {
            "name": parsed.filename,
            "size": parsed.size,
            "sha256": parsed.sha256,
            "delimiter": {",": "comma", ";": "semicolon", "\t": "tab"}[parsed.delimiter],
        },
        "total_rows": len(data_rows),
        "empty_rows": parsed.empty_rows,
        "total_columns": len(parsed.headers),
        "headers": parsed.headers,
        "sample_rows": [
            {"row": number, "cells": [str(cell) for cell in cells[: len(parsed.headers)]]}
            for number, cells in data_rows[:PREVIEW_ROWS]
        ],
        "missing_values": {
            header: missing[index] for index, header in enumerate(parsed.headers)
        },
        "detected_email_column": email_header,
        "duplicate_email_rows": duplicate_emails,
        "missing_email_rows": missing_emails,
        "suggested_mapping": suggestions,
        "warnings": warnings,
        "limits": {"max_rows": max_rows(), "max_bytes": max_bytes()},
    }


# ---------------------------------------------------------------------------
# Validation


@dataclass
class ImportOptions:
    existing_mode: str = MODE_SKIP_EXISTING
    tag_separator: str = "|"

    def as_dict(self) -> dict[str, str]:
        return {"existing_mode": self.existing_mode, "tag_separator": self.tag_separator}


def parse_options(raw) -> ImportOptions:
    if raw in (None, ""):
        raw = {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raise ContactImportError("options must be a JSON object.", code="invalid_options") from None
    if not isinstance(raw, dict):
        raise ContactImportError("options must be a JSON object.", code="invalid_options")
    unknown = sorted(set(raw) - {"existing_mode", "tag_separator"})
    if unknown:
        raise ContactImportError(
            "Unsupported option(s): " + ", ".join(unknown), code="invalid_options"
        )
    mode = str(raw.get("existing_mode") or MODE_SKIP_EXISTING)
    if mode not in EXISTING_MODES:
        raise ContactImportError(
            "existing_mode must be 'skip_existing' or 'fill_empty'.", code="invalid_options"
        )
    separator = str(raw.get("tag_separator") or "|")
    if separator not in TAG_SEPARATORS:
        raise ContactImportError(
            "tag_separator must be one of | , ;", code="invalid_options"
        )
    return ImportOptions(existing_mode=mode, tag_separator=separator)


def parse_mapping(raw) -> dict[str, str]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raise ContactImportError("mapping must be a JSON object.", code="invalid_mapping") from None
    if not isinstance(raw, dict):
        raise ContactImportError("mapping must be a JSON object.", code="invalid_mapping")
    mapping = {}
    for header, target in raw.items():
        target = "" if target is None else str(target).strip()
        mapping[str(header)] = target
    return mapping


def check_mapping(
    parsed: ParsedCsv, mapping: dict[str, str], targets: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Return {header: target} for mapped columns, or raise with every problem."""
    by_alias = {t["alias"]: t for t in targets}
    problems = []
    unknown_headers = sorted(set(mapping) - set(parsed.headers))
    if unknown_headers:
        problems.append(
            {
                "code": "unknown_column",
                "message": "The mapping names columns that are not in the file: "
                + ", ".join(unknown_headers),
            }
        )

    mapped: dict[str, dict[str, Any]] = {}
    used: dict[str, str] = {}
    for header in parsed.headers:
        alias = mapping.get(header, "")
        if not alias:
            continue
        if alias.lower() in BLOCKED_TARGETS:
            problems.append(
                {
                    "code": "blocked_target",
                    "column": header,
                    "message": f"'{header}' cannot be mapped to '{alias}': Mautic sets it itself."
                    + (" A legacy ID never selects or replaces Mautic contacts." if alias.lower() == "id" else ""),
                }
            )
            continue
        target = by_alias.get(alias)
        if target is None:
            problems.append(
                {
                    "code": "unknown_target",
                    "column": header,
                    "message": f"'{alias}' is not a published Mautic contact field.",
                }
            )
            continue
        if not target["importable"]:
            problems.append(
                {
                    "code": "unsupported_target",
                    "column": header,
                    "message": f"'{target['label']}' cannot be imported: {target['reason']}",
                }
            )
            continue
        if alias in used:
            problems.append(
                {
                    "code": "duplicate_target",
                    "column": header,
                    "message": f"'{header}' and '{used[alias]}' are both mapped to '{target['label']}'.",
                }
            )
            continue
        used[alias] = header
        mapped[header] = target

    if EMAIL_TARGET not in used:
        problems.append(
            {"code": "email_required", "message": "Map one column to Email; it is used to match contacts."}
        )

    if problems:
        raise ContactImportError(
            "The field mapping needs attention.", code="invalid_mapping", errors=problems
        )
    return mapped


def _reference_lookup(client, field_type: str):
    """{casefolded value or label: canonical value}, or None when unavailable."""
    try:
        data = marketing_cache.field_type_choices(client, field_type)
    except (PermanentMauticError, TemporaryMauticError):
        return None
    lookup = {}
    for value, label in _choice_pairs(data.get("choices")):
        lookup.setdefault(value.casefold(), value)
        lookup.setdefault(label.casefold(), value)
    return lookup or None


@dataclass
class _RowIssue:
    row: int
    column: str
    field: str
    code: str
    message: str

    def as_dict(self):
        return {
            "row": self.row,
            "column": self.column,
            "field": self.field,
            "code": self.code,
            "message": self.message,
        }


@dataclass
class ValidationResult:
    parsed: ParsedCsv
    mapped: dict[str, dict[str, Any]]
    options: ImportOptions
    # (source row, {alias: normalized value}, email key) for rows that will be sent.
    rows: list[tuple[int, dict[str, str], str]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    issues: list[dict[str, Any]] = field(default_factory=list)
    issue_count: int = 0
    warnings: list[str] = field(default_factory=list)


class _Normalizer:
    def __init__(self, mapped, options, client):
        self.options = options
        self.reference = {}
        self.reference_unchecked = set()
        for target in mapped.values():
            if target["type"] in REFERENCE_TYPES and target["type"] not in self.reference:
                lookup = _reference_lookup(client, target["type"])
                self.reference[target["type"]] = lookup
                if lookup is None:
                    self.reference_unchecked.add(target["label"])
        self.url_validator = URLValidator(schemes=["http", "https"])

    def normalize(self, value: str, target: dict[str, Any]) -> tuple[str, str]:
        """Return (normalized value, error message). Empty value means 'not set'."""
        alias = target["alias"]
        kind = target["type"]

        if alias == TAGS_TARGET:
            return self._tags(value)
        if alias == DNC_TARGET:
            if value == "":
                return "", ""
            lowered = value.lower()
            if lowered in TRUE_VALUES:
                return "1", ""
            if lowered in FALSE_VALUES:
                # Never sent as "false": that would ask Mautic to remove DNC.
                return "", ""
            return "", "Do Not Contact must be true/false, yes/no or 1/0."
        if value == "":
            return "", ""

        limit = target.get("max_length") or MAX_TEXT_LENGTH
        if len(value) > limit:
            return "", f"Longer than {limit} characters."

        if kind == "email":
            try:
                validate_email(value)
            except ValidationError:
                return "", "Not a valid email address."
            return value, ""
        if kind == "tel":
            if not PHONE_PATTERN.match(value):
                return "", "Not a valid phone number."
            return value, ""
        if kind == "url":
            try:
                self.url_validator(value)
            except ValidationError:
                return "", "Not a valid URL (include http:// or https://)."
            return value, ""
        if kind == "number":
            if not NUMBER_PATTERN.match(value):
                return "", "Not a number."
            return value, ""
        if kind == "boolean":
            lowered = value.lower()
            if lowered in TRUE_VALUES:
                return "1", ""
            if lowered in FALSE_VALUES:
                return "0", ""
            return "", "Must be true/false, yes/no or 1/0."
        if kind == "date":
            try:
                return datetime.strptime(value, "%Y-%m-%d").strftime("%Y-%m-%d"), ""
            except ValueError:
                return "", "Dates must use YYYY-MM-DD."
        if kind == "datetime":
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
                try:
                    return datetime.strptime(value, fmt).strftime("%Y-%m-%d %H:%M:%S"), ""
                except ValueError:
                    continue
            return "", "Date-times must use YYYY-MM-DD HH:MM[:SS]."
        if kind == "time":
            for fmt in ("%H:%M:%S", "%H:%M"):
                try:
                    return datetime.strptime(value, fmt).strftime("%H:%M:%S"), ""
                except ValueError:
                    continue
            return "", "Times must use HH:MM[:SS]."
        if kind in ("select", "multiselect"):
            pairs = _choice_pairs(target["choices"])
            if not pairs:
                return value, ""
            lookup = {}
            for choice_value, label in pairs:
                lookup.setdefault(choice_value.casefold(), choice_value)
                lookup.setdefault(label.casefold(), choice_value)
            parts = [part.strip() for part in value.split("|")] if kind == "multiselect" else [value]
            resolved = []
            for part in parts:
                if not part:
                    continue
                if part.casefold() not in lookup:
                    return "", "Not one of the field's allowed options."
                resolved.append(lookup[part.casefold()])
            return "|".join(resolved), ""
        if kind in REFERENCE_TYPES:
            lookup = self.reference.get(kind)
            if lookup is None:
                return value, ""
            canonical = lookup.get(value.casefold())
            if canonical is None:
                return "", f"Not a recognised {kind} value."
            return canonical, ""
        return value, ""

    def _tags(self, value: str) -> tuple[str, str]:
        if value == "":
            return "", ""
        separator = self.options.tag_separator
        if separator != "|" and "|" in value:
            return "", "Tags contain '|' but a different separator was chosen."
        tags = []
        seen = set()
        for tag in value.split(separator):
            tag = tag.strip()
            if not tag:
                continue
            if tag.startswith("-"):
                return "", "Tags cannot start with '-' (Mautic would remove that tag)."
            if len(tag) > MAX_TEXT_LENGTH:
                return "", f"A tag is longer than {MAX_TEXT_LENGTH} characters."
            if tag.casefold() in seen:
                continue
            seen.add(tag.casefold())
            tags.append(tag)
        return "|".join(tags), ""


def _clean_cell(value: str, counters: dict[str, int]) -> str:
    value = str(value or "")
    if LINE_BREAKS.search(value):
        counters["line_breaks"] += 1
        value = LINE_BREAKS.sub(" ", value)
    value = value.strip()
    if value == "NULL":
        # Mautic's importer would clear the field for this exact value.
        counters["null_literals"] += 1
        return ""
    if value.startswith(FORMULA_PREFIXES):
        counters["formula_like"] += 1
    return value


def lookup_existing(client, emails: list[str]) -> dict[str, dict[str, Any]]:
    matches: dict[str, dict[str, Any]] = {}
    for start in range(0, len(emails), LOOKUP_BATCH_SIZE):
        batch = emails[start : start + LOOKUP_BATCH_SIZE]
        result = client.lookup_contact_emails(batch)
        for email, match in result.items():
            if isinstance(match, dict):
                matches[str(email).lower()] = match
    return matches


def validate_import(
    parsed: ParsedCsv,
    mapping: dict[str, str],
    options: ImportOptions,
    *,
    client,
    targets: list[dict[str, Any]] | None = None,
    check_existing: bool = True,
) -> ValidationResult:
    targets = targets if targets is not None else mapping_targets(client)
    mapped = check_mapping(parsed, mapping, targets)
    result = ValidationResult(parsed=parsed, mapped=mapped, options=options)
    normalizer = _Normalizer(mapped, options, client)
    header_index = {header: index for index, header in enumerate(parsed.headers)}

    counters = {"line_breaks": 0, "null_literals": 0, "formula_like": 0}
    issue_rows: set[int] = set()
    first_seen: dict[str, int] = {}
    candidates: list[tuple[int, dict[str, str], str, bool]] = []
    invalid = duplicates = 0
    dnc_rows = 0
    consent_true: dict[str, int] = {
        t["alias"]: 0 for t in mapped.values() if t["consent_like"]
    }

    def add_issue(row, column, target, code, message):
        result.issue_count += 1
        issue_rows.add(row)
        if len(result.issues) < ISSUE_LIMIT:
            result.issues.append(
                _RowIssue(row, column, target["alias"] if target else "", code, message).as_dict()
            )

    for row_number, cells in parsed.rows:
        if not cells:
            continue
        if len(cells) != len(parsed.headers):
            invalid += 1
            add_issue(
                row_number,
                "",
                None,
                "column_count",
                f"Has {len(cells)} values but the header has {len(parsed.headers)} columns.",
            )
            continue

        values: dict[str, str] = {}
        row_ok = True
        row_warned = False
        for header, target in mapped.items():
            before = dict(counters)
            raw = _clean_cell(cells[header_index[header]], counters)
            if counters != before:
                row_warned = True
            normalized, error = normalizer.normalize(raw, target)
            if error:
                row_ok = False
                code = "invalid_email" if target["alias"] == EMAIL_TARGET else "invalid_value"
                add_issue(row_number, header, target, code, error)
                continue
            if normalized != "":
                values[target["alias"]] = normalized

        email = values.get(EMAIL_TARGET, "")
        if row_ok and not email:
            row_ok = False
            email_header = next(h for h, t in mapped.items() if t["alias"] == EMAIL_TARGET)
            add_issue(row_number, email_header, mapped[email_header], "missing_email", "Email is required.")
        if not row_ok:
            invalid += 1
            continue

        key = email.lower()
        if key in first_seen:
            duplicates += 1
            add_issue(
                row_number,
                "",
                None,
                "duplicate_in_file",
                f"Same email as row {first_seen[key]}; only the first occurrence is imported.",
            )
            continue
        first_seen[key] = row_number
        candidates.append((row_number, values, key, row_warned))

    existing: dict[str, dict[str, Any]] = {}
    existing_checked = False
    if check_existing and candidates:
        try:
            existing = lookup_existing(client, [key for _r, _v, key, _w in candidates])
            existing_checked = True
        except (PermanentMauticError, TemporaryMauticError):
            result.warnings.append(
                "Existing Mautic contacts could not be checked, so create/skip counts are "
                "estimates. Skipping or filling existing contacts is still enforced by "
                "Mautic while the import runs."
            )

    to_create = to_update = to_skip = 0
    existing_suppressed = 0
    skipped_dnc_conflicts = 0
    needs_review = 0
    for row_number, values, key, row_warned in candidates:
        match = existing.get(key)
        if match is not None:
            if match.get("dnc_email"):
                existing_suppressed += 1
            if options.existing_mode == MODE_SKIP_EXISTING:
                to_skip += 1
                if values.get(DNC_TARGET) == "1" and not match.get("dnc_email"):
                    skipped_dnc_conflicts += 1
                continue
            to_update += 1
        else:
            to_create += 1
        if row_warned:
            needs_review += 1
        if values.get(DNC_TARGET) == "1":
            dnc_rows += 1
        for alias in consent_true:
            if values.get(alias) in ("1", "true"):
                consent_true[alias] += 1
        result.rows.append((row_number, values, key))

    total = len(parsed.rows) - parsed.empty_rows
    result.summary = {
        "total_rows": total,
        "empty_rows": parsed.empty_rows,
        "valid_rows": len(candidates),
        "invalid_rows": invalid,
        "duplicate_rows": duplicates,
        "existing_rows": to_skip + to_update,
        "existing_checked": existing_checked,
        "existing_suppressed": existing_suppressed,
        "to_create": to_create,
        "to_update": to_update,
        "to_skip": to_skip,
        "to_import": len(result.rows),
        "not_imported": invalid + duplicates + to_skip,
        "dnc_rows": dnc_rows,
        "skipped_dnc_conflicts": skipped_dnc_conflicts,
        "needs_review_rows": needs_review,
        "rows_with_issues": len(issue_rows),
        "consent_fields": [
            {"field": alias, "label": mapped_label, "true_rows": consent_true[alias]}
            for alias, mapped_label in (
                (t["alias"], t["label"]) for t in mapped.values() if t["consent_like"]
            )
        ],
        "existing_mode": options.existing_mode,
    }

    if counters["line_breaks"]:
        result.warnings.append(
            _count(counters["line_breaks"], "value contains", "values contain")
            + " line breaks; they are imported with spaces instead."
        )
    if counters["null_literals"]:
        result.warnings.append(
            _count(counters["null_literals"], "value is", "values are")
            + " the text 'NULL'; these are treated as empty so they never clear existing Mautic data."
        )
    if counters["formula_like"]:
        result.warnings.append(
            _count(counters["formula_like"], "value starts", "values start")
            + " with '=' or '@' (spreadsheet formula characters). These are imported as plain text."
        )
    if normalizer.reference_unchecked:
        result.warnings.append(
            "Allowed values could not be loaded for: "
            + ", ".join(sorted(normalizer.reference_unchecked))
            + ". Those values are imported as written."
        )
    if dnc_rows:
        result.warnings.append(
            _count(dnc_rows, "contact gets", "contacts get")
            + " an email Do Not Contact record. Existing Do Not Contact records are never "
            "removed by an import."
        )
    if skipped_dnc_conflicts:
        result.warnings.append(
            _count(skipped_dnc_conflicts, "existing contact is", "existing contacts are")
            + " marked Do Not Contact in the file but skipped, so the Mautic Do Not Contact "
            "status is not changed. Review them in Mautic or choose 'Fill empty fields only' "
            "to add the Do Not Contact record."
        )
    if existing_suppressed:
        result.warnings.append(
            _count(existing_suppressed, "matching Mautic contact already has", "matching Mautic contacts already have")
            + " email Do Not Contact; it is kept."
        )
    if consent_true:
        result.warnings.append(
            "Consent and preference columns are stored as contact field values only. Importing "
            "does not subscribe anyone, add contacts to segments or campaigns, or send email."
        )
    if options.existing_mode == MODE_FILL_EMPTY and to_update:
        result.warnings.append(
            _count(to_update, "existing contact", "existing contacts")
            + " will only have empty fields filled; values already in Mautic are never "
            "overwritten or blanked."
        )
    return result


def validation_payload(result: ValidationResult) -> dict[str, Any]:
    return {
        "file": {
            "name": result.parsed.filename,
            "size": result.parsed.size,
            "sha256": result.parsed.sha256,
        },
        "mapping": [
            {"column": header, "field": target["alias"], "label": target["label"], "type": target["type"]}
            for header, target in result.mapped.items()
        ],
        "options": result.options.as_dict(),
        "summary": result.summary,
        "issues": result.issues,
        "issue_count": result.issue_count,
        "issues_truncated": result.issue_count > len(result.issues),
        "warnings": result.warnings,
    }


# ---------------------------------------------------------------------------
# Validation token


def _mapping_digest(mapping: dict[str, str], options: ImportOptions) -> str:
    canonical = json.dumps(
        {"mapping": {k: v for k, v in mapping.items() if v}, "options": options.as_dict()},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sign_validation(user, parsed: ParsedCsv, mapping: dict[str, str], options: ImportOptions) -> str:
    return signing.dumps(
        {
            "v": 1,
            "uid": user.pk,
            "vid": uuid.uuid4().hex,
            "sha": parsed.sha256,
            "map": _mapping_digest(mapping, options),
            "iat": int(time.time()),
        },
        salt=TOKEN_SALT,
        compress=True,
    )


def verify_validation(token, user, parsed: ParsedCsv, mapping: dict[str, str], options: ImportOptions) -> dict:
    try:
        claims = signing.loads(str(token or ""), salt=TOKEN_SALT, max_age=TOKEN_MAX_AGE_SECONDS)
    except signing.SignatureExpired:
        raise ContactImportError(
            "This validation has expired. Validate the file again before importing.",
            code="validation_expired",
        ) from None
    except signing.BadSignature:
        raise ContactImportError(
            "Validate the file before starting the import.", code="validation_required"
        ) from None
    if not isinstance(claims, dict) or claims.get("v") != 1 or claims.get("uid") != user.pk:
        raise ContactImportError(
            "Validate the file before starting the import.", code="validation_required"
        )
    if claims.get("sha") != parsed.sha256 or claims.get("map") != _mapping_digest(mapping, options):
        raise ContactImportError(
            "The file, mapping or options changed after validation. Validate again before importing.",
            code="revalidation_required",
        )
    return claims


def idempotency_key(claims: dict) -> str:
    material = f"{claims['vid']}:{claims['sha']}:{claims['map']}:{claims['uid']}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Prepared file for Mautic


def _prepared_header(alias: str) -> str:
    header = re.sub(r"[^a-z0-9_]", "_", alias.lower())
    if not re.match(r"^[a-z]", header):
        header = f"f_{header}"
    return header[:64]


def build_prepared_csv(result: ValidationResult) -> tuple[bytes, dict[str, str]]:
    """RFC 4180, LF line endings, one physical line per record, no trailing
    newline: exactly what Mautic's line-by-line importer and the bridge's
    inspector expect."""
    columns = []
    mapping: dict[str, str] = {}
    for target in result.mapped.values():
        header = _prepared_header(target["alias"])
        if header == SOURCE_ROW_HEADER or header in mapping:
            raise ContactImportError("A mapped field name collides with another column.", code="invalid_mapping")
        mapping[header] = target["alias"]
        columns.append((header, target["alias"]))

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow([header for header, _alias in columns] + [SOURCE_ROW_HEADER])
    for row_number, values, _key in result.rows:
        writer.writerow([values.get(alias, "") for _header, alias in columns] + [str(row_number)])
    content = buffer.getvalue().rstrip("\n").encode("utf-8")
    if len(content) > max_bytes():
        raise ContactImportError("The prepared import is too large.", code="file_too_large")
    return content, mapping


def start_import(client, result: ValidationResult, claims: dict) -> tuple[dict[str, Any], bool]:
    if not getattr(client, "_uses_asserted_user", lambda: False)():
        raise ContactImportUnavailable(
            "Contact imports run as your own Mautic user, and per-user Mautic "
            "execution is not enabled on this server."
        )
    if not result.rows:
        raise ContactImportError("There are no rows to import.", code="nothing_to_import")

    content, header_mapping = build_prepared_csv(result)
    summary = {
        key: value
        for key, value in result.summary.items()
        if isinstance(value, int) and not isinstance(value, bool)
    }
    config = {
        "mapping": header_mapping,
        "mode": result.options.existing_mode,
        "idempotency_key": idempotency_key(claims),
        "expected_sha256": hashlib.sha256(content).hexdigest(),
        "original_filename": result.parsed.filename,
        "prepared_rows": len(result.rows),
        "summary": summary,
    }
    return client.create_contact_import(
        file_name="ecp-contact-import.csv",
        content=content,
        config=config,
    )


# ---------------------------------------------------------------------------
# Job status


def _stalled(state: str, updated_at) -> bool:
    if state not in ("queued", "processing") or not updated_at:
        return False
    moment = parse_datetime(str(updated_at))
    if moment is None:
        return False
    if timezone.is_naive(moment):
        moment = timezone.make_aware(moment, dt_timezone.utc)
    return timezone.now() - moment > timedelta(minutes=STALL_MINUTES)


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_import(data: dict[str, Any]) -> dict[str, Any]:
    ecp = data.get("ecp") if isinstance(data.get("ecp"), dict) else {}
    summary = ecp.get("summary") if isinstance(ecp.get("summary"), dict) else {}
    prepared = _int_or_none(ecp.get("prepared_rows")) or 0
    inserted = _int_or_none(data.get("inserted")) or 0
    updated = _int_or_none(data.get("updated")) or 0
    ignored = _int_or_none(data.get("ignored")) or 0
    processed = inserted + updated + ignored
    guard_skipped = _int_or_none(data.get("skipped_existing"))
    failed = ignored - guard_skipped if guard_skipped is not None else None
    pre_skipped = _int_or_none(summary.get("to_skip")) or 0
    excluded = (_int_or_none(summary.get("invalid_rows")) or 0) + (
        _int_or_none(summary.get("duplicate_rows")) or 0
    )

    status_name = str(data.get("status_name") or "unknown")
    if status_name == "imported":
        # Without the guard breakdown every ignored row counts as a possible error.
        has_errors = failed > 0 if failed is not None else ignored > 0
        state = "completed_with_errors" if has_errors else "completed"
    elif status_name in ("queued", "manual"):
        state = "queued"
    elif status_name == "delayed":
        state = "processing" if processed else "queued"
    elif status_name == "in_progress":
        state = "processing"
    elif status_name in ("failed", "stopped"):
        state = status_name
    else:
        state = "unknown"

    terminal = state in ("completed", "completed_with_errors", "failed", "stopped")
    return {
        "id": _int_or_none(data.get("id")),
        "state": state,
        "terminal": terminal,
        "mautic_status": status_name,
        "status_info": str(data.get("status_info") or "") if state in ("failed", "stopped") else "",
        "file_name": str(data.get("original_file") or ""),
        "mode": str(ecp.get("mode") or ""),
        "total_rows": _int_or_none(summary.get("total_rows")),
        "rows_sent": prepared,
        "processed": processed,
        "remaining": max(prepared - processed, 0),
        "progress_percentage": round(min(processed / prepared, 1) * 100, 1) if prepared else None,
        "created": inserted,
        "updated": updated,
        "skipped_existing": (pre_skipped + guard_skipped) if guard_skipped is not None else None,
        "skipped_existing_before_import": pre_skipped,
        "skipped_existing_during_import": guard_skipped,
        "failed": failed,
        "excluded_invalid": excluded,
        "created_at": data.get("date_added"),
        "started_at": data.get("date_started"),
        "finished_at": data.get("date_ended"),
        "updated_at": data.get("date_modified"),
        # Only meaningful once Mautic has started it; a queued import waits
        # for the queue, which is not a stall.
        "stalled": state == "processing" and _stalled(state, data.get("date_modified")),
        "created_by_mautic_user_id": _int_or_none(data.get("created_by")),
        "created_by_name": str(data.get("created_by_user") or ""),
    }


def normalize_import_errors(data: dict[str, Any]) -> dict[str, Any]:
    results = []
    for item in data.get("errors") or []:
        if not isinstance(item, dict):
            continue
        results.append(
            {
                "row": _int_or_none(item.get("source_row")),
                "line": _int_or_none(item.get("line")),
                "category": str(item.get("category") or "other"),
                "message": str(item.get("message") or "")[:300],
            }
        )
    return {"count": _int_or_none(data.get("total")) or 0, "results": results}


def client_for_reads() -> MauticClient:
    return MauticClient()
