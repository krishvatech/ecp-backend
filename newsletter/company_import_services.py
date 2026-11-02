"""Company CSV import on Mautic's native import queue.

ECP reads the uploaded CSV, suggests which column fills which company field,
checks the values, and hands Mautic a plain comma CSV with the chosen mapping.
The bridge queues a native Import (object "company") as the acting admin, and
``mautic:import`` creates or updates the companies exactly as Mautic's own
wizard does: companies are matched by company name, the only unique company
field. ECP never stores the file. Companies hold no consent data, so no row is
refused for consent reasons.
"""

from __future__ import annotations

import csv
import io
import re
from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import URLValidator, validate_email

from .contact_import_services import _clean_cell

MAX_BYTES = 25 * 1024 * 1024
MAX_ROWS = 50000
MAX_COLUMNS = 100
PREVIEW_ROWS = 10
ISSUE_LIMIT = 50
MODES = ("create_or_update", "skip_existing")
NAME_FIELD = "companyname"
CANDIDATE_DELIMITERS = (",", ";", "\t")
# Header words that point at a company field, beyond its own label and alias.
SYNONYMS = {
    "companyname": {"name", "company", "companyname", "organisation", "organization", "account", "accountname"},
    "companyemail": {"email", "emailaddress", "companyemail"},
    "companywebsite": {"website", "web", "url", "site", "domain", "homepage"},
    "companyphone": {"phone", "telephone", "tel", "phonenumber"},
    "companycity": {"city", "town"},
    "companystate": {"state", "region", "province", "county"},
    "companyzipcode": {"zip", "zipcode", "postcode", "postalcode"},
    "companycountry": {"country"},
    "companyindustry": {"industry", "sector"},
    "companynumber_of_employees": {"employees", "numberofemployees", "headcount", "staff"},
    "companyannual_revenue": {"revenue", "annualrevenue", "turnover"},
    "companyaddress1": {"address", "address1", "street", "addressline1"},
    "companyaddress2": {"address2", "addressline2"},
    "companydescription": {"description", "about", "notes"},
    "companyfax": {"fax"},
}
_KEY = re.compile(r"[^a-z0-9]+")
_NUMBER = re.compile(r"^[+-]?(\d+([.,]\d+)?|[.,]\d+)$")


class CompanyImportError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid_company_import", field: str = ""):
        super().__init__(message)
        self.code = code
        self.field = field


def _key(text: str) -> str:
    return _KEY.sub("", str(text or "").lower())


def company_fields(rows) -> list[dict[str, str]]:
    """Published company fields: the name first, then the rest in Mautic's order."""
    if isinstance(rows, dict):
        rows = list(rows.values())
    fields = []
    for row in rows or []:
        if not isinstance(row, dict) or str(row.get("object") or "") != "company" or not row.get("alias"):
            continue
        if row.get("isPublished") in (False, 0, "0"):
            continue
        fields.append({"alias": str(row["alias"]), "label": str(row.get("label") or row["alias"]), "type": str(row.get("type") or "text")})
    return sorted(fields, key=lambda field: field["alias"] != NAME_FIELD)


def read_csv(upload) -> dict[str, Any]:
    """Headers and rows of an uploaded CSV (UTF-8, comma, semicolon or tab)."""
    if upload is None:
        raise CompanyImportError("Choose a CSV file.", field="file")
    if getattr(upload, "size", 0) > MAX_BYTES:
        raise CompanyImportError("The file is larger than 25 MB.", field="file")
    raw = upload.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise CompanyImportError("Save the file as UTF-8 CSV and upload it again.", field="file") from None
    first_line = text.split("\n", 1)[0]
    delimiter = max(CANDIDATE_DELIMITERS, key=first_line.count)
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
    try:
        headers = [header.strip() for header in next(reader)]
    except StopIteration:
        raise CompanyImportError("The file is empty.", field="file") from None
    if not headers or any(not header for header in headers) or len(set(headers)) != len(headers):
        raise CompanyImportError("The first row must hold unique, non-empty column names.", field="file")
    if len(headers) > MAX_COLUMNS:
        raise CompanyImportError(f"Use {MAX_COLUMNS} columns or fewer.", field="file")
    rows = []
    for values in reader:
        if not any(value.strip() for value in values):
            continue
        rows.append({header: (values[index].strip() if index < len(values) else "") for index, header in enumerate(headers)})
        if len(rows) > MAX_ROWS:
            raise CompanyImportError(f"The file has more than {MAX_ROWS:,} companies.", field="file")
    if not rows:
        raise CompanyImportError("The file has no company rows.", field="file")
    return {"headers": headers, "rows": rows, "delimiter": delimiter}


def suggest_mapping(headers: list[str], fields: list[dict[str, str]]) -> dict[str, str]:
    """{header: alias} for headers that clearly name a company field."""
    by_key = {}
    for field in fields:
        for name in {field["alias"], field["label"], field["alias"].removeprefix("company")} | SYNONYMS.get(field["alias"], set()):
            by_key.setdefault(_key(name), field["alias"])
    mapping, used = {}, set()
    for header in headers:
        alias = by_key.get(_key(header))
        if alias and alias not in used:
            mapping[header] = alias
            used.add(alias)
    return mapping


def parse_mapping(raw, headers: list[str], fields: list[dict[str, str]]) -> dict[str, str]:
    if not isinstance(raw, dict) or not raw:
        raise CompanyImportError("Choose which column holds the company name.", field="mapping")
    aliases = {field["alias"] for field in fields}
    mapping = {}
    for header, alias in raw.items():
        if alias in (None, ""):
            continue
        if header not in headers:
            raise CompanyImportError(f'Column "{header}" is not in the file.', field="mapping")
        if alias not in aliases:
            raise CompanyImportError(f'"{alias}" is not a published company field.', field="mapping")
        mapping[str(header)] = str(alias)
    if NAME_FIELD not in mapping.values():
        raise CompanyImportError("Choose which column holds the company name: Mautic matches companies by name.", field="mapping")
    if len(set(mapping.values())) != len(mapping):
        raise CompanyImportError("Each company field can be filled from one column only.", field="mapping")
    return mapping


def _cleaned(rows: list[dict[str, str]], mapping: dict[str, str], counters: dict[str, int]) -> list[dict[str, str]]:
    """Mapped values as Mautic will get them: line breaks become spaces (its
    importer reads one physical line per row) and a literal NULL, which would
    clear the field, becomes empty."""
    return [{header: _clean_cell(row.get(header, ""), counters) for header in mapping} for row in rows]


def check_rows(rows: list[dict[str, str]], mapping: dict[str, str], fields: list[dict[str, str]]) -> dict[str, Any]:
    """Counts and the first problems found, by row number (1 = first data row)."""
    types = {field["alias"]: field["type"] for field in fields}
    name_column = next(header for header, alias in mapping.items() if alias == NAME_FIELD)
    issues, without_name, seen, duplicates = [], 0, set(), 0
    counters = {"line_breaks": 0, "null_literals": 0, "formula_like": 0}
    rows = _cleaned(rows, mapping, counters)
    url_check = URLValidator(schemes=["http", "https"])
    for number, row in enumerate(rows, start=1):
        name = row.get(name_column, "").strip()
        if not name:
            without_name += 1
            if len(issues) < ISSUE_LIMIT:
                issues.append({"row": number, "column": name_column, "message": "No company name: Mautic will skip this row."})
            continue
        if name.lower() in seen:
            duplicates += 1
        seen.add(name.lower())
        for header, alias in mapping.items():
            value = row.get(header, "").strip()
            if not value or len(issues) >= ISSUE_LIMIT:
                continue
            kind = types.get(alias, "text")
            problem = ""
            if kind == "email":
                try:
                    validate_email(value)
                except DjangoValidationError:
                    problem = "is not an email address"
            elif kind == "url":
                candidate = value if "://" in value else f"https://{value}"
                try:
                    url_check(candidate)
                except DjangoValidationError:
                    problem = "is not a web address"
            elif kind == "number" and not _NUMBER.match(value.replace(" ", "")):
                problem = "is not a number"
            if problem:
                issues.append({"row": number, "column": header, "message": f'"{value[:60]}" {problem}.'})
    return {
        "rows": len(rows),
        "without_name": without_name,
        "duplicate_names": duplicates,
        "line_breaks": counters["line_breaks"],
        "null_literals": counters["null_literals"],
        "issues": issues,
    }


def prepared_csv(rows: list[dict[str, str]], mapping: dict[str, str]) -> bytes:
    """The mapped columns only, as the RFC 4180 comma CSV the bridge expects.

    Each column is headed by its field alias: Mautic reduces header names to
    letters, digits and underscores before it reads the mapping, which aliases
    already are, so any column name in the admin's file is safe. One physical
    line per row and no trailing newline, which Mautic would count as an
    ignored row.
    """
    headers = list(mapping)
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([mapping[header] for header in headers])
    for row in _cleaned(rows, mapping, {"line_breaks": 0, "null_literals": 0, "formula_like": 0}):
        writer.writerow([row[header] for header in headers])
    return buffer.getvalue().rstrip("\n").encode("utf-8")
