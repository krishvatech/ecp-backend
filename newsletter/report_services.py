"""Marketing Hub reports (Mautic's report builder in the custom UI).

Mautic owns the reports. ECP reads the builder metadata (sources, columns,
filters, graphs) and report data through the bridge, and saves reports through
it as the admin's own Mautic user, where Mautic's report form validates every
column and filter again.

ECP validates a report against the source's metadata first, for clear errors
and because filter columns end up in SQL: only keys Mautic itself published are
ever sent. Every save sends the whole definition, so a PATCH never depends on
what the native form does with a missing key.

Datetime filter values are UTC throughout ECP; the bridge converts them for
Mautic's form.
"""

from __future__ import annotations

import re
from datetime import date, timedelta
from typing import Any

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils import timezone

from . import marketing_cache
from .mautic import MauticClient

AGGREGATE_FUNCTIONS = ("COUNT", "AVG", "SUM", "MIN", "MAX")
SCHEDULE_UNITS = ("DAILY", "WEEKLY", "MONTHLY")
SCHEDULE_DAYS = ("MO", "TU", "WE", "TH", "FR", "SA", "SU", "WEEK_DAYS")
MONTH_FREQUENCIES = ("1", "-1")
SETTINGS = ("showGraphsAboveTable", "showDynamicFilters", "hideDateRangeFilter")
LIST_CONDITIONS = ("in", "notIn")
NO_VALUE_CONDITIONS = ("empty", "notEmpty")
MAX_FILTERS = 50
MAX_RECIPIENTS = 20
MAX_RANGE_DAYS = 3660
DEFAULT_RANGE_DAYS = 30
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ReportError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid_report", status_code: int = 400, field: str = ""):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.field = field


# Metadata ------------------------------------------------------------------------


def report_sources(client: MauticClient | None = None) -> list[dict[str, Any]]:
    client = client or MauticClient()
    return marketing_cache.cached_value("report-sources", [], client.list_report_sources, ttl=marketing_cache.metadata_ttl())


def report_source(source: str, client: MauticClient | None = None) -> dict[str, Any]:
    client = client or MauticClient()
    if source not in {row["source"] for row in report_sources(client)}:
        raise ReportError("That data source is not available.", code="invalid_source", status_code=404, field="source")
    return marketing_cache.cached_value(
        "report-source", [source], lambda: client.get_report_source(source), ttl=marketing_cache.metadata_ttl()
    )


# Validation ----------------------------------------------------------------------


def _flag(value) -> int:
    if isinstance(value, str):
        return 1 if value.strip().lower() in ("1", "true", "yes", "on") else 0
    return 1 if value else 0


def _keys(rows) -> list[str]:
    return [str(row["key"]) for row in rows or [] if isinstance(row, dict) and row.get("key")]


def _string_list(value, field: str) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise ReportError(f"{field} must be a list.", field=field)
    return list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))


def _subset(values: list[str], allowed: list[str], field: str, noun: str) -> list[str]:
    allowed_set = set(allowed)
    unknown = [value for value in values if value not in allowed_set]
    if unknown:
        raise ReportError(f"Unknown {noun} for this data source: {', '.join(unknown[:5])}.", field=field)
    return values


def _filters(raw, meta: dict[str, Any]) -> list[dict[str, Any]]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise ReportError("filters must be a list.", field="filters")
    if len(raw) > MAX_FILTERS:
        raise ReportError(f"A report can have at most {MAX_FILTERS} filters.", field="filters")
    definitions = {str(row.get("key")): row for row in meta.get("filters") or [] if isinstance(row, dict)}
    filters = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ReportError(f"Filter {index} is invalid.", field="filters")
        column = str(item.get("column") or "").strip()
        definition = definitions.get(column)
        if definition is None:
            raise ReportError(f"Filter {index}: choose a field from this data source.", field="filters")
        condition = str(item.get("condition") or "").strip()
        operators = {str(option.get("value")) for option in definition.get("operators") or [] if isinstance(option, dict)}
        if condition not in operators:
            raise ReportError(f"Filter {index}: that condition is not available for {definition.get('label') or column}.", field="filters")
        glue = str(item.get("glue") or "and").strip().lower()
        if glue not in ("and", "or"):
            raise ReportError(f"Filter {index}: join filters with and/or.", field="filters")

        raw_value = item.get("value")
        if condition in NO_VALUE_CONDITIONS:
            value: Any = ""
        elif condition in LIST_CONDITIONS:
            value = _string_list(raw_value if isinstance(raw_value, list) else [raw_value] if raw_value not in (None, "") else [], "filters")
            if not value:
                raise ReportError(f"Filter {index}: choose at least one value.", field="filters")
        else:
            if isinstance(raw_value, (list, dict)):
                raise ReportError(f"Filter {index}: enter a single value.", field="filters")
            value = "" if raw_value is None else str(raw_value).strip()
            if len(value) > 500:
                raise ReportError(f"Filter {index}: the value is too long.", field="filters")
        # Dynamic filters are changed per run with one text value (see the bridge).
        dynamic = _flag(item.get("dynamic")) if condition not in LIST_CONDITIONS + NO_VALUE_CONDITIONS else 0
        filters.append({"column": column, "glue": glue, "condition": condition, "value": value, "dynamic": dynamic})
    return filters


def _table_order(raw, columns: list[str]) -> list[dict[str, str]]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise ReportError("tableOrder must be a list.", field="tableOrder")
    order = []
    for item in raw:
        if not isinstance(item, dict):
            raise ReportError("Each sort entry needs a column and a direction.", field="tableOrder")
        column = str(item.get("column") or "").strip()
        if column not in columns:
            raise ReportError("Sort by one of this data source's columns.", field="tableOrder")
        direction = str(item.get("direction") or "ASC").strip().upper()
        if direction not in ("ASC", "DESC"):
            raise ReportError("Sort direction must be ASC or DESC.", field="tableOrder")
        order.append({"column": column, "direction": direction})
    return order


def _aggregators(raw, columns: list[str]) -> list[dict[str, str]]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise ReportError("aggregators must be a list.", field="aggregators")
    aggregators = []
    for item in raw:
        if not isinstance(item, dict):
            raise ReportError("Each calculation needs a function and a column.", field="aggregators")
        function = str(item.get("function") or "").strip().upper()
        column = str(item.get("column") or "").strip()
        if function not in AGGREGATE_FUNCTIONS:
            raise ReportError("Calculations are COUNT, AVG, SUM, MIN or MAX.", field="aggregators")
        if column not in columns:
            raise ReportError("Calculate on one of this data source's columns.", field="aggregators")
        aggregators.append({"function": function, "column": column})
    return aggregators


def _recipients(raw) -> str:
    values = raw if isinstance(raw, list) else str(raw or "").replace(";", ",").split(",")
    emails = list(dict.fromkeys(str(value).strip().lower() for value in values if str(value).strip()))
    if not emails:
        raise ReportError("Add at least one email address to send the report to.", field="toAddress")
    if len(emails) > MAX_RECIPIENTS:
        raise ReportError(f"Send to at most {MAX_RECIPIENTS} addresses.", field="toAddress")
    for email in emails:
        try:
            validate_email(email)
        except ValidationError as exc:
            raise ReportError(f"{email} is not a valid email address.", field="toAddress") from exc
    return ",".join(emails)


def _schedule(data, existing: dict[str, Any] | None) -> dict[str, Any]:
    def pick(key, default=None):
        if key in data:
            return data.get(key)
        return (existing or {}).get(key, default)

    if not _flag(pick("isScheduled", False)):
        # Mautic clears the rest when a report is not scheduled.
        return {"isScheduled": 0, "toAddress": "", "scheduleUnit": "DAILY", "scheduleDay": None, "scheduleMonthFrequency": None}

    unit = str(pick("scheduleUnit") or "").strip().upper()
    if unit not in SCHEDULE_UNITS:
        raise ReportError("Choose how often to send the report: daily, weekly or monthly.", field="scheduleUnit")
    schedule = {"isScheduled": 1, "toAddress": _recipients(pick("toAddress", "")), "scheduleUnit": unit,
                "scheduleDay": None, "scheduleMonthFrequency": None}
    if unit in ("WEEKLY", "MONTHLY"):
        day = str(pick("scheduleDay") or "").strip().upper()
        if day not in SCHEDULE_DAYS:
            raise ReportError("Choose the day to send the report on.", field="scheduleDay")
        schedule["scheduleDay"] = day
    if unit == "MONTHLY":
        frequency = str(pick("scheduleMonthFrequency") or "").strip()
        if frequency not in MONTH_FREQUENCIES:
            raise ReportError("Choose the first or last such day of the month.", field="scheduleMonthFrequency")
        schedule["scheduleMonthFrequency"] = frequency
    return schedule


def normalize_report(data, *, existing: dict[str, Any] | None = None, client: MauticClient | None = None) -> dict[str, Any]:
    """The full native payload for a create (``existing`` None) or an update.

    On update, keys the caller leaves out keep their saved value, and the
    source can never change.
    """
    if not hasattr(data, "get"):
        raise ReportError("Send the report as an object.", code="invalid_payload")

    def pick(key, default=None):
        if key in data:
            return data.get(key)
        return (existing or {}).get(key, default)

    name = str(pick("name") or "").strip()
    if not name:
        raise ReportError("Give the report a name.", field="name")
    if len(name) > 191:
        raise ReportError("The name can be at most 191 characters.", field="name")
    description = str(pick("description") or "").strip()
    if len(description) > 2000:
        raise ReportError("The description can be at most 2000 characters.", field="description")

    if existing is not None:
        source = str(existing.get("source") or "")
        if "source" in data and str(data.get("source") or "") != source:
            raise ReportError("A saved report cannot change its data source. Create a new report instead.", field="source")
    else:
        source = str(data.get("source") or "").strip()
        if not source:
            raise ReportError("Choose a data source.", field="source")
    meta = report_source(source, client)

    columns_allowed = _keys(meta.get("columns"))
    columns = _subset(_string_list(pick("columns"), "columns"), columns_allowed, "columns", "columns")
    graphs = _subset(_string_list(pick("graphs"), "graphs"), _keys(meta.get("graphs")), "graphs", "graphs")
    if not columns and not graphs:
        raise ReportError("Choose at least one column or graph.", field="columns")
    group_by = _subset(
        _string_list(pick("groupBy"), "groupBy"), [str(key) for key in meta.get("groupByColumns") or []], "groupBy", "group-by columns"
    )
    aggregators = _aggregators(pick("aggregators"), columns_allowed)
    if aggregators and not group_by:
        raise ReportError("Calculations need at least one group-by column.", field="aggregators")
    # MySQL (only_full_group_by, the default) refuses a grouped query that also
    # selects ungrouped columns; Mautic would save the report and then fail to run it.
    ungrouped = [column for column in columns if column not in group_by]
    if group_by and ungrouped:
        labels = {str(row["key"]): row.get("label") or row["key"] for row in meta.get("columns") or [] if isinstance(row, dict)}
        names = ", ".join(str(labels.get(column, column)) for column in ungrouped[:3])
        raise ReportError(
            f"With a group-by, every column must be grouped. Add {names} to Group by, or remove it from Columns "
            "(calculations show values per group).",
            field="groupBy",
        )

    raw_settings = pick("settings") or {}
    if not isinstance(raw_settings, dict):
        raise ReportError("settings must be an object.", field="settings")

    table_order = _table_order(pick("tableOrder"), columns_allowed)
    unsortable = [item["column"] for item in table_order if item["column"] not in group_by]
    if group_by and unsortable:
        raise ReportError("With a group-by, sort only by grouped columns.", field="tableOrder")

    payload = {
        "name": name,
        "description": description,
        "isPublished": _flag(pick("isPublished", True)),
        "system": _flag(pick("system", False)),
        "source": source,
        "columns": columns,
        "filters": _filters(pick("filters"), meta),
        "tableOrder": table_order,
        "graphs": graphs,
        "groupBy": group_by,
        "aggregators": aggregators,
        "settings": {key: _flag(raw_settings.get(key)) for key in SETTINGS},
    }
    payload.update(_schedule(data, existing))
    return payload


# Running -------------------------------------------------------------------------


def date_range(params) -> tuple[str, str]:
    """dateFrom/dateTo as YYYY-MM-DD (UTC); the last 30 days by default, as in Mautic."""
    today = timezone.now().date()
    raw_from = str(params.get("dateFrom") or "").strip()
    raw_to = str(params.get("dateTo") or "").strip()
    for value in (raw_from, raw_to):
        if value and not _DATE_RE.match(value):
            raise ReportError("Dates must be in YYYY-MM-DD format.", code="invalid_dates")
    try:
        date_to = date.fromisoformat(raw_to) if raw_to else today
        date_from = date.fromisoformat(raw_from) if raw_from else date_to - timedelta(days=DEFAULT_RANGE_DAYS)
    except ValueError as exc:
        raise ReportError("That date does not exist.", code="invalid_dates") from exc
    if date_from > date_to:
        raise ReportError("The start date must be on or before the end date.", code="invalid_dates")
    if (date_to - date_from).days > MAX_RANGE_DAYS:
        raise ReportError("Choose a date range of at most 10 years.", code="invalid_dates")
    return date_from.isoformat(), date_to.isoformat()


def dynamic_filter_values(raw, report: dict[str, Any]) -> dict[str, str]:
    """Run-time values for the report's dynamic filters only (the bridge re-checks)."""
    if not isinstance(raw, dict):
        return {}
    dynamic = {
        str(item.get("column")) for item in report.get("filters") or []
        if isinstance(item, dict) and _flag(item.get("dynamic")) and item.get("condition") not in LIST_CONDITIONS
    }
    return {
        str(column): str(value).strip()[:500]
        for column, value in raw.items()
        if str(column) in dynamic and isinstance(value, (str, int, float)) and str(value).strip()
    }
