"""Mautic-backed Marketing Hub analytics.

This module is intentionally separate from the legacy ECP newsletter campaign
analytics service. Mautic remains the marketing source of truth here; ECP-owned
newsletter consent can be reported separately when needed.
"""

from __future__ import annotations

import math
import time
from datetime import date, datetime
from typing import Any

from django.conf import settings

from .contact_services import get_admin_stage_analytics
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError


DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100


def parse_date_range(params) -> dict[str, Any]:
    start = _parse_date(params.get("from"), "from")
    end = _parse_date(params.get("to"), "to")
    if start and end and start > end:
        raise ValueError("from must be before or equal to to.")
    return {
        "from": start.isoformat() if start else None,
        "to": end.isoformat() if end else None,
    }


def normalize_paging(params) -> tuple[int, int]:
    try:
        page = max(1, int(params.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = int(params.get("page_size", DEFAULT_PAGE_SIZE))
    except (TypeError, ValueError):
        page_size = DEFAULT_PAGE_SIZE
    return page, max(1, min(page_size, MAX_PAGE_SIZE))


def get_overview_analytics(date_range: dict[str, Any]) -> dict[str, Any]:
    client = MauticClient()
    contacts = client.list_contacts(start=0, limit=1)
    campaigns = client.list_campaigns(start=0, limit=100)
    segments = client.list_segments(start=0, limit=1)

    campaign_rows = _items(campaigns.get("campaigns"))
    budget = ProviderBudget()
    totals = _email_overview_totals(client, budget)

    new_contacts = _count_new_contacts(client, date_range)

    notes = [
        "Sent and opens are Mautic's own email counters. Clicks and "
        "unsubscribes follow Mautic's rule for each email's type: template "
        "emails count each contact once per link and only unsubscribes from "
        "contacts the email was sent to; segment emails count each clicking "
        "contact once and every unsubscribe attributed to the email. Bounces "
        "are Mautic Do Not Contact records attributed to an email.",
        "Date range is applied only to New Contacts in this batch.",
        "Mautic DNC is not mixed with ECP newsletter consent.",
    ]
    if any(value is None for value in totals.values()):
        notes.append(
            "Some email metrics could not be read from Mautic and are shown as "
            "not available rather than as zero."
        )

    return {
        "source": "mautic",
        "date_range": date_range,
        "metrics": [
            _metric("total_contacts", "Total Contacts", _total(contacts), "lifetime"),
            _metric("new_contacts", "New Contacts", new_contacts, "date_range"),
            _metric("total_campaigns", "Total Campaigns", _total(campaigns, campaign_rows), "lifetime"),
            _metric(
                "published_campaigns",
                "Published Campaigns",
                sum(1 for row in campaign_rows if _bool(row.get("isPublished"))),
                "lifetime",
                note="Based on the first 100 campaigns returned by Mautic REST.",
            ),
            _metric("total_segments", "Segments", _total(segments), "lifetime"),
            *[
                _email_metric(key, label, totals[key])
                for key, label in (
                    ("sent", "Emails Sent"),
                    ("opens", "Opens"),
                    ("clicks", "Clicks"),
                    ("bounces", "Bounces"),
                    ("unsubscribes", "Unsubscribes"),
                )
            ],
        ],
        "notes": notes,
    }


EMAIL_METRIC_KEYS = {
    "sent": "emails_sent",
    "opens": "opens",
    "clicks": "clicks",
    "bounces": "bounces",
    "unsubscribes": "unsubscribes",
}


def _email_metric(total_key, label, value):
    return _metric(
        EMAIL_METRIC_KEYS[total_key],
        label,
        value,
        "lifetime",
        available=value is not None,
        note="" if value is not None else "Could not be read from Mautic.",
    )


def overview_is_complete(data) -> bool:
    """Whether an overview may be cached: no email metric is missing."""
    metrics = data.get("metrics") if isinstance(data, dict) else None
    keys = set(EMAIL_METRIC_KEYS.values())
    return isinstance(metrics, list) and all(
        metric.get("available") for metric in metrics if metric.get("key") in keys
    )

def list_campaign_analytics(params) -> dict[str, Any]:
    page, page_size = normalize_paging(params)
    search = str(params.get("search", "") or "").strip()
    query = {"start": (page - 1) * page_size, "limit": page_size}
    if search:
        query["search"] = search
    data = MauticClient().list_campaigns(**query)
    rows = [_normalize_campaign(row) for row in _items(data.get("campaigns"))]
    count = _total(data, rows)
    return _page(rows, count, page, page_size)


def list_email_analytics(params) -> dict[str, Any]:
    page, page_size = normalize_paging(params)
    search = str(params.get("search", "") or "").strip()
    query = {"start": (page - 1) * page_size, "limit": page_size}
    if search:
        query["search"] = search
    client = MauticClient()
    data = client.list_emails(**query)
    emails = _items(data.get("emails"))
    stats = _email_page_stats(client, emails, ProviderBudget())
    rows = [_normalize_email(email, stats.get(str(email.get("id") or ""), {})) for email in emails]
    count = _total(data, rows)
    return _page(rows, count, page, page_size)


EMAIL_ROW_METRICS = ("sent", "opened", "clicked", "bounced", "unsubscribed")


def email_page_is_complete(data) -> bool:
    """Whether an emails page may be cached: every row has every metric."""
    rows = data.get("results") if isinstance(data, dict) else None
    return isinstance(rows, list) and all(
        row.get(metric) is not None for row in rows for metric in EMAIL_ROW_METRICS
    )


def get_contact_analytics(date_range: dict[str, Any]) -> dict[str, Any]:
    client = MauticClient()
    contacts = client.list_contacts(start=0, limit=1)
    stage_analytics = get_admin_stage_analytics()
    return {
        "source": "mautic",
        "date_range": date_range,
        "metrics": [
            _metric("total_contacts", "Total Contacts", _total(contacts), "lifetime"),
            _metric("new_contacts", "New Contacts", _count_new_contacts(client, date_range), "date_range"),
            _metric("dnc", "Mautic DNC", None, "not_available", available=False),
        ],
        "stage_distribution": stage_analytics,
        "notes": [
            "Mautic DNC is separate from ECP newsletter consent and is deferred until a reliable aggregate source is available.",
        ],
    }


def list_segment_analytics(params) -> dict[str, Any]:
    page, page_size = normalize_paging(params)
    search = str(params.get("search", "") or "").strip()
    query = {"start": (page - 1) * page_size, "limit": page_size}
    if search:
        query["search"] = search
    client = MauticClient()
    data = client.list_segments(**query)
    rows = [_normalize_segment(client, row) for row in _items(data.get("lists") or data.get("segments"))]
    count = _total(data, rows)
    return _page(rows, count, page, page_size)


def _parse_date(value, field_name: str) -> date | None:
    if value in (None, ""):
        return None
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DD.") from exc


def _items(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [item for item in value.values() if isinstance(item, dict)]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _total(data: dict[str, Any], rows: list[dict[str, Any]] | None = None) -> int:
    try:
        return max(0, int(data.get("total")))
    except (TypeError, ValueError):
        return len(rows or [])


def _page(rows, count, page, page_size):
    return {
        "source": "mautic",
        "count": count,
        "page": page,
        "page_size": page_size,
        "num_pages": math.ceil(count / page_size) if count else 0,
        "results": rows,
    }


def _metric(key, label, value, scope, *, available=True, note=""):
    return {
        "key": key,
        "label": label,
        "value": value if available else None,
        "available": available,
        "scope": scope,
        "note": note,
    }


def _bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _count_new_contacts(client: MauticClient, date_range: dict[str, Any]) -> int | None:
    if not date_range.get("from") and not date_range.get("to"):
        return None
    params: dict[str, Any] = {"start": 0, "limit": 1}
    index = 0
    if date_range.get("from"):
        params[f"where[{index}][col]"] = "dateAdded"
        params[f"where[{index}][expr]"] = "gte"
        params[f"where[{index}][val]"] = f"{date_range['from']} 00:00:00"
        index += 1
    if date_range.get("to"):
        params[f"where[{index}][col]"] = "dateAdded"
        params[f"where[{index}][expr]"] = "lte"
        params[f"where[{index}][val]"] = f"{date_range['to']} 23:59:59"
    data = client.list_contacts(**params)
    return _total(data)


#: Bounded provider reads. Every aggregate pages through Mautic's stats API at
#: most this far; a result that would need more is reported as unavailable,
#: never as a partial number.
EMAIL_LIST_PAGE_SIZE = 100
MAX_EMAIL_LIST_PAGES = 50  # overview totals cover up to 5,000 emails
STATS_PAGE_SIZE = 500
MAX_STATS_PAGES = 40  # 20,000 stats rows per aggregate
DEFAULT_PROVIDER_BUDGET_SECONDS = 25

DNC_UNSUBSCRIBED = 1  # Mautic DoNotContact::UNSUBSCRIBED
DNC_BOUNCED = 2  # Mautic DoNotContact::BOUNCED


class MetricUnavailable(Exception):
    """A metric could not be read completely; it is reported as unavailable."""


class ProviderBudget:
    """Bounds the Mautic reads one analytics request makes.

    After a temporary provider failure (timeout, connection error, 429, 5xx)
    no further read is attempted for the rest of the request, so an outage or
    rate limit costs one request instead of one per metric. A deadline caps
    the total time spent.
    """

    def __init__(self, seconds: float | None = None):
        if seconds is None:
            seconds = float(
                getattr(
                    settings,
                    "MARKETING_ANALYTICS_PROVIDER_BUDGET_SECONDS",
                    DEFAULT_PROVIDER_BUDGET_SECONDS,
                )
            )
        self.deadline = time.monotonic() + max(0.0, seconds)
        self.tripped = False

    def call(self, function, *args, **kwargs):
        if self.tripped or time.monotonic() > self.deadline:
            raise MetricUnavailable()
        try:
            return function(*args, **kwargs)
        except TemporaryMauticError as exc:
            self.tripped = True
            raise MetricUnavailable() from exc
        except PermanentMauticError as exc:
            raise MetricUnavailable() from exc


def _stat_int(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _all_stat_rows(client: MauticClient, budget: ProviderBudget, table: str, filters) -> list[dict[str, Any]]:
    """Every row of a filtered stats table, or MetricUnavailable past the bound."""
    rows: list[dict[str, Any]] = []
    for page in range(MAX_STATS_PAGES):
        batch, total = budget.call(
            client.list_stat_rows,
            table,
            filters,
            start=page * STATS_PAGE_SIZE,
            limit=STATS_PAGE_SIZE,
        )
        rows.extend(batch)
        if len(rows) >= total or not batch:
            return rows
    raise MetricUnavailable()


#: Mautic 7.1.3 counts clicks and unsubscribes differently per email type
#: (EmailGraphStatsController: 'template' -> getEmailGeneralStats, anything
#: else -> getEmailListStats). An email with another or no type is reported
#: as unavailable rather than counted by a guessed rule.
EMAIL_TYPE_TEMPLATE = "template"
EMAIL_TYPE_LIST = "list"
SUPPORTED_EMAIL_TYPES = (EMAIL_TYPE_TEMPLATE, EMAIL_TYPE_LIST)
STATS_LEAD_BATCH = 200  # contacts per email_stats lookup (keeps URLs bounded)


def _email_types(emails) -> dict[str, str | None]:
    types = {}
    for email in emails:
        if not email.get("id"):
            continue
        value = str(email.get("emailType") or "").strip()
        types[str(email.get("id"))] = value if value in SUPPORTED_EMAIL_TYPES else None
    return types


def _id_filter(column: str, email_ids, scoped: bool):
    return [(column, "in", ",".join(email_ids))] if scoped else [(column, "isNotNull", None)]


def _unique_clicks_by_email(client, budget, email_types: dict[str, str | None], *, scoped: bool = True) -> dict[str, int | None]:
    """Mautic's "unique clicked" per email, by the email's own type:

    * template (ClickedHelper): COUNT(DISTINCT email_id, redirect_id, lead_id)
      over email page hits — one per contact per link; rows with any NULL in
      those columns are not counted, as MySQL's multi-column COUNT DISTINCT.
    * list (TrackableRepository::getCount): COUNT(DISTINCT lead_id) over the
      page hits joined to the email's tracked links — one per contact.

    ``scoped`` filters the reads to these emails (one page of emails); the
    overview reads every email hit and keeps the existing emails only.
    """
    email_ids = list(email_types)
    hits = _all_stat_rows(
        client,
        budget,
        "page_hits",
        [("source", "eq", "email"), ("lead_id", "isNotNull", None), ("redirect_id", "isNotNull", None)]
        + _id_filter("source_id", email_ids, scoped),
    )
    tracked: set[tuple[str, str]] = set()
    if EMAIL_TYPE_LIST in email_types.values():
        for row in _all_stat_rows(
            client, budget, "channel_url_trackables",
            [("channel", "eq", "email")] + _id_filter("channel_id", email_ids, scoped),
        ):
            tracked.add((str(row.get("channel_id") or ""), str(row.get("redirect_id") or "")))

    seen: dict[str, set] = {email_id: set() for email_id in email_ids}
    for row in hits:
        email_id = str(row.get("source_id") or "")
        email_type = email_types.get(email_id)
        lead, redirect = str(row.get("lead_id") or ""), str(row.get("redirect_id") or "")
        if email_type is None or not lead or not redirect:
            continue
        if email_type == EMAIL_TYPE_TEMPLATE:
            if row.get("email_id") not in (None, ""):
                seen[email_id].add((str(row.get("email_id")), redirect, lead))
        elif (email_id, redirect) in tracked:
            seen[email_id].add(lead)
    return {
        email_id: (len(seen[email_id]) if email_types[email_id] else None)
        for email_id in email_ids
    }


def _delivered_pairs(client, budget, pairs: set[tuple[str, str]], *, scoped: bool) -> set[tuple[str, str]]:
    """Which (email, contact) pairs have an email_stats (sent) record, read in
    batches of contacts rather than one request per record."""
    if not pairs:
        return set()
    email_ids = sorted({email_id for email_id, _ in pairs})
    leads = sorted({lead for _, lead in pairs})
    found: set[tuple[str, str]] = set()
    for start in range(0, len(leads), STATS_LEAD_BATCH):
        batch = leads[start:start + STATS_LEAD_BATCH]
        for row in _all_stat_rows(
            client, budget, "email_stats",
            _id_filter("email_id", email_ids, scoped) + [("lead_id", "in", ",".join(batch))],
        ):
            pair = (str(row.get("email_id") or ""), str(row.get("lead_id") or ""))
            if pair in pairs:
                found.add(pair)
    return found


def _dnc_by_email(client, budget, email_types: dict[str, str | None], *, scoped: bool = True) -> dict[str, dict[str, int | None]]:
    """Unsubscribed and bounced contacts per email from Mautic's Do Not
    Contact records attributed to the email, each contact counted once:

    * unsubscribed, template (UnsubscribedHelper): only contacts with an
      email_stats record for that email (they were sent it);
    * unsubscribed, list (DoNotContactRepository::getCount): every
      email-attributed record;
    * bounced: unchanged — every email-attributed bounce record.
    """
    email_ids = list(email_types)
    rows = _all_stat_rows(
        client,
        budget,
        "lead_donotcontact",
        [("channel", "eq", "email"), ("reason", "in", f"{DNC_UNSUBSCRIBED},{DNC_BOUNCED}")]
        + _id_filter("channel_id", email_ids, scoped),
    )
    seen: dict[str, dict[int, set]] = {
        email_id: {DNC_UNSUBSCRIBED: set(), DNC_BOUNCED: set()} for email_id in email_ids
    }
    for row in rows:
        email_id = str(row.get("channel_id") or "")
        reason = _stat_int(row.get("reason"))
        if email_id in seen and reason in seen[email_id]:
            seen[email_id][reason].add(str(row.get("lead_id") or row.get("id")))

    template_pairs = {
        (email_id, lead)
        for email_id, reasons in seen.items()
        if email_types[email_id] == EMAIL_TYPE_TEMPLATE
        for lead in reasons[DNC_UNSUBSCRIBED]
    }
    delivered = _delivered_pairs(client, budget, template_pairs, scoped=scoped)

    def unsubscribed(email_id):
        leads = seen[email_id][DNC_UNSUBSCRIBED]
        email_type = email_types[email_id]
        if email_type == EMAIL_TYPE_TEMPLATE:
            return sum(1 for lead in leads if (email_id, lead) in delivered)
        if email_type == EMAIL_TYPE_LIST:
            return len(leads)
        return None

    return {
        email_id: {"unsubscribed": unsubscribed(email_id), "bounced": len(reasons[DNC_BOUNCED])}
        for email_id, reasons in seen.items()
    }


def _latest_activity(client, budget, email_id: str):
    try:
        rows, _ = budget.call(
            client.list_stat_rows,
            "email_stats",
            [("email_id", "eq", email_id)],
            limit=1,
            order=("date_sent", "DESC"),
        )
    except MetricUnavailable:
        return None
    return rows[0].get("date_sent") if rows else None


def _email_page_stats(client, emails, budget) -> dict[str, dict[str, Any]]:
    """Clicks, unsubscribes, bounces and last activity for one page of emails:
    batched aggregates plus one small read per email."""
    email_types = _email_types(emails)
    if not email_types:
        return {}
    try:
        clicks = _unique_clicks_by_email(client, budget, email_types)
    except MetricUnavailable:
        clicks = {}
    try:
        dnc = _dnc_by_email(client, budget, email_types)
    except MetricUnavailable:
        dnc = {}
    return {
        email_id: {
            "clicked": clicks.get(email_id),
            "unsubscribed": dnc.get(email_id, {}).get("unsubscribed"),
            "bounced": dnc.get(email_id, {}).get("bounced"),
            "lastActivity": _latest_activity(client, budget, email_id),
        }
        for email_id in email_types
    }


def _sum_or_unavailable(values) -> int:
    values = list(values)
    if any(value is None for value in values):
        raise MetricUnavailable()
    return sum(values)


def _email_overview_totals(client, budget) -> dict[str, int | None]:
    """Lifetime totals over every existing email, each None when not fully
    readable. They equal the sum of the emails page's rows (the same per-type
    rules): Mautic keeps the tracked links, page hits and Do Not Contact
    records of a deleted email, so only emails that still exist are counted."""
    totals: dict[str, int | None] = {}

    def attempt(key, function):
        try:
            totals[key] = function()
        except MetricUnavailable:
            totals[key] = None

    # One walk of the email list (read at most once, success or not) gives
    # sent, opens and the IDs and types the other totals are matched against.
    walk: dict[str, Any] = {}

    def email_list():
        if "result" not in walk:
            walk["result"] = _walk_email_list()
        if walk["result"] is None:
            raise MetricUnavailable()
        return walk["result"]

    def _walk_email_list():
        sent = opens = 0
        types: dict[str, str | None] = {}
        try:
            for page in range(MAX_EMAIL_LIST_PAGES):
                data = budget.call(
                    client.list_emails,
                    start=page * EMAIL_LIST_PAGE_SIZE,
                    limit=EMAIL_LIST_PAGE_SIZE,
                )
                rows = _items(data.get("emails"))
                for email in rows:
                    sent += _stat_int(email.get("sentCount"))
                    opens += _stat_int(email.get("readCount"))
                types.update(_email_types(rows))
                if not rows or (page + 1) * EMAIL_LIST_PAGE_SIZE >= _total(data, rows):
                    return {"sent": sent, "opens": opens, "types": types}
        except MetricUnavailable:
            return None
        return None

    def clicks():
        types = email_list()["types"]
        if not types:
            return 0
        return _sum_or_unavailable(_unique_clicks_by_email(client, budget, types, scoped=False).values())

    dnc: dict[str, Any] = {}

    def dnc_totals():
        if "result" not in dnc:
            try:
                types = email_list()["types"]
                dnc["result"] = _dnc_by_email(client, budget, types, scoped=False) if types else {}
            except MetricUnavailable:
                dnc["result"] = None
        if dnc["result"] is None:
            raise MetricUnavailable()
        return dnc["result"]

    attempt("sent", lambda: email_list()["sent"])
    attempt("opens", lambda: email_list()["opens"])
    attempt("clicks", clicks)
    attempt("unsubscribes", lambda: _sum_or_unavailable(row["unsubscribed"] for row in dnc_totals().values()))
    attempt("bounces", lambda: _sum_or_unavailable(row["bounced"] for row in dnc_totals().values()))
    return totals


def _normalize_campaign(campaign: dict[str, Any]) -> dict[str, Any]:
    events = _items(campaign.get("events"))
    return {
        "id": str(campaign.get("id") or ""),
        "name": str(campaign.get("name") or "").strip(),
        "status": "published" if _bool(campaign.get("isPublished")) else "unpublished",
        "isPublished": _bool(campaign.get("isPublished")),
        "contactCount": _int_or_none(campaign.get("contactCount")),
        "eventCount": len(events),
        "dateModified": campaign.get("dateModified"),
        "dateAdded": campaign.get("dateAdded"),
    }


def _normalize_email(email: dict[str, Any], stats: dict[str, Any]) -> dict[str, Any]:
    # Sent and opened are Mautic's own per-email counters (readCount counts a
    # contact's first open once); the rest come from the page's stats reads
    # and are None when they could not be read.
    sent = _int_or_none(email.get("sentCount"))
    opened = _int_or_none(email.get("readCount"))
    clicked = stats.get("clicked")
    bounced = stats.get("bounced")
    unsubscribed = stats.get("unsubscribed")

    return {
        "id": str(email.get("id") or ""),
        "name": str(email.get("name") or "").strip(),
        "subject": str(email.get("subject") or ""),
        "emailType": str(email.get("emailType") or ""),
        "status": "published" if _bool(email.get("isPublished")) else "unpublished",
        "isPublished": _bool(email.get("isPublished")),
        "sent": sent,
        "opened": opened,
        "clicked": clicked,
        "bounced": bounced,
        "unsubscribed": unsubscribed,
        "openRate": _rate(opened, sent),
        "clickRate": _rate(clicked, sent),
        "dateModified": email.get("dateModified"),
        "dateAdded": email.get("dateAdded"),
        "lastActivity": stats.get("lastActivity") or email.get("dateModified"),
    }



def _normalize_segment(client: MauticClient, segment: dict[str, Any]) -> dict[str, Any]:
    counts = client.get_segment_count_via_bridge(segment.get("id"))
    filters = segment.get("filters")
    return {
        "id": str(segment.get("id") or ""),
        "name": str(segment.get("name") or "").strip(),
        "alias": str(segment.get("alias") or ""),
        "isPublished": _bool(segment.get("isPublished")),
        "isDynamic": bool(filters),
        "segmentType": "dynamic" if filters else "static",
        "totalContacts": _int_or_none(counts.get("total")),
        "activeContacts": _int_or_none(counts.get("active")),
        "dateModified": segment.get("dateModified"),
        "dateAdded": segment.get("dateAdded"),
    }


def _int_or_none(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _rate(numerator, denominator) -> float | None:
    if numerator is None or denominator in (None, 0):
        return None
    return numerator / denominator
