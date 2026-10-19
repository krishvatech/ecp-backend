"""Marketing Hub email analytics read Mautic's own sources of truth.

Mautic 7.1.3: the email entity carries ``sentCount``/``readCount`` (no click,
bounce or unsubscribe counters); ``email_stats`` has no click or unsubscribe
column; unsubscribes/bounces are ``lead_donotcontact`` rows (reason 1/2)
attributed to the email by ``channel_id``. Clicks and unsubscribes are counted
per the email's type (EmailGraphStatsController):

* template: unique clicks = COUNT(DISTINCT email_id, redirect_id, lead_id) over
  email page hits (ClickedHelper); unsubscribes only from contacts with an
  email_stats record for the email (UnsubscribedHelper);
* list (segment): unique clicks = COUNT(DISTINCT lead_id) over page hits joined
  to the email's tracked links (TrackableRepository::getCount); unsubscribes =
  every email-attributed DNC record (DoNotContactRepository::getCount).

The stats API returns 100 rows by default with an exact ``total``.
"""

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter import marketing_cache
from newsletter import mautic_analytics_services as analytics
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.tests.marketing_actors import grant_marketing_access


User = get_user_model()


class FakeStats:
    """Mautic's stats API over in-memory tables: eq / in / isNotNull filters,
    start/limit paging and an exact total, like ``/api/stats/{table}``."""

    def __init__(self, tables=None, *, fail=None):
        self.tables = tables or {}
        self.fail = fail or {}
        self.calls = []

    @staticmethod
    def _matches(row, filters):
        for column, expr, value in filters or []:
            cell = row.get(column)
            if expr == "eq" and str(cell) != str(value):
                return False
            if expr == "in" and str(cell) not in str(value).split(","):
                return False
            if expr == "isNotNull" and cell in (None, ""):
                return False
        return True

    def list_stat_rows(self, table, filters=None, *, start=0, limit=100, order=None):
        self.calls.append((table, tuple(filters or []), start, limit))
        if table in self.fail:
            raise self.fail[table]
        rows = [row for row in self.tables.get(table, []) if self._matches(row, filters)]
        if order:
            column, direction = order
            rows = sorted(rows, key=lambda row: str(row.get(column) or ""), reverse=direction == "DESC")
        return rows[start:start + limit], len(rows)

    def count_stat_rows(self, table, filters=None):
        return self.list_stat_rows(table, filters, limit=1)[1]

    def table_calls(self, table):
        return [call for call in self.calls if call[0] == table]


def email(email_id, *, sent=0, read=0, type="template", **extra):
    row = {"id": email_id, "name": f"Email {email_id}", "sentCount": sent, "readCount": read, **extra}
    if type is not None:
        row["emailType"] = type
    return row


def link(email_id, redirect_id, *, hits=1, unique=1, channel="email"):
    return {"channel": channel, "channel_id": str(email_id), "redirect_id": str(redirect_id),
            "hits": str(hits), "unique_hits": str(unique)}


def page_hit(email_id, redirect_id, lead_id, *, source="email", email_column="same"):
    return {"source": source, "source_id": str(email_id),
            "email_id": str(email_id) if email_column == "same" else email_column,
            "redirect_id": None if redirect_id is None else str(redirect_id),
            "lead_id": None if lead_id is None else str(lead_id)}


def sent_stat(email_id, lead_id, date_sent="2026-10-01 09:00:00"):
    return {"email_id": str(email_id), "lead_id": str(lead_id), "date_sent": date_sent}


def dnc(lead_id, email_id, reason, *, channel="email"):
    return {"id": f"{lead_id}-{email_id}-{reason}", "lead_id": str(lead_id), "channel": channel,
            "channel_id": None if email_id is None else str(email_id), "reason": str(reason)}


def paged_emails(emails):
    def list_emails(start=0, limit=30, **params):
        return {"total": len(emails), "emails": emails[start:start + limit]}
    return list_emails


def client_with(stats, emails=()):
    client = MagicMock()
    client.list_stat_rows.side_effect = stats.list_stat_rows
    client.count_stat_rows.side_effect = stats.count_stat_rows
    client.list_emails.side_effect = paged_emails(list(emails))
    client.list_contacts.return_value = {"total": 0, "contacts": []}
    client.list_campaigns.return_value = {"total": 0, "campaigns": []}
    client.list_segments.return_value = {"total": 0, "lists": []}
    return client


def metric_values(data):
    return {row["key"]: row for row in data["metrics"]}


def engagement_tables():
    """Template email 5 and segment email 6 with the cases that separate the
    two native rules (shared by the overview and emails-page tests)."""
    return {
        "page_hits": [
            # template 5: lead 1 clicks link 1 three times and link 2 once -> 2;
            # lead 2 clicks link 1 -> 1; anonymous and email_id-less hits don't count
            page_hit(5, 1, 1), page_hit(5, 1, 1), page_hit(5, 1, 1), page_hit(5, 2, 1),
            page_hit(5, 1, 2), page_hit(5, 1, None), page_hit(5, 2, 9, email_column=None),
            # segment 6: lead 3 clicks both links, lead 4 one link -> 2 contacts;
            # a hit on an untracked redirect is not joined
            page_hit(6, 3, 3), page_hit(6, 4, 3), page_hit(6, 3, 4), page_hit(6, 77, 8),
            page_hit(6, 3, None),
        ],
        "channel_url_trackables": [link(5, 1), link(5, 2), link(6, 3), link(6, 4)],
        "lead_donotcontact": [
            dnc(1, 5, 1), dnc(2, 5, 1), dnc(2, 5, 1),  # lead 2 never sent email 5
            dnc(3, 5, 2), dnc(4, 5, 3),
            dnc(7, 6, 1), dnc(8, 6, 1),               # segment: both count
            dnc(9, 6, 1, channel="sms"),
        ],
        "email_stats": [sent_stat(5, 1), sent_stat(5, 3), sent_stat(6, 3), sent_stat(6, 7, "2026-10-03 09:00:00")],
    }


class OverviewTotalsTests(SimpleTestCase):
    def _overview(self, stats, emails=()):
        with patch.object(analytics, "MauticClient", return_value=client_with(stats, emails)) as cls:
            data = analytics.get_overview_analytics({"from": None, "to": None})
        return data, cls.return_value

    def test_totals_cover_every_email_past_the_first_100(self):
        emails = [email(i, sent=10, read=3) for i in range(1, 251)]
        data, client = self._overview(FakeStats(), emails)

        metrics = metric_values(data)
        self.assertEqual(metrics["emails_sent"]["value"], 2500)
        self.assertEqual(metrics["opens"]["value"], 750)
        self.assertEqual(client.list_emails.call_count, 3)  # 100 + 100 + 50

    def test_opens_use_mautics_read_counter_not_a_page_of_stat_rows(self):
        data, _ = self._overview(FakeStats(), [email(8, sent=400, read=250)])
        self.assertEqual(metric_values(data)["opens"]["value"], 250)

    def test_overview_applies_each_emails_type_rule_and_equals_the_page_rows(self):
        stats = FakeStats(engagement_tables())
        emails = [email(5, sent=3), email(6, sent=4, type="list")]
        data, _ = self._overview(stats, emails)

        metrics = metric_values(data)
        self.assertEqual(metrics["clicks"]["value"], 3 + 2)
        self.assertEqual(metrics["unsubscribes"]["value"], 1 + 2)
        self.assertEqual(metrics["bounces"]["value"], 1)
        with patch.object(analytics, "MauticClient", return_value=client_with(FakeStats(engagement_tables()), emails)):
            rows = analytics.list_email_analytics({})["results"]
        self.assertEqual(sum(row["clicked"] for row in rows), metrics["clicks"]["value"])
        self.assertEqual(sum(row["unsubscribed"] for row in rows), metrics["unsubscribes"]["value"])

    def test_clicks_are_read_across_stats_pages(self):
        # 1,200 hits (three 500-row pages): 600 links each clicked twice by lead 7.
        hits = [page_hit(1, i, 7) for i in range(1, 601)] * 2
        stats = FakeStats({"page_hits": hits})
        data, _ = self._overview(stats, [email(1)])

        self.assertEqual(metric_values(data)["clicks"]["value"], 600)
        self.assertEqual(len(stats.table_calls("page_hits")), 3)

    def test_empty_mautic_reports_confirmed_zeros(self):
        data, _ = self._overview(FakeStats())

        metrics = metric_values(data)
        for key in ("emails_sent", "opens", "clicks", "bounces", "unsubscribes"):
            self.assertEqual((metrics[key]["value"], metrics[key]["available"]), (0, True), key)
        self.assertTrue(analytics.overview_is_complete(data))

    def test_provider_outage_reports_unavailable_not_zero_and_stops_reading(self):
        stats = FakeStats(fail={"page_hits": TemporaryMauticError("HTTP 429")})
        data, _ = self._overview(stats, [email(1, sent=5, read=2)])

        metrics = metric_values(data)
        self.assertEqual(metrics["emails_sent"]["value"], 5)
        for key in ("clicks", "unsubscribes", "bounces"):
            self.assertEqual((metrics[key]["value"], metrics[key]["available"]), (None, False), key)
        self.assertEqual(stats.table_calls("lead_donotcontact"), [])
        self.assertFalse(analytics.overview_is_complete(data))
        self.assertTrue(any("not available rather than as zero" in note for note in data["notes"]))

    def test_permanent_error_on_one_aggregate_only_loses_that_metric(self):
        stats = FakeStats(
            {"lead_donotcontact": [dnc(1, 5, 1)], "email_stats": [sent_stat(5, 1)]},
            fail={"page_hits": PermanentMauticError("HTTP 400")},
        )
        data, _ = self._overview(stats, [email(5)])

        metrics = metric_values(data)
        self.assertFalse(metrics["clicks"]["available"])
        self.assertEqual(metrics["unsubscribes"]["value"], 1)

    def test_too_many_stats_rows_report_unavailable_instead_of_a_partial_number(self):
        hits = [page_hit(1, i, 7) for i in range(analytics.MAX_STATS_PAGES * analytics.STATS_PAGE_SIZE + 1)]
        stats = FakeStats({"page_hits": hits})
        data, _ = self._overview(stats, [email(1, sent=4)])

        metrics = metric_values(data)
        self.assertIsNone(metrics["clicks"]["value"])
        self.assertEqual(metrics["emails_sent"]["value"], 4)
        self.assertEqual(len(stats.table_calls("page_hits")), analytics.MAX_STATS_PAGES)

    def test_too_many_emails_report_every_email_total_unavailable(self):
        stats = FakeStats()
        emails = [email(i, sent=1) for i in range(analytics.MAX_EMAIL_LIST_PAGES * analytics.EMAIL_LIST_PAGE_SIZE + 1)]
        data, client = self._overview(stats, emails)

        metrics = metric_values(data)
        for key in ("emails_sent", "opens", "clicks", "unsubscribes", "bounces"):
            self.assertIsNone(metrics[key]["value"], key)
        self.assertEqual(client.list_emails.call_count, analytics.MAX_EMAIL_LIST_PAGES)
        self.assertEqual(stats.calls, [])

    def test_records_left_behind_by_deleted_emails_are_not_counted(self):
        # Mautic keeps a deleted email's tracked links, page hits and DNC records.
        stats = FakeStats({
            "page_hits": [page_hit(5, 1, 1), page_hit(77, 2, 2), page_hit(78, 3, 3)],
            "channel_url_trackables": [link(5, 1), link(78, 3)],
            "lead_donotcontact": [dnc(1, 5, 1), dnc(2, 77, 1), dnc(3, 77, 2)],
            "email_stats": [sent_stat(5, 1)],
        })
        data, _ = self._overview(stats, [email(5)])

        metrics = metric_values(data)
        self.assertEqual(
            (metrics["clicks"]["value"], metrics["unsubscribes"]["value"], metrics["bounces"]["value"]),
            (1, 1, 0),
        )

    def test_an_email_without_a_supported_type_makes_click_and_unsubscribe_totals_unavailable(self):
        stats = FakeStats({"page_hits": [page_hit(5, 1, 1)], "lead_donotcontact": [dnc(2, 6, 2)]})
        data, _ = self._overview(stats, [email(5), email(6, type=None)])

        metrics = metric_values(data)
        self.assertIsNone(metrics["clicks"]["value"])
        self.assertIsNone(metrics["unsubscribes"]["value"])
        self.assertEqual(metrics["bounces"]["value"], 1)  # bounce semantics do not depend on type
        self.assertFalse(analytics.overview_is_complete(data))

    def test_expired_budget_makes_no_provider_reads(self):
        budget = analytics.ProviderBudget(seconds=0)
        budget.deadline -= 1
        client = MagicMock()
        totals = analytics._email_overview_totals(client, budget)

        self.assertEqual(set(totals.values()), {None})
        client.list_emails.assert_not_called()
        client.list_stat_rows.assert_not_called()


class EmailPageTests(SimpleTestCase):
    def _page(self, stats, emails, params=None):
        client = client_with(stats, emails)
        with patch.object(analytics, "MauticClient", return_value=client):
            data = analytics.list_email_analytics(params or {})
        return {row["id"]: row for row in data["results"]}, data, client

    def test_template_and_segment_emails_follow_their_native_rules(self):
        rows, data, _ = self._page(FakeStats(engagement_tables()),
                                   [email(5, sent=10, read=4), email(6, sent=4, read=2, type="list")])

        template, segment = rows["5"], rows["6"]
        # template: (link 1, lead 1), (link 2, lead 1), (link 1, lead 2); repeats once
        self.assertEqual(template["clicked"], 3)
        # template: lead 2's unsubscribe is dropped (never sent the email)
        self.assertEqual(template["unsubscribed"], 1)
        self.assertEqual(template["bounced"], 1)
        # segment: leads 3 and 4 clicked tracked links -> 2 contacts
        self.assertEqual(segment["clicked"], 2)
        # segment: every email-attributed unsubscribe, sent to or not
        self.assertEqual(segment["unsubscribed"], 2)
        self.assertEqual((template["sent"], template["opened"], template["openRate"]), (10, 4, 0.4))
        self.assertEqual(template["clickRate"], 0.3)
        self.assertEqual(segment["lastActivity"], "2026-10-03 09:00:00")
        self.assertTrue(analytics.email_page_is_complete(data))

    def test_the_page_is_read_in_batches_with_native_filters(self):
        stats = FakeStats(engagement_tables())
        self._page(stats, [email(5), email(6, type="list")])

        hits = stats.table_calls("page_hits")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][1], (("source", "eq", "email"), ("lead_id", "isNotNull", None),
                                      ("redirect_id", "isNotNull", None), ("source_id", "in", "5,6")))
        tracked = stats.table_calls("channel_url_trackables")
        self.assertEqual([call[1] for call in tracked], [(("channel", "eq", "email"), ("channel_id", "in", "5,6"))])
        dnc_calls = stats.table_calls("lead_donotcontact")
        self.assertEqual([call[1] for call in dnc_calls],
                         [(("channel", "eq", "email"), ("reason", "in", "1,2"), ("channel_id", "in", "5,6"))])
        stat_filters = [call[1] for call in stats.table_calls("email_stats")]
        # one batched delivery check for the template unsubscribes, plus last activity per email
        self.assertIn((("email_id", "in", "5"), ("lead_id", "in", "1,2")), stat_filters)
        self.assertEqual(len(stat_filters), 3)

    def test_template_only_pages_do_not_read_tracked_links(self):
        stats = FakeStats({"page_hits": [page_hit(5, 1, 1)]})
        rows, _, _ = self._page(stats, [email(5)])
        self.assertEqual(rows["5"]["clicked"], 1)
        self.assertEqual(stats.table_calls("channel_url_trackables"), [])

    def test_delivery_checks_are_batched_by_contact(self):
        leads = list(range(1, analytics.STATS_LEAD_BATCH * 2 + 2))
        stats = FakeStats({
            "lead_donotcontact": [dnc(lead, 5, 1) for lead in leads],
            "email_stats": [sent_stat(5, lead) for lead in leads if lead % 2],
        })
        rows, _, _ = self._page(stats, [email(5)])

        self.assertEqual(rows["5"]["unsubscribed"], len([lead for lead in leads if lead % 2]))
        delivery_calls = [call for call in stats.table_calls("email_stats") if call[1][0][1] == "in"]
        self.assertEqual(len(delivery_calls), 3)  # 200 + 200 + 1 contacts

    def test_opens_beyond_the_stats_page_size_are_not_capped(self):
        rows, _, _ = self._page(FakeStats(), [email(5, sent=1000, read=640)])
        self.assertEqual(rows["5"]["opened"], 640)

    def test_missing_or_unknown_email_type_is_unavailable_not_guessed(self):
        stats = FakeStats({"page_hits": [page_hit(5, 1, 1), page_hit(6, 1, 1)],
                           "lead_donotcontact": [dnc(1, 5, 1), dnc(1, 6, 2)]})
        rows, data, _ = self._page(stats, [email(5, type=None), email(6, type="sms-blast")])

        for email_id in ("5", "6"):
            self.assertIsNone(rows[email_id]["clicked"])
            self.assertIsNone(rows[email_id]["unsubscribed"])
            self.assertIsNone(rows[email_id]["clickRate"])
        self.assertEqual(rows["6"]["bounced"], 1)
        self.assertFalse(analytics.email_page_is_complete(data))

    def test_missing_counters_are_unknown_not_zero(self):
        rows, data, _ = self._page(FakeStats(), [{"id": 5, "name": "Bare", "emailType": "template"}])

        self.assertIsNone(rows["5"]["sent"])
        self.assertIsNone(rows["5"]["opened"])
        self.assertIsNone(rows["5"]["openRate"])
        self.assertEqual(rows["5"]["clicked"], 0)
        self.assertFalse(analytics.email_page_is_complete(data))

    def test_provider_failure_marks_page_metrics_unavailable(self):
        stats = FakeStats(fail={"page_hits": TemporaryMauticError("timeout")})
        rows, data, _ = self._page(stats, [email(5, sent=3, read=1)])

        self.assertEqual((rows["5"]["sent"], rows["5"]["opened"]), (3, 1))
        self.assertEqual((rows["5"]["clicked"], rows["5"]["unsubscribed"], rows["5"]["bounced"]), (None, None, None))
        self.assertIsNone(rows["5"]["clickRate"])
        self.assertEqual(stats.table_calls("lead_donotcontact"), [])
        self.assertFalse(analytics.email_page_is_complete(data))

    def test_delivery_check_failure_makes_unsubscribes_unavailable(self):
        stats = FakeStats({"lead_donotcontact": [dnc(1, 5, 1)]},
                          fail={"email_stats": PermanentMauticError("HTTP 400")})
        rows, _, _ = self._page(stats, [email(5)])
        self.assertIsNone(rows["5"]["unsubscribed"])

    def test_empty_page_makes_no_stats_reads(self):
        stats = FakeStats()
        rows, data, _ = self._page(stats, [])

        self.assertEqual(rows, {})
        self.assertEqual(stats.calls, [])
        self.assertTrue(analytics.email_page_is_complete(data))


class StatsClientTests(SimpleTestCase):
    def _client(self, payload, status_code=200):
        client = MauticClient.__new__(MauticClient)
        client.base_url = "http://mautic.test"
        client.username, client.password, client.timeout = "u", "p", 5
        response = MagicMock(status_code=status_code)
        response.json.return_value = payload
        response.headers = {"Content-Type": "application/json"}
        client.session = MagicMock()
        client.session.request.return_value = response
        return client

    def test_list_stat_rows_encodes_filters_paging_and_order(self):
        client = self._client({"total": "7", "stats": [{"id": 1}]})

        rows, total = client.list_stat_rows(
            "lead_donotcontact",
            [("channel", "eq", "email"), ("channel_id", "isNotNull", None)],
            start=500, limit=500, order=("date_added", "DESC"),
        )

        self.assertEqual((rows, total), ([{"id": 1}], 7))
        args, kwargs = client.session.request.call_args
        self.assertEqual(args, ("GET", "http://mautic.test/api/stats/lead_donotcontact"))
        self.assertEqual(kwargs["params"], {
            "where[0][col]": "channel", "where[0][expr]": "eq", "where[0][val]": "email",
            "where[1][col]": "channel_id", "where[1][expr]": "isNotNull",
            "start": 500, "limit": 500,
            "order[0][col]": "date_added", "order[0][dir]": "DESC",
        })

    def test_a_response_without_total_is_a_temporary_error(self):
        client = self._client({"errors": [{"message": "x"}]})
        with self.assertRaises(TemporaryMauticError):
            client.list_stat_rows("email_stats")

    def test_rate_limit_is_temporary(self):
        client = self._client({}, status_code=429)
        with self.assertRaises(TemporaryMauticError):
            client.count_stat_rows("email_stats")


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "p1-analytics"}},
    MARKETING_RESPONSE_CACHE_ENABLED=True,
)
class AnalyticsCachingTests(TestCase):
    def setUp(self):
        cache.clear()
        marketing_cache.reset_failure_state()
        self.addCleanup(marketing_cache.reset_failure_state)
        self.client = APIClient()
        staff = User.objects.create_user(
            username="p1-analytics", email="p1-analytics@example.test", password="pw",
            is_staff=True, is_superuser=True,
        )
        grant_marketing_access(staff)
        self.client.force_authenticate(user=staff)

    def test_degraded_overview_is_not_cached_and_recovers(self):
        outage = FakeStats(fail={"page_hits": TemporaryMauticError("down")})
        healthy = FakeStats({"page_hits": [page_hit(1, 1, 1), page_hit(1, 1, 1)]})
        url = reverse("newsletter-admin-analytics-overview")

        with patch.object(analytics, "MauticClient", return_value=client_with(outage, [email(1)])):
            degraded = self.client.get(url)
        with patch.object(analytics, "MauticClient", return_value=client_with(healthy, [email(1)])):
            recovered = self.client.get(url)
            cached = self.client.get(url)

        self.assertEqual(degraded.status_code, 200)
        self.assertFalse(metric_values(degraded.data)["clicks"]["available"])
        self.assertEqual(recovered["X-Marketing-Cache"], "MISS")
        self.assertEqual(metric_values(recovered.data)["clicks"]["value"], 1)
        self.assertEqual(cached["X-Marketing-Cache"], "HIT")

    def test_degraded_email_page_is_not_cached(self):
        outage = FakeStats(fail={"lead_donotcontact": TemporaryMauticError("down")})
        url = reverse("newsletter-admin-analytics-emails")

        with patch.object(analytics, "MauticClient", return_value=client_with(outage, [email(5, sent=1)])):
            first = self.client.get(url)
            second = self.client.get(url)

        self.assertIsNone(first.data["results"][0]["unsubscribed"])
        self.assertEqual(second["X-Marketing-Cache"], "MISS")
