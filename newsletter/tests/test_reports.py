import csv
import io
import json
import tempfile
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.files.storage import default_storage
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from openpyxl import load_workbook
from rest_framework.response import Response
from rest_framework.test import APIClient

from newsletter import report_export_services as exports
from newsletter import report_services as svc
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticIdentityConfigurationError
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, REPORT_CREATE, REPORT_DELETE, REPORT_UPDATE
from newsletter.models import MauticIdentityAuditLog
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import response

User = get_user_model()
TMP = tempfile.mkdtemp(prefix="report-export-tests-")
ISOLATED = {
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "report-tests"}},
    "STORAGES": {
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage", "OPTIONS": {"location": TMP}},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    },
}
META = {
    "source": "email.stats",
    "columns": [
        {"key": "e.subject", "label": "Subject", "type": "string", "alias": "subject"},
        {"key": "es.date_sent", "label": "Date sent", "type": "datetime", "alias": "date_sent"},
        {"key": "es.id", "label": "Stat ID", "type": "int", "alias": "id"},
    ],
    "groupByColumns": ["e.subject", "es.date_sent", "es.id"],
    "filters": [
        {"key": "e.subject", "label": "Subject", "type": "string",
         "operators": [{"value": "eq", "label": "equals"}, {"value": "like", "label": "like"}, {"value": "empty", "label": "empty"}]},
        {"key": "dnc", "label": "DNC", "type": "multiselect",
         "operators": [{"value": "in", "label": "including"}, {"value": "notIn", "label": "excluding"}]},
    ],
    "graphs": [{"key": "mautic.email.graph.line.stats", "label": "Emails sent", "type": "line"}],
}
VALID = {
    "name": "  Opens by subject ",
    "source": "email.stats",
    "columns": ["e.subject", "es.id"],
    "filters": [{"column": "e.subject", "condition": "like", "value": "News", "dynamic": True}],
    "tableOrder": [{"column": "e.subject", "direction": "desc"}],
    "graphs": ["mautic.email.graph.line.stats"],
    "settings": {"showDynamicFilters": True},
}


def with_meta(test):
    return patch("newsletter.report_services.report_source", return_value=META)(test)


class NormalizeReportTests(SimpleTestCase):
    @with_meta
    def test_a_valid_report_becomes_the_full_native_payload(self, _meta):
        payload = svc.normalize_report(VALID)
        self.assertEqual(payload["name"], "Opens by subject")
        self.assertEqual(payload["filters"], [{"column": "e.subject", "glue": "and", "condition": "like", "value": "News", "dynamic": 1}])
        self.assertEqual(payload["tableOrder"], [{"column": "e.subject", "direction": "DESC"}])
        self.assertEqual(payload["settings"], {"showGraphsAboveTable": 0, "showDynamicFilters": 1, "hideDateRangeFilter": 0})
        self.assertEqual((payload["isPublished"], payload["system"], payload["isScheduled"], payload["scheduleUnit"]), (1, 0, 0, "DAILY"))
        self.assertNotIn("createdBy", payload)

    @with_meta
    def test_only_keys_mautic_published_are_ever_sent(self, _meta):
        cases = [
            ({"columns": ["e.subject", "l.password"]}, "columns"),
            ({"filters": [{"column": "1=1) OR (1", "condition": "eq", "value": "x"}]}, "filters"),
            ({"filters": [{"column": "e.subject", "condition": "in", "value": ["x"]}]}, "filters"),
            ({"filters": [{"column": "e.subject", "condition": "eq", "value": "x", "glue": "xor"}]}, "filters"),
            ({"tableOrder": [{"column": "e.body", "direction": "ASC"}]}, "tableOrder"),
            ({"graphs": ["mautic.page.graph.line.hits"]}, "graphs"),
            ({"groupBy": ["l.email"]}, "groupBy"),
            ({"groupBy": ["e.subject"], "aggregators": [{"function": "DROP", "column": "es.id"}]}, "aggregators"),
        ]
        for change, field in cases:
            with self.subTest(change=change), self.assertRaises(svc.ReportError) as raised:
                svc.normalize_report({**VALID, **change})
            self.assertEqual(raised.exception.field, field)

    @with_meta
    def test_filter_values_follow_the_condition(self, _meta):
        payload = svc.normalize_report({**VALID, "filters": [
            {"column": "dnc", "condition": "in", "value": ["email", "email", "sms"], "dynamic": True},
            {"column": "e.subject", "condition": "empty", "value": "ignored", "dynamic": True},
        ]})
        self.assertEqual(payload["filters"][0]["value"], ["email", "sms"])
        # Dynamic filters take one text value per run, so lists and empty checks are never dynamic.
        self.assertEqual([f["dynamic"] for f in payload["filters"]], [0, 0])
        self.assertEqual(payload["filters"][1]["value"], "")
        with self.assertRaises(svc.ReportError):
            svc.normalize_report({**VALID, "filters": [{"column": "dnc", "condition": "in", "value": []}]})

    @with_meta
    def test_calculations_need_a_group_by(self, _meta):
        with self.assertRaises(svc.ReportError) as raised:
            svc.normalize_report({**VALID, "aggregators": [{"function": "count", "column": "es.id"}]})
        self.assertEqual(raised.exception.field, "aggregators")
        payload = svc.normalize_report({**VALID, "columns": ["e.subject"], "groupBy": ["e.subject"],
                                        "aggregators": [{"function": "count", "column": "es.id"}]})
        self.assertEqual(payload["aggregators"], [{"function": "COUNT", "column": "es.id"}])

    @with_meta
    def test_a_grouped_report_shows_only_grouped_columns(self, _meta):
        # MySQL's only_full_group_by would refuse the query when the report runs.
        with self.assertRaises(svc.ReportError) as raised:
            svc.normalize_report({**VALID, "groupBy": ["e.subject"]})
        self.assertEqual(raised.exception.field, "groupBy")
        self.assertIn("Add Stat ID to Group by", str(raised.exception))
        with self.assertRaises(svc.ReportError) as raised:
            svc.normalize_report({**VALID, "columns": ["e.subject"], "groupBy": ["e.subject"],
                                  "tableOrder": [{"column": "es.date_sent", "direction": "ASC"}]})
        self.assertEqual(raised.exception.field, "tableOrder")

    @with_meta
    def test_a_report_needs_a_name_and_a_column_or_graph(self, _meta):
        for change, field in (({"name": " "}, "name"), ({"columns": [], "graphs": []}, "columns"), ({"source": ""}, "source")):
            with self.subTest(change=change), self.assertRaises(svc.ReportError) as raised:
                svc.normalize_report({**VALID, **change})
            self.assertEqual(raised.exception.field, field)
        self.assertEqual(svc.normalize_report({**VALID, "columns": []})["columns"], [])

    @with_meta
    def test_schedules(self, _meta):
        weekly = svc.normalize_report({**VALID, "isScheduled": True, "scheduleUnit": "weekly", "scheduleDay": "mo",
                                       "toAddress": "A@x.test; b@x.test, a@x.test"})
        self.assertEqual((weekly["scheduleUnit"], weekly["scheduleDay"], weekly["scheduleMonthFrequency"], weekly["toAddress"]),
                         ("WEEKLY", "MO", None, "a@x.test,b@x.test"))
        monthly = svc.normalize_report({**VALID, "isScheduled": 1, "scheduleUnit": "MONTHLY", "scheduleDay": "WEEK_DAYS",
                                        "scheduleMonthFrequency": "-1", "toAddress": ["a@x.test"]})
        self.assertEqual((monthly["scheduleDay"], monthly["scheduleMonthFrequency"]), ("WEEK_DAYS", "-1"))
        for change, field in (
            ({"scheduleUnit": "HOURLY"}, "scheduleUnit"),
            ({"scheduleUnit": "WEEKLY"}, "scheduleDay"),
            ({"scheduleUnit": "MONTHLY", "scheduleDay": "MO"}, "scheduleMonthFrequency"),
            ({"scheduleUnit": "DAILY", "toAddress": ""}, "toAddress"),
            ({"scheduleUnit": "DAILY", "toAddress": "not-an-email"}, "toAddress"),
        ):
            with self.subTest(change=change), self.assertRaises(svc.ReportError) as raised:
                svc.normalize_report({**VALID, "isScheduled": True, "toAddress": "a@x.test", **change})
            self.assertEqual(raised.exception.field, field)

    @with_meta
    def test_an_update_keeps_saved_values_and_its_source(self, _meta):
        existing = {**svc.normalize_report(VALID), "id": 4, "isScheduled": True, "scheduleUnit": "DAILY", "toAddress": "a@x.test"}
        payload = svc.normalize_report({"name": "Renamed"}, existing=existing)
        self.assertEqual((payload["name"], payload["columns"], payload["isScheduled"], payload["toAddress"]),
                         ("Renamed", ["e.subject", "es.id"], 1, "a@x.test"))
        unscheduled = svc.normalize_report({"isScheduled": False}, existing=existing)
        self.assertEqual((unscheduled["isScheduled"], unscheduled["toAddress"]), (0, ""))
        with self.assertRaises(svc.ReportError) as raised:
            svc.normalize_report({"source": "leads"}, existing=existing)
        self.assertEqual(raised.exception.field, "source")

    def test_unknown_sources_are_refused_before_their_metadata_is_read(self):
        client = Mock()
        client.list_report_sources.return_value = [{"source": "email.stats"}]
        with override_settings(**ISOLATED), self.assertRaises(svc.ReportError) as raised:
            svc.report_source("audit.log", client)
        self.assertEqual(raised.exception.status_code, 404)
        client.get_report_source.assert_not_called()


class RunOptionTests(SimpleTestCase):
    def test_date_range(self):
        self.assertEqual(svc.date_range({"dateFrom": "2026-10-01", "dateTo": "2026-10-29"}), ("2026-10-01", "2026-10-29"))
        start, end = svc.date_range({})
        from datetime import date
        self.assertEqual((date.fromisoformat(end) - date.fromisoformat(start)).days, 30)
        for params in ({"dateFrom": "01/10/2026"}, {"dateFrom": "2026-02-30"}, {"dateFrom": "2026-10-29", "dateTo": "2026-10-01"},
                       {"dateFrom": "2000-01-01", "dateTo": "2026-01-01"}):
            with self.subTest(params=params), self.assertRaises(svc.ReportError):
                svc.date_range(params)

    def test_dynamic_values_only_for_dynamic_filters(self):
        report = {"filters": [
            {"column": "e.subject", "condition": "like", "dynamic": 1},
            {"column": "es.date_sent", "condition": "gt", "dynamic": 0},
            {"column": "dnc", "condition": "in", "dynamic": 1},
        ]}
        values = svc.dynamic_filter_values({"e.subject": " News ", "es.date_sent": "x", "dnc": "email", "l.email": "y"}, report)
        self.assertEqual(values, {"e.subject": "News"})
        self.assertEqual(svc.dynamic_filter_values({"e.subject": {"column": "x"}}, report), {})
        self.assertEqual(svc.dynamic_filter_values("nope", report), {})


class ReportClientTests(SimpleTestCase):
    def test_writes_require_the_admins_identity(self):
        session = Mock()
        client = MauticClient(session=session)
        for call in (lambda: client.create_report({}), lambda: client.update_report(4, {}), lambda: client.delete_report(4)):
            with self.assertRaises(MauticIdentityConfigurationError):
                call()
        session.request.assert_not_called()

    def test_writes_use_the_bridge_with_their_own_operations(self):
        session = Mock()
        session.request.return_value = response(201, {"report": {"id": 9, "name": "R"}})
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)
        self.assertEqual(client.create_report({"name": "R"})["id"], 9)
        method, url = session.request.call_args.args[:2]
        self.assertEqual((method, url.endswith("/api/ecp/bridge/reports/new")), ("POST", True))
        self.assertEqual(session.request.call_args.kwargs["json"], {"name": "R"})
        client.update_report(9, {"name": "S"})
        self.assertTrue(session.request.call_args.args[1].endswith("/api/ecp/bridge/reports/9/edit"))
        self.assertEqual(session.request.call_args.args[0], "PATCH")
        session.request.return_value = response(200, {"report": {"id": None}})
        client.delete_report(9)
        self.assertTrue(session.request.call_args.args[1].endswith("/api/ecp/bridge/reports/9/delete"))
        self.assertEqual([c.args[0] for c in provider.call_args_list], [REPORT_CREATE, REPORT_UPDATE, REPORT_DELETE])
        self.assertTrue({REPORT_CREATE, REPORT_UPDATE, REPORT_DELETE} <= ASSERTABLE_OPERATIONS)

    def test_reads(self):
        session = Mock()
        session.request.return_value = response(200, {"rows": [], "columns": [], "totalResults": 0})
        MauticClient(session=session).get_report_data(4, page=2, limit=10)
        self.assertTrue(session.request.call_args.args[1].endswith("/api/ecp/reports/4/data"))
        self.assertEqual(session.request.call_args.kwargs["params"], {"page": 2, "limit": 10})
        with self.assertRaises(PermanentMauticError):
            MauticClient(session=session).get_report_source("../users")
        with self.assertRaises(PermanentMauticError):
            MauticClient(session=session).get_report("4 OR 1")


def data_page(rows, total):
    return {
        "totalResults": total,
        "columns": [{"key": "e.subject", "alias": "subject", "label": "Subject"}, {"key": "es.id", "alias": "id", "label": "Stat ID"}],
        "rows": rows,
    }


@override_settings(**ISOLATED)
class ReportExportTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_superuser(username="report-export-admin", email="rea@example.test", password="x")
        grant_marketing_access(self.user)
        self.report = {"id": 4, "name": "Opens by subject", "columns": ["e.subject"]}

    def job(self, fmt="csv", **extra):
        return exports.create_job(self.user, report=self.report, fmt=fmt, date_from="2026-10-01", date_to="2026-10-29",
                                  dynamic_filters=extra.get("dynamic", {}))

    def test_pages_until_every_row_is_read(self):
        client = Mock()
        first = [{"subject": f"S{i}", "id": str(i)} for i in range(exports.PAGE_SIZE)]
        client.get_report_data.side_effect = [data_page(first, exports.PAGE_SIZE + 1),
                                              data_page([{"subject": "=cmd()", "id": "x"}], exports.PAGE_SIZE + 1)]
        job = exports.run_export(self.job(dynamic={"e.subject": "News"})["id"], client=client)
        self.assertEqual((job["status"], job["rows"], job["total"]), ("done", exports.PAGE_SIZE + 1, exports.PAGE_SIZE + 1))
        first_call, second_call = client.get_report_data.call_args_list
        self.assertEqual(first_call.kwargs["export"], 1)
        self.assertEqual(first_call.kwargs["graphs"], 0)
        self.assertNotIn("totalResults", first_call.kwargs)
        self.assertEqual((second_call.kwargs["page"], second_call.kwargs["totalResults"]), (2, exports.PAGE_SIZE + 1))
        self.assertEqual(json.loads(first_call.kwargs["dynamicFilters"]), {"e.subject": "News"})

        rows = list(csv.reader(io.StringIO(exports.read_file(job).decode("utf-8-sig"))))
        self.assertEqual(rows[0], ["Subject", "Stat ID"])
        self.assertEqual(rows[-1], ["'=cmd()", "x"], "spreadsheet formulas are neutralised")
        self.assertTrue(job["filename"].startswith("opens-by-subject-") and job["filename"].endswith(".csv"))
        with default_storage.open(job["storage_name"], "rb") as handle:
            self.assertNotIn(b"Subject", handle.read(), "the stored file is encrypted")

        from friends.models import Notification

        note = Notification.objects.get(recipient=self.user)
        self.assertEqual((note.title, note.data["type"], note.data["url"]),
                         ("Report export ready", "marketing_report_export", "/admin/newsletter/reports/4"))

    def test_xlsx(self):
        client = Mock()
        client.get_report_data.return_value = data_page([{"subject": "Hi", "id": "1"}], 1)
        job = exports.run_export(self.job("xlsx")["id"], client=client)
        sheet = load_workbook(io.BytesIO(exports.read_file(job))).active
        self.assertEqual((sheet.title, [c.value for c in sheet[1]], [c.value for c in sheet[2]]), ("Report", ["Subject", "Stat ID"], ["Hi", "1"]))

    def test_failures_end_the_job_with_a_reason(self):
        cases = [
            (data_page([], 10 ** 9), "at most"),
            (PermanentMauticError("Mautic report data (HTTP 403): Exporting reports is not allowed"), "not allowed to export"),
            (PermanentMauticError("Mautic report data (HTTP 404)"), "no longer exists"),
            (TemporaryMauticError("down"), "could not be read"),
        ]
        for outcome, message in cases:
            client = Mock()
            client.get_report_data.side_effect = [outcome]
            with self.subTest(message=message):
                job = exports.run_export(self.job()["id"], client=client)
                self.assertEqual(job["status"], "failed")
                self.assertIn(message, job["error"])
                self.assertEqual(job["storage_name"], "")

    def test_jobs_belong_to_their_owner(self):
        job = self.job()
        other = User.objects.create_superuser(username="report-export-other", email="reo@example.test", password="x")
        with self.assertRaises(exports.ReportExportError) as raised:
            exports.get_owned_job(job["id"], other)
        self.assertEqual(raised.exception.status_code, 404)
        self.assertNotIn("key", exports.public_job(job))
        self.assertNotIn("storage_name", exports.public_job(job))


@override_settings(**ISOLATED)
class ReportApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="report-admin", email="ra@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api = APIClient()
        self.api.force_authenticate(self.admin)

    def test_list_adds_source_labels(self):
        with patch.object(MauticClient, "list_reports", return_value=[{"id": 4, "name": "A", "source": "email.stats"}]), \
                patch("newsletter.report_views.report_sources", return_value=[{"source": "email.stats", "label": "Emails Sent", "groupLabel": "Emails"}]):
            body = self.api.get(reverse("newsletter-admin-report-list")).json()
        self.assertEqual(body["results"][0]["sourceLabel"], "Emails Sent")

    def test_create_runs_as_the_admin_and_is_audited(self):
        def mutation(request, action, resource_id, mutate, **kwargs):
            client = Mock()
            client.create_report.return_value = {"id": 12, "name": "Opens by subject"}
            result = mutate(client)
            self.assertEqual(client.create_report.call_args.args[0]["source"], "email.stats")
            self.assertEqual(kwargs["resource_id_from_result"](result), 12)
            return result, None

        with patch("newsletter.report_services.report_source", return_value=META), \
                patch("newsletter.report_views._mutation", side_effect=mutation) as run:
            r = self.api.post(reverse("newsletter-admin-report-list"), VALID, format="json")
        self.assertEqual((r.status_code, r.json()["id"]), (201, 12))
        self.assertEqual(run.call_args.args[1], REPORT_CREATE)

    def test_invalid_reports_never_reach_mautic(self):
        with patch("newsletter.report_services.report_source", return_value=META), \
                patch("newsletter.report_views._mutation") as run:
            r = self.api.post(reverse("newsletter-admin-report-list"), {**VALID, "columns": ["l.password"]}, format="json")
        self.assertEqual((r.status_code, r.json()["field"]), (400, "columns"))
        run.assert_not_called()

    def test_provider_errors_map_to_codes(self):
        url = reverse("newsletter-admin-report-detail", args=[4])
        cases = [
            (PermanentMauticError("Mautic report lookup (HTTP 404)"), 404, "report_not_found"),
            (PermanentMauticError("Mautic report lookup (HTTP 403)"), 403, "report_forbidden"),
            (TemporaryMauticError("down"), 502, "mautic_error"),
        ]
        for exc, status_code, code in cases:
            with self.subTest(code=code), patch.object(MauticClient, "get_report", side_effect=exc):
                r = self.api.get(url)
            self.assertEqual((r.status_code, r.json()["code"]), (status_code, code))
        refused = PermanentMauticError("Mautic report update (HTTP 400): source: This value is not valid.")
        with patch.object(MauticClient, "get_report", return_value={**VALID, "id": 4}), \
                patch("newsletter.report_services.report_source", return_value=META), \
                patch("newsletter.report_views._mutation", side_effect=refused):
            r = self.api.patch(url, {"name": "X"}, format="json")
        self.assertEqual((r.status_code, r.json()["detail"]), (400, "Mautic refused the report: source: This value is not valid."))

    def test_identity_refusals_are_returned_as_is(self):
        with patch("newsletter.report_views._mutation", return_value=(None, Response({"detail": "no"}, status=403))):
            r = self.api.delete(reverse("newsletter-admin-report-detail", args=[4]))
        self.assertEqual(r.status_code, 403)

    def test_data_passes_only_dynamic_values(self):
        report = {"id": 4, "filters": [{"column": "e.subject", "condition": "like", "dynamic": 1}]}
        with patch.object(MauticClient, "get_report", return_value=report), \
                patch.object(MauticClient, "get_report_data", return_value=data_page([], 0)) as data:
            r = self.api.get(reverse("newsletter-admin-report-data", args=[4]), {
                "dateFrom": "2026-10-01", "dateTo": "2026-10-29", "page": 2, "limit": 9999,
                "dynamicFilters": json.dumps({"e.subject": "News", "l.email": "x"}),
            })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Cache-Control"], "no-store")
        kwargs = data.call_args.kwargs
        self.assertEqual((kwargs["page"], kwargs["limit"], kwargs["graphs"]), (2, 500, 1))
        self.assertEqual(json.loads(kwargs["dynamicFilters"]), {"e.subject": "News"})
        bad = self.api.get(reverse("newsletter-admin-report-data", args=[4]), {"dateFrom": "x"})
        self.assertEqual(bad.json()["code"], "invalid_dates")

    def test_export_start_download_and_audit(self):
        with patch.object(MauticClient, "get_report", return_value={"id": 4, "name": "R", "columns": ["e.subject"]}), \
                patch("newsletter.tasks.run_report_export.delay") as delay:
            r = self.api.post(reverse("newsletter-admin-report-exports", args=[4]),
                              {"format": "xlsx", "dateFrom": "2026-10-01", "dateTo": "2026-10-29"}, format="json")
        self.assertEqual(r.status_code, 202)
        job_id = r.json()["id"]
        delay.assert_called_once_with(job_id)
        self.assertEqual(self.api.get(reverse("newsletter-admin-report-exports", args=[4])).json()["results"][0]["id"], job_id)
        self.assertEqual(self.api.get(reverse("newsletter-admin-report-exports", args=[5])).json()["results"], [])
        self.assertEqual(self.api.get(reverse("newsletter-admin-report-export-download", args=[job_id])).json()["code"], "export_not_ready")

        client = Mock()
        client.get_report_data.return_value = data_page([{"subject": "Hi", "id": "1"}], 1)
        exports.run_export(job_id, client=client)
        download = self.api.get(reverse("newsletter-admin-report-export-download", args=[job_id]))
        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment;", download["Content-Disposition"])
        actions = set(MauticIdentityAuditLog.objects.values_list("action", flat=True))
        self.assertTrue({"report.export.create", "report.export.download"} <= actions)

        other_admin = User.objects.create_superuser(username="report-other", email="ro@example.test", password="x")
        grant_marketing_access(other_admin)
        other = APIClient()
        other.force_authenticate(other_admin)
        self.assertEqual(other.get(reverse("newsletter-admin-report-export-download", args=[job_id])).status_code, 404)

    def test_exports_need_table_columns(self):
        with patch.object(MauticClient, "get_report", return_value={"id": 4, "name": "R", "columns": []}):
            r = self.api.post(reverse("newsletter-admin-report-exports", args=[4]), {"format": "csv"}, format="json")
        self.assertEqual(r.json()["code"], "export_no_columns")

    def test_non_marketing_users_are_denied(self):
        normal = APIClient()
        normal.force_authenticate(User.objects.create_user(username="report-normal", email="rn@example.test", password="x"))
        for url in (reverse("newsletter-admin-report-list"), reverse("newsletter-admin-report-sources"),
                    reverse("newsletter-admin-report-data", args=[4])):
            self.assertIn(normal.get(url).status_code, (401, 403))
