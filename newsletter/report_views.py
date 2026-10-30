"""Marketing Hub reports endpoints (see report_services and report_export_services)."""

from __future__ import annotations

import json
import logging

from django.http import HttpResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .contact_export_services import FORMATS
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.operations import REPORT_CREATE, REPORT_DELETE, REPORT_UPDATE
from .mautic_identity_audit import record_identity_audit
from .mautic_identity_execution import run_interactive_mutation
from .models import MauticIdentityAuditLog
from .report_export_services import (
    ReportExportError,
    create_job,
    delete_job,
    get_owned_job,
    list_user_jobs,
    public_job,
    read_file,
)
from .report_services import (
    ReportError,
    date_range,
    dynamic_filter_values,
    normalize_report,
    report_source,
    report_sources,
)

logger = logging.getLogger(__name__)

EXPORT_CREATE = "report.export.create"
EXPORT_DOWNLOAD = "report.export.download"
EXPORT_DELETE = "report.export.delete"
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
_PROVIDER_ERRORS = (TemporaryMauticError, PermanentMauticError)


def _report_error(exc: ReportError | ReportExportError) -> Response:
    body = {"detail": str(exc), "code": exc.code}
    if getattr(exc, "field", ""):
        body["field"] = exc.field
    return Response(body, status=exc.status_code)


def _provider_error(exc, *, action: str = "read") -> Response:
    message = str(exc)
    if isinstance(exc, PermanentMauticError):
        if "HTTP 404" in message:
            return Response({"detail": "That report was not found in Mautic.", "code": "report_not_found"},
                            status=status.HTTP_404_NOT_FOUND)
        if "HTTP 403" in message:
            return Response({"detail": "Your Mautic user is not allowed to do that with reports.", "code": "report_forbidden"},
                            status=status.HTTP_403_FORBIDDEN)
        if "HTTP 400" in message or "HTTP 422" in message:
            # Mautic's own form refused the report: show its reason.
            reason = message.split(": ", 1)[1] if ": " in message else ""
            return Response({"detail": f"Mautic refused the report{': ' + reason if reason else '.'}", "code": "report_invalid"},
                            status=status.HTTP_400_BAD_REQUEST)
    verb = {"read": "read", "save": "saved", "delete": "deleted"}.get(action, action)
    detail = ("Mautic could not be reached. Try again." if action == "read"
              else f"Mautic could not be reached. Nothing was {verb}; try again.")
    return Response({"detail": detail, "code": "mautic_error"}, status=status.HTTP_502_BAD_GATEWAY)


def _private(response):
    response["Cache-Control"] = "no-store"
    return response


def _with_source_labels(reports: list[dict], client: MauticClient) -> list[dict]:
    try:
        labels = {row["source"]: row for row in report_sources(client)}
    except _PROVIDER_ERRORS:
        labels = {}
    for report in reports:
        source = labels.get(report.get("source"), {})
        report["sourceLabel"] = source.get("label") or report.get("source") or ""
        report["sourceGroup"] = source.get("groupLabel") or ""
    return reports


def _mutation(request, action: str, resource_id, mutate, **kwargs):
    return run_interactive_mutation(
        request,
        action=action,
        resource="report",
        resource_id=resource_id,
        mutate=mutate,
        client_factory=MauticClient,
        audit_and_reraise=_PROVIDER_ERRORS,
        **kwargs,
    )


class NewsletterAdminReportSourcesView(APIView):
    """The data sources a report can be built on (Mautic's own list, minus the system audit log)."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            return Response({"results": report_sources()})
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)


class NewsletterAdminReportSourceView(APIView):
    """One source's columns, filters (with operators), group-by columns and graphs."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, source):
        try:
            return Response(report_source(source))
        except ReportError as exc:
            return _report_error(exc)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)


class NewsletterAdminReportListCreateView(APIView):
    """Every report the Mautic service user can see; POST creates one as the admin's Mautic user."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        client = MauticClient()
        try:
            reports = client.list_reports()
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        return Response({"results": _with_source_labels(reports, client)})

    def post(self, request):
        try:
            payload = normalize_report(request.data)
        except ReportError as exc:
            return _report_error(exc)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)

        try:
            report, identity_response = _mutation(
                request, REPORT_CREATE, "", lambda client: client.create_report(payload),
                resource_id_from_result=lambda result: result.get("id"),
                detail=f"source {payload['source']}",
            )
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc, action="save")
        if identity_response is not None:
            return identity_response
        return Response(report, status=status.HTTP_201_CREATED)


class NewsletterAdminReportDetailView(APIView):
    """A report's definition; PATCH saves the whole definition; DELETE removes it."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, report_id):
        try:
            report = MauticClient().get_report(report_id)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        return Response(_with_source_labels([report], MauticClient())[0])

    def patch(self, request, report_id):
        try:
            existing = MauticClient().get_report(report_id)
            payload = normalize_report(request.data, existing=existing)
        except ReportError as exc:
            return _report_error(exc)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)

        try:
            report, identity_response = _mutation(
                request, REPORT_UPDATE, report_id, lambda client: client.update_report(report_id, payload)
            )
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc, action="save")
        if identity_response is not None:
            return identity_response
        return Response(report)

    def delete(self, request, report_id):
        try:
            _, identity_response = _mutation(request, REPORT_DELETE, report_id, lambda client: client.delete_report(report_id))
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc, action="delete")
        if identity_response is not None:
            return identity_response
        return Response(status=status.HTTP_204_NO_CONTENT)


def _dynamic_filters(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


class NewsletterAdminReportDataView(APIView):
    """Run a report: one page of rows plus its graphs, for a date range."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, report_id):
        params = request.query_params
        try:
            date_from, date_to = date_range(params)
        except ReportError as exc:
            return _report_error(exc)
        try:
            page = max(1, int(params.get("page") or 1))
            limit = min(MAX_PAGE_SIZE, max(1, int(params.get("limit") or DEFAULT_PAGE_SIZE)))
        except (TypeError, ValueError):
            return Response({"detail": "page and limit must be numbers.", "code": "invalid_page"}, status=status.HTTP_400_BAD_REQUEST)

        client = MauticClient()
        try:
            report = client.get_report(report_id)
            query = {
                "dateFrom": date_from, "dateTo": date_to, "page": page, "limit": limit,
                "graphs": 0 if str(params.get("graphs") or "1") == "0" else 1,
            }
            dynamic = dynamic_filter_values(_dynamic_filters(params.get("dynamicFilters")), report)
            if dynamic:
                query["dynamicFilters"] = json.dumps(dynamic)
            data = client.get_report_data(report_id, **query)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        data["dynamicFilters"] = dynamic
        return _private(Response(data))


def _audit_export(request, action: str, job: dict, detail: str) -> None:
    record_identity_audit(
        action=action,
        status=MauticIdentityAuditLog.Status.SUCCEEDED,
        actor=request.user,
        resource="report_export",
        resource_id=job["id"][:12],
        detail=detail[:250],
    )


def _describe(job: dict) -> str:
    return f"report {job['report_id']}, {job['format']}, {job['date_from']} to {job['date_to']}"


class NewsletterAdminReportExportListCreateView(APIView):
    """Start a CSV/XLSX export of a report for a date range; list my recent exports of it."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, report_id):
        return _private(Response({"results": [public_job(job) for job in list_user_jobs(request.user, report_id=str(report_id))]}))

    def post(self, request, report_id):
        data = request.data if hasattr(request.data, "get") else {}
        fmt = str(data.get("format") or "csv").strip().lower()
        if fmt not in FORMATS:
            return Response({"detail": "Format must be csv or xlsx.", "code": "invalid_format"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            date_from, date_to = date_range(data)
        except ReportError as exc:
            return _report_error(exc)
        try:
            report = MauticClient().get_report(report_id)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        if not report.get("columns"):
            return Response({"detail": "This report has no table columns to export.", "code": "export_no_columns"},
                            status=status.HTTP_400_BAD_REQUEST)

        job = create_job(
            request.user, report=report, fmt=fmt, date_from=date_from, date_to=date_to,
            dynamic_filters=dynamic_filter_values(_dynamic_filters(data.get("dynamicFilters")), report),
        )
        from .tasks import run_report_export

        try:
            run_report_export.delay(job["id"])
        except Exception:  # noqa: BLE001 - broker outages surface as a clear error
            logger.exception("Could not queue report export %s", job["id"])
            delete_job(job)
            return Response(
                {"detail": "The export could not be started. Try again in a moment.", "code": "export_not_queued"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        _audit_export(request, EXPORT_CREATE, job, _describe(job))
        return _private(Response(public_job(job), status=status.HTTP_202_ACCEPTED))


class NewsletterAdminReportExportDetailView(APIView):
    """An export's progress; delete it (and its file) early."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, job_id):
        try:
            return _private(Response(public_job(get_owned_job(job_id, request.user))))
        except ReportExportError as exc:
            return _report_error(exc)

    def delete(self, request, job_id):
        try:
            job = get_owned_job(job_id, request.user)
        except ReportExportError as exc:
            return _report_error(exc)
        delete_job(job)
        _audit_export(request, EXPORT_DELETE, job, _describe(job))
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminReportExportDownloadView(APIView):
    """The decrypted file, for the admin who started the export only."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, job_id):
        try:
            job = get_owned_job(job_id, request.user)
            content = read_file(job)
        except ReportExportError as exc:
            return _report_error(exc)
        _audit_export(request, EXPORT_DOWNLOAD, job, f"{_describe(job)}, {job.get('rows', 0)} rows")
        response = HttpResponse(content, content_type=FORMATS[job["format"]]["content_type"])
        response["Content-Disposition"] = f'attachment; filename="{job["filename"]}"'
        return _private(response)

