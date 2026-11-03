"""Company CSV import (native Mautic queue) and company export endpoints.

See company_import_services and company_export_services.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets

from django.http import HttpResponse
from rest_framework import status
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from . import marketing_cache
from .company_export_services import (
    CompanyExportError,
    create_job,
    delete_job,
    get_owned_job,
    list_user_jobs,
    public_job,
    read_file,
)
from .company_import_services import (
    MODES,
    NAME_FIELD,
    PREVIEW_ROWS,
    CompanyImportError,
    check_rows,
    company_fields,
    parse_mapping,
    prepared_csv,
    read_csv,
    suggest_mapping,
)
from .contact_export_services import FORMATS
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.exceptions import MauticRequestNotSentError
from .mautic.operations import COMPANY_IMPORT_CREATE
from .mautic_identity_audit import record_identity_audit
from .mautic_identity_execution import run_interactive_mutation
from .models import MauticIdentityAuditLog

logger = logging.getLogger(__name__)

EXPORT_CREATE = "company.export.create"
EXPORT_DOWNLOAD = "company.export.download"
EXPORT_DELETE = "company.export.delete"
_ATTEMPT_RE = re.compile(r"^[a-f0-9]{32}$")


def _error(message: str, code: str, http_status: int, **extra) -> Response:
    return Response({"detail": message, "code": code, **extra}, status=http_status)


def _import_error(exc: CompanyImportError) -> Response:
    return _error(str(exc), exc.code, status.HTTP_400_BAD_REQUEST, errors={exc.field: str(exc)} if exc.field else {})


def _fields() -> list[dict[str, str]]:
    data = marketing_cache.fields(MauticClient(), "company", limit=500)
    return company_fields(data.get("fields") if isinstance(data, dict) else [])


def _mapping_from(request) -> object:
    raw = request.data.get("mapping")
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return None
    return raw


class NewsletterAdminCompanyImportPreviewView(APIView):
    """POST a CSV: its columns, a suggested mapping, a preview and the checks."""

    permission_classes = [HasMarketingHubAccess]
    parser_classes = [MultiPartParser]

    def post(self, request):
        try:
            fields = _fields()
            parsed = read_csv(request.FILES.get("file"))
            raw_mapping = _mapping_from(request)
            mapping = parse_mapping(raw_mapping, parsed["headers"], fields) if raw_mapping else suggest_mapping(parsed["headers"], fields)
        except CompanyImportError as exc:
            return _import_error(exc)
        except (TemporaryMauticError, PermanentMauticError):
            return _error("Mautic's company fields could not be read. Try again.", "mautic_error", status.HTTP_502_BAD_GATEWAY)
        checks = check_rows(parsed["rows"], mapping, fields) if NAME_FIELD in mapping.values() else None
        response = Response({
            "headers": parsed["headers"],
            "fields": fields,
            "mapping": mapping,
            "preview": parsed["rows"][:PREVIEW_ROWS],
            "rows": len(parsed["rows"]),
            "checks": checks,
            # Sent back with Start: a double-click or retry of this preview is
            # caught, while choosing the file again can import it again.
            "attempt": secrets.token_hex(16),
        })
        response["Cache-Control"] = "no-store, private"
        return response


class NewsletterAdminCompanyImportListCreateView(APIView):
    """GET recent company imports; POST a CSV, mapping and mode to queue one."""

    permission_classes = [HasMarketingHubAccess]
    parser_classes = [MultiPartParser]

    def get(self, request):
        try:
            data = MauticClient().list_company_imports(limit=10)
        except (TemporaryMauticError, PermanentMauticError):
            return _error("Mautic could not return the imports. Try again.", "mautic_error", status.HTTP_502_BAD_GATEWAY)
        return Response({"count": int(data.get("total") or 0), "results": data["imports"]})

    def post(self, request):
        upload = request.FILES.get("file")
        mode = str(request.data.get("mode") or "")
        if mode not in MODES:
            return _error("Choose whether existing companies are updated or skipped.", "invalid_company_import", status.HTTP_400_BAD_REQUEST)
        attempt = str(request.data.get("attempt") or "")
        if attempt and not _ATTEMPT_RE.match(attempt):
            return _error("Choose the file again and retry.", "invalid_company_import", status.HTTP_400_BAD_REQUEST)
        try:
            fields = _fields()
            parsed = read_csv(upload)
            mapping = parse_mapping(_mapping_from(request), parsed["headers"], fields)
        except CompanyImportError as exc:
            return _import_error(exc)
        except (TemporaryMauticError, PermanentMauticError):
            return _error("Mautic's company fields could not be read. Try again.", "mautic_error", status.HTTP_502_BAD_GATEWAY)
        checks = check_rows(parsed["rows"], mapping, fields)
        if checks["without_name"] == checks["rows"]:
            return _error("No row has a company name, so nothing would be imported.", "invalid_company_import", status.HTTP_400_BAD_REQUEST)
        content = prepared_csv(parsed["rows"], mapping)
        key = hashlib.sha256(b"|".join([content, json.dumps(mapping, sort_keys=True).encode(), mode.encode(),
                                        str(request.user.pk).encode(), attempt.encode()])).hexdigest()[:40]
        # prepared_csv heads each column with its field alias.
        config = {"mapping": {alias: alias for alias in mapping.values()}, "mode": mode, "idempotency_key": key,
                  "original_filename": str(getattr(upload, "name", "") or "companies.csv")[:191]}
        try:
            result, error_response = run_interactive_mutation(
                request,
                action=COMPANY_IMPORT_CREATE,
                resource="company_import",
                resource_id="",
                mutate=lambda client: client.create_company_import(file_name="companies.csv", content=content, config=config),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                resource_id_from_result=lambda created: str((created[0] or {}).get("id") or ""),
                detail=f"{checks['rows']} rows, {mode}",
            )
        except MauticRequestNotSentError:
            return _error("Mautic could not be reached; nothing was queued.", "mautic_unavailable", status.HTTP_503_SERVICE_UNAVAILABLE)
        except PermanentMauticError as exc:
            message = str(exc).split(": ", 1)[1] if ": " in str(exc) else str(exc)
            return _error(message, "company_import_refused", status.HTTP_400_BAD_REQUEST)
        except TemporaryMauticError:
            return _error("Mautic did not confirm the import. Check the import list before trying again.",
                          "company_import_unconfirmed", status.HTTP_502_BAD_GATEWAY)
        if error_response is not None:
            return error_response
        company_import, duplicate = result
        return Response({"import": company_import, "duplicate": duplicate, "checks": checks},
                        status=status.HTTP_200_OK if duplicate else status.HTTP_201_CREATED)


class NewsletterAdminCompanyImportDetailView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request, import_id):
        try:
            return Response(MauticClient().get_company_import(import_id))
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc) or "numeric" in str(exc):
                return _error("Import not found.", "import_not_found", status.HTTP_404_NOT_FOUND)
            return _error("Mautic could not return the import.", "mautic_error", status.HTTP_502_BAD_GATEWAY)
        except TemporaryMauticError:
            return _error("Mautic could not return the import.", "mautic_error", status.HTTP_502_BAD_GATEWAY)


def _private(response):
    response["Cache-Control"] = "no-store, private"
    response["Pragma"] = "no-cache"
    return response


def _export_error(exc: CompanyExportError) -> Response:
    return _private(_error(str(exc), exc.code, exc.status_code))


def _audit_export(request, action: str, job: dict, detail: str) -> None:
    record_identity_audit(action=action, status=MauticIdentityAuditLog.Status.SUCCEEDED, actor=request.user,
                          resource="company_export", resource_id=job["id"][:12], detail=detail[:250])


class NewsletterAdminCompanyExportListCreateView(APIView):
    """Start a CSV/XLSX export of the companies (optionally a search); list mine."""

    permission_classes = [HasMarketingHubAccess]
    parser_classes = [JSONParser]

    def get(self, request):
        return _private(Response({"results": [public_job(job) for job in list_user_jobs(request.user)]}))

    def post(self, request):
        data = request.data if hasattr(request.data, "get") else {}
        fmt = str(data.get("format") or "csv").strip().lower()
        if fmt not in FORMATS:
            return _private(_error("Format must be csv or xlsx.", "invalid_format", status.HTTP_400_BAD_REQUEST))
        job = create_job(request.user, fmt=fmt, search=str(data.get("search") or ""))
        from .tasks import run_company_export

        try:
            run_company_export.delay(job["id"])
        except Exception:  # noqa: BLE001 - broker outages surface as a clear error
            logger.exception("Could not queue company export %s", job["id"])
            delete_job(job)
            return _private(_error("The export could not be started. Try again in a moment.", "export_not_queued",
                                   status.HTTP_503_SERVICE_UNAVAILABLE))
        _audit_export(request, EXPORT_CREATE, job, f"{fmt}, search {job['search'] or '(all)'}")
        return _private(Response(public_job(job), status=status.HTTP_202_ACCEPTED))


class NewsletterAdminCompanyExportDetailView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request, job_id):
        try:
            return _private(Response(public_job(get_owned_job(job_id, request.user))))
        except CompanyExportError as exc:
            return _export_error(exc)

    def delete(self, request, job_id):
        try:
            job = get_owned_job(job_id, request.user)
        except CompanyExportError as exc:
            return _export_error(exc)
        delete_job(job)
        _audit_export(request, EXPORT_DELETE, job, job["format"])
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminCompanyExportDownloadView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request, job_id):
        try:
            job = get_owned_job(job_id, request.user)
            content = read_file(job)
        except CompanyExportError as exc:
            return _export_error(exc)
        _audit_export(request, EXPORT_DOWNLOAD, job, f"{job['format']}, {job.get('rows', 0)} rows")
        response = HttpResponse(content, content_type=FORMATS[job["format"]]["content_type"])
        response["Content-Disposition"] = f'attachment; filename="{job["filename"]}"'
        return _private(response)
