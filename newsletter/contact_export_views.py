"""Marketing Hub contact export endpoints (see contact_export_services)."""

from __future__ import annotations

import logging

from django.http import HttpResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .contact_export_services import (
    FORMATS,
    ContactExportError,
    create_job,
    delete_job,
    get_owned_job,
    list_user_jobs,
    parse_request,
    public_job,
    read_file,
)
from .marketing_permissions import HasMarketingHubAccess
from .mautic_identity_audit import record_identity_audit
from .models import MauticIdentityAuditLog

logger = logging.getLogger(__name__)

EXPORT_CREATE = "contact.export.create"
EXPORT_DOWNLOAD = "contact.export.download"
EXPORT_DELETE = "contact.export.delete"


def _error_response(exc: ContactExportError) -> Response:
    return Response({"detail": str(exc), "code": exc.code}, status=exc.status_code)


def _private(response):
    response["Cache-Control"] = "no-store"
    return response


def _audit(request, action: str, job: dict, detail: str) -> None:
    record_identity_audit(
        action=action,
        status=MauticIdentityAuditLog.Status.SUCCEEDED,
        actor=request.user,
        resource="contact_export",
        resource_id=job["id"][:12],
        detail=detail[:250],
    )


def _describe(job: dict) -> str:
    if job["scope"] == "selected":
        return f"{job['format']}, {len(job.get('contact_ids') or [])} selected contacts"
    filters = job.get("filters") or {}
    parts = [job["format"], "filter"]
    if filters.get("search"):
        parts.append("search set")
    if filters.get("stage_id"):
        parts.append(f"stage {filters['stage_id']}")
    return ", ".join(parts)


class NewsletterAdminContactExportListCreateView(APIView):
    """Start an export of the filtered list or the ticked contacts; list my recent exports."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        return _private(Response({"results": [public_job(job) for job in list_user_jobs(request.user)]}))

    def post(self, request):
        try:
            options = parse_request(request.data)
        except ContactExportError as exc:
            return _error_response(exc)
        job = create_job(request.user, options)
        from .tasks import run_contact_export

        try:
            run_contact_export.delay(job["id"])
        except Exception:  # noqa: BLE001 - broker outages surface as a clear error
            logger.exception("Could not queue contact export %s", job["id"])
            delete_job(job)
            return Response(
                {"detail": "The export could not be started. Try again in a moment.", "code": "export_not_queued"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        _audit(request, EXPORT_CREATE, job, _describe(job))
        return _private(Response(public_job(job), status=status.HTTP_202_ACCEPTED))


class NewsletterAdminContactExportDetailView(APIView):
    """An export's progress; delete it (and its file) early."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, job_id):
        try:
            return _private(Response(public_job(get_owned_job(job_id, request.user))))
        except ContactExportError as exc:
            return _error_response(exc)

    def delete(self, request, job_id):
        try:
            job = get_owned_job(job_id, request.user)
        except ContactExportError as exc:
            return _error_response(exc)
        delete_job(job)
        _audit(request, EXPORT_DELETE, job, _describe(job))
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminContactExportDownloadView(APIView):
    """The decrypted file, for the admin who started the export only."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, job_id):
        try:
            job = get_owned_job(job_id, request.user)
            content = read_file(job)
        except ContactExportError as exc:
            return _error_response(exc)
        _audit(request, EXPORT_DOWNLOAD, job, f"{_describe(job)}, {job.get('rows', 0)} rows")
        response = HttpResponse(content, content_type=FORMATS[job["format"]]["content_type"])
        response["Content-Disposition"] = f'attachment; filename="{job["filename"]}"'
        return _private(response)
