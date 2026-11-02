"""Marketing Hub Form submission export endpoints (see form_submission_export_services)."""

from __future__ import annotations

import logging

from django.http import HttpResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .contact_export_services import FORMATS
from .form_submission_export_services import (
    SubmissionExportError,
    create_job,
    delete_job,
    get_owned_job,
    list_user_jobs,
    public_job,
    read_file,
)
from .form_views import _form_id, _invalid_id_response, _private, _read_form
from .marketing_permissions import HasMarketingHubAccess
from .mautic_identity_audit import record_identity_audit
from .models import MauticIdentityAuditLog

logger = logging.getLogger(__name__)

EXPORT_CREATE = "form.submission.export.create"
EXPORT_DOWNLOAD = "form.submission.export.download"
EXPORT_DELETE = "form.submission.export.delete"


def _export_error(exc: SubmissionExportError) -> Response:
    return _private(Response({"detail": str(exc), "code": exc.code}, status=exc.status_code))


def _audit_export(request, action: str, job: dict, detail: str) -> None:
    record_identity_audit(
        action=action,
        status=MauticIdentityAuditLog.Status.SUCCEEDED,
        actor=request.user,
        resource="form_submission_export",
        resource_id=job["id"][:12],
        detail=detail[:250],
    )


def _describe(job: dict) -> str:
    return f"form {job['form_id']}, {job['format']}"


class NewsletterAdminFormSubmissionExportListCreateView(APIView):
    """Start a CSV/XLSX export of a Form's submissions; list my recent exports of it."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, form_id):
        normalized = _form_id(form_id)
        if normalized is None:
            return _private(_invalid_id_response())
        return _private(Response({"results": [public_job(job) for job in list_user_jobs(request.user, form_id=normalized)]}))

    def post(self, request, form_id):
        normalized = _form_id(form_id)
        if normalized is None:
            return _private(_invalid_id_response())
        data = request.data if hasattr(request.data, "get") else {}
        fmt = str(data.get("format") or "csv").strip().lower()
        if fmt not in FORMATS:
            return _private(Response({"detail": "Format must be csv or xlsx.", "code": "invalid_format"},
                                     status=status.HTTP_400_BAD_REQUEST))
        form, error = _read_form(normalized)
        if error is not None:
            return _private(error)

        job = create_job(request.user, form=form, fmt=fmt)
        from .tasks import run_form_submission_export

        try:
            run_form_submission_export.delay(job["id"])
        except Exception:  # noqa: BLE001 - broker outages surface as a clear error
            logger.exception("Could not queue form submission export %s", job["id"])
            delete_job(job)
            return _private(Response(
                {"detail": "The export could not be started. Try again in a moment.", "code": "export_not_queued"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            ))
        _audit_export(request, EXPORT_CREATE, job, _describe(job))
        return _private(Response(public_job(job), status=status.HTTP_202_ACCEPTED))


class NewsletterAdminFormSubmissionExportDetailView(APIView):
    """An export's progress; delete it (and its file) early."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, job_id):
        try:
            return _private(Response(public_job(get_owned_job(job_id, request.user))))
        except SubmissionExportError as exc:
            return _export_error(exc)

    def delete(self, request, job_id):
        try:
            job = get_owned_job(job_id, request.user)
        except SubmissionExportError as exc:
            return _export_error(exc)
        delete_job(job)
        _audit_export(request, EXPORT_DELETE, job, _describe(job))
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminFormSubmissionExportDownloadView(APIView):
    """The decrypted file, for the admin who started the export only."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, job_id):
        try:
            job = get_owned_job(job_id, request.user)
            content = read_file(job)
        except SubmissionExportError as exc:
            return _export_error(exc)
        _audit_export(request, EXPORT_DOWNLOAD, job, f"{_describe(job)}, {job.get('rows', 0)} rows")
        response = HttpResponse(content, content_type=FORMATS[job["format"]]["content_type"])
        response["Content-Disposition"] = f'attachment; filename="{job["filename"]}"'
        return _private(response)
