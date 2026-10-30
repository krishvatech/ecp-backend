"""Marketing Hub report export (CSV or Excel), in the background.

Mautic's own export streams the file from its web UI, which ECP admins do not
use, so ECP pages through the report's data on the bridge (the bridge requires
the native export permission for these pages) and builds the file in a Celery
task, as the contact export does: the file is encrypted before it is stored
under the same private prefix (and so purged by the same hourly task), its key
lives only in the cached job for 24 hours, and downloads go through ECP for
the admin who started the export only, audited.

Jobs are kept in the cache (no model, no migration).
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.utils import timezone
from django.utils.text import slugify

from .contact_export_services import FORMATS, STORAGE_PREFIX, _cell, _write_csv, _write_xlsx, retention
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError

logger = logging.getLogger(__name__)

CACHE_PREFIX = "marketing:report-export"
PAGE_SIZE = 1000
PAGE_TIMEOUT_SECONDS = 120
NOTIFICATION_TYPE = "marketing_report_export"
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"


class ReportExportError(ValueError):
    def __init__(self, message: str, *, code: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def max_rows() -> int:
    return int(getattr(settings, "NEWSLETTER_REPORT_EXPORT_MAX_ROWS", 100_000))


def _job_key(job_id: str) -> str:
    return f"{CACHE_PREFIX}:{job_id}"


def _user_key(user_id) -> str:
    return f"{CACHE_PREFIX}:user:{user_id}"


def _ttl_seconds() -> int:
    return int(retention().total_seconds())


def _save_job(job: dict[str, Any]) -> None:
    cache.set(_job_key(job["id"]), job, timeout=_ttl_seconds())


def get_job(job_id: str) -> dict[str, Any] | None:
    if not _JOB_ID_RE.match(str(job_id or "")):
        return None
    job = cache.get(_job_key(job_id))
    return job if isinstance(job, dict) else None


def _update_job(job_id: str, **changes) -> dict[str, Any] | None:
    job = get_job(job_id)
    if job is None:
        return None
    job.update(changes)
    _save_job(job)
    return job


def get_owned_job(job_id: str, user) -> dict[str, Any]:
    job = get_job(job_id)
    # Someone else's export is reported exactly like a missing one.
    if job is None or job.get("owner_id") != getattr(user, "pk", None):
        raise ReportExportError("Export not found. Exports are kept for 24 hours.", code="export_not_found", status_code=404)
    return expire_if_stale(job)


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    """What the admin may see: never the storage name or the key."""
    return {
        key: job.get(key)
        for key in ("id", "status", "format", "report_id", "report_name", "date_from", "date_to", "total", "processed",
                    "rows", "created_at", "finished_at", "expires_at", "error", "filename")
    }


def list_user_jobs(user, *, report_id: str = "") -> list[dict[str, Any]]:
    ids = cache.get(_user_key(user.pk)) or []
    jobs = [get_job(job_id) for job_id in ids]
    jobs = [expire_if_stale(job) for job in jobs if job and job.get("owner_id") == user.pk]
    if report_id:
        jobs = [job for job in jobs if str(job.get("report_id")) == str(report_id)]
    return sorted(jobs, key=lambda job: job.get("created_at") or "", reverse=True)


def create_job(user, *, report: dict[str, Any], fmt: str, date_from: str, date_to: str,
               dynamic_filters: dict[str, str]) -> dict[str, Any]:
    if fmt not in FORMATS:
        raise ReportExportError("Format must be csv or xlsx.", code="invalid_format")
    now = timezone.now()
    job = {
        "id": secrets.token_urlsafe(18),
        "owner_id": user.pk,
        "status": STATUS_QUEUED,
        "format": fmt,
        "report_id": str(report["id"]),
        "report_name": str(report.get("name") or "")[:191],
        "date_from": date_from,
        "date_to": date_to,
        "dynamic_filters": dynamic_filters,
        "total": None,
        "processed": 0,
        "rows": 0,
        "created_at": now.isoformat(),
        "finished_at": None,
        "expires_at": (now + retention()).isoformat(),
        "error": "",
        "filename": "",
        "storage_name": "",
        "key": "",
    }
    _save_job(job)
    ids = [job_id for job_id in (cache.get(_user_key(user.pk)) or []) if get_job(job_id)]
    cache.set(_user_key(user.pk), [job["id"], *ids][:20], timeout=_ttl_seconds())
    return job


def _page_params(job: dict[str, Any], page: int, total: int | None) -> dict[str, Any]:
    params: dict[str, Any] = {
        "export": 1, "graphs": 0, "page": page, "limit": PAGE_SIZE,
        "dateFrom": job["date_from"], "dateTo": job["date_to"],
    }
    if job.get("dynamic_filters"):
        params["dynamicFilters"] = json.dumps(job["dynamic_filters"])
    if total:
        # Mautic counts the whole query on every page unless told the total.
        params["totalResults"] = total
    return params


def collect_rows(job: dict[str, Any], client: MauticClient, *, on_progress=None) -> tuple[list[dict[str, Any]], list[list[str]]]:
    """The report's columns and every row, page by page."""
    columns: list[dict[str, Any]] = []
    rows: list[list[str]] = []
    total: int | None = None
    page = 1
    while True:
        data = client.get_report_data(job["report_id"], timeout=PAGE_TIMEOUT_SECONDS, **_page_params(job, page, total))
        if total is None:
            total = int(data.get("totalResults") or 0)
            if total > max_rows():
                raise ReportExportError(
                    f"The report has {total:,} rows for these dates. An export can hold at most {max_rows():,}; "
                    "choose a shorter date range or add filters.",
                    code="export_too_large",
                )
            columns = [column for column in data.get("columns") or [] if isinstance(column, dict)]
            if on_progress:
                on_progress(total=total, processed=0)
        page_rows = [row for row in data.get("rows") or [] if isinstance(row, dict)]
        rows.extend([_cell(row.get(column.get("alias"))) for column in columns] for row in page_rows)
        if on_progress:
            on_progress(total=total, processed=len(rows))
        if len(page_rows) < PAGE_SIZE or len(rows) >= total:
            return columns, rows
        page += 1


def run_export(job_id: str, *, client: MauticClient | None = None) -> dict[str, Any] | None:
    """Builds, encrypts and stores the file. Failures end in a failed job, never an exception."""
    job = _update_job(job_id, status=STATUS_RUNNING)
    if job is None:
        return None
    client = client or MauticClient()
    try:
        columns, rows = collect_rows(job, client, on_progress=lambda **progress: _update_job(job_id, **progress))
        if not columns:
            raise ReportExportError("This report has no table columns to export.", code="export_no_columns")
        headers = [{"label": str(column.get("label") or column.get("alias") or "")} for column in columns]
        content = (
            _write_xlsx(headers, rows, sheet_name="Report") if job["format"] == "xlsx" else _write_csv(headers, rows)
        )

        key = Fernet.generate_key()
        storage_name = default_storage.save(
            f"{STORAGE_PREFIX}/report-{job_id}-{secrets.token_hex(16)}.bin", ContentFile(Fernet(key).encrypt(content))
        )
        stamp = timezone.now().strftime("%Y%m%d-%H%M")
        slug = slugify(job.get("report_name") or "")[:60] or f"report-{job['report_id']}"
        return _finish(
            job_id,
            status=STATUS_DONE,
            rows=len(rows),
            processed=len(rows),
            storage_name=storage_name,
            key=key.decode("ascii"),
            filename=f"{slug}-{stamp}.{FORMATS[job['format']]['extension']}",
        )
    except ReportExportError as exc:
        return _finish(job_id, status=STATUS_FAILED, error=str(exc))
    except PermanentMauticError as exc:
        logger.warning("Report export %s was refused by Mautic", job_id, exc_info=True)
        message = str(exc)
        if "HTTP 403" in message:
            error = "Your Mautic user is not allowed to export reports."
        elif "HTTP 404" in message:
            error = "The report no longer exists in Mautic."
        else:
            error = "Mautic could not run the report. Check its filters and try again."
        return _finish(job_id, status=STATUS_FAILED, error=error)
    except TemporaryMauticError:
        logger.warning("Report export %s could not read Mautic", job_id, exc_info=True)
        return _finish(job_id, status=STATUS_FAILED, error="Mautic could not be read. Try the export again.")
    except Exception:  # noqa: BLE001 - a job must always finish with a status
        logger.exception("Report export %s failed", job_id)
        return _finish(job_id, status=STATUS_FAILED, error="The export failed. Try again.")


def _finish(job_id: str, **changes) -> dict[str, Any] | None:
    job = _update_job(job_id, finished_at=timezone.now().isoformat(), **changes)
    if job is not None:
        notify_owner(job)
    return job


def notify_owner(job: dict[str, Any]) -> None:
    """An ECP system notification, shown by the Marketing Hub bell. Never raises."""
    from friends.models import Notification

    done = job.get("status") == STATUS_DONE
    rows = int(job.get("rows") or 0)
    name = job.get("report_name") or "Report"
    try:
        Notification.objects.create(
            recipient_id=job["owner_id"],
            kind="system",
            title="Report export ready" if done else "Report export failed",
            description=(
                f"{name}: {rows:,} row{'' if rows == 1 else 's'} exported as {str(job.get('format')).upper()}. "
                "Download it within 24 hours."
                if done else f"{name}: {job.get('error') or 'The export failed. Try again.'}"
            ),
            data={
                "type": NOTIFICATION_TYPE,
                "job_id": job["id"],
                "status": job.get("status"),
                "filename": job.get("filename") or "",
                "rows": rows,
                "report_id": job.get("report_id"),
                "url": f"/admin/newsletter/reports/{job.get('report_id')}",
            },
        )
    except Exception:  # noqa: BLE001 - a lost notification must not fail the export
        logger.exception("Could not notify the owner of report export %s", job.get("id"))


STALE_QUEUED_SECONDS = 3 * 60
STALE_RUNNING_SECONDS = 35 * 60


def expire_if_stale(job: dict[str, Any], *, now=None) -> dict[str, Any]:
    from django.utils.dateparse import parse_datetime

    now = now or timezone.now()
    created = parse_datetime(str(job.get("created_at") or ""))
    if created is None:
        return job
    age = (now - created).total_seconds()
    if job.get("status") == STATUS_QUEUED and age > STALE_QUEUED_SECONDS:
        message = "The export did not start: the background workers may not be running. Try again."
    elif job.get("status") == STATUS_RUNNING and age > STALE_RUNNING_SECONDS:
        message = "The export was interrupted before it finished. Try again."
    else:
        return job
    return _finish(job["id"], status=STATUS_FAILED, error=message) or job


def read_file(job: dict[str, Any]) -> bytes:
    if job.get("status") != STATUS_DONE or not job.get("storage_name") or not job.get("key"):
        raise ReportExportError("This export is not ready.", code="export_not_ready", status_code=409)
    try:
        with default_storage.open(job["storage_name"], "rb") as handle:
            return Fernet(job["key"].encode("ascii")).decrypt(handle.read())
    except (FileNotFoundError, InvalidToken, OSError) as exc:
        raise ReportExportError("The export file is no longer available. Run the export again.",
                                code="export_file_gone", status_code=410) from exc


def delete_job(job: dict[str, Any]) -> None:
    if job.get("storage_name"):
        try:
            default_storage.delete(job["storage_name"])
        except OSError:
            logger.warning("Could not delete report export file for job %s", job.get("id"), exc_info=True)
    cache.delete(_job_key(job["id"]))
