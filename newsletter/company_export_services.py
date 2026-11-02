"""Marketing Hub company export (CSV or Excel), in the background.

Pages through Mautic's companies (optionally narrowed by the list's search) and
builds the file in a Celery task, as the contact and report exports do: the
file is encrypted before it is stored under the same private prefix (and so
purged by the same hourly task), its key lives only in the cached job for 24
hours, and downloads go through ECP for the admin who started the export only,
audited. Columns are every published company field in Mautic's order.

Jobs are kept in the cache (no model, no migration).
"""

from __future__ import annotations

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

from . import marketing_cache
from .company_import_services import company_fields
from .company_services import _flatten_company_fields
from .contact_export_services import FORMATS, STORAGE_PREFIX, _cell, _write_csv, _write_xlsx, retention
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError

logger = logging.getLogger(__name__)

CACHE_PREFIX = "marketing:company-export"
PAGE_SIZE = 200
PAGE_TIMEOUT_SECONDS = 60
NOTIFICATION_TYPE = "marketing_company_export"
SEARCH_MAX = 200
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"


class CompanyExportError(ValueError):
    def __init__(self, message: str, *, code: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def max_rows() -> int:
    return int(getattr(settings, "NEWSLETTER_COMPANY_EXPORT_MAX_ROWS", 100_000))


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
        raise CompanyExportError("Export not found. Exports are kept for 24 hours.", code="export_not_found", status_code=404)
    return expire_if_stale(job)


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    """What the admin may see: never the storage name or the key."""
    return {key: job.get(key) for key in ("id", "status", "format", "search", "total", "processed", "rows",
                                          "created_at", "finished_at", "expires_at", "error", "filename")}


def list_user_jobs(user) -> list[dict[str, Any]]:
    ids = cache.get(_user_key(user.pk)) or []
    jobs = [get_job(job_id) for job_id in ids]
    jobs = [expire_if_stale(job) for job in jobs if job and job.get("owner_id") == user.pk]
    return sorted(jobs, key=lambda job: job.get("created_at") or "", reverse=True)


def create_job(user, *, fmt: str, search: str) -> dict[str, Any]:
    if fmt not in FORMATS:
        raise CompanyExportError("Format must be csv or xlsx.", code="invalid_format")
    now = timezone.now()
    job = {
        "id": secrets.token_urlsafe(18),
        "owner_id": user.pk,
        "status": STATUS_QUEUED,
        "format": fmt,
        "search": str(search or "").strip()[:SEARCH_MAX],
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


def _companies(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = data.get("companies")
    if isinstance(rows, dict):
        rows = list(rows.values())
    return [row for row in rows or [] if isinstance(row, dict)]


def collect_rows(job: dict[str, Any], client: MauticClient, *, on_progress=None) -> tuple[list[str], list[list[str]]]:
    data = marketing_cache.fields(client, "company", limit=500)
    fields = company_fields(data.get("fields") if isinstance(data, dict) else [])
    labels = ["Company ID", *[field["label"] for field in fields], "Date added"]
    rows: list[list[str]] = []
    total: int | None = None
    start = 0
    while True:
        params: dict[str, Any] = {"start": start, "limit": PAGE_SIZE, "orderBy": "comp.id", "orderByDir": "ASC"}
        if job.get("search"):
            params["search"] = job["search"]
        page = client.list_companies(**params)
        if total is None:
            total = max(0, int(page.get("total") or 0))
            if total > max_rows():
                raise CompanyExportError(f"There are {total:,} companies. An export can hold at most {max_rows():,}; narrow the search.",
                                         code="export_too_large")
            if on_progress:
                on_progress(total=total, processed=0)
        batch = _companies(page)
        for company in batch:
            values = _flatten_company_fields(company)
            rows.append([_cell(company.get("id")), *[_cell(values.get(field["alias"])) for field in fields], _cell(company.get("dateAdded"))])
        if on_progress:
            on_progress(total=total, processed=len(rows))
        if len(batch) < PAGE_SIZE or start + len(batch) >= total:
            return labels, rows
        start += len(batch)


def run_export(job_id: str, *, client: MauticClient | None = None) -> dict[str, Any] | None:
    """Builds, encrypts and stores the file. Failures end in a failed job, never an exception."""
    job = _update_job(job_id, status=STATUS_RUNNING)
    if job is None:
        return None
    client = client or MauticClient()
    try:
        labels, rows = collect_rows(job, client, on_progress=lambda **progress: _update_job(job_id, **progress))
        headers = [{"label": label} for label in labels]
        content = _write_xlsx(headers, rows, sheet_name="Companies") if job["format"] == "xlsx" else _write_csv(headers, rows)
        key = Fernet.generate_key()
        storage_name = default_storage.save(
            f"{STORAGE_PREFIX}/companies-{job_id}-{secrets.token_hex(16)}.bin", ContentFile(Fernet(key).encrypt(content))
        )
        stamp = timezone.now().strftime("%Y%m%d-%H%M")
        return _finish(job_id, status=STATUS_DONE, rows=len(rows), processed=len(rows), storage_name=storage_name,
                       key=key.decode("ascii"), filename=f"companies-{stamp}.{FORMATS[job['format']]['extension']}")
    except CompanyExportError as exc:
        return _finish(job_id, status=STATUS_FAILED, error=str(exc))
    except PermanentMauticError:
        logger.warning("Company export %s was refused by Mautic", job_id, exc_info=True)
        return _finish(job_id, status=STATUS_FAILED, error="Mautic could not return the companies. Try again.")
    except TemporaryMauticError:
        logger.warning("Company export %s could not read Mautic", job_id, exc_info=True)
        return _finish(job_id, status=STATUS_FAILED, error="Mautic could not be read. Try the export again.")
    except Exception:  # noqa: BLE001 - a job must always finish with a status
        logger.exception("Company export %s failed", job_id)
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
    try:
        Notification.objects.create(
            recipient_id=job["owner_id"],
            kind="system",
            title="Company export ready" if done else "Company export failed",
            description=(
                f"{rows:,} compan{'y' if rows == 1 else 'ies'} exported as {str(job.get('format')).upper()}. Download it within 24 hours."
                if done else job.get("error") or "The export failed. Try again."
            ),
            data={"type": NOTIFICATION_TYPE, "job_id": job["id"], "status": job.get("status"), "filename": job.get("filename") or "",
                  "rows": rows, "url": "/admin/newsletter/companies"},
        )
    except Exception:  # noqa: BLE001 - a lost notification must not fail the export
        logger.exception("Could not notify the owner of company export %s", job.get("id"))


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
        raise CompanyExportError("This export is not ready.", code="export_not_ready", status_code=409)
    try:
        with default_storage.open(job["storage_name"], "rb") as handle:
            return Fernet(job["key"].encode("ascii")).decrypt(handle.read())
    except (FileNotFoundError, InvalidToken, OSError) as exc:
        raise CompanyExportError("The export file is no longer available. Run the export again.",
                                 code="export_file_gone", status_code=410) from exc


def delete_job(job: dict[str, Any]) -> None:
    if job.get("storage_name"):
        try:
            default_storage.delete(job["storage_name"])
        except OSError:
            logger.warning("Could not delete company export file for job %s", job.get("id"), exc_info=True)
    cache.delete(_job_key(job["id"]))
