"""Marketing Hub contact export (CSV or Excel).

Mautic has no export API, so ECP pages through the contact list (keyset by
contact id, so contacts added or removed mid-export never shift the pages) and
builds the file in a Celery task. A job is either the list's current filter
(search + stage, exactly as the Contacts page applies them) or the ticked
contacts.

The file is personal data. The storage bucket serves objects publicly by URL,
so the file is encrypted (Fernet) before it is stored, under a random name;
its key lives only in the job record in the shared cache and expires with it
after 24 hours. Downloads go through ECP, only for the admin who started the
export, and are audited. An hourly task deletes stored files older than the
retention period, so nothing outlives it even when the cache is lost.

Jobs are kept in the cache (no model, no migration).
"""

from __future__ import annotations

import csv
import io
import logging
import re
import secrets
from datetime import timedelta
from typing import Any, Iterable

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.utils import timezone

from . import marketing_cache
from .contact_services import (
    _contact_field,
    _contact_stage,
    _contacts_from_response,
    _stage_contact_filter_params,
    contact_filter_params,
)
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .models import MauticContactMapping, NewsletterSubscription

logger = logging.getLogger(__name__)

FORMATS = {
    "csv": {"extension": "csv", "content_type": "text/csv; charset=utf-8"},
    "xlsx": {
        "extension": "xlsx",
        "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    },
}
STORAGE_PREFIX = "private/marketing-exports"
CACHE_PREFIX = "marketing:contact-export"
PAGE_SIZE = 200
SELECTED_MAX = 1000
DNC_REASONS = {1: "Unsubscribed", 2: "Bounced", 3: "Manual"}
# Spreadsheet apps run cells that start with these as formulas.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
# Characters XLSX (XML) cannot hold.
_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"


class ContactExportError(ValueError):
    def __init__(self, message: str, *, code: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def retention() -> timedelta:
    return timedelta(hours=int(getattr(settings, "NEWSLETTER_CONTACT_EXPORT_RETENTION_HOURS", 24)))


def max_rows() -> int:
    return int(getattr(settings, "NEWSLETTER_CONTACT_EXPORT_MAX_ROWS", 100_000))


def _job_key(job_id: str) -> str:
    return f"{CACHE_PREFIX}:{job_id}"


def _user_key(user_id) -> str:
    return f"{CACHE_PREFIX}:user:{user_id}"


def _ttl_seconds() -> int:
    return int(retention().total_seconds())


# Jobs ----------------------------------------------------------------------------


def _save_job(job: dict[str, Any]) -> None:
    cache.set(_job_key(job["id"]), job, timeout=_ttl_seconds())


def get_job(job_id: str) -> dict[str, Any] | None:
    if not _JOB_ID_RE.match(str(job_id or "")):
        return None
    job = cache.get(_job_key(job_id))
    return job if isinstance(job, dict) else None


def get_owned_job(job_id: str, user) -> dict[str, Any]:
    job = get_job(job_id)
    # Someone else's export is reported exactly like a missing one.
    if job is None or job.get("owner_id") != getattr(user, "pk", None):
        raise ContactExportError("Export not found. Exports are kept for 24 hours.", code="export_not_found", status_code=404)
    return expire_if_stale(job)


def _update_job(job_id: str, **changes) -> dict[str, Any] | None:
    job = get_job(job_id)
    if job is None:
        return None
    job.update(changes)
    _save_job(job)
    return job


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    """What the admin may see: never the storage name or the key."""
    return {
        key: job.get(key)
        for key in ("id", "status", "format", "scope", "filters", "total", "processed", "rows",
                    "created_at", "finished_at", "expires_at", "error", "filename")
    }


def list_user_jobs(user) -> list[dict[str, Any]]:
    ids = cache.get(_user_key(user.pk)) or []
    jobs = [get_job(job_id) for job_id in ids]
    jobs = [expire_if_stale(job) for job in jobs if job and job.get("owner_id") == user.pk]
    return sorted(jobs, key=lambda job: job.get("created_at") or "", reverse=True)


def parse_request(data) -> dict[str, Any]:
    if not hasattr(data, "get"):
        raise ContactExportError("Send the export options as an object.", code="invalid_payload")
    fmt = str(data.get("format") or "csv").strip().lower()
    if fmt not in FORMATS:
        raise ContactExportError("Format must be csv or xlsx.", code="invalid_format")

    raw_ids = data.get("contact_ids")
    if raw_ids not in (None, "", []):
        if not isinstance(raw_ids, list):
            raise ContactExportError("contact_ids must be a list of Mautic contact IDs.", code="invalid_contact_ids")
        ids = []
        for value in raw_ids:
            text = str(value).strip()
            if isinstance(value, bool) or not text.isdigit() or int(text) <= 0:
                raise ContactExportError("contact_ids must be a list of Mautic contact IDs.", code="invalid_contact_ids")
            ids.append(str(int(text)))
        ids = list(dict.fromkeys(ids))
        if len(ids) > SELECTED_MAX:
            raise ContactExportError(f"Select at most {SELECTED_MAX} contacts, or export the filtered list instead.", code="too_many_selected")
        return {"format": fmt, "scope": "selected", "contact_ids": ids, "filters": {"selected": len(ids)}}

    search = str(data.get("search") or "").strip()[:500]
    stage_id = str(data.get("stage_id") or "").strip()
    owner_id = str(data.get("owner_id") or "").strip()
    try:
        _stage_contact_filter_params(stage_id)
    except ValueError as exc:
        raise ContactExportError(str(exc), code="invalid_stage") from exc
    try:
        contact_filter_params(owner_id=owner_id)
    except ValueError as exc:
        raise ContactExportError(str(exc), code="invalid_owner") from exc
    filters = {"search": search, "stage_id": stage_id}
    if owner_id:
        filters["owner_id"] = owner_id
    return {"format": fmt, "scope": "filter", "contact_ids": [], "filters": filters}


def create_job(user, options: dict[str, Any]) -> dict[str, Any]:
    now = timezone.now()
    job = {
        "id": secrets.token_urlsafe(18),
        "owner_id": user.pk,
        "status": STATUS_QUEUED,
        "format": options["format"],
        "scope": options["scope"],
        "filters": options["filters"],
        "contact_ids": options["contact_ids"],
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


# Rows ----------------------------------------------------------------------------


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        value = " | ".join(str(item) for item in value if item not in (None, ""))
    text = _ILLEGAL_XML.sub("", str(value))
    return f"'{text}" if text.startswith(_FORMULA_START) else text


def _contact_fields() -> list[dict[str, Any]]:
    """Mautic's contact (lead) fields in Mautic's own order; company fields excluded."""
    data = marketing_cache.contact_fields(MauticClient())
    source = data.get("fields") if isinstance(data.get("fields"), (dict, list)) else data
    rows = list(source.values()) if isinstance(source, dict) else list(source or [])
    fields = [
        row for row in rows
        if isinstance(row, dict) and str(row.get("alias") or "").strip() and str(row.get("object") or "lead") == "lead"
        and row.get("isPublished", True) not in (False, 0, "0")
    ]

    def order(row):
        try:
            return int(row.get("order") or 0), int(row.get("id") or 0)
        except (TypeError, ValueError):
            return 0, 0

    return sorted(fields, key=order)


def _field_label(field: dict[str, Any]) -> str:
    label = str(field.get("label") or "").strip()
    # Some core labels come back as untranslated keys (mautic.lead.field.linkedin).
    if not label or label.startswith("mautic."):
        label = str(field["alias"]).replace("_", " ").title()
    return label


# ECP extras, each skipped when a Mautic field already exports the same value.
_EXTRAS = (
    ("points", "Points", "points"), ("stage", "Stage", None), ("tags", "Tags", None),
    ("dnc_email", "Email Do Not Contact", None), ("owner", "Owner", None),
    ("last_active", "Last Active", "last_active"), ("date_added", "Date Added", None),
    ("date_identified", "Date Identified", None), ("ecp_user", "IMAA Connect Account", None),
    ("lists", "Subscription Lists", None),
)


def export_columns() -> list[dict[str, str]]:
    """Mautic ID, every contact field in Mautic's order, then ECP extras."""
    fields = _contact_fields()
    aliases = {str(field["alias"]) for field in fields}
    columns = [{"key": "id", "label": "Mautic ID"}]
    seen = {"Mautic ID"}
    for field in fields:
        label = _field_label(field)
        if label in seen:
            label = f"{label} ({field['alias']})"
        seen.add(label)
        columns.append({"key": f"field:{field['alias']}", "label": label})
    for key, label, covered_by in _EXTRAS:
        if covered_by and covered_by in aliases:
            continue
        columns.append({"key": key, "label": label if label not in seen else f"{label} (ECP)"})
    return columns


def _email_dnc(contact: dict[str, Any]) -> str:
    reasons = []
    for entry in contact.get("doNotContact") or []:
        if isinstance(entry, dict) and str(entry.get("channel") or "email") == "email":
            try:
                reasons.append(DNC_REASONS.get(int(entry.get("reason")), "Yes"))
            except (TypeError, ValueError):
                reasons.append("Yes")
    return ", ".join(dict.fromkeys(reasons))


def _owner(contact: dict[str, Any]) -> str:
    owner = contact.get("owner")
    if isinstance(owner, dict):
        name = " ".join(str(owner.get(part) or "").strip() for part in ("firstName", "lastName")).strip()
        return name or str(owner.get("username") or "")
    return ""


def _ecp_extras(contacts: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    ids = [str(contact.get("id")) for contact in contacts if contact.get("id") is not None]
    mappings = {
        str(mapping.mautic_contact_id): mapping
        for mapping in MauticContactMapping.objects.filter(mautic_contact_id__in=ids).select_related("user")
    }
    lists: dict[int, list[str]] = {}
    for subscription in (
        NewsletterSubscription.objects.filter(user_id__in=[m.user_id for m in mappings.values()], is_subscribed=True)
        .select_related("category")
        .order_by("category__name")
    ):
        lists.setdefault(subscription.user_id, []).append(subscription.category.name)
    return {
        contact_id: {"ecp_user": "Yes", "lists": "; ".join(lists.get(mapping.user_id, []))}
        for contact_id, mapping in mappings.items()
    }


def contact_row(contact: dict[str, Any], columns: list[dict[str, str]], extras: dict[str, str]) -> list[str]:
    stage = _contact_stage(contact) or {}
    tags = [str(tag.get("tag") or "") for tag in contact.get("tags") or [] if isinstance(tag, dict)]
    values = {
        "id": contact.get("id"),
        "points": contact.get("points"),
        "stage": stage.get("name") if isinstance(stage, dict) else "",
        "tags": tags,
        "dnc_email": _email_dnc(contact),
        "owner": _owner(contact),
        "last_active": contact.get("lastActive"),
        "date_added": contact.get("dateAdded"),
        "date_identified": contact.get("dateIdentified"),
        "ecp_user": extras.get("ecp_user", "No"),
        "lists": extras.get("lists", ""),
    }
    row = []
    for column in columns:
        key = column["key"]
        value = _contact_field(contact, key[6:]) if key.startswith("field:") else values.get(key)
        row.append(_cell(value))
    return row


def iter_contacts(job: dict[str, Any], client: MauticClient, *, on_total=None) -> Iterable[list[dict[str, Any]]]:
    """Yields pages of Mautic contacts for the job, in contact-id order."""
    if job["scope"] == "selected":
        ids = job["contact_ids"]
        if on_total:
            on_total(len(ids))
        for start in range(0, len(ids), PAGE_SIZE):
            chunk = ids[start:start + PAGE_SIZE]
            data = client.list_contacts(search="ids:" + ",".join(chunk), limit=len(chunk), orderBy="id", orderByDir="ASC")
            yield _contacts_from_response(data)
        return

    filters = job["filters"]
    base: dict[str, Any] = {"limit": PAGE_SIZE, "orderBy": "id", "orderByDir": "ASC"}
    if filters.get("search"):
        base["search"] = filters["search"]
    base.update(contact_filter_params(stage_id=filters.get("stage_id"), owner_id=filters.get("owner_id")))
    cursor_index = sum(1 for key in base if key.endswith("][col]"))
    last_id = 0
    first = True
    while True:
        params = dict(base)
        if last_id:
            params.update({
                f"where[{cursor_index}][col]": "id",
                f"where[{cursor_index}][expr]": "gt",
                f"where[{cursor_index}][val]": last_id,
            })
        data = client.list_contacts(**params)
        if first:
            first = False
            total = int(data.get("total") or 0)
            if total > max_rows():
                raise ContactExportError(
                    f"{total:,} contacts match. An export can hold at most {max_rows():,}; narrow the search or stage filter.",
                    code="export_too_large",
                )
            if on_total:
                on_total(total)
        contacts = _contacts_from_response(data)
        if not contacts:
            return
        yield contacts
        last_id = max(int(contact.get("id") or 0) for contact in contacts)
        if len(contacts) < PAGE_SIZE:
            return


# Files ---------------------------------------------------------------------------


def _write_csv(columns, rows) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([column["label"] for column in columns])
    writer.writerows(rows)
    # The BOM makes Excel read UTF-8 correctly.
    return buffer.getvalue().encode("utf-8-sig")


def _write_xlsx(columns, rows) -> bytes:
    from openpyxl import Workbook

    workbook = Workbook(write_only=True)
    sheet = workbook.create_sheet("Contacts")
    sheet.append([column["label"] for column in columns])
    for row in rows:
        sheet.append(row)
    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def run_export(job_id: str, *, client: MauticClient | None = None) -> dict[str, Any] | None:
    """Builds, encrypts and stores the file. Failures end in a failed job, never an exception."""
    job = _update_job(job_id, status=STATUS_RUNNING)
    if job is None:
        return None
    client = client or MauticClient()
    try:
        columns = export_columns()
        rows: list[list[str]] = []
        for contacts in iter_contacts(job, client, on_total=lambda total: _update_job(job_id, total=total)):
            extras = _ecp_extras(contacts)
            rows.extend(contact_row(contact, columns, extras.get(str(contact.get("id")), {})) for contact in contacts)
            _update_job(job_id, processed=len(rows))
        content = _write_xlsx(columns, rows) if job["format"] == "xlsx" else _write_csv(columns, rows)

        key = Fernet.generate_key()
        stamp = timezone.now().strftime("%Y%m%d-%H%M")
        storage_name = default_storage.save(
            f"{STORAGE_PREFIX}/{job_id}-{secrets.token_hex(16)}.bin", ContentFile(Fernet(key).encrypt(content))
        )
        return _finish(
            job_id,
            status=STATUS_DONE,
            rows=len(rows),
            processed=len(rows),
            storage_name=storage_name,
            key=key.decode("ascii"),
            filename=f"contacts-{stamp}.{FORMATS[job['format']]['extension']}",
        )
    except ContactExportError as exc:
        return _finish(job_id, status=STATUS_FAILED, error=str(exc))
    except (TemporaryMauticError, PermanentMauticError):
        logger.warning("Contact export %s could not read Mautic", job_id, exc_info=True)
        return _finish(job_id, status=STATUS_FAILED, error="Mautic could not be read. Try the export again.")
    except Exception:  # noqa: BLE001 - a job must always finish with a status
        logger.exception("Contact export %s failed", job_id)
        return _finish(job_id, status=STATUS_FAILED, error="The export failed. Try again.")


NOTIFICATION_TYPE = "marketing_contact_export"


def _finish(job_id: str, **changes) -> dict[str, Any] | None:
    """Ends a job (done or failed) and tells its owner in the Marketing Hub."""
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
            title="Contact export ready" if done else "Contact export failed",
            description=(
                f"{rows:,} contact{'' if rows == 1 else 's'} exported as {str(job.get('format')).upper()}. "
                "Download it within 24 hours."
                if done else (job.get("error") or "The export failed. Try again.")
            ),
            data={
                "type": NOTIFICATION_TYPE,
                "job_id": job["id"],
                "status": job.get("status"),
                "filename": job.get("filename") or "",
                "rows": rows,
                "url": "/admin/newsletter/contacts",
            },
        )
    except Exception:  # noqa: BLE001 - a lost notification must not fail the export
        logger.exception("Could not notify the owner of contact export %s", job.get("id"))


# A queued job no worker picked up, or a running one past the task's hard limit.
STALE_QUEUED = timedelta(minutes=3)
STALE_RUNNING = timedelta(minutes=35)


def expire_if_stale(job: dict[str, Any], *, now=None) -> dict[str, Any]:
    from django.utils.dateparse import parse_datetime

    now = now or timezone.now()
    created = parse_datetime(str(job.get("created_at") or ""))
    if created is None:
        return job
    if job.get("status") == STATUS_QUEUED and now - created > STALE_QUEUED:
        message = "The export did not start: the background workers may not be running. Try again."
    elif job.get("status") == STATUS_RUNNING and now - created > STALE_RUNNING:
        message = "The export was interrupted before it finished. Try again."
    else:
        return job
    return _finish(job["id"], status=STATUS_FAILED, error=message) or job


def read_file(job: dict[str, Any]) -> bytes:
    if job.get("status") != STATUS_DONE or not job.get("storage_name") or not job.get("key"):
        raise ContactExportError("This export is not ready.", code="export_not_ready", status_code=409)
    try:
        with default_storage.open(job["storage_name"], "rb") as handle:
            return Fernet(job["key"].encode("ascii")).decrypt(handle.read())
    except (FileNotFoundError, InvalidToken, OSError) as exc:
        raise ContactExportError("The export file is no longer available. Run the export again.",
                                 code="export_file_gone", status_code=410) from exc


def delete_job(job: dict[str, Any]) -> None:
    if job.get("storage_name"):
        try:
            default_storage.delete(job["storage_name"])
        except OSError:
            logger.warning("Could not delete export file for job %s", job.get("id"), exc_info=True)
    cache.delete(_job_key(job["id"]))


def purge_expired_files(*, now=None) -> int:
    """Deletes stored export files older than the retention period."""
    cutoff = (now or timezone.now()) - retention()
    try:
        _, files = default_storage.listdir(STORAGE_PREFIX)
    except (FileNotFoundError, OSError):
        return 0
    deleted = 0
    for name in files:
        path = f"{STORAGE_PREFIX}/{name}"
        try:
            if default_storage.get_modified_time(path) < cutoff:
                default_storage.delete(path)
                deleted += 1
        except (FileNotFoundError, OSError, NotImplementedError):
            logger.warning("Could not check export file %s", path, exc_info=True)
    return deleted
