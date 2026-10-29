"""Compile Marketing Hub visual-editor MJML into email HTML.

The visual editor renders its design to MJML in the browser; this module turns
that MJML into the HTML Mautic sends. It reuses the CMS compiler
(``cms.api.compile_mjml``: Python ``mrml``, falling back to the ``mjml`` CLI)
and adds the limits that matter for marketing email:

* bounded input size, and an ``<mjml>`` root;
* no ``<mj-include>``: the CLI fallback would read files from the server;
* no script URLs or ``<script>`` tags in the output;
* every Mautic token in the MJML (``{contactfield=firstname}``,
  ``{unsubscribe_url}`` ...) must come out unchanged, so personalization and
  unsubscribe links can never be lost silently.

Compilation never contacts Mautic, publishes, or sends anything.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import zlib
from contextlib import contextmanager
from dataclasses import dataclass

from django.db import connection, transaction
from rest_framework import serializers

from cms.api import compile_mjml

from .models import NewsletterEmailDesign

logger = logging.getLogger(__name__)

MAX_MJML_BYTES = 512 * 1024

# Mautic body tokens: {contactfield=alias}, {companyfield=alias}, {unsubscribe_url} ...
MAUTIC_TOKEN_RE = re.compile(r"\{[a-z][a-z0-9_]*(?:=[A-Za-z0-9_]+)?\}")
_MJML_ROOT_RE = re.compile(r"^\s*<mjml[\s>]", re.IGNORECASE)
_MJ_INCLUDE_RE = re.compile(r"<\s*mj-include\b", re.IGNORECASE)
_SCRIPT_URL_RE = re.compile(
    r"""\b(?:href|src)\s*=\s*["']?\s*(?:javascript|vbscript):""",
    re.IGNORECASE,
)
_SCRIPT_TAG_RE = re.compile(r"<\s*script\b", re.IGNORECASE)


class EmailDesignCompileError(ValueError):
    """The MJML cannot be turned into a safe marketing email."""


def _validation_message(exc: serializers.ValidationError) -> str:
    detail = exc.detail
    if isinstance(detail, dict):
        detail = next(iter(detail.values()), "")
    if isinstance(detail, (list, tuple)):
        detail = detail[0] if detail else ""
    return str(detail) or "MJML compilation failed."


def mautic_tokens(text: str) -> set[str]:
    return set(MAUTIC_TOKEN_RE.findall(text or ""))


def compile_marketing_mjml(mjml) -> dict:
    """Return ``{"html": ..., "tokens": [...]}`` or raise EmailDesignCompileError."""
    if not isinstance(mjml, str) or not mjml.strip():
        raise EmailDesignCompileError("MJML content is required.")
    if len(mjml.encode("utf-8")) > MAX_MJML_BYTES:
        raise EmailDesignCompileError(
            f"MJML content cannot exceed {MAX_MJML_BYTES // 1024} KB."
        )
    if not _MJML_ROOT_RE.match(mjml):
        raise EmailDesignCompileError("MJML content must start with an <mjml> element.")
    if _MJ_INCLUDE_RE.search(mjml):
        raise EmailDesignCompileError("<mj-include> is not allowed in marketing emails.")

    try:
        html = compile_mjml(mjml)
    except serializers.ValidationError as exc:
        raise EmailDesignCompileError(_validation_message(exc)) from exc

    if not isinstance(html, str) or not html.strip():
        raise EmailDesignCompileError("MJML compilation produced no HTML.")
    if _SCRIPT_URL_RE.search(html) or _SCRIPT_TAG_RE.search(html):
        raise EmailDesignCompileError("Scripts are not allowed in marketing emails.")

    html_tokens = mautic_tokens(html)
    lost = sorted(mautic_tokens(mjml) - html_tokens)
    if lost:
        raise EmailDesignCompileError(
            "Mautic tokens were changed during compilation: " + ", ".join(lost)
        )

    return {"html": html, "tokens": sorted(html_tokens)}


# --------------------------------------------------------------- designs --
#
# A design is the editor's own source, stored by ECP only (NewsletterEmailDesign).
# The frontend sends it as the envelope {"editor": "templatical", "version": 1,
# "content": {...}} together with the MJML it rendered; the server compiles that
# MJML itself, so the delivered HTML never depends on HTML supplied by the client.

DESIGN_EDITOR = "templatical"
DESIGN_VERSION = 1
MAX_DESIGN_BYTES = 1024 * 1024
MAX_DESIGN_BLOCKS = 500
MAX_DESIGN_DEPTH = 4
MAX_BLOCK_ID_LENGTH = 100
DESIGN_BLOCK_TYPES = frozenset(
    {
        "section",
        "title",
        "paragraph",
        "image",
        "button",
        "divider",
        "video",
        "social",
        "spacer",
        "html",
        "menu",
        "table",
        "countdown",
    }
)

DESIGN_STATUS_NONE = "none"
DESIGN_STATUS_IN_SYNC = "in_sync"
DESIGN_STATUS_STALE = "stale"
DESIGN_STATUS_INVALID = "invalid"


class EmailDesignValidationError(ValueError):
    """The submitted design cannot be stored or reopened."""


@dataclass(frozen=True)
class PreparedEmailDesign:
    """A validated design with the HTML compiled from its MJML."""

    design: dict
    mjml: str
    html: str


def html_fingerprint(html) -> str:
    return hashlib.sha256(str(html or "").encode("utf-8")).hexdigest()


def _validate_blocks(blocks, depth, counter):
    if not isinstance(blocks, list):
        raise EmailDesignValidationError("Design blocks must be a list.")
    if depth > MAX_DESIGN_DEPTH:
        raise EmailDesignValidationError("Design sections are nested too deeply.")
    for block in blocks:
        if not isinstance(block, dict):
            raise EmailDesignValidationError("Every design block must be an object.")
        block_id = block.get("id")
        if not isinstance(block_id, str) or not block_id or len(block_id) > MAX_BLOCK_ID_LENGTH:
            raise EmailDesignValidationError("Every design block needs a valid id.")
        block_type = block.get("type")
        if block_type not in DESIGN_BLOCK_TYPES:
            raise EmailDesignValidationError(f"Unsupported design block type: {block_type!r}.")
        counter[0] += 1
        if counter[0] > MAX_DESIGN_BLOCKS:
            raise EmailDesignValidationError(
                f"A design cannot contain more than {MAX_DESIGN_BLOCKS} blocks."
            )
        if block_type == "section":
            columns = block.get("children")
            if not isinstance(columns, list) or not 1 <= len(columns) <= 3:
                raise EmailDesignValidationError("A section must have one to three columns.")
            for column in columns:
                _validate_blocks(column, depth + 1, counter)


def validate_design(design) -> dict:
    """Return the design if it is a reopenable envelope, else raise.

    Never repairs or replaces content: an invalid design is refused so the
    caller can report it, not silently swapped for a starter layout.
    """
    if not isinstance(design, dict):
        raise EmailDesignValidationError("The visual design must be an object.")
    if design.get("editor") != DESIGN_EDITOR:
        raise EmailDesignValidationError("The visual design was made with an unsupported editor.")
    version = design.get("version")
    if isinstance(version, bool) or version != DESIGN_VERSION:
        raise EmailDesignValidationError("The visual design version is not supported.")
    content = design.get("content")
    if not isinstance(content, dict):
        raise EmailDesignValidationError("The visual design has no content.")
    settings_data = content.get("settings")
    if not isinstance(settings_data, dict):
        raise EmailDesignValidationError("The visual design has no settings.")
    width = settings_data.get("width")
    if isinstance(width, bool) or not isinstance(width, (int, float)) or not 200 <= width <= 1200:
        raise EmailDesignValidationError("The visual design width must be between 200 and 1200 pixels.")
    _validate_blocks(content.get("blocks"), 0, [0])
    if len(json.dumps(design, separators=(",", ":")).encode("utf-8")) > MAX_DESIGN_BYTES:
        raise EmailDesignValidationError(
            f"The visual design cannot exceed {MAX_DESIGN_BYTES // 1024} KB."
        )
    return design


def prepare_email_design(design, mjml) -> PreparedEmailDesign:
    """Validate a design and compile its MJML. Raises a ValueError subclass."""
    validate_design(design)
    compiled = compile_marketing_mjml(mjml)
    return PreparedEmailDesign(design=design, mjml=mjml, html=compiled["html"])


def design_state(design_row, current_html) -> dict:
    """How a stored design relates to the owner's current HTML.

    in_sync - the design produced exactly this HTML; safe to reopen visually.
    stale   - the HTML changed since (HTML mode, the Mautic UI, a partial
              save); the HTML is authoritative and the design is offered only
              as an explicit restore.
    invalid - the stored design can no longer be opened by this editor.
    none    - no visual design exists (legacy or HTML-only content).
    """
    fingerprint = html_fingerprint(current_html)
    if design_row is None:
        return {"status": DESIGN_STATUS_NONE, "design": None, "html_fingerprint": fingerprint, "updated_at": None}
    try:
        validate_design(design_row.design_json)
    except EmailDesignValidationError:
        return {
            "status": DESIGN_STATUS_INVALID,
            "design": None,
            "html_fingerprint": fingerprint,
            "updated_at": design_row.updated_at,
        }
    status = DESIGN_STATUS_IN_SYNC if design_row.html_sha256 == fingerprint else DESIGN_STATUS_STALE
    return {
        "status": status,
        "design": design_row.design_json,
        "html_fingerprint": fingerprint,
        "updated_at": design_row.updated_at,
    }


def template_design_state(mautic_email_id, current_html) -> dict:
    row = NewsletterEmailDesign.objects.filter(mautic_email_id=str(mautic_email_id)).first()
    return design_state(row, current_html)


def save_template_design(mautic_email_id, prepared: PreparedEmailDesign, stored_html, *, user):
    """Store the design for a Mautic Template whose stored HTML is ``stored_html``.

    ``stored_html`` must be the HTML read back from Mautic: Mautic normalizes
    what it receives, so the submitted HTML is not byte-identical to it.
    """
    with transaction.atomic():
        row = (
            NewsletterEmailDesign.objects.select_for_update()
            .filter(mautic_email_id=str(mautic_email_id))
            .first()
        )
        if row is None:
            row = NewsletterEmailDesign(mautic_email_id=str(mautic_email_id), created_by=user)
        row.design_json = prepared.design
        row.mjml = prepared.mjml
        row.html_sha256 = html_fingerprint(stored_html)
        row.updated_by = user
        row.save()
    return row


def copy_template_design(source_email_id, source_html, target_email_id, target_html, *, user):
    """Give a duplicated Template its own copy of the source's design.

    Copied only when the source design is valid and in sync with the source
    HTML; otherwise the duplicate is an HTML-only Template. Returns the new row
    or None.
    """
    source = NewsletterEmailDesign.objects.filter(mautic_email_id=str(source_email_id)).first()
    if design_state(source, source_html)["status"] != DESIGN_STATUS_IN_SYNC:
        return None
    return NewsletterEmailDesign.objects.create(
        mautic_email_id=str(target_email_id),
        design_json=source.design_json,
        mjml=source.mjml,
        html_sha256=html_fingerprint(target_html),
        created_by=user,
        updated_by=user,
    )


def delete_template_design(mautic_email_id) -> None:
    """Remove a deleted Template's design. Never raises: an orphan is harmless."""
    try:
        NewsletterEmailDesign.objects.filter(mautic_email_id=str(mautic_email_id)).delete()
    except Exception:  # noqa: BLE001 - the provider delete already succeeded
        logger.warning(
            "Could not delete the visual design of deleted Mautic template id=%s",
            mautic_email_id,
            exc_info=True,
        )


def save_campaign_design(campaign, prepared: PreparedEmailDesign, *, user):
    """Store a Broadcast's design. Call inside the transaction holding the campaign lock."""
    row = NewsletterEmailDesign.objects.select_for_update().filter(campaign=campaign).first()
    if row is None:
        row = NewsletterEmailDesign(campaign=campaign, created_by=user)
    row.design_json = prepared.design
    row.mjml = prepared.mjml
    row.html_sha256 = html_fingerprint(campaign.html_content)
    row.updated_by = user
    row.save()
    return row


def campaign_design_row(campaign):
    try:
        return campaign.email_design
    except NewsletterEmailDesign.DoesNotExist:
        return None


def copy_campaign_design(source, target, *, user):
    """Give a duplicated Broadcast its own copy of an in-sync source design."""
    row = campaign_design_row(source)
    if design_state(row, source.html_content)["status"] != DESIGN_STATUS_IN_SYNC:
        return None
    return NewsletterEmailDesign.objects.create(
        campaign=target,
        design_json=row.design_json,
        mjml=row.mjml,
        html_sha256=html_fingerprint(target.html_content),
        created_by=user,
        updated_by=user,
    )


class TemplateSaveInProgress(Exception):
    """Another ECP request is already saving this Template."""


_TEMPLATE_LOCK_NAMESPACE = 42_017


def _template_lock_key(template_id) -> int:
    value = str(template_id or "").strip()
    if value.isdigit() and int(value) < 2**31:
        return int(value)
    return zlib.crc32(value.encode("utf-8")) & 0x7FFFFFFF


@contextmanager
def template_save_lock(template_id):
    """Serialize ECP saves of one Mautic Template across workers.

    A session-level PostgreSQL advisory lock, deliberately not a transaction:
    the Mautic call and its identity audit rows must never be rolled back with
    a local transaction. Not acquiring it means another save is running.
    """
    if connection.vendor != "postgresql":
        yield
        return
    key = _template_lock_key(template_id)
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s, %s)", [_TEMPLATE_LOCK_NAMESPACE, key])
        acquired = cursor.fetchone()[0]
    if not acquired:
        raise TemplateSaveInProgress
    try:
        yield
    finally:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock(%s, %s)", [_TEMPLATE_LOCK_NAMESPACE, key])


def copy_campaign_design_to_email(campaign, target_email_id, target_html, *, user):
    """Give a Broadcast's A/B variant or translation its own copy of the
    Broadcast's in-sync design, keyed by the copy's Mautic email id (like a
    Template). Returns the new row or None (the copy is then HTML-only)."""
    row = campaign_design_row(campaign)
    if design_state(row, campaign.html_content)["status"] != DESIGN_STATUS_IN_SYNC:
        return None
    return NewsletterEmailDesign.objects.update_or_create(
        mautic_email_id=str(target_email_id),
        defaults={
            "design_json": row.design_json,
            "mjml": row.mjml,
            "html_sha256": html_fingerprint(target_html),
            "created_by": user,
            "updated_by": user,
        },
    )[0]
