"""Marketing Hub Landing Pages: native Mautic landing pages (LP1).

Mautic owns pages and serves them from its public address (site_url/alias);
ECP keeps no page records. Reads use the service account, like Forms. Every
write goes through the ECP bridge as the acting admin's own Mautic user and
fails closed when that identity is unavailable.

LP1 edits a page's HTML directly. Policy:

* Head/footer script fields are never offered: the native API strips their
  script tags and never returns them, so they cannot round-trip.
* Page HTML that runs code (see page_html_policy) may only be saved by
  superusers, because pages share an origin with the Mautic admin.
* Preference-center pages decide unsubscribe behaviour and stay read-only.
* Delete is refused while Campaigns or preference-center Emails name the page,
  or while it has variants or translations. (Segments cannot name a page: the
  page_id segment filter is a yes/no "visited any landing page" flag.)
* Unpublished pages answer 403 Forbidden, or their redirect when one is set.
"""

from __future__ import annotations

import math
import re
from datetime import timedelta, timezone as dt_timezone
from typing import Any
from urllib.parse import quote, urlsplit

from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import marketing_cache
from .form_views import _public_base_url as mautic_public_base_url
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.exceptions import MauticIdentityConfigurationError, MauticRequestNotSentError
from .mautic.operations import (
    PAGE_CREATE,
    PAGE_DELETE,
    PAGE_DUPLICATE,
    PAGE_TRANSLATION_CREATE,
    PAGE_UPDATE,
    PAGE_VARIANT_CREATE,
    PAGE_VARIANT_UPDATE,
    PAGE_VARIANT_WINNER,
)
from .mautic_identity_execution import run_interactive_mutation
from .page_html_policy import find_active_content

TITLE_MAX_LENGTH = 191
ALIAS_MAX_LENGTH = 191
META_DESCRIPTION_MAX_LENGTH = 255
REDIRECT_URL_MAX_LENGTH = 2048
# Well inside Django's default request-body limit.
HTML_MAX_LENGTH = 1_000_000
USAGE_TIMEOUT = 10

EDITABLE_SETTINGS = (
    "title",
    "alias",
    "customHtml",
    "metaDescription",
    "noIndex",
    "redirectType",
    "redirectUrl",
    "category",
    "language",
)
# Refused by name with a reason, so a caller learns why rather than guessing.
REFUSED_SETTINGS = {
    "headScript": "Head and footer scripts cannot be saved through the Mautic API. Superusers can add scripts to the page HTML.",
    "footerScript": "Head and footer scripts cannot be saved through the Mautic API. Superusers can add scripts to the page HTML.",
    "isPreferenceCenter": "Preference-center pages are managed in Mautic.",
    "isPublished": "Use Publish or Unpublish to change publication.",
}

REDIRECT_TYPES = {"301", "302", "303", "307", "308"}
STATUS_FILTERS = {"published": "is:published", "unpublished": "is:unpublished"}
SORTS = {"newest": ("id", "DESC"), "title": ("title", "ASC"), "modified": ("dateModified", "DESC")}

_ALIAS_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_LANGUAGE_RE = re.compile(r"^[a-z]{2,3}(?:_[A-Z]{2})?$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# First path segments Mautic serves itself: a page alias there would be shadowed.
RESERVED_ALIASES = frozenset(
    {
        "api", "app", "asset", "dwc", "ecp", "email", "focus", "form", "index", "installer", "login", "logout",
        "mautic", "media", "mtc", "notification", "oauth", "oauth2", "p", "page", "passwordreset", "plugins",
        "r", "redirect", "s", "saml", "themes",
    }
)


class PagePolicyError(ValueError):
    def __init__(self, message: str, *, code: str, field: str = "", status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.field = field
        self.status_code = status_code


def _error(message: str, *, code: str, http_status: int, field: str = "", **extra) -> Response:
    body: dict[str, Any] = {"detail": message, "code": code}
    if field:
        body["errors"] = {field: message}
    body.update(extra)
    return Response(body, status=http_status)


def _policy_error_response(exc: PagePolicyError) -> Response:
    return _error(str(exc), code=exc.code, http_status=exc.status_code, field=exc.field)


def _provider_message(exc) -> str:
    """The provider's own reason, without our 'request failed (HTTP n):' prefix."""
    message = str(exc)
    return message.split(": ", 1)[1] if ": " in message else message


def _provider_error_response(exc) -> Response:
    message = str(exc)
    if isinstance(exc, MauticRequestNotSentError):
        return _error(
            "Mautic could not be reached; nothing was changed. Try again.",
            code="mautic_unavailable",
            http_status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if isinstance(exc, PermanentMauticError):
        if "HTTP 404" in message:
            return _error("Landing page not found in Mautic.", code="page_not_found", http_status=status.HTTP_404_NOT_FOUND)
        if "HTTP 409" in message:
            return _error(_provider_message(exc), code="page_conflict", http_status=status.HTTP_409_CONFLICT)
        if any(f"HTTP {code}" in message for code in (400, 422)):
            return _error(_provider_message(exc), code="mautic_validation_failed", http_status=status.HTTP_400_BAD_REQUEST)
    return _error(
        "Mautic did not complete the landing page request.",
        code="mautic_error",
        http_status=status.HTTP_502_BAD_GATEWAY,
    )


# Normalisation -----------------------------------------------------------------


def _provider_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _collection(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = list(value.values())
    return [item for item in value or [] if isinstance(item, dict)] if isinstance(value, list) else []


def _related_id(value) -> str | None:
    if isinstance(value, dict):
        value = value.get("id")
    text = str(value or "").strip()
    return text or None


def public_page_url(alias: str, base: str | None, *, language: str = "") -> str | None:
    if not base or not alias:
        return None
    prefix = f"{quote(language, safe='')}/" if language else ""
    return f"{base}/{prefix}{quote(alias, safe='')}"


def page_role(page: dict[str, Any]) -> str:
    """main, variant (A/B) or translation."""
    if _related_id(page.get("variantParent")):
        return "variant"
    if _related_id(page.get("translationParent")):
        return "translation"
    return "main"


def family_parent(page: dict[str, Any]) -> dict[str, Any] | None:
    parent = page.get("variantParent") or page.get("translationParent")
    if not isinstance(parent, dict) or parent.get("id") is None:
        return None
    return {"id": str(parent.get("id")), "title": str(parent.get("title") or ""), "alias": str(parent.get("alias") or "")}


def _public_url_for(page: dict[str, Any], base: str | None) -> str | None:
    """The address visitors use. Mautic serves a translation at
    /{language}/{alias}; a variant is only reachable through its main page."""
    role = page_role(page)
    if role == "translation":
        return public_page_url(str(page.get("alias") or ""), base, language=str(page.get("language") or ""))
    if role == "variant":
        return public_page_url((family_parent(page) or {}).get("alias", ""), base)
    return public_page_url(str(page.get("alias") or ""), base)


def normalize_page_summary(page: dict[str, Any], *, base: str | None) -> dict[str, Any]:
    category = page.get("category")
    alias = str(page.get("alias") or "")
    return {
        "id": str(page.get("id")) if page.get("id") is not None else None,
        "title": str(page.get("title") or "").strip(),
        "alias": alias,
        "publicUrl": _public_url_for(page, base),
        "role": page_role(page),
        "familyParent": family_parent(page),
        "isPublished": _provider_bool(page.get("isPublished", False)),
        "isPreferenceCenter": _provider_bool(page.get("isPreferenceCenter", False)),
        "language": str(page.get("language") or ""),
        "category": (
            {"id": str(category.get("id") or ""), "title": str(category.get("title") or "")}
            if isinstance(category, dict) else None
        ),
        "hits": int(page.get("hits") or 0),
        "uniqueHits": int(page.get("uniqueHits") or 0),
        "variantParentId": _related_id(page.get("variantParent")),
        "translationParentId": _related_id(page.get("translationParent")),
        "dateAdded": page.get("dateAdded"),
        "dateModified": page.get("dateModified"),
        "createdBy": str(page.get("createdByUser") or "").strip(),
        "modifiedBy": str(page.get("modifiedByUser") or "").strip(),
    }


def publish_blockers(page: dict[str, Any]) -> list[str]:
    blockers = []
    if _provider_bool(page.get("isPreferenceCenter")):
        blockers.append("Preference-center pages are managed in Mautic.")
    if not str(page.get("customHtml") or "").strip():
        blockers.append("The page has no content yet. Add its HTML first.")
    return blockers


def normalize_page_detail(page: dict[str, Any], *, base: str | None, user) -> dict[str, Any]:
    html = str(page.get("customHtml") or "")
    active = find_active_content(html)
    preference_center = _provider_bool(page.get("isPreferenceCenter", False))
    detail = normalize_page_summary(page, base=base)
    detail.update(
        {
            "customHtml": html,
            "template": str(page.get("template") or ""),
            "metaDescription": str(page.get("metaDescription") or ""),
            "noIndex": _provider_bool(page.get("noIndex", False)),
            "redirectType": str(page.get("redirectType") or ""),
            "redirectUrl": str(page.get("redirectUrl") or ""),
            "variantChildrenCount": len(_collection(page.get("variantChildren"))),
            "translationChildrenCount": len(_collection(page.get("translationChildren"))),
            "translations": [
                {
                    "id": str(child.get("id")),
                    "title": str(child.get("title") or ""),
                    "language": str(child.get("language") or ""),
                    "isPublished": _provider_bool(child.get("isPublished", False)),
                    "publicUrl": public_page_url(str(child.get("alias") or ""), base, language=str(child.get("language") or "")),
                }
                for child in _collection(page.get("translationChildren"))
            ],
            "variantSettings": (
                {
                    "weight": int((page.get("variantSettings") or {}).get("weight") or 0),
                    "winnerCriteria": str((page.get("variantSettings") or {}).get("winnerCriteria") or ""),
                }
                if page_role(page) == "variant" and isinstance(page.get("variantSettings"), dict) else None
            ),
            "activeContent": active,
            # Only superusers may change HTML that runs code (LP1 policy).
            "htmlLocked": bool(active) and not getattr(user, "is_superuser", False),
            "editable": not preference_center,
            "publishBlockers": publish_blockers(page),
        }
    )
    detail["publishable"] = not detail["publishBlockers"]
    return detail


# Parsing -----------------------------------------------------------------------


def _text(data, key: str, *, max_length: int, label: str, required: bool = False) -> str:
    value = data.get(key)
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise PagePolicyError(f"{label} must be text.", code="invalid_setting", field=key)
    value = value.strip()
    if required and not value:
        raise PagePolicyError(f"{label} is required.", code="invalid_setting", field=key)
    if len(value) > max_length:
        raise PagePolicyError(f"{label} must be {max_length} characters or fewer.", code="invalid_setting", field=key)
    if _CONTROL_CHARS.search(value):
        raise PagePolicyError(f"{label} contains unsupported characters.", code="invalid_setting", field=key)
    return value


def validate_redirect_url(value: str) -> str:
    url = value.strip()
    if len(url) > REDIRECT_URL_MAX_LENGTH:
        raise PagePolicyError(
            f"Redirect URL must be {REDIRECT_URL_MAX_LENGTH} characters or fewer.", code="invalid_setting", field="redirectUrl"
        )
    if any(char.isspace() for char in url) or "{" in url or "}" in url:
        raise PagePolicyError("Redirect URL cannot contain spaces or Mautic tokens.", code="invalid_setting", field="redirectUrl")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise PagePolicyError("Redirect URL must be a full http:// or https:// address.", code="invalid_setting", field="redirectUrl") from exc
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise PagePolicyError("Redirect URL must be a full http:// or https:// address.", code="invalid_setting", field="redirectUrl")
    if parts.username or parts.password:
        raise PagePolicyError("Redirect URL cannot contain a username or password.", code="invalid_setting", field="redirectUrl")
    return url


def parse_page_settings(data, *, current: dict[str, Any] | None = None) -> dict[str, Any]:
    """The settings to send: all supplied editable settings for a create, only
    the supplied ones for an edit. Raises PagePolicyError on anything else."""
    if not hasattr(data, "keys"):
        raise PagePolicyError("Send the page settings as an object.", code="invalid_payload")
    for key in data.keys():
        if key in REFUSED_SETTINGS:
            raise PagePolicyError(REFUSED_SETTINGS[key], code="setting_not_allowed", field=key)
    unsupported = sorted(set(data.keys()) - set(EDITABLE_SETTINGS))
    if unsupported:
        raise PagePolicyError(
            "Unsupported landing page setting(s): " + ", ".join(unsupported) + ".", code="unsupported_setting"
        )

    creating = current is None
    payload: dict[str, Any] = {}
    if creating or "title" in data:
        payload["title"] = _text(data, "title", max_length=TITLE_MAX_LENGTH, label="Page title", required=True)

    if "alias" in data:
        alias = _text(data, "alias", max_length=ALIAS_MAX_LENGTH, label="Page URL", required=not creating)
        if alias:
            if not _ALIAS_RE.match(alias):
                raise PagePolicyError(
                    "Page URL may use lowercase letters, numbers and single hyphens only.", code="invalid_setting", field="alias"
                )
            if alias in RESERVED_ALIASES:
                raise PagePolicyError(
                    f'"{alias}" is used by Mautic itself. Choose another page URL.', code="invalid_setting", field="alias"
                )
            payload["alias"] = alias

    if "customHtml" in data:
        html = data.get("customHtml")
        if html is None:
            html = ""
        if not isinstance(html, str):
            raise PagePolicyError("Page HTML must be text.", code="invalid_setting", field="customHtml")
        if len(html) > HTML_MAX_LENGTH:
            raise PagePolicyError(
                f"Page HTML must be {HTML_MAX_LENGTH:,} characters or fewer.", code="invalid_setting", field="customHtml"
            )
        payload["customHtml"] = html

    if "metaDescription" in data:
        payload["metaDescription"] = _text(
            data, "metaDescription", max_length=META_DESCRIPTION_MAX_LENGTH, label="Meta description"
        )

    if "noIndex" in data:
        value = data.get("noIndex")
        if not isinstance(value, bool):
            raise PagePolicyError("Hide from search engines must be true or false.", code="invalid_setting", field="noIndex")
        payload["noIndex"] = value

    if "language" in data:
        language = _text(data, "language", max_length=10, label="Language", required=True)
        if not _LANGUAGE_RE.match(language):
            raise PagePolicyError("Language must be a locale code such as en or en_US.", code="invalid_setting", field="language")
        payload["language"] = language

    if "category" in data:
        category = data.get("category")
        if category in (None, ""):
            payload["category"] = ""
        else:
            text = str(category).strip()
            if isinstance(category, bool) or not text.isdigit() or int(text) <= 0:
                raise PagePolicyError("Category must be a Mautic Category ID.", code="invalid_setting", field="category")
            payload["category"] = int(text)

    if "redirectType" in data or "redirectUrl" in data:
        before_type = str((current or {}).get("redirectType") or "")
        before_url = str((current or {}).get("redirectUrl") or "")
        redirect_type = str(data.get("redirectType", before_type) or "").strip()
        redirect_url = str(data.get("redirectUrl", before_url) or "").strip()
        if redirect_type and redirect_type not in REDIRECT_TYPES:
            raise PagePolicyError("Redirect type must be 301, 302, 303, 307 or 308.", code="invalid_setting", field="redirectType")
        if redirect_type and not redirect_url:
            raise PagePolicyError("Enter the address visitors are redirected to.", code="invalid_setting", field="redirectUrl")
        payload["redirectType"] = redirect_type
        payload["redirectUrl"] = validate_redirect_url(redirect_url) if redirect_type else ""

    return payload


def _require_script_permission(request, html: str) -> Response | None:
    if getattr(request.user, "is_superuser", False):
        return None
    findings = find_active_content(html)
    if not findings:
        return None
    return _error(
        "Only superusers can save page HTML that runs code. Remove: " + "; ".join(findings) + ".",
        code="page_scripts_superuser_only",
        http_status=status.HTTP_403_FORBIDDEN,
        field="customHtml",
        activeContent=findings,
    )


# Views -------------------------------------------------------------------------


def _asserted(client):
    """Page writes run as the acting admin's Mautic user or not at all; the
    client enforces this too, and this keeps the view honest on its own."""
    if getattr(client, "_uses_asserted_user", lambda: False)() is not True:
        raise MauticIdentityConfigurationError("Mautic landing page changes require per-user Mautic identity")
    return client


def _int_param(request, key: str, default: int) -> int:
    try:
        return int(request.query_params.get(key, default))
    except (TypeError, ValueError):
        return default


def _page_id(page_id) -> str | None:
    value = str(page_id or "").strip()
    return value if value.isdigit() and int(value) > 0 else None


def _invalid_id_response() -> Response:
    return _error("Landing page links use a numeric Mautic page ID.", code="invalid_page_id", http_status=status.HTTP_400_BAD_REQUEST)


def _read_page(page_id: str):
    try:
        return MauticClient().get_page(page_id), None
    except (TemporaryMauticError, PermanentMauticError) as exc:
        return None, _provider_error_response(exc)


def _not_editable_response() -> Response:
    return _error(
        "This is a preference-center page. It decides how contacts unsubscribe, so it is managed in Mautic.",
        code="page_managed_in_mautic",
        http_status=status.HTTP_409_CONFLICT,
    )


def _written_response(request, stored: dict[str, Any], payload: dict[str, Any], *, http_status=status.HTTP_200_OK) -> Response:
    detail = normalize_page_detail(stored, base=mautic_public_base_url(), user=request.user)
    requested = payload.get("alias")
    # Mautic silently renames an alias that another page already uses.
    detail["aliasAdjusted"] = bool(requested) and requested != detail["alias"]
    return Response(detail, status=http_status)


def _recent(page: dict[str, Any], since) -> bool:
    added = parse_datetime(str(page.get("dateAdded") or ""))
    if added is None:
        return False
    if timezone.is_naive(added):
        added = added.replace(tzinfo=dt_timezone.utc)
    return added >= since


def reconcile_uncertain_create(title: str, since, *, base: str | None) -> list[dict[str, Any]]:
    """Pages Mautic may have created for an uncertain create: same exact title,
    added since the attempt began. Read-only; never retries or deletes."""
    data = MauticClient().list_pages(search=title, orderBy="id", orderByDir="DESC", limit=20)
    found = []
    for page in _collection(data.get("pages")):
        if str(page.get("title") or "").strip() == title and _recent(page, since):
            summary = normalize_page_summary(page, base=base)
            found.append({key: summary[key] for key in ("id", "title", "alias", "isPublished", "dateAdded", "createdBy")})
    return found


def _uncertain_create_response(title: str, started) -> Response:
    try:
        candidates = reconcile_uncertain_create(title, started, base=mautic_public_base_url())
    except (TemporaryMauticError, PermanentMauticError):
        candidates = None
    if candidates is None:
        detail = (
            "Mautic did not confirm whether the page was created, and it could not be checked. "
            "Search the Landing Pages list for this title before trying again."
        )
    elif candidates:
        ids = ", ".join(f"#{item['id']}" for item in candidates)
        detail = (
            f"Mautic did not confirm the create, but it has a matching page ({ids}). "
            "Open it instead of creating another. Nothing was retried or deleted."
        )
    else:
        detail = "Mautic did not confirm the create and no matching page was found. It is safe to try again."
    return _error(
        detail,
        code="page_create_uncertain",
        http_status=status.HTTP_502_BAD_GATEWAY,
        candidates=candidates or [],
        verified=candidates is not None,
    )


def _verified_state_response(request, page_id: str, message: str, *, code: str) -> Response:
    stored, read_error = _read_page(page_id)
    return _error(
        message if read_error is None else message.split(".")[0] + ", and the page could not be read back. Reload it to check.",
        code=code,
        http_status=status.HTTP_502_BAD_GATEWAY,
        page=normalize_page_detail(stored, base=mautic_public_base_url(), user=request.user) if read_error is None else None,
        verified=read_error is None,
    )


class NewsletterAdminPageListCreateView(APIView):
    """List native Mautic landing pages and create an unpublished one."""

    permission_classes = [HasMarketingHubAccess]
    default_page_size = 25
    max_page_size = 100

    @marketing_cache.cached_get("pages", marketing_cache.list_ttl)
    def get(self, request):
        page = max(1, _int_param(request, "page", 1))
        page_size = max(1, min(_int_param(request, "page_size", self.default_page_size), self.max_page_size))
        search = str(request.query_params.get("search", "") or "").strip()[:TITLE_MAX_LENGTH]
        status_filter = str(request.query_params.get("status", "") or "").strip()
        if status_filter and status_filter != "all" and status_filter not in STATUS_FILTERS:
            return _error("Status must be all, published or unpublished.", code="invalid_filter", http_status=status.HTTP_400_BAD_REQUEST)
        sort = str(request.query_params.get("sort", "") or "newest").strip()
        if sort not in SORTS:
            return _error("Sort must be newest, title or modified.", code="invalid_filter", http_status=status.HTTP_400_BAD_REQUEST)

        # Mautic's search commands filter status, like Forms.
        terms = [term for term in (STATUS_FILTERS.get(status_filter, ""), search) if term]
        order_by, direction = SORTS[sort]
        params: dict[str, Any] = {
            "start": (page - 1) * page_size,
            "limit": page_size,
            "orderBy": order_by,
            "orderByDir": direction,
        }
        if terms:
            params["search"] = " ".join(terms)

        try:
            data = MauticClient().list_pages(**params)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        rows = _collection(data.get("pages"))
        try:
            total = max(0, int(data.get("total", len(rows))))
        except (TypeError, ValueError):
            total = len(rows)
        base = mautic_public_base_url()
        return Response(
            {
                "count": total,
                "page": page,
                "page_size": page_size,
                "num_pages": math.ceil(total / page_size) if total else 0,
                "publicBaseUrl": base,
                "results": [normalize_page_summary(row, base=base) for row in rows],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        try:
            payload = parse_page_settings(request.data)
        except PagePolicyError as exc:
            return _policy_error_response(exc)
        refusal = _require_script_permission(request, payload.get("customHtml", ""))
        if refusal is not None:
            return refusal

        started = timezone.now() - timedelta(seconds=5)
        try:
            page, error_response = run_interactive_mutation(
                request,
                action=PAGE_CREATE,
                resource="page",
                mutate=lambda client: _asserted(client).create_page(payload),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                resource_id_from_result=lambda created: created.get("id"),
            )
        except MauticRequestNotSentError as exc:
            return _provider_error_response(exc)
        except TemporaryMauticError:
            return _uncertain_create_response(payload["title"], started)
        except PermanentMauticError as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        # Confirm what Mautic stored before reporting success.
        stored, read_error = _read_page(str(page.get("id")))
        if read_error is not None:
            return _error(
                f"Mautic created page #{page.get('id')} but it could not be read back. Open it from the Landing Pages list.",
                code="page_create_unconfirmed",
                http_status=status.HTTP_502_BAD_GATEWAY,
                page={"id": str(page.get("id"))},
            )
        return _written_response(request, stored, payload, http_status=status.HTTP_201_CREATED)


def blocking_usage(usage: dict[str, Any]) -> dict[str, Any]:
    """What must be removed before the page can be deleted (empty when none)."""
    campaigns: dict[str, str] = {}
    for event in _collection(usage.get("campaignEvents")):
        campaigns.setdefault(str(event.get("campaignId")), str(event.get("campaignName") or ""))
    blocking: dict[str, Any] = {}
    if campaigns:
        blocking["campaigns"] = [
            {"id": cid, "name": name}
            for cid, name in sorted(campaigns.items(), key=lambda item: int(item[0]) if item[0].isdigit() else 0)
        ]
    emails = [{"id": str(row.get("id")), "name": str(row.get("name") or "")} for row in _collection(usage.get("preferenceCenterEmails"))]
    if emails:
        blocking["preferenceCenterEmails"] = emails
    variants = int(usage.get("variantChildren") or 0)
    translations = int(usage.get("translationChildren") or 0)
    if variants or translations:
        blocking["children"] = {"variants": variants, "translations": translations}
    return blocking


def _page_gone(page_id: str) -> bool | None:
    """True once Mautic reports the page missing, False while it exists, None when unknown."""
    try:
        MauticClient().get_page(page_id)
    except PermanentMauticError as exc:
        return True if "HTTP 404" in str(exc) else None
    except TemporaryMauticError:
        return None
    return False


class NewsletterAdminPageDetailView(APIView):
    """Read, edit or delete one landing page."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, page_id):
        normalized = _page_id(page_id)
        if normalized is None:
            return _invalid_id_response()
        page, error = _read_page(normalized)
        if error is not None:
            return error
        return Response(normalize_page_detail(page, base=mautic_public_base_url(), user=request.user))

    def patch(self, request, page_id):
        normalized = _page_id(page_id)
        if normalized is None:
            return _invalid_id_response()
        current, error = _read_page(normalized)
        if error is not None:
            return error
        if _provider_bool(current.get("isPreferenceCenter")):
            return _not_editable_response()
        try:
            payload = parse_page_settings(request.data, current=current)
        except PagePolicyError as exc:
            return _policy_error_response(exc)
        if not payload:
            return _error("No page settings were provided.", code="invalid_payload", http_status=status.HTTP_400_BAD_REQUEST)
        if "language" in payload:
            conflict = _language_conflict(current, payload["language"])
            if conflict is not None:
                return conflict
        if "customHtml" in payload:
            refusal = _require_script_permission(request, payload["customHtml"])
            if refusal is not None:
                return refusal
            if not payload["customHtml"].strip() and _provider_bool(current.get("isPublished")):
                return _error(
                    "A published page needs content. Unpublish it before removing all of its HTML.",
                    code="page_content_required",
                    http_status=status.HTTP_400_BAD_REQUEST,
                    field="customHtml",
                )

        try:
            _, error_response = run_interactive_mutation(
                request,
                action=PAGE_UPDATE,
                resource="page",
                resource_id=normalized,
                mutate=lambda client: _asserted(client).update_page(normalized, payload),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                detail="changed: " + ", ".join(sorted(payload)),
            )
        except MauticRequestNotSentError as exc:
            return _provider_error_response(exc)
        except TemporaryMauticError:
            return _verified_state_response(
                request, normalized,
                "Mautic did not confirm the update. The page's current saved state is shown; check it before saving again.",
                code="page_update_uncertain",
            )
        except PermanentMauticError as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        stored, read_error = _read_page(normalized)
        if read_error is not None:
            return _error(
                "Mautic accepted the update but the page could not be read back. Reload it to check.",
                code="page_update_unconfirmed",
                http_status=status.HTTP_502_BAD_GATEWAY,
            )
        return _written_response(request, stored, payload)

    def delete(self, request, page_id):
        """Delete as the acting admin: Mautic decides who may (own/other
        against Created by). Refused while anything still depends on the page."""
        normalized = _page_id(page_id)
        if normalized is None:
            return _invalid_id_response()
        current, error = _read_page(normalized)
        if error is not None:
            return error
        if _provider_bool(current.get("isPreferenceCenter")):
            return _not_editable_response()
        try:
            usage = MauticClient().get_page_usage(normalized, timeout=USAGE_TIMEOUT)
        except (TemporaryMauticError, PermanentMauticError):
            return _error(
                "Could not check where this page is used; nothing was deleted. Try again.",
                code="page_usage_unavailable",
                http_status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        blocking = blocking_usage(usage)
        if blocking:
            return _error(
                "This page is still in use. Remove it from the items listed before deleting it.",
                code="page_in_use",
                http_status=status.HTTP_409_CONFLICT,
                blocking=blocking,
            )

        try:
            _, error_response = run_interactive_mutation(
                request,
                action=PAGE_DELETE,
                resource="page",
                resource_id=normalized,
                mutate=lambda client: _asserted(client).delete_page(normalized),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                detail=f"title: {str(current.get('title') or '')[:TITLE_MAX_LENGTH]}",
            )
        except MauticRequestNotSentError as exc:
            return _provider_error_response(exc)
        except TemporaryMauticError:
            if _page_gone(normalized) is not True:
                return _error(
                    "Mautic did not confirm the delete. Reload the Landing Pages list to check before trying again.",
                    code="page_delete_uncertain",
                    http_status=status.HTTP_502_BAD_GATEWAY,
                )
            return _deleted_response(normalized, current)
        except PermanentMauticError as exc:
            if "HTTP 409" in str(exc):
                return _error(_provider_message(exc), code="page_in_use", http_status=status.HTTP_409_CONFLICT)
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        if _page_gone(normalized) is not True:
            return _error(
                "Mautic accepted the delete but the page can still be read. Reload the Landing Pages list to check.",
                code="page_delete_unconfirmed",
                http_status=status.HTTP_502_BAD_GATEWAY,
            )
        return _deleted_response(normalized, current)


def _language_conflict(page: dict[str, Any], language: str) -> Response | None:
    """A page and its translations must each have their own language."""
    page_id = str(page.get("id"))
    if page_role(page) == "translation":
        parent, error = _read_page(_related_id(page.get("translationParent")))
        if error is not None:
            return error
        family = [parent, *_collection(parent.get("translationChildren"))]
    elif page_role(page) == "main":
        family = _collection(page.get("translationChildren"))
    else:
        return None
    taken = {str(member.get("language") or "") for member in family if str(member.get("id")) != page_id}
    if language in taken:
        return _error(
            f"Another version of this page already uses {language}.",
            code="page_language_taken",
            http_status=status.HTTP_409_CONFLICT,
            field="language",
        )
    return None


def _deleted_response(page_id: str, page: dict[str, Any]) -> Response:
    return Response({"deleted": True, "id": page_id, "title": page.get("title") or ""})


class _PagePublicationView(APIView):
    permission_classes = [HasMarketingHubAccess]
    publish = True

    def post(self, request, page_id):
        normalized = _page_id(page_id)
        if normalized is None:
            return _invalid_id_response()
        current, error = _read_page(normalized)
        if error is not None:
            return error
        if _provider_bool(current.get("isPreferenceCenter")):
            return _not_editable_response()
        if self.publish:
            blockers = publish_blockers(current)
            if blockers:
                return _error(
                    " ".join(blockers),
                    code="page_not_publishable",
                    http_status=status.HTTP_409_CONFLICT,
                    blockers=blockers,
                )
        payload = {"isPublished": self.publish}

        try:
            _, error_response = run_interactive_mutation(
                request,
                action=PAGE_UPDATE,
                resource="page",
                resource_id=normalized,
                mutate=lambda client: _asserted(client).update_page(normalized, payload),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                detail="published" if self.publish else "unpublished",
            )
        except MauticRequestNotSentError as exc:
            return _provider_error_response(exc)
        except TemporaryMauticError:
            return _verified_state_response(
                request, normalized,
                "Mautic did not confirm the change. The page's current saved state is shown.",
                code="page_publication_uncertain",
            )
        except PermanentMauticError as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        stored, read_error = _read_page(normalized)
        if read_error is not None:
            return _error(
                "Mautic accepted the change but the page could not be read back. Reload it to check.",
                code="page_update_unconfirmed",
                http_status=status.HTTP_502_BAD_GATEWAY,
            )
        if _provider_bool(stored.get("isPublished")) is not self.publish:
            return _error(
                "Mautic did not apply the change. The page's current saved state is shown.",
                code="page_publication_not_applied",
                http_status=status.HTTP_409_CONFLICT,
                page=normalize_page_detail(stored, base=mautic_public_base_url(), user=request.user),
            )
        return _written_response(request, stored, {})


class NewsletterAdminPagePublishView(_PagePublicationView):
    publish = True


class NewsletterAdminPageUnpublishView(_PagePublicationView):
    publish = False


class NewsletterAdminPageDuplicateView(APIView):
    """Copy a page into a new unpublished page (no scripts, variants or translations)."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, page_id):
        normalized = _page_id(page_id)
        if normalized is None:
            return _invalid_id_response()
        try:
            title = _text(request.data, "title", max_length=TITLE_MAX_LENGTH, label="Page title") if hasattr(request.data, "get") else ""
        except PagePolicyError as exc:
            return _policy_error_response(exc)
        current, error = _read_page(normalized)
        if error is not None:
            return error
        if _provider_bool(current.get("isPreferenceCenter")):
            return _not_editable_response()
        # A copy carries the HTML, so the same script rule applies to it.
        refusal = _require_script_permission(request, str(current.get("customHtml") or ""))
        if refusal is not None:
            return refusal

        try:
            page, error_response = run_interactive_mutation(
                request,
                action=PAGE_DUPLICATE,
                resource="page",
                resource_id=normalized,
                mutate=lambda client: _asserted(client).duplicate_page(normalized, title=title or None),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
            )
        except MauticRequestNotSentError as exc:
            return _provider_error_response(exc)
        except TemporaryMauticError:
            expected = title or f"{str(current.get('title') or '').strip()} Copy"
            return _uncertain_create_response(expected, timezone.now() - timedelta(minutes=1))
        except PermanentMauticError as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        stored, read_error = _read_page(str(page.get("id")))
        if read_error is not None:
            return _error(
                f"Mautic created copy #{page.get('id')} but it could not be read back. Open it from the Landing Pages list.",
                code="page_create_unconfirmed",
                http_status=status.HTTP_502_BAD_GATEWAY,
                page={"id": str(page.get("id"))},
            )
        return _written_response(request, stored, {}, http_status=status.HTTP_201_CREATED)


# A/B variants and translations ---------------------------------------------------

# Mautic 7.1's page winner criteria, in the words the UI shows.
WINNER_CRITERIA = {
    "page.dwelltime": "Time on page (longest wins)",
    "page.bouncerate": "Bounce rate (lowest wins)",
    "form.submissions": "Form submissions (most wins)",
}


def _parse_weight(value) -> int:
    if isinstance(value, bool) or not str(value).strip().isdigit() or not 1 <= int(str(value).strip()) <= 100:
        raise PagePolicyError("Weight must be a whole number from 1 to 100.", code="invalid_setting", field="weight")
    return int(str(value).strip())


def _parse_criteria(value) -> str:
    criteria = str(value or "").strip()
    if criteria not in WINNER_CRITERIA:
        raise PagePolicyError("Choose how the winner is judged.", code="invalid_setting", field="winnerCriteria")
    return criteria


def _create_family_member(request, page_id, *, action, mutate, default_suffix):
    """Shared by variant and translation creation: both copy a main page."""
    normalized = _page_id(page_id)
    if normalized is None:
        return _invalid_id_response()
    current, error = _read_page(normalized)
    if error is not None:
        return error
    if _provider_bool(current.get("isPreferenceCenter")):
        return _not_editable_response()
    if page_role(current) != "main":
        return _error(
            "Variants and translations can only be added to a main page, not to another variant or translation.",
            code="page_not_main",
            http_status=status.HTTP_409_CONFLICT,
        )
    # The copy carries the HTML, so the same script rule applies to it.
    refusal = _require_script_permission(request, str(current.get("customHtml") or ""))
    if refusal is not None:
        return refusal

    try:
        created, error_response = run_interactive_mutation(
            request,
            action=action,
            resource="page",
            resource_id=normalized,
            mutate=lambda client: mutate(_asserted(client), normalized),
            client_factory=MauticClient,
            audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
        )
    except MauticRequestNotSentError as exc:
        return _provider_error_response(exc)
    except TemporaryMauticError:
        expected = f"{str(current.get('title') or '').strip()} ({default_suffix})"
        return _uncertain_create_response(expected, timezone.now() - timedelta(minutes=1))
    except PermanentMauticError as exc:
        return _provider_error_response(exc)
    if error_response is not None:
        return error_response

    stored, read_error = _read_page(str(created.get("id")))
    if read_error is not None:
        return _error(
            f"Mautic created page #{created.get('id')} but it could not be read back. Open it from the Landing Pages list.",
            code="page_create_unconfirmed",
            http_status=status.HTTP_502_BAD_GATEWAY,
            page={"id": str(created.get("id"))},
        )
    return _written_response(request, stored, {}, http_status=status.HTTP_201_CREATED)


def _optional_title(data) -> str:
    return _text(data, "title", max_length=TITLE_MAX_LENGTH, label="Page title") if hasattr(data, "get") else ""


class NewsletterAdminPageVariantCreateView(APIView):
    """Add an unpublished A/B variant (a copy of the main page) with its weight."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, page_id):
        try:
            weight = _parse_weight(request.data.get("weight"))
            criteria = _parse_criteria(request.data.get("winnerCriteria"))
            title = _optional_title(request.data)
        except PagePolicyError as exc:
            return _policy_error_response(exc)
        return _create_family_member(
            request, page_id, action=PAGE_VARIANT_CREATE, default_suffix="Variant",
            mutate=lambda client, pid: client.create_page_variant(pid, weight=weight, winner_criteria=criteria, title=title or None),
        )


class NewsletterAdminPageTranslationCreateView(APIView):
    """Add an unpublished translation (a copy of the main page in another language)."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, page_id):
        try:
            language = _text(request.data, "language", max_length=10, label="Language", required=True)
            if not _LANGUAGE_RE.match(language):
                raise PagePolicyError("Language must be a locale code such as fr or fr_CA.", code="invalid_setting", field="language")
            title = _optional_title(request.data)
        except PagePolicyError as exc:
            return _policy_error_response(exc)
        return _create_family_member(
            request, page_id, action=PAGE_TRANSLATION_CREATE, default_suffix=language.upper(),
            mutate=lambda client, pid: client.create_page_translation(pid, language=language, title=title or None),
        )


def normalize_abtest(test: dict[str, Any]) -> dict[str, Any]:
    winners = {str(winner) for winner in test.get("winners") or []}
    results = {str(row.get("pageId")): row for row in _collection(test.get("support"))}
    criteria = str(test.get("criteria") or "")
    versions = []
    for version in _collection(test.get("versions")):
        version_id = str(version.get("id"))
        result = results.get(version_id) or {}
        versions.append(
            {
                "id": version_id,
                "title": str(version.get("title") or ""),
                "isMain": bool(version.get("isMain")),
                "isPublished": bool(version.get("isPublished")),
                "weight": int(version.get("weight") or 0),
                "variantHits": int(version.get("variantHits") or 0),
                "uniqueHits": int(version.get("uniqueHits") or 0),
                "result": result.get("value"),
                "isLeading": version_id in winners,
            }
        )
    running = any(not v["isMain"] and v["isPublished"] for v in versions)
    return {
        "parentId": str(test.get("parentId")),
        "criteria": criteria,
        "criteriaLabel": WINNER_CRITERIA.get(criteria, criteria),
        "mixedCriteria": bool(test.get("mixedCriteria")),
        "criteriaOptions": [{"value": key, "label": label} for key, label in WINNER_CRITERIA.items()],
        "running": running,
        "versions": versions,
    }


class NewsletterAdminPageAbTestView(APIView):
    """Read the A/B test a page belongs to, or change a variant's weight or the test's criteria."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, page_id):
        normalized = _page_id(page_id)
        if normalized is None:
            return _invalid_id_response()
        try:
            test = MauticClient().get_page_abtest(normalized, timeout=USAGE_TIMEOUT)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        return Response(normalize_abtest(test))

    def patch(self, request, page_id):
        normalized = _page_id(page_id)
        if normalized is None:
            return _invalid_id_response()
        data = request.data if hasattr(request.data, "keys") else {}
        unsupported = sorted(set(data.keys()) - {"weight", "winnerCriteria"})
        if unsupported or not data:
            return _error("Send a weight and/or winner criteria only.", code="invalid_payload", http_status=status.HTTP_400_BAD_REQUEST)
        try:
            weight = _parse_weight(data["weight"]) if "weight" in data else None
            criteria = _parse_criteria(data["winnerCriteria"]) if "winnerCriteria" in data else None
        except PagePolicyError as exc:
            return _policy_error_response(exc)

        try:
            _, error_response = run_interactive_mutation(
                request,
                action=PAGE_VARIANT_UPDATE,
                resource="page",
                resource_id=normalized,
                mutate=lambda client: _asserted(client).update_page_variant(normalized, weight=weight, winner_criteria=criteria),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                detail=", ".join(part for part in (f"weight {weight}" if weight is not None else "", f"criteria {criteria}" if criteria else "") if part),
            )
        except MauticRequestNotSentError as exc:
            return _provider_error_response(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response
        return self.get(request, normalized)


class NewsletterAdminPageWinnerView(APIView):
    """Make a variant the main page. Mautic unpublishes the old main page and the other variants."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, page_id):
        normalized = _page_id(page_id)
        if normalized is None:
            return _invalid_id_response()
        current, error = _read_page(normalized)
        if error is not None:
            return error
        if page_role(current) != "variant":
            return _error("Only a variant can be made the winner.", code="page_not_variant", http_status=status.HTTP_409_CONFLICT)
        previous_main = (family_parent(current) or {}).get("id")

        try:
            _, error_response = run_interactive_mutation(
                request,
                action=PAGE_VARIANT_WINNER,
                resource="page",
                resource_id=normalized,
                mutate=lambda client: _asserted(client).make_page_variant_winner(normalized),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                detail=f"previous main page #{previous_main}",
            )
        except MauticRequestNotSentError as exc:
            return _provider_error_response(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        stored, read_error = _read_page(normalized)
        if read_error is not None or page_role(stored) != "main":
            return _error(
                "Mautic did not confirm the winner. Reload the page to check.",
                code="page_winner_unconfirmed",
                http_status=status.HTTP_502_BAD_GATEWAY,
            )
        return Response({"winner": normalize_page_detail(stored, base=mautic_public_base_url(), user=request.user),
                         "previousMainId": previous_main})


class NewsletterAdminPageCategoriesView(APIView):
    """Mautic categories a page can use: page and global ones."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            data = marketing_cache.categories(MauticClient(), limit=500)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        results = [
            {"id": str(category.get("id")), "title": str(category.get("title") or ""), "bundle": str(category.get("bundle") or "")}
            for category in _collection(data.get("categories"))
            if str(category.get("bundle") or "") in {"page", "global"} and category.get("id") is not None
        ]
        return Response({"count": len(results), "results": results})


class NewsletterAdminPageUsageView(APIView):
    """Read-only: where the page is used and what blocks deleting it."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, page_id):
        normalized = _page_id(page_id)
        if normalized is None:
            return _invalid_id_response()
        try:
            usage = MauticClient().get_page_usage(normalized, timeout=USAGE_TIMEOUT)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        def rows(key):
            return [
                {"id": str(row.get("id")), "name": str(row.get("name") or ""), "published": bool(row.get("published"))}
                for row in _collection(usage.get(key))
            ]

        return Response(
            {
                "campaignEvents": [
                    {
                        "id": str(event.get("id")),
                        "campaignId": str(event.get("campaignId")),
                        "campaignName": str(event.get("campaignName") or ""),
                        "campaignPublished": bool(event.get("campaignPublished")),
                    }
                    for event in _collection(usage.get("campaignEvents"))
                ],
                "preferenceCenterEmails": rows("preferenceCenterEmails"),
                "pointActions": rows("pointActions"),
                "variantChildren": int(usage.get("variantChildren") or 0),
                "translationChildren": int(usage.get("translationChildren") or 0),
                "hasHeadScript": bool(usage.get("hasHeadScript")),
                "hasFooterScript": bool(usage.get("hasFooterScript")),
                "blocking": blocking_usage(usage),
            }
        )
