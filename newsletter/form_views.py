"""Marketing Hub Forms: native Mautic Forms, basic settings and publication.

Mautic owns Forms; ECP keeps no Form records. Reads use the service account
(like Templates). Every write goes through the ECP bridge as the acting admin's
own Mautic user, and fails closed when that identity is unavailable: there is
no service-account fallback for Form changes.

Only basic settings are editable here. Fields and submit actions are shown
read-only and never sent, so an edit cannot add, remove, reorder or rewrite
them, change their mappings, or disconnect Campaign sources.
"""

from __future__ import annotations

import math
import re
from datetime import timedelta, timezone as dt_timezone
from typing import Any
from urllib.parse import urlsplit

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import marketing_cache
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.exceptions import MauticIdentityConfigurationError, MauticRequestNotSentError
from .form_actions import (
    ActionPolicyError,
    TAGS,
    action_matches,
    action_type_catalogue,
    normalize_action,
    ordered_actions,
    parse_action_order,
    plan_action_update,
    plan_new_action,
    tag_catalogue,
    unexpected_changes as unexpected_action_changes,
)
from .form_fields import (
    FieldPolicyError,
    contact_field_choices,
    field_matches,
    field_type_catalogue,
    fields_lock_reason,
    normalize_field,
    ordered_fields,
    parse_order,
    plan_field_update,
    plan_new_field,
    unexpected_changes,
)
from .mautic.operations import (
    FORM_ACTION_CREATE,
    FORM_ACTION_REORDER,
    FORM_ACTION_UPDATE,
    FORM_CREATE,
    FORM_FIELD_CREATE,
    FORM_FIELD_REORDER,
    FORM_FIELD_UPDATE,
    FORM_PUBLISH,
    FORM_UNPUBLISH,
    FORM_UPDATE,
)
from .mautic_identity_execution import run_interactive_mutation
from .mautic_identity_audit import record_identity_audit
from .models import MauticIdentityAuditLog, NewsletterCategory

NAME_MAX_LENGTH = 191
DESCRIPTION_MAX_LENGTH = 2000
MESSAGE_MAX_LENGTH = 2000
REDIRECT_MAX_LENGTH = 2048

POST_ACTIONS = ("message", "redirect", "return", "hideform")
# After-submit behaviours that show the admin's message.
MESSAGE_POST_ACTIONS = ("message", "hideform")
DEFAULT_POST_ACTION = "message"
# formType is deprecated in Mautic 7.1 (removed in 8.0); ECP never sends it.
SUPPORTED_FORM_TYPE = "standalone"

EDITABLE_SETTINGS = ("name", "description", "postAction", "postActionProperty")
# Accepted only with their safe values, and never forwarded.
READ_ONLY_SETTINGS = ("formType", "isPublished")

# Submit actions ECP policy never allows: they bypass contact consent.
PROHIBITED_ACTION_TYPES = {
    "lead.remove_do_not_contact": "Remove Do Not Contact",
    "email.send.lead": "Send email to contact",
}
SEGMENT_ACTION_TYPE = "lead.changelist"
# Fields a visitor cannot fill in.
NON_INPUT_FIELD_TYPES = {"button", "freetext", "freehtml", "pagebreak", "captcha", "hidden"}

STATUS_FILTERS = {"published": "is:published", "unpublished": "is:unpublished"}
SORTS = {"newest": ("id", "DESC"), "name": ("name", "ASC"), "modified": ("dateModified", "DESC")}

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class FormPolicyError(ValueError):
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


def _policy_error_response(exc: FormPolicyError) -> Response:
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
            return _error("Form not found in Mautic.", code="form_not_found", http_status=status.HTTP_404_NOT_FOUND)
        if "HTTP 409" in message:
            return _error(_provider_message(exc), code="form_not_publishable", http_status=status.HTTP_409_CONFLICT)
        if any(f"HTTP {code}" in message for code in (400, 422)):
            return _error(_provider_message(exc), code="mautic_validation_failed", http_status=status.HTTP_400_BAD_REQUEST)
    return _error(
        "Mautic did not complete the Form request.",
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


def _ordered(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def order(item):
        try:
            return int(item.get("order") or 0), int(item.get("id") or 0)
        except (TypeError, ValueError):
            return 0, 0
    return sorted(items, key=order)


def _user_label(form: dict[str, Any], key: str) -> str:
    return str(form.get(key) or "").strip()


def _id_list(value) -> list[str]:
    if isinstance(value, dict):
        value = list(value.values())
    if not isinstance(value, (list, tuple)):
        value = [value] if value not in (None, "") else []
    out = []
    for item in value:
        if isinstance(item, dict):
            item = item.get("id")
        text = str(item or "").strip()
        if text:
            out.append(text)
    return out


def subscription_list_segment_ids() -> set[str]:
    """Mautic segments that back ECP Subscription Lists, in any lifecycle
    state. Forms must never add contacts to or remove them from these."""
    return {
        str(value).strip()
        for value in NewsletterCategory.objects.exclude(mautic_segment_id="").values_list("mautic_segment_id", flat=True)
        if str(value or "").strip()
    }


def _action_policy(action: dict[str, Any], protected: set[str]) -> tuple[str, str]:
    action_type = str(action.get("type") or "")
    if action_type in PROHIBITED_ACTION_TYPES:
        return "prohibited", f"{PROHIBITED_ACTION_TYPES[action_type]} is not allowed by ECP policy."
    if action_type == SEGMENT_ACTION_TYPE:
        properties = action.get("properties") if isinstance(action.get("properties"), dict) else {}
        targets = set(_id_list(properties.get("addToLists"))) | set(_id_list(properties.get("removeFromLists")))
        if targets & protected:
            return "protected_segment", "Changes an ECP Subscription List segment, which Forms may not do."
    return "allowed", ""


def publish_blockers(form: dict[str, Any], protected: set[str]) -> list[str]:
    types = [str(field.get("type") or "") for field in _collection(form.get("fields"))]
    blockers = []
    if not [field_type for field_type in types if field_type not in NON_INPUT_FIELD_TYPES]:
        blockers.append("The Form has no fields a visitor can fill in. Add fields in Mautic first.")
    if "button" not in types:
        blockers.append("The Form has no submit button. Add one in Mautic first.")
    for action in _collection(form.get("actions")):
        policy, reason = _action_policy(action, protected)
        if policy != "allowed":
            name = str(action.get("name") or action.get("type") or "Submit action")
            blockers.append(f'Submit action "{name}": {reason}')
    return blockers


def normalize_form_summary(form: dict[str, Any]) -> dict[str, Any]:
    category = form.get("category")
    return {
        "id": str(form.get("id")) if form.get("id") is not None else None,
        "name": str(form.get("name") or "").strip(),
        "alias": str(form.get("alias") or ""),
        "description": str(form.get("description") or ""),
        "isPublished": _provider_bool(form.get("isPublished", False)),
        "formType": str(form.get("formType") or SUPPORTED_FORM_TYPE),
        "postAction": str(form.get("postAction") or DEFAULT_POST_ACTION),
        "postActionProperty": str(form.get("postActionProperty") or ""),
        "category": (
            {"id": str(category.get("id") or ""), "title": str(category.get("title") or "")}
            if isinstance(category, dict) else None
        ),
        "fieldCount": len(_collection(form.get("fields"))),
        "actionCount": len(_collection(form.get("actions"))),
        "dateAdded": form.get("dateAdded"),
        "dateModified": form.get("dateModified"),
        "createdBy": _user_label(form, "createdByUser"),
        "modifiedBy": _user_label(form, "modifiedByUser"),
    }


# Mautic 7.1 has one Form type: `formType` is deprecated, the API stores
# "standalone" whatever is sent, and every Form can be a Campaign source.
FORM_TYPE_NOTE = (
    "Mautic 7.1 uses a single Form type. Every Form can be used on its own "
    "and as a Campaign source."
)


def normalize_form_detail(form: dict[str, Any], protected: set[str]) -> dict[str, Any]:
    lock = fields_lock_reason(form)
    fields = [normalize_field(field, locked=lock) for field in _ordered(_collection(form.get("fields")))]
    raw_actions = _ordered(_collection(form.get("actions")))
    catalogue = _tag_catalogue() if any(str(a.get("type")) == TAGS for a in raw_actions) else {}
    actions = []
    for action in raw_actions:
        policy, reason = _action_policy(action, protected)
        actions.append(normalize_action(action, catalogue, policy=policy, policy_reason=reason))
    blockers = publish_blockers(form, protected)
    return {
        **normalize_form_summary(form),
        "fields": fields,
        "actions": actions,
        "publishable": not blockers,
        "publishBlockers": blockers,
        "publishUp": form.get("publishUp"),
        "publishDown": form.get("publishDown"),
        "fieldsEditable": not lock,
        "fieldsLockReason": lock,
        "campaignSource": True,
        "formTypeNote": FORM_TYPE_NOTE,
        "submitAddress": submit_address_status(form),
    }


def _written_response(stored: dict[str, Any], protected: set[str], *, http_status=status.HTTP_200_OK, **extra) -> Response:
    """Report an ECP write that Mautic confirmed. A published Form whose stored
    submit address is not Mautic's public address is an explicit error: the
    change is saved, but visitors could not complete a submission."""
    body = {**normalize_form_detail(stored, protected), **extra}
    if body["submitAddress"]["status"] == "mismatch" and _provider_bool(stored.get("isPublished")):
        return _error(
            "The change was saved, but Mautic stored a submit address that is not its public address "
            f"({body['submitAddress']['stored']} instead of {body['submitAddress']['expected']}). Visitors may not "
            "see the success message or reach Mautic. Check the Mautic plugin version and site_url before using "
            "this Form.",
            code="form_submit_address_mismatch",
            http_status=status.HTTP_409_CONFLICT,
            saved=True,
            form=body,
        )
    return Response(body, status=http_status)


def _structure(form: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Field and action ids in their stored order: what a basic edit must keep."""
    return (
        [str(field.get("id")) for field in _ordered(_collection(form.get("fields")))],
        [str(action.get("id")) for action in _ordered(_collection(form.get("actions")))],
    )


def _after_submit(form: dict[str, Any]) -> tuple[str, str]:
    return str(form.get("postAction") or ""), str(form.get("postActionProperty") or "")


def _kept(before: dict[str, Any], after: dict[str, Any], payload: dict[str, Any]) -> bool:
    """True when a write changed nothing it was not asked to: fields, actions
    and (unless this write set it) the after-submit behaviour. Mautic's native
    PATCH resets postAction when it is omitted; the bridge re-sends it, and
    this confirms it held."""
    if _structure(after) != _structure(before):
        return False
    return "postAction" in payload or _after_submit(after) == _after_submit(before)


# Validation --------------------------------------------------------------------


def _text(data, key: str, *, max_length: int, label: str) -> str:
    value = data.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise FormPolicyError(f"{label} must be text.", code="invalid_form_settings", field=key)
    value = value.strip()
    if _CONTROL_CHARS.search(value):
        raise FormPolicyError(f"{label} contains unsupported control characters.", code="invalid_form_settings", field=key)
    if len(value) > max_length:
        raise FormPolicyError(f"{label} must be {max_length} characters or fewer.", code="invalid_form_settings", field=key)
    return value


def validate_redirect_url(value: str) -> str:
    message = "Redirect URL must be a full http:// or https:// address."
    if not value:
        raise FormPolicyError("Redirect URL is required when the Form redirects.", code="invalid_form_settings", field="postActionProperty")
    if len(value) > REDIRECT_MAX_LENGTH:
        raise FormPolicyError(f"Redirect URL must be {REDIRECT_MAX_LENGTH} characters or fewer.", code="invalid_form_settings", field="postActionProperty")
    if any(char.isspace() for char in value) or "{" in value or "}" in value:
        raise FormPolicyError("Redirect URL cannot contain spaces or Mautic tokens.", code="invalid_form_settings", field="postActionProperty")
    try:
        parts = urlsplit(value)
        parts.port  # raises on an invalid port
    except ValueError:
        raise FormPolicyError(message, code="invalid_form_settings", field="postActionProperty") from None
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise FormPolicyError(message, code="invalid_form_settings", field="postActionProperty")
    if parts.username or parts.password:
        raise FormPolicyError("Redirect URL cannot contain a username or password.", code="invalid_form_settings", field="postActionProperty")
    return value


def _reject_structure(data, protected: set[str]) -> None:
    actions = data.get("actions")
    if actions is not None:
        for action in actions if isinstance(actions, list) else []:
            if not isinstance(action, dict):
                continue
            policy, reason = _action_policy(action, protected)
            if policy == "prohibited":
                raise FormPolicyError(reason, code="form_action_prohibited", field="actions")
            if policy == "protected_segment":
                raise FormPolicyError(reason, code="form_action_protected_segment", field="actions")
        raise FormPolicyError(
            "Submit actions cannot be changed here yet; existing actions are kept as they are.",
            code="form_actions_not_supported",
            field="actions",
        )
    if data.get("fields") is not None:
        raise FormPolicyError(
            "Form fields cannot be changed here yet; existing fields are kept as they are.",
            code="form_fields_not_supported",
            field="fields",
        )


def parse_form_settings(data, *, current: dict[str, Any] | None = None, protected: set[str] | None = None) -> dict[str, Any]:
    """Validate a create (``current`` is None) or a basic edit, and return only
    the native settings to send. Never returns fields, actions, formType or
    isPublished."""
    if not isinstance(data, dict):
        raise FormPolicyError("Send the Form settings as a JSON object.", code="invalid_form_settings")
    _reject_structure(data, protected if protected is not None else set())

    unsupported = sorted(set(data) - set(EDITABLE_SETTINGS) - set(READ_ONLY_SETTINGS))
    if unsupported:
        raise FormPolicyError(
            "Unsupported Form setting(s): " + ", ".join(unsupported) + ".",
            code="unsupported_form_settings",
        )
    if "formType" in data and data.get("formType") not in (None, "", SUPPORTED_FORM_TYPE):
        raise FormPolicyError("Only standalone Forms are supported.", code="invalid_form_settings", field="formType")
    if "isPublished" in data and _provider_bool(data.get("isPublished")):
        raise FormPolicyError(
            "Save the Form first, then publish it with Publish.",
            code="form_publish_separately",
            field="isPublished",
        )

    creating = current is None
    payload: dict[str, Any] = {}

    if creating or "name" in data:
        name = _text(data, "name", max_length=NAME_MAX_LENGTH, label="Form name")
        if not name:
            raise FormPolicyError("Form name is required.", code="invalid_form_settings", field="name")
        payload["name"] = name
    if "description" in data:
        payload["description"] = _text(data, "description", max_length=DESCRIPTION_MAX_LENGTH, label="Description")

    current_action = str((current or {}).get("postAction") or DEFAULT_POST_ACTION)
    current_property = str((current or {}).get("postActionProperty") or "")
    action_given = "postAction" in data and data.get("postAction") not in (None, "")
    action = data.get("postAction") if action_given else (DEFAULT_POST_ACTION if creating else current_action)
    if action not in POST_ACTIONS:
        raise FormPolicyError(
            "After submit must be one of: show a message, hide the form with a message, redirect, or return to the page.",
            code="invalid_form_settings",
            field="postAction",
        )
    property_given = "postActionProperty" in data
    if property_given:
        limit = REDIRECT_MAX_LENGTH if action == "redirect" else MESSAGE_MAX_LENGTH
        prop = _text(data, "postActionProperty", max_length=limit, label="After-submit value")
    else:
        # Switching behaviour needs its own value; keeping it reuses the stored one.
        prop = current_property if (not creating and action == current_action) else ""

    if action in MESSAGE_POST_ACTIONS and not prop:
        raise FormPolicyError("Enter the message visitors see after submitting.", code="invalid_form_settings", field="postActionProperty")
    if action == "redirect":
        prop = validate_redirect_url(prop)
    if action == "return":
        prop = ""

    if creating or action != current_action or prop != current_property:
        payload["postAction"] = action
        payload["postActionProperty"] = prop

    if not creating:
        # Send only what changes; the post-action pair above already travels
        # together and only when one of them changes.
        for key in ("name", "description"):
            if key in payload and payload[key] == str(current.get(key) or "").strip():
                del payload[key]
    return payload


# Reconciliation ----------------------------------------------------------------


def _recent(form: dict[str, Any], since) -> bool:
    added = parse_datetime(str(form.get("dateAdded") or ""))
    if added is None:
        return False
    if timezone.is_naive(added):
        added = timezone.make_aware(added, dt_timezone.utc)
    return added >= since


def reconcile_uncertain_create(name: str, since) -> list[dict[str, Any]]:
    """Forms Mautic may have created for an uncertain create: same exact name,
    added since the attempt began. Read-only; never retries or deletes."""
    data = MauticClient().list_forms(search=name, orderBy="id", orderByDir="DESC", limit=20)
    found = []
    for form in _collection(data.get("forms")):
        if str(form.get("name") or "").strip() == name and _recent(form, since):
            found.append({key: normalize_form_summary(form)[key] for key in ("id", "name", "isPublished", "dateAdded", "createdBy")})
    return found


# Views -------------------------------------------------------------------------


def _asserted(client):
    """Form writes run as the acting admin's Mautic user or not at all; the
    client enforces this too, and this keeps the view honest on its own."""
    if getattr(client, "_uses_asserted_user", lambda: False)() is not True:
        raise MauticIdentityConfigurationError("Mautic Form changes require per-user Mautic identity")
    return client


def _int_param(request, key: str, default: int) -> int:
    try:
        return int(request.query_params.get(key, default))
    except (TypeError, ValueError):
        return default


def _form_id(form_id) -> str | None:
    value = str(form_id or "").strip()
    return value if value.isdigit() and int(value) > 0 else None


def _invalid_id_response() -> Response:
    return _error("Form links use a numeric Mautic Form ID.", code="invalid_form_id", http_status=status.HTTP_400_BAD_REQUEST)


def _read_form(form_id: str):
    try:
        return MauticClient().get_form(form_id), None
    except (TemporaryMauticError, PermanentMauticError) as exc:
        return None, _provider_error_response(exc)


class NewsletterAdminFormListCreateView(APIView):
    """List native Mautic Forms and create an unpublished one from basic settings."""

    permission_classes = [HasMarketingHubAccess]
    default_page_size = 25
    max_page_size = 100

    @marketing_cache.cached_get("forms", marketing_cache.list_ttl)
    def get(self, request):
        page = max(1, _int_param(request, "page", 1))
        page_size = max(1, min(_int_param(request, "page_size", self.default_page_size), self.max_page_size))
        search = str(request.query_params.get("search", "") or "").strip()[:NAME_MAX_LENGTH]
        status_filter = str(request.query_params.get("status", "") or "").strip()
        if status_filter and status_filter != "all" and status_filter not in STATUS_FILTERS:
            return _error("Status must be all, published or unpublished.", code="invalid_filter", http_status=status.HTTP_400_BAD_REQUEST)
        sort = str(request.query_params.get("sort", "") or "newest").strip()
        if sort not in SORTS:
            return _error("Sort must be newest, name or modified.", code="invalid_filter", http_status=status.HTTP_400_BAD_REQUEST)

        # Mautic ignores publishedOnly here; its search commands filter status.
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
            data = MauticClient().list_forms(**params)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        rows = _collection(data.get("forms"))
        try:
            total = max(0, int(data.get("total", len(rows))))
        except (TypeError, ValueError):
            total = len(rows)
        return Response(
            {
                "count": total,
                "page": page,
                "page_size": page_size,
                "num_pages": math.ceil(total / page_size) if total else 0,
                "results": [normalize_form_summary(form) for form in rows],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        protected = subscription_list_segment_ids()
        try:
            payload = parse_form_settings(request.data, protected=protected)
        except FormPolicyError as exc:
            return _policy_error_response(exc)

        started = timezone.now() - timedelta(seconds=5)
        try:
            form, error_response = run_interactive_mutation(
                request,
                action=FORM_CREATE,
                resource="form",
                mutate=lambda client: _asserted(client).create_form(payload),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                resource_id_from_result=lambda created: created.get("id"),
            )
        except MauticRequestNotSentError as exc:
            return _provider_error_response(exc)
        except TemporaryMauticError:
            return self._uncertain_create(payload["name"], started)
        except PermanentMauticError as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        # Confirm what Mautic stored before reporting success.
        stored, read_error = _read_form(str(form.get("id")))
        if read_error is not None:
            return _error(
                f"Mautic created Form #{form.get('id')} but it could not be read back. Open it from the Forms list.",
                code="form_create_unconfirmed",
                http_status=status.HTTP_502_BAD_GATEWAY,
                form={"id": str(form.get("id"))},
            )
        return _written_response(stored, protected, http_status=status.HTTP_201_CREATED)

    @staticmethod
    def _uncertain_create(name: str, started) -> Response:
        try:
            candidates = reconcile_uncertain_create(name, started)
        except (TemporaryMauticError, PermanentMauticError):
            candidates = None
        if candidates is None:
            detail = (
                "Mautic did not confirm whether the Form was created, and it could not be checked. "
                "Search the Forms list for this name before trying again."
            )
        elif candidates:
            ids = ", ".join(f"#{item['id']}" for item in candidates)
            detail = (
                f"Mautic did not confirm the create, but it has a matching Form ({ids}). "
                "Open it instead of creating another. Nothing was retried or deleted."
            )
        else:
            detail = "Mautic did not confirm the create and no matching Form was found. It is safe to try again."
        return _error(
            detail,
            code="form_create_uncertain",
            http_status=status.HTTP_502_BAD_GATEWAY,
            candidates=candidates or [],
            verified=candidates is not None,
        )


class NewsletterAdminFormDetailView(APIView):
    """Read a Form (fields and actions read-only) and edit its basic settings."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, form_id):
        normalized = _form_id(form_id)
        if normalized is None:
            return _invalid_id_response()
        form, error = _read_form(normalized)
        if error is not None:
            return error
        return Response(normalize_form_detail(form, subscription_list_segment_ids()))

    def patch(self, request, form_id):
        normalized = _form_id(form_id)
        if normalized is None:
            return _invalid_id_response()
        protected = subscription_list_segment_ids()
        current, error = _read_form(normalized)
        if error is not None:
            return error
        try:
            payload = parse_form_settings(request.data, current=current, protected=protected)
        except FormPolicyError as exc:
            return _policy_error_response(exc)
        if not payload:
            return Response({**normalize_form_detail(current, protected), "unchanged": True})

        try:
            _, error_response = run_interactive_mutation(
                request,
                action=FORM_UPDATE,
                resource="form",
                resource_id=normalized,
                mutate=lambda client: _asserted(client).update_form(normalized, payload),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                detail="changed: " + ", ".join(sorted(payload)),
            )
        except MauticRequestNotSentError as exc:
            return _provider_error_response(exc)
        except TemporaryMauticError:
            return _verified_state_response(
                normalized, protected,
                "Mautic did not confirm the update. The Form's current saved state is shown; check it before saving again.",
                code="form_update_uncertain",
            )
        except PermanentMauticError as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        stored, read_error = _read_form(normalized)
        if read_error is not None:
            return _error(
                "Mautic accepted the update but the Form could not be read back. Reload it to check.",
                code="form_update_unconfirmed",
                http_status=status.HTTP_502_BAD_GATEWAY,
            )
        if not _kept(current, stored, payload):
            return _error(
                "Mautic changed more than the requested settings while saving. Review the Form in Mautic.",
                code="form_structure_changed",
                http_status=status.HTTP_409_CONFLICT,
                form=normalize_form_detail(stored, protected),
            )
        return _written_response(stored, protected)


def _verified_state_response(form_id: str, protected: set[str], message: str, *, code: str) -> Response:
    stored, read_error = _read_form(form_id)
    return _error(
        message if read_error is None else message.split(".")[0] + ", and the Form could not be read back. Reload it to check.",
        code=code,
        http_status=status.HTTP_502_BAD_GATEWAY,
        form=normalize_form_detail(stored, protected) if read_error is None else None,
        verified=read_error is None,
    )


class _FormPublicationView(APIView):
    permission_classes = [HasMarketingHubAccess]
    publish = True

    def post(self, request, form_id):
        normalized = _form_id(form_id)
        if normalized is None:
            return _invalid_id_response()
        protected = subscription_list_segment_ids()
        current, error = _read_form(normalized)
        if error is not None:
            return error
        if _provider_bool(current.get("isPublished")) == self.publish:
            return Response({**normalize_form_detail(current, protected), "unchanged": True})
        if self.publish:
            blockers = publish_blockers(current, protected)
            if blockers:
                return _error(
                    "The Form cannot be published yet: " + " ".join(blockers),
                    code="form_not_publishable",
                    http_status=status.HTTP_409_CONFLICT,
                    publishBlockers=blockers,
                )

        verb = "publish" if self.publish else "unpublish"
        try:
            _, error_response = run_interactive_mutation(
                request,
                action=FORM_PUBLISH if self.publish else FORM_UNPUBLISH,
                resource="form",
                resource_id=normalized,
                mutate=lambda client: _asserted(client).set_form_published(normalized, self.publish),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
            )
        except MauticRequestNotSentError as exc:
            return _provider_error_response(exc)
        except TemporaryMauticError:
            return _verified_state_response(
                normalized, protected,
                f"Mautic did not confirm the {verb}. The Form's current state is shown.",
                code=f"form_{verb}_uncertain",
            )
        except PermanentMauticError as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        stored, read_error = _read_form(normalized)
        if read_error is not None or _provider_bool(stored.get("isPublished")) != self.publish:
            return _verified_state_response(
                normalized, protected,
                f"Mautic did not confirm the {verb}. The Form's current state is shown.",
                code=f"form_{verb}_unconfirmed",
            )
        if not _kept(current, stored, {}):
            return _error(
                f"Mautic changed more than the publication state during the {verb}. Review the Form in Mautic.",
                code="form_structure_changed",
                http_status=status.HTTP_409_CONFLICT,
                form=normalize_form_detail(stored, protected),
            )
        return _written_response(stored, protected)


class NewsletterAdminFormPublishView(_FormPublicationView):
    publish = True


class NewsletterAdminFormUnpublishView(_FormPublicationView):
    publish = False


# Field Builder ------------------------------------------------------------------


def _field_policy_response(exc: FieldPolicyError) -> Response:
    return _error(str(exc), code=exc.code, http_status=status.HTTP_400_BAD_REQUEST, field=exc.field)


def _contact_field_types() -> dict[str, str]:
    data = marketing_cache.fields(MauticClient(), "contact", limit=500)
    rows = data.get("fields") if isinstance(data, dict) else []
    return {row["alias"]: row["type"] for row in contact_field_choices(rows)}


def _field_target(form_id, field_id=None):
    """Read the Form (and field) to change, refusing what ECP cannot manage."""
    normalized = _form_id(form_id)
    if normalized is None:
        return None, None, None, _invalid_id_response()
    if field_id is not None and _form_id(field_id) is None:
        return None, None, None, _error("Field links use a numeric Mautic field ID.", code="invalid_form_field_id", http_status=status.HTTP_400_BAD_REQUEST)
    form, error = _read_form(normalized)
    if error is not None:
        return None, None, None, error
    lock = fields_lock_reason(form)
    if lock:
        return None, None, None, _error(lock, code="form_fields_managed_in_mautic", http_status=status.HTTP_409_CONFLICT)
    field = None
    if field_id is not None:
        field = next((f for f in ordered_fields(form) if str(f.get("id")) == str(field_id)), None)
        if field is None:
            return None, None, None, _error("Form field not found in Mautic.", code="form_field_not_found", http_status=status.HTTP_404_NOT_FOUND)
    return normalized, form, field, None


def _run_field_write(request, *, action, form_id, resource_id, detail, mutate, verify, kind="field"):
    """Run one bridged field (or submit-action) write as the acting admin,
    then confirm Mautic's stored Form shows exactly the intended change."""
    protected = subscription_list_segment_ids()
    try:
        result, error_response = run_interactive_mutation(
            request,
            action=action,
            resource=f"form_{kind}",
            resource_id=resource_id,
            mutate=lambda client: mutate(_asserted(client)),
            client_factory=MauticClient,
            audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
            resource_id_from_result=lambda saved: verify(saved, None)[1] or resource_id,
            detail=detail,
        )
    except MauticRequestNotSentError as exc:
        return _provider_error_response(exc)
    except TemporaryMauticError:
        return _verified_state_response(
            form_id, protected,
            f"Mautic did not confirm the {kind} change. The Form's current saved state is shown; check it before trying again.",
            code=f"form_{kind}_write_uncertain",
        )
    except PermanentMauticError as exc:
        return _provider_error_response(exc)
    if error_response is not None:
        return error_response

    stored, read_error = _read_form(form_id)
    if read_error is not None:
        return _error(
            f"Mautic accepted the {kind} change but the Form could not be read back. Reload it to check.",
            code=f"form_{kind}_write_unconfirmed",
            http_status=status.HTTP_502_BAD_GATEWAY,
        )
    problems, field_ref = verify(stored, stored)
    if problems:
        return _error(
            "Mautic's saved Form does not match the requested change: " + "; ".join(problems) + ". Review it in Mautic.",
            code=f"form_{kind}_write_mismatch",
            http_status=status.HTTP_409_CONFLICT,
            form=normalize_form_detail(stored, protected),
        )
    return _written_response(stored, protected, **{f"{kind}Id": field_ref.split(":")[-1] if ":" in (field_ref or "") else None})


class NewsletterAdminFormBuilderMetadataView(APIView):
    """Supported field types and the Contact fields a Form may fill."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            data = marketing_cache.fields(MauticClient(), "contact", limit=500)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        rows = data.get("fields") if isinstance(data, dict) else []
        return Response(
            {
                "fieldTypes": field_type_catalogue(),
                "contactFields": contact_field_choices(rows),
                "formTypeNote": FORM_TYPE_NOTE,
                "consentNote": (
                    "Forms never record marketing consent: ECP consent fields and system "
                    "fields cannot be filled by a Form."
                ),
            }
        )


class NewsletterAdminFormFieldListCreateView(APIView):
    """A Form's fields (read) and adding one supported field."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, form_id):
        normalized = _form_id(form_id)
        if normalized is None:
            return _invalid_id_response()
        form, error = _read_form(normalized)
        if error is not None:
            return error
        lock = fields_lock_reason(form)
        return Response({
            "fields": [normalize_field(field, locked=lock) for field in ordered_fields(form)],
            "fieldsEditable": not lock,
            "fieldsLockReason": lock,
        })

    def post(self, request, form_id):
        normalized, form, _, error = _field_target(form_id)
        if error is not None:
            return error
        try:
            native, position = plan_new_field(request.data, form, _contact_field_types())
        except FieldPolicyError as exc:
            return _field_policy_response(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        before_ids = [str(f.get("id")) for f in ordered_fields(form)]

        def verify(saved, _stored):
            new = [f for f in ordered_fields(saved) if str(f.get("id")) not in before_ids]
            if len(new) != 1:
                return ["the new field was not saved exactly once"], ""
            new_id = str(new[0].get("id"))
            expected = list(before_ids)
            expected.insert(len(before_ids) if position is None else position, new_id)
            problems = unexpected_changes(form, saved, expected_order=expected)
            if not field_matches(new[0], native):
                problems.append("the new field's settings differ from the request")
            return problems, f"{normalized}:{new_id}"

        response = _run_field_write(
            request,
            action=FORM_FIELD_CREATE,
            form_id=normalized,
            resource_id=normalized,
            detail=f"added {native['type']} field {native['alias']}",
            mutate=lambda client: client.create_form_field(normalized, native, position),
            verify=verify,
        )
        if response.status_code == status.HTTP_200_OK:
            response.status_code = status.HTTP_201_CREATED
        return response


class NewsletterAdminFormFieldDetailView(APIView):
    """Change one supported field's settings (never its type or alias)."""

    permission_classes = [HasMarketingHubAccess]

    def patch(self, request, form_id, field_id):
        normalized, form, field, error = _field_target(form_id, field_id)
        if error is not None:
            return error
        try:
            native = plan_field_update(request.data, field, form, _contact_field_types())
        except FieldPolicyError as exc:
            return _field_policy_response(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        target = str(field.get("id"))
        if not native:
            body = normalize_form_detail(form, subscription_list_segment_ids())
            return Response({**body, "fieldId": target, "unchanged": True})
        order = [str(f.get("id")) for f in ordered_fields(form)]

        def verify(saved, _stored):
            problems = unexpected_changes(form, saved, target_id=target, expected_order=order)
            stored_field = next((f for f in ordered_fields(saved) if str(f.get("id")) == target), None)
            if stored_field is None or not field_matches(stored_field, native):
                problems.append("the field's saved settings differ from the request")
            elif {k: v for k, v in (stored_field.get("properties") or {}).items() if k not in (native.get("properties") or {})} \
                    != {k: v for k, v in (field.get("properties") or {}).items() if k not in (native.get("properties") or {})}:
                problems.append("other settings of the field changed")
            return problems, f"{normalized}:{target}"

        return _run_field_write(
            request,
            action=FORM_FIELD_UPDATE,
            form_id=normalized,
            resource_id=f"{normalized}:{target}",
            detail="changed: " + ", ".join(sorted(native)),
            mutate=lambda client: client.update_form_field(normalized, target, native),
            verify=verify,
        )


class NewsletterAdminFormFieldReorderView(APIView):
    """Put a Form's fields in a new order."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, form_id):
        normalized, form, _, error = _field_target(form_id)
        if error is not None:
            return error
        try:
            order = parse_order(request.data, form)
        except FieldPolicyError as exc:
            return _field_policy_response(exc)
        if order == [str(f.get("id")) for f in ordered_fields(form)]:
            body = normalize_form_detail(form, subscription_list_segment_ids())
            return Response({**body, "unchanged": True})

        def verify(saved, _stored):
            return unexpected_changes(form, saved, target_id="", expected_order=order), normalized

        return _run_field_write(
            request,
            action=FORM_FIELD_REORDER,
            form_id=normalized,
            resource_id=normalized,
            detail="order: " + ",".join(order)[:200],
            mutate=lambda client: client.reorder_form_fields(normalized, order),
            verify=verify,
        )


# Submit actions -------------------------------------------------------------------

TAG_CATALOGUE_LIMIT = 1000


def _tag_catalogue() -> dict[str, str]:
    """``{tag_id: name}`` straight from Mautic (never cached: a stale list
    could map a stored tag name to the wrong ID)."""
    try:
        data = MauticClient().list_tags(limit=TAG_CATALOGUE_LIMIT)
    except (TemporaryMauticError, PermanentMauticError):
        return {}
    return tag_catalogue(data.get("tags") if isinstance(data, dict) else [])


def _action_policy_response(exc: ActionPolicyError) -> Response:
    return _error(str(exc), code=exc.code, http_status=status.HTTP_400_BAD_REQUEST, field=exc.field)


def _action_target(form_id, action_id=None):
    normalized = _form_id(form_id)
    if normalized is None:
        return None, None, None, _invalid_id_response()
    if action_id is not None and _form_id(action_id) is None:
        return None, None, None, _error("Action links use a numeric Mautic action ID.", code="invalid_form_action_id",
                                        http_status=status.HTTP_400_BAD_REQUEST)
    form, error = _read_form(normalized)
    if error is not None:
        return None, None, None, error
    action = None
    if action_id is not None:
        action = next((a for a in ordered_actions(form) if str(a.get("id")) == str(action_id)), None)
        if action is None:
            return None, None, None, _error("Submit action not found in Mautic.", code="form_action_not_found",
                                            http_status=status.HTTP_404_NOT_FOUND)
    return normalized, form, action, None


class NewsletterAdminFormActionMetadataView(APIView):
    """Submit action types ECP manages, and Mautic's tags to choose from."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        catalogue = _tag_catalogue()
        return Response({
            "actionTypes": action_type_catalogue(),
            "tags": sorted(({"id": tag_id, "name": name} for tag_id, name in catalogue.items()), key=lambda t: t["name"].lower()),
            "tagLimit": TAG_CATALOGUE_LIMIT,
            "policyNote": (
                "Forms can tag contacts or adjust their points. Actions that lift Do Not Contact, "
                "send email to the contact or change segment membership are not offered."
            ),
        })


class NewsletterAdminFormActionListCreateView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request, form_id):
        normalized = _form_id(form_id)
        if normalized is None:
            return _invalid_id_response()
        form, error = _read_form(normalized)
        if error is not None:
            return error
        return Response({"actions": normalize_form_detail(form, subscription_list_segment_ids())["actions"]})

    def post(self, request, form_id):
        normalized, form, _, error = _action_target(form_id)
        if error is not None:
            return error
        catalogue = _tag_catalogue()
        try:
            native, position = plan_new_action(request.data, form, catalogue)
        except ActionPolicyError as exc:
            return _action_policy_response(exc)

        before_ids = [str(a.get("id")) for a in ordered_actions(form)]

        def verify(saved, _stored):
            new = [a for a in ordered_actions(saved) if str(a.get("id")) not in before_ids]
            if len(new) != 1:
                return ["the new action was not saved exactly once"], ""
            new_id = str(new[0].get("id"))
            expected = list(before_ids)
            expected.insert(len(before_ids) if position is None else position, new_id)
            problems = unexpected_action_changes(form, saved, target_id=None, expected_order=expected)
            if not action_matches(new[0], native, catalogue):
                problems.append("the new action's settings differ from the request")
            return problems, f"{normalized}:{new_id}"

        response = _run_field_write(
            request,
            action=FORM_ACTION_CREATE,
            form_id=normalized,
            resource_id=normalized,
            detail=f"added {native['type']} action",
            mutate=lambda client: client.create_form_action(normalized, native, position),
            verify=verify,
            kind="action",
        )
        if response.status_code == status.HTTP_200_OK:
            response.status_code = status.HTTP_201_CREATED
        return response


class NewsletterAdminFormActionDetailView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def patch(self, request, form_id, action_id):
        normalized, form, action, error = _action_target(form_id, action_id)
        if error is not None:
            return error
        catalogue = _tag_catalogue()
        try:
            native = plan_action_update(request.data, action, catalogue)
        except ActionPolicyError as exc:
            return _action_policy_response(exc)
        target = str(action.get("id"))
        if not native:
            return Response({**normalize_form_detail(form, subscription_list_segment_ids()), "actionId": target, "unchanged": True})
        order = [str(a.get("id")) for a in ordered_actions(form)]

        def verify(saved, _stored):
            problems = unexpected_action_changes(form, saved, target_id=target, expected_order=order)
            stored = next((a for a in ordered_actions(saved) if str(a.get("id")) == target), None)
            if stored is None or not action_matches({**stored}, {**native, "type": action.get("type")}, catalogue):
                problems.append("the action's saved settings differ from the request")
            elif "properties" not in native and stored.get("properties") != action.get("properties"):
                problems.append("the action's settings changed")
            return problems, f"{normalized}:{target}"

        return _run_field_write(
            request,
            action=FORM_ACTION_UPDATE,
            form_id=normalized,
            resource_id=f"{normalized}:{target}",
            detail="changed: " + ", ".join(sorted(native)),
            mutate=lambda client: client.update_form_action(normalized, target, native),
            verify=verify,
            kind="action",
        )


class NewsletterAdminFormActionReorderView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def post(self, request, form_id):
        normalized, form, _, error = _action_target(form_id)
        if error is not None:
            return error
        try:
            order = parse_action_order(request.data, form)
        except ActionPolicyError as exc:
            return _action_policy_response(exc)
        if order == [str(a.get("id")) for a in ordered_actions(form)]:
            return Response({**normalize_form_detail(form, subscription_list_segment_ids()), "unchanged": True})

        def verify(saved, _stored):
            return unexpected_action_changes(form, saved, target_id="", expected_order=order), normalized

        return _run_field_write(
            request,
            action=FORM_ACTION_REORDER,
            form_id=normalized,
            resource_id=normalized,
            detail="order: " + ",".join(order)[:200],
            mutate=lambda client: client.reorder_form_actions(normalized, order),
            verify=verify,
            kind="action",
        )


# Submissions (read-only, personal data) ---------------------------------------------

SUBMISSION_PAGE_SIZE = 25
SUBMISSION_MAX_PAGE_SIZE = 50
SUBMISSION_TIMEOUT = 10
MASKED_FIELD_TYPES = {"password"}
NON_VALUE_FIELD_TYPES = {"button", "freetext", "freehtml", "pagebreak", "captcha"}
# Columns Mautic adds to every results row; they are not submitted values.
NATIVE_RESULT_COLUMNS = {"form_id", "submission_id"}


def _private(response: Response) -> Response:
    """Submission data is personal: never stored by browsers or proxies."""
    response["Cache-Control"] = "no-store, private"
    response["Pragma"] = "no-cache"
    return response


def _submission_contact(submission: dict[str, Any]) -> dict[str, Any] | None:
    lead = submission.get("lead") if isinstance(submission.get("lead"), dict) else None
    if not lead or not lead.get("id"):
        return None
    # Only what identifies the contact; the rest of the profile stays in Mautic.
    return {"id": str(lead["id"]), "email": str(lead.get("email") or "")}


def _submission_values(submission: dict[str, Any], form: dict[str, Any]) -> list[dict[str, Any]]:
    results = submission.get("results") if isinstance(submission.get("results"), dict) else {}
    values, seen = [], set()
    for field in _ordered(_collection(form.get("fields"))):
        alias = str(field.get("alias") or "")
        field_type = str(field.get("type") or "")
        if not alias or field_type in NON_VALUE_FIELD_TYPES:
            continue
        seen.add(alias)
        raw = results.get(alias)
        masked = field_type in MASKED_FIELD_TYPES
        values.append({
            "alias": alias,
            "label": str(field.get("label") or alias),
            "type": field_type,
            "value": None if masked else ("" if raw is None else str(raw)),
            "masked": masked,
        })
    # Values of fields removed from the Form since: shown by alias only.
    for alias, raw in results.items():
        if alias not in seen and alias not in NATIVE_RESULT_COLUMNS:
            values.append({"alias": str(alias), "label": str(alias), "type": "", "value": "" if raw is None else str(raw),
                           "masked": False, "removedField": True})
    return values


def _submission_form_matches(submission: dict[str, Any], form_id: str) -> bool:
    form = submission.get("form") if isinstance(submission.get("form"), dict) else {}
    return str(form.get("id") or "") == str(form_id)


class NewsletterAdminFormSubmissionListView(APIView):
    """Native submissions of one Form, newest first. Read-only, uncached."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, form_id):
        normalized = _form_id(form_id)
        if normalized is None:
            return _private(_invalid_id_response())
        page = max(1, _int_param(request, "page", 1))
        page_size = max(1, min(_int_param(request, "page_size", SUBMISSION_PAGE_SIZE), SUBMISSION_MAX_PAGE_SIZE))
        form, error = _read_form(normalized)
        if error is not None:
            return _private(error)
        try:
            data = MauticClient().list_form_submissions(
                normalized, start=(page - 1) * page_size, limit=page_size, timeout=SUBMISSION_TIMEOUT)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _private(_provider_error_response(exc))
        rows = _collection(data.get("submissions"))
        try:
            total = max(0, int(data.get("total", len(rows))))
        except (TypeError, ValueError):
            total = len(rows)
        results = []
        for submission in rows:
            if not _submission_form_matches(submission, normalized):
                continue
            values = [v for v in _submission_values(submission, form) if not v["masked"] and v["value"]]
            results.append({
                "id": str(submission.get("id") or ""),
                "dateSubmitted": submission.get("dateSubmitted"),
                "contact": _submission_contact(submission),
                "preview": [{"label": v["label"], "value": v["value"][:120]} for v in values[:2]],
            })
        return _private(Response({
            "form": {"id": normalized, "name": str(form.get("name") or "")},
            "count": total,
            "page": page,
            "page_size": page_size,
            "num_pages": math.ceil(total / page_size) if total else 0,
            "results": results,
        }))


class NewsletterAdminFormSubmissionDetailView(APIView):
    """One native submission with its field values. Viewing is audited (IDs only)."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, form_id, submission_id):
        normalized = _form_id(form_id)
        submission_ref = _form_id(submission_id)
        if normalized is None or submission_ref is None:
            return _private(_error("Submission links use numeric Mautic IDs.", code="invalid_form_submission_id",
                                   http_status=status.HTTP_400_BAD_REQUEST))
        form, error = _read_form(normalized)
        if error is not None:
            return _private(error)
        try:
            submission = MauticClient().get_form_submission(normalized, submission_ref, timeout=SUBMISSION_TIMEOUT)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            if isinstance(exc, PermanentMauticError) and "HTTP 404" in str(exc):
                return _private(_error("Submission not found for this Form.", code="form_submission_not_found",
                                       http_status=status.HTTP_404_NOT_FOUND))
            return _private(_provider_error_response(exc))
        # Mautic resolves the submission by its own ID: refuse one of another Form.
        if not _submission_form_matches(submission, normalized):
            return _private(_error("Submission not found for this Form.", code="form_submission_not_found",
                                   http_status=status.HTTP_404_NOT_FOUND))
        record_identity_audit(
            action="form.submission.view",
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            actor=request.user,
            resource="form_submission",
            resource_id=f"{normalized}:{submission_ref}",
            auth_mode="service_account",
        )
        return _private(Response({
            "form": {"id": normalized, "name": str(form.get("name") or "")},
            "id": str(submission.get("id")),
            "dateSubmitted": submission.get("dateSubmitted"),
            "contact": _submission_contact(submission),
            "values": _submission_values(submission, form),
        }))


class NewsletterAdminFormUsageView(APIView):
    """Read-only: Campaigns and point actions using the Form, and its stored submissions."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, form_id):
        normalized = _form_id(form_id)
        if normalized is None:
            return _invalid_id_response()
        try:
            usage = MauticClient().get_form_usage(normalized, timeout=SUBMISSION_TIMEOUT)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        return Response({
            "campaignSources": _collection(usage.get("campaignSources")),
            "campaignEvents": _collection(usage.get("campaignEvents")),
            "pointActions": _collection(usage.get("pointActions")),
            "submissions": usage.get("submissions") if isinstance(usage.get("submissions"), dict) else {"total": 0, "latest": None},
        })


# Native preview and embedding (read-only) -----------------------------------------
#
# Mautic renders a Form once per save into `cachedHtml` and serves that HTML at
# its public routes: /form/{id} (full page), /form/generate.js?id={id} (the
# recommended JavaScript embed) and /form/embed/{id}. All three answer only for
# published Forms. Mautic's own draft preview (/s/forms/preview/{id}) needs a
# Mautic login session, which ECP admins do not have, so a draft is previewed
# from its saved `cachedHtml` in a fully sandboxed frame: native markup and
# styles, no scripts, no network, no submission. Nothing here publishes a Form
# or writes to Mautic.

PREVIEW_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; form-action 'none'"
_SCRIPT_TAGS = re.compile(r"<script\b[^>]*>.*?</script\s*>|<script\b[^>]*/?>", re.IGNORECASE | re.DOTALL)
_SUBMIT_ACTION = re.compile(r'<form\b[^>]*\baction="(https?://[^"\s<>]+?)/form/submit\?formId=(\d+)"', re.IGNORECASE)


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def validate_public_url(value, *, require_https: bool | None = None) -> str | None:
    """Mautic's configured public base URL, or None when it is not a plain
    http(s) address (no credentials, query, fragment or markup characters).

    Visitors submit Forms to this address, so outside DEBUG it must be https;
    plain http is accepted for loopback hosts (local development) only."""
    if require_https is None:
        require_https = not settings.DEBUG
    text = str(value or "").strip().rstrip("/")
    if not text or len(text) > 255 or any(char in text for char in "\"'<> \t\r\n\\`"):
        return None
    try:
        parts = urlsplit(text)
        parts.port  # noqa: B018 - raises on an invalid port
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        return None
    if parts.query or parts.fragment:
        return None
    if require_https and parts.scheme != "https" and parts.hostname not in LOOPBACK_HOSTS:
        return None
    return text


def _base_key(value: str | None) -> tuple | None:
    """Scheme, host, effective port and path: two spellings of one address compare equal."""
    if not value:
        return None
    try:
        parts = urlsplit(value)
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
    except ValueError:
        return None
    return parts.scheme.lower(), (parts.hostname or "").lower(), port, parts.path.rstrip("/")


SUBMIT_ADDRESS_MESSAGES = {
    "match": "Visitors submit to Mautic's public address.",
    "mismatch": (
        "Mautic stored a different submit address for this Form than its public address. Submissions may be "
        "saved while visitors see no success message or redirect, or may not reach Mautic at all. Saving any "
        "change to the Form through ECP stores the public address again."
    ),
    "missing": "Mautic has not rendered this Form's submit address yet. Save the Form once.",
    "public_url_unavailable": "Mautic's public address is not available, so the submit address cannot be checked.",
}


def submit_address_status(form: dict[str, Any]) -> dict[str, Any]:
    """Compare the submit address in Mautic's stored Form HTML with Mautic's
    trusted public address (site_url, from the plugin). Read-only."""
    form_id = str(form.get("id") or "")
    stored = native_submit_base(str(form.get("cachedHtml") or ""), form_id)
    expected = _public_base_url()
    if expected is None:
        state = "public_url_unavailable"
    elif stored is None:
        state = "missing"
    else:
        state = "match" if _base_key(stored) == _base_key(expected) else "mismatch"
    return {"status": state, "stored": stored, "expected": expected, "message": SUBMIT_ADDRESS_MESSAGES[state]}


def _public_base_url() -> str | None:
    try:
        capabilities = marketing_cache.cached_value(
            "mautic-bridge-capabilities", [], lambda: MauticClient().get_marketing_bridge_capabilities(),
            ttl=marketing_cache.reference_ttl(),
        )
    except (TemporaryMauticError, PermanentMauticError):
        return None
    return validate_public_url(capabilities.get("publicUrl") if isinstance(capabilities, dict) else None)


def _is_live(form: dict[str, Any]) -> bool:
    """Published and inside its publish window: what Mautic's public routes require."""
    if not _provider_bool(form.get("isPublished")):
        return False
    now = timezone.now()

    def moment(value):
        parsed = parse_datetime(str(value or ""))
        if parsed is not None and timezone.is_naive(parsed):
            parsed = timezone.make_aware(parsed, dt_timezone.utc)  # Mautic stores UTC
        return parsed

    up, down = moment(form.get("publishUp")), moment(form.get("publishDown"))
    return not (up and up > now) and not (down and down <= now)


def native_submit_base(html: str, form_id: str) -> str | None:
    match = _SUBMIT_ACTION.search(html or "")
    return match.group(1) if match and match.group(2) == str(form_id) else None


def preview_document(html: str) -> str:
    """Mautic's saved Form HTML as a self-contained, inert document."""
    body = _SCRIPT_TAGS.sub("", html or "")
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"{PREVIEW_CSP}\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<style>body{margin:16px;font-family:Arial,Helvetica,sans-serif;color:#1B2A4A;background:#fff}</style>"
        f"</head><body>{body}</body></html>"
    )


def embed_snippets(base: str, form_id: str) -> list[dict[str, str]]:
    """Mautic's own "automatic" embed codes (FormBundle details.html.twig)."""
    return [
        {
            "method": "javascript",
            "label": "JavaScript (recommended)",
            "code": f'<script type="text/javascript" src="{base}/form/generate.js?id={form_id}"></script>',
            "help": "Paste where the Form should appear. Later changes in Mautic show automatically.",
        },
        {
            "method": "iframe",
            "label": "iframe",
            "code": (
                f'<iframe src="{base}/form/{form_id}" width="300" height="300" title="Embedded form">'
                "<p>Your browser does not support iframes.</p></iframe>"
            ),
            "help": "Adjust the width and height so the Form fits.",
        },
    ]


class NewsletterAdminFormPreviewView(APIView):
    """The saved native Form as Mautic renders it, for a sandboxed frame."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, form_id):
        normalized = _form_id(form_id)
        if normalized is None:
            return _private(_invalid_id_response())
        form, error = _read_form(normalized)
        if error is not None:
            return _private(error)
        html = str(form.get("cachedHtml") or "")
        if "<form" not in html.lower():
            return _private(_error("Mautic has not rendered this Form yet. Save it once, then preview again.",
                                   code="form_preview_unavailable", http_status=status.HTTP_409_CONFLICT))
        live = _is_live(form)
        base = _public_base_url()
        return _private(Response({
            "formId": normalized,
            "name": str(form.get("name") or ""),
            "isPublished": _provider_bool(form.get("isPublished")),
            "isLive": live,
            "savedAt": form.get("dateModified") or form.get("dateAdded"),
            "document": preview_document(html),
            "liveUrl": f"{base}/form/{normalized}" if live and base else None,
            "note": (
                "This is the last saved version, rendered by Mautic. Unsaved changes in the editor are not included."
            ),
        }))


class NewsletterAdminFormEmbedView(APIView):
    """Native embed codes for a Form, built from Mautic's configured public URL."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, form_id):
        normalized = _form_id(form_id)
        if normalized is None:
            return _invalid_id_response()
        form, error = _read_form(normalized)
        if error is not None:
            return error
        base = _public_base_url()
        if base is None:
            return _error("Mautic's public address is not available, so embed codes cannot be generated.",
                          code="form_public_url_unavailable", http_status=status.HTTP_503_SERVICE_UNAVAILABLE)
        live = _is_live(form)
        submit = submit_address_status(form)
        submit_base = submit["stored"]
        warnings = []
        if not live:
            warnings.append("This Form is not published, so the embed codes will show nothing until it is published.")
        if submit["status"] == "mismatch":
            warnings.append(
                f"Mautic stored this Form's submit address as {submit_base}, which differs from its public address "
                f"{base}. Submissions may be saved while visitors see no success message or redirect, or may not "
                "reach Mautic at all. Saving any change to the Form through ECP stores the public address again."
            )
        return Response({
            "formId": normalized,
            "name": str(form.get("name") or ""),
            "isPublished": _provider_bool(form.get("isPublished")),
            "isLive": live,
            "publicUrl": base,
            "formUrl": f"{base}/form/{normalized}",
            "submitBase": submit_base,
            "submitAddress": submit,
            "methods": embed_snippets(base, normalized),
            "warnings": warnings,
        })
