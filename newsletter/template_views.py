from __future__ import annotations

import logging
import math
import re
from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from django.db import DatabaseError
from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import marketing_cache
from .campaign_services import deliver_temporary_test_email
from .email_design_services import (
    TemplateSaveInProgress,
    copy_template_design,
    delete_template_design,
    html_fingerprint,
    prepare_email_design,
    save_template_design,
    template_design_state,
    template_save_lock,
)
from .marketing_permissions import HasMarketingHubAccess
from .models import NewsletterEmailDesign

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.operations import (
    NEWSLETTER_TEST_SEND,
    TEMPLATE_CREATE,
    TEMPLATE_DELETE,
    TEMPLATE_DUPLICATE,
    TEMPLATE_UPDATE,
)
from .mautic_identity_execution import run_interactive_mutation


logger = logging.getLogger(__name__)

SYSTEM_TOKENS = [
    {
        "token": "{unsubscribe_url}",
        "label": "Unsubscribe URL",
        "group": "Email",
    },
    {
        "token": "{webview_url}",
        "label": "Web View URL",
        "group": "Email",
    },
]

_TEMPLATE_FIELDS = {
    "name",
    "subject",
    "preheaderText",
    "fromName",
    "fromAddress",
    "plainText",
    "customHtml",
    "isPublished",
    "category",
    "template",
}


def _provider_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    return bool(value)


def _parse_bool(value, *, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{field_name} must be a boolean.")


def _normalize_template(email: dict[str, Any]) -> dict[str, Any]:
    email_id = email.get("id")
    category = email.get("category")
    if isinstance(category, dict):
        normalized_category = {
            "id": str(category.get("id")) if category.get("id") is not None else None,
            "title": str(category.get("title") or category.get("name") or ""),
        }
    elif category:
        normalized_category = {"id": str(category), "title": ""}
    else:
        normalized_category = None

    return {
        "id": str(email_id) if email_id is not None else None,
        "name": str(email.get("name") or "").strip(),
        "subject": str(email.get("subject") or ""),
        "preheaderText": str(email.get("preheaderText") or ""),
        "fromName": str(email.get("fromName") or ""),
        "fromAddress": str(email.get("fromAddress") or ""),
        "plainText": str(email.get("plainText") or ""),
        "customHtml": str(email.get("customHtml") or ""),
        "emailType": str(email.get("emailType") or ""),
        "category": normalized_category,
        "template": str(email.get("template") or ""),
        "isPublished": _provider_bool(email.get("isPublished", False)),
        "dateAdded": email.get("dateAdded"),
        "dateModified": email.get("dateModified"),
        "sentCount": email.get("sentCount"),
        "readCount": email.get("readCount"),
    }


def _parse_template_payload(data, *, partial: bool = False) -> dict[str, Any]:
    unsupported = sorted(set(data.keys()) - _TEMPLATE_FIELDS)
    if unsupported:
        raise ValueError(
            "Unsupported Newsletter Template field(s): " + ", ".join(unsupported)
        )

    payload: dict[str, Any] = {}

    if not partial or "name" in data:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("Newsletter Template name is required.")
        if len(name) > 190:
            raise ValueError("Newsletter Template name cannot exceed 190 characters.")
        payload["name"] = name

    text_fields = (
        "subject",
        "preheaderText",
        "fromName",
        "plainText",
        "customHtml",
        "template",
    )
    for field in text_fields:
        if field not in data:
            continue
        value = str(data.get(field) or "")
        if field in {"subject", "fromName"}:
            value = value.strip()
        if field == "subject" and len(value) > 190:
            raise ValueError("Newsletter Template subject cannot exceed 190 characters.")
        payload[field] = value

    if "fromAddress" in data:
        from_address = str(data.get("fromAddress") or "").strip()
        if from_address:
            try:
                validate_email(from_address)
            except DjangoValidationError as exc:
                raise ValueError(
                    "Newsletter Template fromAddress must be a valid email address."
                ) from exc
        payload["fromAddress"] = from_address

    if "category" in data:
        category = data.get("category")
        if category in (None, ""):
            payload["category"] = ""
        else:
            try:
                category_id = int(category)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "Newsletter Template category must be a Mautic Category ID."
                ) from exc
            if category_id <= 0:
                raise ValueError(
                    "Newsletter Template category must be a Mautic Category ID."
                )
            payload["category"] = category_id

    if "isPublished" in data:
        payload["isPublished"] = _parse_bool(
            data.get("isPublished"),
            field_name="Newsletter Template isPublished",
        )
    elif not partial:
        # Templates created from ECP are drafts unless staff explicitly publish.
        payload["isPublished"] = False

    if partial and not payload:
        raise ValueError("At least one Newsletter Template field is required.")

    return payload


# Visual-builder fields: handled by ECP, never forwarded to Mautic.
_VISUAL_FIELDS = ("design", "mjml", "baseFingerprint")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


class TemplateChangedError(Exception):
    """The Template's HTML in Mautic is not the version the editor loaded."""


def _split_visual_fields(data) -> tuple[dict[str, Any], dict[str, Any]]:
    plain = {key: data.get(key) for key in data.keys() if key not in _VISUAL_FIELDS}
    visual = {key: data.get(key) for key in _VISUAL_FIELDS if key in data}
    return plain, visual


def _prepare_visual_design(visual: dict[str, Any], plain: dict[str, Any]):
    """Validate + compile a submitted visual design, or None for HTML-mode saves."""
    if "design" not in visual and "mjml" not in visual:
        return None
    if "design" not in visual or "mjml" not in visual:
        raise ValueError("A visual design needs both design and mjml.")
    if "customHtml" in plain:
        raise ValueError(
            "customHtml is generated from the visual design; send one or the other."
        )
    return prepare_email_design(visual["design"], visual["mjml"])


def _parse_base_fingerprint(visual: dict[str, Any], *, required: bool):
    value = visual.get("baseFingerprint")
    if value in (None, ""):
        if required:
            raise ValueError(
                "baseFingerprint is required to save a visual design over an existing Template."
            )
        return None
    if not isinstance(value, str) or not _FINGERPRINT_RE.match(value):
        raise ValueError("baseFingerprint must be a SHA-256 hex digest.")
    return value


def _design_payload(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": state["status"],
        "design": state["design"],
        "htmlFingerprint": state["html_fingerprint"],
        "updatedAt": state["updated_at"],
    }


def _template_with_design(template: dict[str, Any]) -> dict[str, Any]:
    """The normalized Template plus the state of its ECP visual design."""
    if template.get("id"):
        state = template_design_state(template["id"], template["customHtml"])
        template["visualDesign"] = _design_payload(state)
    return template


def _design_not_saved_response(template: dict[str, Any], *, created: bool) -> Response:
    # Mautic and PostgreSQL are separate systems: the Template change is real,
    # only the editable design is missing. Say so instead of reporting success.
    action = "created" if created else "saved"
    return Response(
        {
            "detail": (
                f"The Template was {action} in Mautic, but its visual design could not "
                "be stored. Its HTML is safe; reopen it to continue in HTML mode, or "
                "save the visual design again."
            ),
            "code": "design_not_saved",
            "designSaved": False,
            "template": template,
        },
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


def _store_template_design(request, template_id, prepared, *, fallback_email, created):
    """Persist the design against the HTML Mautic actually stored.

    Mautic normalizes HTML on save, so the fingerprint is taken from a fresh
    read, never from the submitted HTML.
    """
    try:
        stored = _normalize_template(MauticClient().get_email_template(template_id))
    except (TemporaryMauticError, PermanentMauticError):
        logger.warning(
            "Could not read back Mautic template id=%s to store its visual design",
            template_id,
            exc_info=True,
        )
        return _design_not_saved_response(
            _template_with_design(_normalize_template(fallback_email)),
            created=created,
        )
    try:
        save_template_design(template_id, prepared, stored["customHtml"], user=request.user)
    except DatabaseError:
        logger.exception("Could not store the visual design of Mautic template id=%s", template_id)
        return _design_not_saved_response(_template_with_design(stored), created=created)
    return Response(
        _template_with_design(stored),
        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
    )


def _update_template_if_unchanged(client, template_id, payload, base_fingerprint):
    if base_fingerprint is not None:
        current = _normalize_template(MauticClient().get_email_template(template_id))
        if html_fingerprint(current["customHtml"]) != base_fingerprint:
            raise TemplateChangedError
    return client.update_email_template(template_id, payload)


def _collection_values(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        rows = value.values()
    elif isinstance(value, list):
        rows = value
    else:
        return []
    return [row for row in rows if isinstance(row, dict)]


def _normalize_category(category: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(category.get("id")) if category.get("id") is not None else None,
        "title": str(category.get("title") or category.get("name") or ""),
        "alias": str(category.get("alias") or ""),
        "bundle": str(category.get("bundle") or ""),
        "color": str(category.get("color") or ""),
    }


def _normalize_theme(theme: dict[str, Any]) -> dict[str, Any]:
    config = theme.get("config") if isinstance(theme.get("config"), dict) else {}
    return {
        "key": str(theme.get("key") or ""),
        "name": str(theme.get("name") or config.get("name") or theme.get("key") or ""),
        "features": config.get("features") if isinstance(config.get("features"), list) else [],
        "builder": config.get("builder") if isinstance(config.get("builder"), list) else [],
    }


def _field_tokens(fields: dict[str, Any], *, group: str, prefix: str) -> list[dict[str, str]]:
    tokens = []
    for field in _collection_values(fields.get("fields")):
        alias = str(field.get("alias") or "").strip()
        if not alias:
            continue
        label = str(field.get("label") or alias)
        tokens.append(
            {
                "token": f"{{{prefix}={alias}}}",
                "label": label,
                "group": group,
            }
        )
    return tokens


def _provider_error_response(exc):
    message = str(exc)
    if isinstance(exc, PermanentMauticError):
        if "HTTP 404" in message or "is not a Mautic template email" in message:
            raise Http404
        if any(f"HTTP {code}" in message for code in (400, 409, 422)):
            return Response(
                {"detail": message},
                status=status.HTTP_400_BAD_REQUEST,
            )
    return Response(
        {"detail": message or "Mautic Newsletter Template operation failed."},
        status=status.HTTP_502_BAD_GATEWAY,
    )


class NewsletterAdminTemplateListCreateView(APIView):
    """List and create reusable provider-backed Mautic email Templates."""

    permission_classes = [HasMarketingHubAccess]
    default_page_size = 25
    max_page_size = 100

    @marketing_cache.cached_get("templates", marketing_cache.list_ttl)
    def get(self, request):
        try:
            page = max(1, int(request.query_params.get("page", 1)))
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(
                request.query_params.get("page_size", self.default_page_size)
            )
        except (TypeError, ValueError):
            page_size = self.default_page_size
        page_size = max(1, min(page_size, self.max_page_size))
        search = str(request.query_params.get("search", "") or "").strip()

        params = {
            "start": (page - 1) * page_size,
            "limit": page_size,
        }
        if search:
            params["search"] = search

        try:
            data = MauticClient().list_email_templates(**params)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        rows = data.get("emails")
        if not isinstance(rows, list):
            rows = []
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
                "results": [
                    _normalize_template(email)
                    for email in rows
                    if isinstance(email, dict)
                ],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        plain, visual = _split_visual_fields(request.data)
        try:
            prepared = _prepare_visual_design(visual, plain)
            payload = _parse_template_payload(plain)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if prepared is not None:
            payload["customHtml"] = prepared.html

        try:
            email, error_response = run_interactive_mutation(
                request,
                action=TEMPLATE_CREATE,
                resource="template",
                mutate=lambda client: client.create_email_template(payload),
                client_factory=MauticClient,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        if prepared is not None:
            return _store_template_design(
                request,
                str(email.get("id")),
                prepared,
                fallback_email=email,
                created=True,
            )
        return Response(
            _template_with_design(_normalize_template(email)),
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminTemplateDetailView(APIView):
    """Read, update, or delete one reusable Mautic email Template."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, template_id):
        try:
            email = MauticClient().get_email_template(template_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _template_with_design(_normalize_template(email)),
            status=status.HTTP_200_OK,
        )

    def patch(self, request, template_id):
        plain, visual = _split_visual_fields(request.data)
        try:
            prepared = _prepare_visual_design(visual, plain)
            # A visual save may change nothing but the design itself.
            payload = (
                _parse_template_payload(plain, partial=True)
                if plain or prepared is None
                else {}
            )
            base_fingerprint = _parse_base_fingerprint(visual, required=prepared is not None)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if prepared is not None:
            payload["customHtml"] = prepared.html

        try:
            with template_save_lock(template_id):
                email, error_response = run_interactive_mutation(
                    request,
                    action=TEMPLATE_UPDATE,
                    resource="template",
                    resource_id=template_id,
                    mutate=lambda client: _update_template_if_unchanged(
                        client, template_id, payload, base_fingerprint
                    ),
                    client_factory=MauticClient,
                )
                if error_response is not None:
                    return error_response
                if prepared is not None:
                    return _store_template_design(
                        request,
                        template_id,
                        prepared,
                        fallback_email=email,
                        created=False,
                    )
        except TemplateSaveInProgress:
            return Response(
                {
                    "detail": "This Template is being saved by another request. Try again in a moment.",
                    "code": "template_save_in_progress",
                },
                status=status.HTTP_409_CONFLICT,
            )
        except TemplateChangedError:
            return Response(
                {
                    "detail": (
                        "This Template was changed since you opened it. Your changes were "
                        "not saved; reopen it to see the current version."
                    ),
                    "code": "template_changed",
                },
                status=status.HTTP_409_CONFLICT,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _template_with_design(_normalize_template(email)),
            status=status.HTTP_200_OK,
        )

    def delete(self, request, template_id):
        try:
            _, error_response = run_interactive_mutation(
                request,
                action=TEMPLATE_DELETE,
                resource="template",
                resource_id=template_id,
                mutate=lambda client: client.delete_email_template(template_id),
                client_factory=MauticClient,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        # Only after Mautic confirmed the deletion.
        delete_template_design(template_id)
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminTemplateDuplicateView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def post(self, request, template_id):
        name = str(request.data.get("name") or "").strip()
        if name and len(name) > 190:
            return Response(
                {"detail": "Newsletter Template name cannot exceed 190 characters."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            email, error_response = run_interactive_mutation(
                request,
                action=TEMPLATE_DUPLICATE,
                resource="template",
                resource_id=template_id,
                mutate=lambda client: client.duplicate_email_template(
                    template_id,
                    name=name or None,
                ),
                client_factory=MauticClient,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        duplicate = _normalize_template(email)
        duplicate["designCopied"] = _copy_duplicate_design(request, template_id, duplicate)
        return Response(_template_with_design(duplicate), status=status.HTTP_201_CREATED)


def _copy_duplicate_design(request, source_id, duplicate: dict[str, Any]) -> bool:
    """Copy an in-sync source design to the duplicate. The duplicate exists
    regardless; a failed copy only leaves it HTML-only."""
    if not duplicate.get("id"):
        return False
    if not NewsletterEmailDesign.objects.filter(mautic_email_id=str(source_id)).exists():
        return False
    try:
        client = MauticClient()
        source = _normalize_template(client.get_email_template(source_id))
        # Fingerprint the duplicate as Mautic stored it.
        target = _normalize_template(client.get_email_template(duplicate["id"]))
        duplicate["customHtml"] = target["customHtml"]
        copied = copy_template_design(
            source_id,
            source["customHtml"],
            duplicate["id"],
            target["customHtml"],
            user=request.user,
        )
    except (TemporaryMauticError, PermanentMauticError, DatabaseError):
        logger.warning(
            "Could not copy the visual design of Mautic template id=%s to id=%s",
            source_id,
            duplicate.get("id"),
            exc_info=True,
        )
        return False
    return copied is not None


class NewsletterAdminTemplatePreviewView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request, template_id):
        try:
            email = MauticClient().get_email_template(template_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        template = _template_with_design(_normalize_template(email))
        return Response(
            {
                "type": "raw_html",
                "tokenResolution": "placeholders_only",
                "template": template,
                "html": template["customHtml"],
                "plainText": template["plainText"],
            },
            status=status.HTTP_200_OK,
        )


def _template_test_email_payload(template: dict[str, Any]) -> dict[str, Any]:
    """A published throwaway copy of a template for exactly one test send.

    Mautic bumps the sent count and writes email_stats rows for whatever email
    it sends, so sending the template itself would change the Sent/Read counts
    shown in the Templates list.
    """
    name = template["name"] or f"Template {template['id']}"
    payload: dict[str, Any] = {
        "name": f"{name} - Test"[:190],
        "subject": template["subject"],
        "customHtml": template["customHtml"],
        "emailType": "template",
        "isPublished": True,
    }
    for field in ("preheaderText", "fromName", "fromAddress", "plainText", "template"):
        if template[field]:
            payload[field] = template[field]
    return payload


def _parse_test_recipient(value) -> str:
    recipient = str(value or "").strip().lower()
    if not recipient:
        raise ValueError("Test recipient email is required.")
    try:
        validate_email(recipient)
    except DjangoValidationError as exc:
        raise ValueError("Test recipient email must be valid.") from exc
    return recipient


def send_template_test_email(template_id, recipient, *, provider_client, send_client):
    template = _normalize_template(provider_client.get_email_template(template_id))
    if not template["subject"]:
        raise ValueError("Add a subject to this Template before sending a test.")
    if not (template["customHtml"].strip() or template["plainText"].strip()):
        raise ValueError(
            "Add HTML or plain-text content to this Template before sending a test."
        )

    delivery = deliver_temporary_test_email(
        _template_test_email_payload(template),
        recipient,
        provider_client=provider_client,
        send_client=send_client,
        label="template",
    )
    return {"recipient_email": recipient, **delivery}


class NewsletterAdminTemplateTestSendView(APIView):
    """Send one Template to one address through a temporary Mautic copy."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, template_id):
        try:
            recipient = _parse_test_recipient(request.data.get("email"))
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        try:
            result, error_response = run_interactive_mutation(
                request,
                action=NEWSLETTER_TEST_SEND,
                resource="template",
                resource_id=template_id,
                mutate=lambda client: send_template_test_email(
                    template_id,
                    recipient,
                    provider_client=MauticClient(),
                    send_client=client,
                ),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        return Response(
            {
                "success": True,
                "recipient_email": result["recipient_email"],
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminTemplateTokensView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            client = MauticClient()
            contact_fields = marketing_cache.fields(client, "contact", limit=500)
            company_fields = marketing_cache.fields(client, "company", limit=500)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        tokens = [
            *SYSTEM_TOKENS,
            *_field_tokens(contact_fields, group="Contact Fields", prefix="contactfield"),
            *_field_tokens(company_fields, group="Company Fields", prefix="companyfield"),
        ]
        return Response(
            {
                "total": len(tokens),
                "results": tokens,
                "source": "mautic_rest_fields",
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminTemplateCategoriesView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            data = marketing_cache.categories(MauticClient(), limit=500)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        categories = [
            _normalize_category(category)
            for category in _collection_values(data.get("categories"))
        ]
        email_categories = [
            category
            for category in categories
            if category["bundle"] in {"email", ""}
        ]
        return Response(
            {
                "count": len(email_categories),
                "results": email_categories,
                "source": "mautic_rest_categories",
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminTemplateThemesView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            data = marketing_cache.themes(MauticClient())
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        themes = [
            _normalize_theme(theme)
            for theme in _collection_values(data.get("themes"))
        ]
        email_themes = [
            theme
            for theme in themes
            if not theme["features"] or "email" in theme["features"]
        ]
        return Response(
            {
                "count": len(email_themes),
                "results": email_themes,
                "source": "mautic_rest_themes",
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminTemplateUsageView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request, template_id):
        try:
            template = _normalize_template(MauticClient().get_email_template(template_id))
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            {
                "available": False,
                "template": {
                    "id": template["id"],
                    "name": template["name"],
                    "sentCount": template["sentCount"],
                    "readCount": template["readCount"],
                },
                "dependencies": [],
                "deletePolicy": "provider_enforced",
                "detail": (
                    "No verified Mautic REST endpoint exposes campaign/template "
                    "dependency usage for template emails. Delete remains guarded "
                    "by Mautic provider validation."
                ),
                "bridgeRequired": True,
            },
            status=status.HTTP_200_OK,
        )
