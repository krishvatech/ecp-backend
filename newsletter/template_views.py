from __future__ import annotations

import math
from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import marketing_cache
from .campaign_services import deliver_temporary_test_email
from .marketing_permissions import HasMarketingHubAccess

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.operations import (
    NEWSLETTER_TEST_SEND,
    TEMPLATE_CREATE,
    TEMPLATE_DELETE,
    TEMPLATE_DUPLICATE,
    TEMPLATE_UPDATE,
)
from .mautic_identity_execution import run_interactive_mutation


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
        try:
            payload = _parse_template_payload(request.data)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

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

        return Response(
            _normalize_template(email),
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
            _normalize_template(email),
            status=status.HTTP_200_OK,
        )

    def patch(self, request, template_id):
        try:
            payload = _parse_template_payload(request.data, partial=True)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            email, error_response = run_interactive_mutation(
                request,
                action=TEMPLATE_UPDATE,
                resource="template",
                resource_id=template_id,
                mutate=lambda client: client.update_email_template(template_id, payload),
                client_factory=MauticClient,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        if error_response is not None:
            return error_response

        return Response(
            _normalize_template(email),
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

        return Response(_normalize_template(email), status=status.HTTP_201_CREATED)


class NewsletterAdminTemplatePreviewView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request, template_id):
        try:
            email = MauticClient().get_email_template(template_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        template = _normalize_template(email)
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
