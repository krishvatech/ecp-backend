from __future__ import annotations

import math
from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError


_TEMPLATE_FIELDS = {
    "name",
    "subject",
    "preheaderText",
    "fromName",
    "fromAddress",
    "plainText",
    "customHtml",
    "isPublished",
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

    permission_classes = [IsStaffOrSuperuser]
    default_page_size = 25
    max_page_size = 100

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
            email = MauticClient().create_email_template(payload)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_template(email),
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminTemplateDetailView(APIView):
    """Read, update, or delete one reusable Mautic email Template."""

    permission_classes = [IsStaffOrSuperuser]

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
            email = MauticClient().update_email_template(
                template_id,
                payload,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_template(email),
            status=status.HTTP_200_OK,
        )

    def delete(self, request, template_id):
        try:
            MauticClient().delete_email_template(template_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)
