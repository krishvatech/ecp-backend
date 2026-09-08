from __future__ import annotations

import math
import re
from typing import Any

from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError


_PROPERTY_ALIAS_RE = re.compile(r"^[A-Za-z0-9_]+$")
_POINT_FIELDS = {
    "name",
    "description",
    "type",
    "delta",
    "repeatable",
    "isPublished",
    "properties",
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


def _points_from_response(data: dict[str, Any]) -> list[dict[str, Any]]:
    points = data.get("points") or []
    if isinstance(points, dict):
        return [item for item in points.values() if isinstance(item, dict)]
    if isinstance(points, list):
        return [item for item in points if isinstance(item, dict)]
    return []


def _normalize_point_action(
    point: dict[str, Any],
    *,
    type_labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    point_id = point.get("id")

    delta = point.get("delta")
    try:
        delta = int(delta) if delta not in (None, "") else 0
    except (TypeError, ValueError):
        delta = 0

    point_type = str(point.get("type") or "").strip()
    properties = point.get("properties")
    if not isinstance(properties, dict):
        properties = {}

    category = point.get("category")
    group = point.get("group")

    return {
        "id": str(point_id) if point_id is not None else None,
        "name": str(point.get("name") or "").strip(),
        "description": str(point.get("description") or ""),
        "type": point_type,
        "type_label": (
            str((type_labels or {}).get(point_type) or point_type)
            if point_type
            else ""
        ),
        "delta": delta,
        "repeatable": _provider_bool(point.get("repeatable", False)),
        "isPublished": _provider_bool(
            point.get("isPublished", point.get("is_published", False))
        ),
        "properties": properties,
        "category": category if isinstance(category, dict) else None,
        "group": group if isinstance(group, dict) else None,
        "dateAdded": point.get("dateAdded"),
        "dateModified": point.get("dateModified"),
        "publishUp": point.get("publishUp"),
        "publishDown": point.get("publishDown"),
    }


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


def _flatten_properties(properties) -> dict[str, Any]:
    if properties in (None, ""):
        return {}
    if not isinstance(properties, dict):
        raise ValueError("Point Action properties must be an object.")

    payload = {}
    for raw_alias, value in properties.items():
        alias = str(raw_alias or "").strip()
        if not alias or not _PROPERTY_ALIAS_RE.fullmatch(alias):
            raise ValueError(
                "Point Action property names may contain only letters, numbers, and underscores."
            )
        if isinstance(value, dict):
            raise ValueError(
                f"Point Action property '{alias}' cannot be a nested object."
            )
        payload[f"properties[{alias}]"] = value
    return payload


def _parse_point_action_payload(data, *, partial: bool = False) -> dict[str, Any]:
    unsupported = sorted(set(data.keys()) - _POINT_FIELDS)
    if unsupported:
        raise ValueError(
            "Unsupported Point Action field(s): " + ", ".join(unsupported)
        )

    payload: dict[str, Any] = {}

    if not partial or "name" in data:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("Point Action name is required.")
        payload["name"] = name

    if "description" in data:
        payload["description"] = str(data.get("description") or "").strip()

    if not partial or "type" in data:
        point_type = str(data.get("type") or "").strip()
        if not point_type:
            raise ValueError("Point Action type is required.")
        payload["type"] = point_type

    if not partial or "delta" in data:
        value = data.get("delta")
        if isinstance(value, bool):
            raise ValueError("Point Action delta must be an integer.")
        try:
            payload["delta"] = int(str(value).strip())
        except (TypeError, ValueError):
            raise ValueError("Point Action delta must be an integer.")

    if "repeatable" in data:
        payload["repeatable"] = _parse_bool(
            data.get("repeatable"),
            field_name="Point Action repeatable",
        )

    if "isPublished" in data:
        payload["isPublished"] = _parse_bool(
            data.get("isPublished"),
            field_name="Point Action isPublished",
        )

    if "properties" in data:
        payload.update(_flatten_properties(data.get("properties")))

    if partial and not payload:
        raise ValueError("At least one Point Action field is required.")

    return payload


def _point_provider_error_response(exc):
    message = str(exc)
    if isinstance(exc, PermanentMauticError):
        if "HTTP 404" in message:
            raise Http404
        if any(f"HTTP {code}" in message for code in (400, 409, 422)):
            return Response(
                {"detail": message},
                status=status.HTTP_400_BAD_REQUEST,
            )
    return Response(
        {"detail": message or "Mautic Point operation failed."},
        status=status.HTTP_502_BAD_GATEWAY,
    )


def _validate_point_type(client: MauticClient, point_type: str) -> dict[str, str]:
    type_labels = client.list_point_action_types()
    if point_type not in type_labels:
        raise ValueError(
            f"Unsupported Mautic Point Action type: {point_type}."
        )
    return type_labels


class NewsletterAdminPointActionTypesView(APIView):
    """Return Point Action types exposed by the connected Mautic instance."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            type_labels = MauticClient().list_point_action_types()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _point_provider_error_response(exc)

        return Response(
            {
                "types": [
                    {"value": value, "label": label}
                    for value, label in type_labels.items()
                ]
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminPointActionListCreateView(APIView):
    """List and create provider-backed Mautic Point Actions."""

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

        client = MauticClient()
        try:
            data = client.list_point_actions(**params)
            type_labels = client.list_point_action_types()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _point_provider_error_response(exc)

        points = _points_from_response(data)
        try:
            total = max(0, int(data.get("total", len(points))))
        except (TypeError, ValueError):
            total = len(points)

        return Response(
            {
                "count": total,
                "page": page,
                "page_size": page_size,
                "num_pages": math.ceil(total / page_size) if total else 0,
                "results": [
                    _normalize_point_action(point, type_labels=type_labels)
                    for point in points
                ],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        try:
            payload = _parse_point_action_payload(request.data)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        client = MauticClient()
        try:
            type_labels = _validate_point_type(client, payload["type"])
            point = client.create_point_action(payload)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _point_provider_error_response(exc)

        return Response(
            _normalize_point_action(point, type_labels=type_labels),
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminPointActionDetailView(APIView):
    """Read, update, or delete one provider-backed Mautic Point Action."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, point_id):
        client = MauticClient()
        try:
            point = client.get_point_action(point_id)
            type_labels = client.list_point_action_types()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _point_provider_error_response(exc)

        return Response(
            _normalize_point_action(point, type_labels=type_labels),
            status=status.HTTP_200_OK,
        )

    def patch(self, request, point_id):
        try:
            payload = _parse_point_action_payload(request.data, partial=True)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        client = MauticClient()
        try:
            type_labels = client.list_point_action_types()
            if "type" in payload and payload["type"] not in type_labels:
                return Response(
                    {
                        "detail": (
                            "Unsupported Mautic Point Action type: "
                            f"{payload['type']}."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            has_properties = any(
                str(key).startswith("properties[")
                for key in payload
            )
            if has_properties and "type" not in payload:
                existing = client.get_point_action(point_id)
                existing_type = str(existing.get("type") or "").strip()
                if existing_type:
                    payload["type"] = existing_type

            point = client.update_point_action(point_id, payload)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _point_provider_error_response(exc)

        return Response(
            _normalize_point_action(point, type_labels=type_labels),
            status=status.HTTP_200_OK,
        )

    def delete(self, request, point_id):
        try:
            MauticClient().delete_point_action(point_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _point_provider_error_response(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminContactPointsView(APIView):
    """Apply an audited manual plus/minus Point adjustment to one Contact."""

    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, mautic_contact_id):
        allowed_fields = {"operation", "amount", "reason"}
        unsupported = sorted(set(request.data.keys()) - allowed_fields)
        if unsupported:
            return Response(
                {
                    "detail": (
                        "Unsupported contact Point field(s): "
                        + ", ".join(unsupported)
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        operation = str(request.data.get("operation") or "").strip().lower()
        if operation not in {"add", "subtract"}:
            return Response(
                {"detail": "operation must be either 'add' or 'subtract'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        raw_amount = request.data.get("amount")
        if isinstance(raw_amount, bool):
            return Response(
                {"detail": "amount must be a positive integer."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            amount = int(str(raw_amount).strip())
        except (TypeError, ValueError):
            return Response(
                {"detail": "amount must be a positive integer."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if amount <= 0:
            return Response(
                {"detail": "amount must be a positive integer."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        reason = str(request.data.get("reason") or "").strip()
        if len(reason) > 240:
            return Response(
                {"detail": "reason cannot exceed 240 characters."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        event_name = reason or "Manual Point adjustment from ECP"
        operator = "plus" if operation == "add" else "minus"

        client = MauticClient()
        try:
            before = client.get_contact(mautic_contact_id)
            before_points = int(before.get("points") or 0)

            client.adjust_contact_points(
                mautic_contact_id,
                operator,
                amount,
                event_name=event_name,
                action_name="ECP Newsletter",
            )

            after = client.get_contact(mautic_contact_id)
            after_points = int(after.get("points") or 0)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _point_provider_error_response(exc)
        except (TypeError, ValueError):
            return Response(
                {"detail": "Mautic returned an invalid Contact Point value."},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        expected = (
            before_points + amount
            if operation == "add"
            else before_points - amount
        )
        if after_points != expected:
            return Response(
                {
                    "detail": (
                        "Mautic did not confirm the requested Contact "
                        "Point adjustment."
                    )
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )

        return Response(
            {
                "mautic_contact_id": str(mautic_contact_id),
                "operation": operation,
                "amount": amount,
                "previous_points": before_points,
                "points": after_points,
                "reason": event_name,
            },
            status=status.HTTP_200_OK,
        )
