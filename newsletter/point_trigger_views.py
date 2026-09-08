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


_TRIGGER_FIELDS = {
    "name",
    "description",
    "points",
    "color",
    "triggerExistingLeads",
    "isPublished",
}
_TRIGGER_EVENT_FIELDS = {
    "name",
    "description",
    "type",
    "order",
    "properties",
}
_HEX_COLOR_RE = re.compile(r"^[0-9a-fA-F]{6}$")


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


def _parse_integer(value, *, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer.")
    try:
        return int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer.") from exc


def _normalize_color(value) -> str:
    color = str(value or "").strip().lstrip("#")
    if not _HEX_COLOR_RE.fullmatch(color):
        raise ValueError("Point Trigger color must be a 6-digit hexadecimal value.")
    return color.lower()


def _trigger_items(data: dict[str, Any]) -> list[dict[str, Any]]:
    triggers = data.get("triggers") or []
    if isinstance(triggers, dict):
        return [item for item in triggers.values() if isinstance(item, dict)]
    if isinstance(triggers, list):
        return [item for item in triggers if isinstance(item, dict)]
    return []


def _event_items(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [item for item in value.values() if isinstance(item, dict)]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _event_trigger_id(event: dict[str, Any]) -> str | None:
    trigger = event.get("trigger")
    if isinstance(trigger, dict):
        trigger_id = trigger.get("id")
        if trigger_id not in (None, ""):
            return str(trigger_id)
        trigger = trigger.get("@id")
    if isinstance(trigger, str):
        normalized = trigger.rstrip("/")
        if normalized:
            return normalized.rsplit("/", 1)[-1]
    return None


def _normalize_trigger_event(
    event: dict[str, Any],
    *,
    type_labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    event_id = event.get("id")
    event_type = str(event.get("type") or "").strip()

    order = event.get("order")
    try:
        order = int(order) if order not in (None, "") else 0
    except (TypeError, ValueError):
        order = 0

    properties = event.get("properties")
    if not isinstance(properties, dict):
        properties = {}

    return {
        "id": str(event_id) if event_id is not None else None,
        "name": str(event.get("name") or "").strip(),
        "description": str(event.get("description") or ""),
        "type": event_type,
        "type_label": (
            str((type_labels or {}).get(event_type) or event_type)
            if event_type
            else ""
        ),
        "order": order,
        "properties": properties,
        "trigger_id": _event_trigger_id(event),
    }


def _normalize_trigger(
    trigger: dict[str, Any],
    *,
    type_labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    trigger_id = trigger.get("id")

    points = trigger.get("points")
    try:
        points = int(points) if points not in (None, "") else 0
    except (TypeError, ValueError):
        points = 0

    category = trigger.get("category")
    group = trigger.get("group")

    return {
        "id": str(trigger_id) if trigger_id is not None else None,
        "name": str(trigger.get("name") or "").strip(),
        "description": str(trigger.get("description") or ""),
        "points": points,
        "color": str(trigger.get("color") or "a0acb8").lstrip("#"),
        "triggerExistingLeads": _provider_bool(
            trigger.get("triggerExistingLeads", False)
        ),
        "isPublished": _provider_bool(
            trigger.get("isPublished", trigger.get("is_published", False))
        ),
        "events": [
            _normalize_trigger_event(event, type_labels=type_labels)
            for event in _event_items(trigger.get("events"))
        ],
        "category": category if isinstance(category, dict) else None,
        "group": group if isinstance(group, dict) else None,
        "dateAdded": trigger.get("dateAdded"),
        "dateModified": trigger.get("dateModified"),
        "publishUp": trigger.get("publishUp"),
        "publishDown": trigger.get("publishDown"),
    }


def _parse_trigger_payload(data, *, partial: bool = False) -> dict[str, Any]:
    unsupported = sorted(set(data.keys()) - _TRIGGER_FIELDS)
    if unsupported:
        raise ValueError(
            "Unsupported Point Trigger field(s): " + ", ".join(unsupported)
        )

    payload: dict[str, Any] = {}

    if not partial or "name" in data:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("Point Trigger name is required.")
        payload["name"] = name

    if "description" in data:
        payload["description"] = str(data.get("description") or "").strip()

    if "points" in data:
        payload["points"] = _parse_integer(
            data.get("points"),
            field_name="Point Trigger points",
        )

    if "color" in data:
        payload["color"] = _normalize_color(data.get("color"))

    if "triggerExistingLeads" in data:
        payload["triggerExistingLeads"] = _parse_bool(
            data.get("triggerExistingLeads"),
            field_name="Point Trigger triggerExistingLeads",
        )

    if "isPublished" in data:
        payload["isPublished"] = _parse_bool(
            data.get("isPublished"),
            field_name="Point Trigger isPublished",
        )

    if partial and not payload:
        raise ValueError("At least one Point Trigger field is required.")

    return payload


def _parse_event_payload(data, *, partial: bool = False) -> dict[str, Any]:
    unsupported = sorted(set(data.keys()) - _TRIGGER_EVENT_FIELDS)
    if unsupported:
        raise ValueError(
            "Unsupported Point Trigger Event field(s): " + ", ".join(unsupported)
        )

    payload: dict[str, Any] = {}

    if not partial or "name" in data:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("Point Trigger Event name is required.")
        payload["name"] = name

    if "description" in data:
        payload["description"] = str(data.get("description") or "").strip()

    if not partial or "type" in data:
        event_type = str(data.get("type") or "").strip()
        if not event_type:
            raise ValueError("Point Trigger Event type is required.")
        payload["type"] = event_type

    if "order" in data:
        order = _parse_integer(
            data.get("order"),
            field_name="Point Trigger Event order",
        )
        if order < 1:
            raise ValueError("Point Trigger Event order must be at least 1.")
        payload["order"] = order
    elif not partial:
        payload["order"] = 1

    if "properties" in data:
        properties = data.get("properties")
        if not isinstance(properties, dict):
            raise ValueError("Point Trigger Event properties must be an object.")
        payload["properties"] = properties
    elif not partial:
        payload["properties"] = {}

    if partial and not payload:
        raise ValueError("At least one Point Trigger Event field is required.")

    return payload


def _provider_error_response(exc):
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
        {"detail": message or "Mautic Point Trigger operation failed."},
        status=status.HTTP_502_BAD_GATEWAY,
    )


def _validate_event_type(
    client: MauticClient,
    event_type: str,
) -> dict[str, str]:
    type_labels = client.list_point_trigger_event_types()
    if event_type not in type_labels:
        raise ValueError(
            f"Unsupported Mautic Point Trigger Event type: {event_type}."
        )
    return type_labels


def _event_belongs_to_trigger(
    event: dict[str, Any],
    trigger_id: int | str,
) -> bool:
    return _event_trigger_id(event) == str(trigger_id or "").strip()


def _get_trigger_event(
    client: MauticClient,
    *,
    trigger_id: int | str,
    event_id: int | str,
) -> dict[str, Any]:
    event = client.get_point_trigger_event(event_id)
    if not _event_belongs_to_trigger(event, trigger_id):
        raise Http404
    return event


class NewsletterAdminPointTriggerEventTypesView(APIView):
    """Return Point Trigger Event types exposed by the connected Mautic instance."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            type_labels = MauticClient().list_point_trigger_event_types()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            {
                "types": [
                    {"value": value, "label": label}
                    for value, label in type_labels.items()
                ]
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminPointTriggerListCreateView(APIView):
    """List and create provider-backed Mautic Point Triggers."""

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
            data = client.list_point_triggers(**params)
            type_labels = client.list_point_trigger_event_types()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        triggers = _trigger_items(data)
        try:
            total = max(0, int(data.get("total", len(triggers))))
        except (TypeError, ValueError):
            total = len(triggers)

        return Response(
            {
                "count": total,
                "page": page,
                "page_size": page_size,
                "num_pages": math.ceil(total / page_size) if total else 0,
                "results": [
                    _normalize_trigger(trigger, type_labels=type_labels)
                    for trigger in triggers
                ],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        try:
            payload = _parse_trigger_payload(request.data)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        client = MauticClient()
        try:
            trigger = client.create_point_trigger(payload)
            type_labels = client.list_point_trigger_event_types()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_trigger(trigger, type_labels=type_labels),
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminPointTriggerDetailView(APIView):
    """Read, update, or delete one provider-backed Mautic Point Trigger."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, trigger_id):
        client = MauticClient()
        try:
            trigger = client.get_point_trigger(trigger_id)
            type_labels = client.list_point_trigger_event_types()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_trigger(trigger, type_labels=type_labels),
            status=status.HTTP_200_OK,
        )

    def patch(self, request, trigger_id):
        try:
            payload = _parse_trigger_payload(request.data, partial=True)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        client = MauticClient()
        try:
            trigger = client.update_point_trigger(trigger_id, payload)
            type_labels = client.list_point_trigger_event_types()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_trigger(trigger, type_labels=type_labels),
            status=status.HTTP_200_OK,
        )

    def delete(self, request, trigger_id):
        try:
            MauticClient().delete_point_trigger(trigger_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminPointTriggerEventListCreateView(APIView):
    """List or create events belonging to one Mautic Point Trigger."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, trigger_id):
        client = MauticClient()
        try:
            trigger = client.get_point_trigger(trigger_id)
            type_labels = client.list_point_trigger_event_types()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        events = _event_items(trigger.get("events"))
        return Response(
            {
                "count": len(events),
                "results": [
                    _normalize_trigger_event(event, type_labels=type_labels)
                    for event in events
                ],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request, trigger_id):
        try:
            payload = _parse_event_payload(request.data)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        client = MauticClient()
        try:
            client.get_point_trigger(trigger_id)
            type_labels = _validate_event_type(client, payload["type"])
            event = client.create_point_trigger_event(trigger_id, payload)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_trigger_event(event, type_labels=type_labels),
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminPointTriggerEventDetailView(APIView):
    """Read, update, or persistently delete one Mautic Point Trigger Event."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, trigger_id, event_id):
        client = MauticClient()
        try:
            event = _get_trigger_event(
                client,
                trigger_id=trigger_id,
                event_id=event_id,
            )
            type_labels = client.list_point_trigger_event_types()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_trigger_event(event, type_labels=type_labels),
            status=status.HTTP_200_OK,
        )

    def patch(self, request, trigger_id, event_id):
        try:
            payload = _parse_event_payload(request.data, partial=True)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        client = MauticClient()
        try:
            existing = _get_trigger_event(
                client,
                trigger_id=trigger_id,
                event_id=event_id,
            )
            type_labels = client.list_point_trigger_event_types()

            if "type" in payload:
                event_type = payload["type"]
                if event_type not in type_labels:
                    return Response(
                        {
                            "detail": (
                                "Unsupported Mautic Point Trigger Event type: "
                                f"{event_type}."
                            )
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                existing_type = str(existing.get("type") or "").strip()
                if existing_type and event_type != existing_type:
                    return Response(
                        {
                            "detail": (
                                "Point Trigger Event type cannot be changed. "
                                "Delete the event and create a new one instead."
                            )
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            event = client.update_point_trigger_event(event_id, payload)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_trigger_event(event, type_labels=type_labels),
            status=status.HTTP_200_OK,
        )

    def delete(self, request, trigger_id, event_id):
        client = MauticClient()
        try:
            _get_trigger_event(
                client,
                trigger_id=trigger_id,
                event_id=event_id,
            )
            client.delete_point_trigger_event(event_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)
