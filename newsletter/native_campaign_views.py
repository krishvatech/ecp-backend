from __future__ import annotations

import math
from typing import Any

from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError


_CAMPAIGN_FIELDS = {
    "name",
    "description",
    "isPublished",
    "lists",
    "forms",
    "events",
    "canvasSettings",
}

_EVENT_TYPES = {"action", "condition", "decision"}


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


def _collection_items(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        rows = list(value.values())
    elif isinstance(value, list):
        rows = list(value)
    else:
        return []
    return [row for row in rows if isinstance(row, dict)]


def _normalize_relation_id(value):
    if isinstance(value, dict):
        value = value.get("id")
    if value in (None, ""):
        return None
    return str(value)


def _normalize_campaign(campaign: dict[str, Any]) -> dict[str, Any]:
    campaign_id = campaign.get("id")
    lists = _collection_items(campaign.get("lists"))
    forms = _collection_items(campaign.get("forms"))
    events = _collection_items(campaign.get("events"))

    normalized_events = []
    for event in events:
        event_id = event.get("id")
        children = event.get("children")
        if isinstance(children, dict):
            child_values = list(children.values())
        elif isinstance(children, list):
            child_values = children
        else:
            child_values = []

        normalized_events.append(
            {
                "id": str(event_id) if event_id is not None else None,
                "name": str(event.get("name") or ""),
                "description": str(event.get("description") or ""),
                "type": str(event.get("type") or ""),
                "eventType": str(event.get("eventType") or ""),
                "order": event.get("order"),
                "properties": (
                    event.get("properties")
                    if isinstance(event.get("properties"), (dict, list))
                    else {}
                ),
                "triggerInterval": event.get("triggerInterval"),
                "triggerIntervalUnit": event.get("triggerIntervalUnit"),
                "triggerMode": event.get("triggerMode"),
                "triggerDate": event.get("triggerDate"),
                "parent": _normalize_relation_id(event.get("parent")),
                "decisionPath": event.get("decisionPath"),
                "children": [
                    child_id
                    for child_id in (
                        _normalize_relation_id(child)
                        for child in child_values
                    )
                    if child_id is not None
                ],
            }
        )

    return {
        "id": str(campaign_id) if campaign_id is not None else None,
        "name": str(campaign.get("name") or "").strip(),
        "description": str(campaign.get("description") or ""),
        "isPublished": _provider_bool(campaign.get("isPublished", False)),
        "dateAdded": campaign.get("dateAdded"),
        "dateModified": campaign.get("dateModified"),
        "contactCount": campaign.get("contactCount"),
        "lists": [
            {
                "id": str(row.get("id")) if row.get("id") is not None else None,
                "name": str(row.get("name") or ""),
                "alias": str(row.get("alias") or ""),
            }
            for row in lists
        ],
        "forms": [
            {
                "id": str(row.get("id")) if row.get("id") is not None else None,
                "name": str(row.get("name") or ""),
            }
            for row in forms
        ],
        "events": normalized_events,
        "canvasSettings": (
            campaign.get("canvasSettings")
            if isinstance(campaign.get("canvasSettings"), dict)
            else {}
        ),
    }


def _normalize_source_rows(value) -> list[dict[str, Any]]:
    return [
        {
            "id": str(row.get("id")) if row.get("id") is not None else None,
            "name": str(row.get("name") or ""),
            "alias": str(row.get("alias") or ""),
            "isPublished": _provider_bool(row.get("isPublished", False)),
        }
        for row in _collection_items(value)
    ]


def _parse_source_ids(value, *, field_name: str) -> list[dict[str, int]]:
    if not isinstance(value, list):
        raise ValueError(f"Native Mautic Campaign {field_name} must be a list.")

    result = []
    seen = set()
    for item in value:
        raw_id = item.get("id") if isinstance(item, dict) else item
        if isinstance(raw_id, bool):
            raise ValueError(
                f"Native Mautic Campaign {field_name} IDs must be positive integers."
            )
        try:
            source_id = int(raw_id)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Native Mautic Campaign {field_name} IDs must be positive integers."
            ) from exc
        if source_id <= 0:
            raise ValueError(
                f"Native Mautic Campaign {field_name} IDs must be positive integers."
            )
        if source_id not in seen:
            result.append({"id": source_id})
            seen.add(source_id)
    return result


def _parse_events(value) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("Native Mautic Campaign events must be a list.")

    parsed = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} must be an object."
            )

        event_id = str(item.get("id") or "").strip()
        name = str(item.get("name") or "").strip()
        provider_type = str(item.get("type") or "").strip()
        event_type = str(item.get("eventType") or "").strip()

        if not event_id:
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} id is required."
            )
        if not name:
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} name is required."
            )
        if not provider_type:
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} type is required."
            )
        if event_type not in _EVENT_TYPES:
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} eventType must be "
                "action, condition, or decision."
            )

        properties = item.get("properties", {})
        if not isinstance(properties, (dict, list)):
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} properties "
                "must be an object or list."
            )

        children = item.get("children", [])
        if not isinstance(children, list):
            raise ValueError(
                f"Native Mautic Campaign event #{index + 1} children must be a list."
            )

        event = {
            "id": event_id,
            "name": name,
            "type": provider_type,
            "eventType": event_type,
            "properties": properties,
            "children": [str(child) for child in children],
        }

        optional_fields = (
            "description",
            "order",
            "triggerInterval",
            "triggerIntervalUnit",
            "triggerMode",
            "triggerDate",
            "parent",
            "decisionPath",
        )
        for field in optional_fields:
            if field in item:
                event[field] = item.get(field)

        parsed.append(event)

    return parsed


def _parse_canvas(value) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Native Mautic Campaign canvasSettings must be an object.")

    nodes = value.get("nodes", [])
    connections = value.get("connections", [])
    if not isinstance(nodes, list) or not isinstance(connections, list):
        raise ValueError(
            "Native Mautic Campaign canvasSettings nodes and connections must be lists."
        )
    if any(not isinstance(node, dict) for node in nodes):
        raise ValueError("Native Mautic Campaign canvas nodes must be objects.")
    if any(not isinstance(connection, dict) for connection in connections):
        raise ValueError("Native Mautic Campaign canvas connections must be objects.")

    return {
        "nodes": nodes,
        "connections": connections,
    }


def _parse_campaign_payload(data, *, partial: bool = False) -> dict[str, Any]:
    if not hasattr(data, "keys"):
        raise ValueError("Native Mautic Campaign payload must be an object.")

    unsupported = sorted(set(data.keys()) - _CAMPAIGN_FIELDS)
    if unsupported:
        raise ValueError(
            "Unsupported Native Mautic Campaign field(s): " + ", ".join(unsupported)
        )

    payload: dict[str, Any] = {}

    if not partial or "name" in data:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("Native Mautic Campaign name is required.")
        if len(name) > 190:
            raise ValueError(
                "Native Mautic Campaign name cannot exceed 190 characters."
            )
        payload["name"] = name

    if "description" in data:
        payload["description"] = str(data.get("description") or "")

    if "isPublished" in data:
        payload["isPublished"] = _parse_bool(
            data.get("isPublished"),
            field_name="Native Mautic Campaign isPublished",
        )
    elif not partial:
        payload["isPublished"] = False

    for field in ("lists", "forms"):
        if field in data:
            payload[field] = _parse_source_ids(
                data.get(field),
                field_name=field,
            )

    if "events" in data:
        payload["events"] = _parse_events(data.get("events"))

    if "canvasSettings" in data:
        payload["canvasSettings"] = _parse_canvas(data.get("canvasSettings"))

    if not partial:
        if not payload.get("lists") and not payload.get("forms"):
            raise ValueError(
                "Native Mautic Campaign requires at least one Segment or Form source."
            )
        if not payload.get("events"):
            raise ValueError(
                "Native Mautic Campaign requires at least one workflow event."
            )
        payload.setdefault("lists", [])
        payload.setdefault("forms", [])
        payload.setdefault(
            "canvasSettings",
            {"nodes": [], "connections": []},
        )

    if partial and not payload:
        raise ValueError("At least one Native Mautic Campaign field is required.")

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
        {"detail": message or "Native Mautic Campaign operation failed."},
        status=status.HTTP_502_BAD_GATEWAY,
    )


class NewsletterAdminMauticCampaignListCreateView(APIView):
    """Staff-only native Mautic Campaign list and create API."""

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
            "withContactCounts": "true",
        }
        if search:
            params["search"] = search

        try:
            data = MauticClient().list_campaigns(**params)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        rows = _collection_items(data.get("campaigns"))
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
                    _normalize_campaign(campaign)
                    for campaign in rows
                ],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        try:
            payload = _parse_campaign_payload(request.data)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            campaign = MauticClient().create_campaign(payload)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_campaign(campaign),
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminMauticCampaignCapabilitiesView(APIView):
    """Staff-only native Mautic Campaign Builder capability discovery API."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            client = MauticClient()
            segments = client.list_segments(limit=200)
            forms = client.list_forms(limit=200)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            {
                "actions": [],
                "conditions": [],
                "decisions": [],
                "connection_restrictions": {},
                "builder_metadata": {
                    "available": False,
                    "reason": (
                        "Mautic 7.1.3 builds Campaign Builder provider metadata "
                        "internally via CampaignEvents::CAMPAIGN_ON_BUILD and "
                        "does not expose a stable REST metadata endpoint."
                    ),
                    "source": "mautic-provider-audit",
                },
                "sources": {
                    "segments": _normalize_source_rows(
                        segments.get("lists", segments.get("segments"))
                    ),
                    "forms": _normalize_source_rows(forms.get("forms")),
                },
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminMauticCampaignDetailView(APIView):
    """Staff-only native Mautic Campaign detail, update and delete API."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, campaign_id):
        try:
            campaign = MauticClient().get_campaign(campaign_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_campaign(campaign),
            status=status.HTTP_200_OK,
        )

    def patch(self, request, campaign_id):
        try:
            payload = _parse_campaign_payload(
                request.data,
                partial=True,
            )
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            campaign = MauticClient().update_campaign(
                campaign_id,
                payload,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_campaign(campaign),
            status=status.HTTP_200_OK,
        )

    def delete(self, request, campaign_id):
        try:
            MauticClient().delete_campaign(campaign_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)
