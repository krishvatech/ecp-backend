from __future__ import annotations

import math
from typing import Any

from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError


_POINT_GROUP_FIELDS = {
    "name",
    "description",
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


def _items(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [item for item in value.values() if isinstance(item, dict)]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _provider_total(data: dict[str, Any], key: str) -> int:
    rows = _items(data.get(key))
    try:
        total = int(data.get("total", len(rows)))
    except (TypeError, ValueError):
        total = len(rows)
    return max(0, total, len(rows))


def _normalize_point_group(group: dict[str, Any]) -> dict[str, Any]:
    group_id = group.get("id")
    return {
        "id": str(group_id) if group_id is not None else None,
        "name": str(group.get("name") or "").strip(),
        "description": str(group.get("description") or ""),
        "isPublished": _provider_bool(
            group.get("isPublished", group.get("is_published", False))
        ),
        "dateAdded": group.get("dateAdded"),
        "dateModified": group.get("dateModified"),
    }


def _normalize_group_score(score: dict[str, Any]) -> dict[str, Any]:
    group = score.get("group")
    if not isinstance(group, dict):
        group = {}
    raw_score = score.get("score")
    try:
        normalized_score = int(raw_score) if raw_score not in (None, "") else 0
    except (TypeError, ValueError):
        normalized_score = 0

    group_id = group.get("id")
    return {
        "group_id": str(group_id) if group_id is not None else None,
        "group_name": str(group.get("name") or "").strip(),
        "group_description": str(group.get("description") or ""),
        "score": normalized_score,
    }


def _parse_point_group_payload(data, *, partial: bool = False) -> dict[str, Any]:
    unsupported = sorted(set(data.keys()) - _POINT_GROUP_FIELDS)
    if unsupported:
        raise ValueError(
            "Unsupported Point Group field(s): " + ", ".join(unsupported)
        )

    payload: dict[str, Any] = {}

    if not partial or "name" in data:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("Point Group name is required.")
        payload["name"] = name

    if "description" in data:
        payload["description"] = str(data.get("description") or "").strip()

    if "isPublished" in data:
        payload["isPublished"] = _parse_bool(
            data.get("isPublished"),
            field_name="Point Group isPublished",
        )

    if partial and not payload:
        raise ValueError("At least one Point Group field is required.")

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
        {"detail": message or "Mautic Point Group operation failed."},
        status=status.HTTP_502_BAD_GATEWAY,
    )


def _delete_guard(client: MauticClient) -> dict[str, Any]:
    """Return a conservative Mautic 7.1.3 delete guard.

    Legacy Point/Trigger responses do not expose a reliable numeric Point Group
    relation. Because live Mautic 7.1.3 testing proved that deleting a Point
    Group cascades to linked Point Actions and Point Triggers, ECP only permits
    Group deletion when there are no Point Actions or Point Triggers at all.
    This intentionally favors data safety over permissive deletion.
    """

    point_data = client.list_point_actions(start=0, limit=1)
    trigger_data = client.list_point_triggers(start=0, limit=1)
    point_actions = _provider_total(point_data, "points")
    point_triggers = _provider_total(trigger_data, "triggers")
    return {
        "mode": "global_conservative",
        "point_actions": point_actions,
        "point_triggers": point_triggers,
        "delete_allowed": point_actions == 0 and point_triggers == 0,
    }


def _parse_manual_adjustment(data) -> tuple[str, int, str]:
    allowed_fields = {"operation", "amount", "reason"}
    unsupported = sorted(set(data.keys()) - allowed_fields)
    if unsupported:
        raise ValueError(
            "Unsupported contact Point Group field(s): " + ", ".join(unsupported)
        )

    operation = str(data.get("operation") or "").strip().lower()
    if operation not in {"add", "subtract"}:
        raise ValueError("operation must be either 'add' or 'subtract'.")

    raw_amount = data.get("amount")
    if isinstance(raw_amount, bool):
        raise ValueError("amount must be a positive integer.")
    try:
        amount = int(str(raw_amount).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("amount must be a positive integer.") from exc
    if amount <= 0:
        raise ValueError("amount must be a positive integer.")

    reason = str(data.get("reason") or "").strip()
    if len(reason) > 240:
        raise ValueError("reason cannot exceed 240 characters.")

    return operation, amount, reason or "Manual Point Group adjustment from ECP"


def _score_for_group(data: dict[str, Any], group_id: int | str) -> int:
    wanted = str(group_id or "").strip()
    for item in _items(data.get("groupScores")):
        group = item.get("group")
        if not isinstance(group, dict) or str(group.get("id") or "") != wanted:
            continue
        try:
            return int(item.get("score") or 0)
        except (TypeError, ValueError):
            raise ValueError("Mautic returned an invalid Contact Point Group score.")
    return 0


class NewsletterAdminPointGroupListCreateView(APIView):
    """List and create provider-backed Mautic Point Groups."""

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
            data = MauticClient().list_point_groups(**params)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        groups = _items(data.get("pointGroups"))
        total = _provider_total(data, "pointGroups")

        return Response(
            {
                "count": total,
                "page": page,
                "page_size": page_size,
                "num_pages": math.ceil(total / page_size) if total else 0,
                "results": [_normalize_point_group(group) for group in groups],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        try:
            payload = _parse_point_group_payload(request.data)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            group = MauticClient().create_point_group(payload)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_point_group(group),
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminPointGroupDetailView(APIView):
    """Read, update, or safely delete one provider-backed Mautic Point Group."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, group_id):
        try:
            group = MauticClient().get_point_group(group_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_point_group(group),
            status=status.HTTP_200_OK,
        )

    def patch(self, request, group_id):
        try:
            payload = _parse_point_group_payload(request.data, partial=True)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            group = MauticClient().update_point_group(group_id, payload)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_point_group(group),
            status=status.HTTP_200_OK,
        )

    def delete(self, request, group_id):
        client = MauticClient()
        try:
            # Confirm the target exists before evaluating the global safety guard.
            client.get_point_group(group_id)
            guard = _delete_guard(client)
            if not guard["delete_allowed"]:
                return Response(
                    {
                        "detail": (
                            "Point Group cannot be deleted safely while Mautic "
                            "contains Point Actions or Point Triggers. Mautic "
                            "7.1.3 may cascade-delete linked items. Remove or "
                            "ungroup Point Actions and Point Triggers first."
                        ),
                        "delete_guard": guard,
                    },
                    status=status.HTTP_409_CONFLICT,
                )
            client.delete_point_group(group_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminPointGroupDeleteCheckView(APIView):
    """Return the conservative Mautic 7.1.3 Point Group delete guard."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, group_id):
        client = MauticClient()
        try:
            client.get_point_group(group_id)
            guard = _delete_guard(client)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(guard, status=status.HTTP_200_OK)


class NewsletterAdminContactPointGroupsView(APIView):
    """List provider-backed Point Group scores for one Mautic Contact."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, mautic_contact_id):
        try:
            data = MauticClient().list_contact_point_groups(mautic_contact_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        scores = _items(data.get("groupScores"))
        return Response(
            {
                "mautic_contact_id": str(mautic_contact_id),
                "count": _provider_total(data, "groupScores"),
                "results": [_normalize_group_score(score) for score in scores],
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminContactPointGroupDetailView(APIView):
    """Read or manually adjust one Mautic Contact Point Group score."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, mautic_contact_id, group_id):
        try:
            score = MauticClient().get_contact_point_group(
                mautic_contact_id,
                group_id,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        data = _normalize_group_score(score)
        data["mautic_contact_id"] = str(mautic_contact_id)
        return Response(data, status=status.HTTP_200_OK)

    def post(self, request, mautic_contact_id, group_id):
        try:
            operation, amount, reason = _parse_manual_adjustment(request.data)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        operator = "plus" if operation == "add" else "minus"
        client = MauticClient()
        try:
            before_data = client.list_contact_point_groups(mautic_contact_id)
            before_score = _score_for_group(before_data, group_id)

            adjusted = client.adjust_contact_group_points(
                mautic_contact_id,
                group_id,
                operator,
                amount,
                event_name=reason,
                action_name="ECP Newsletter",
            )
            after = client.get_contact_point_group(mautic_contact_id, group_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        adjusted_normalized = _normalize_group_score(adjusted)
        after_normalized = _normalize_group_score(after)
        expected = before_score + amount if operation == "add" else before_score - amount
        if (
            adjusted_normalized["score"] != expected
            or after_normalized["score"] != expected
        ):
            return Response(
                {
                    "detail": (
                        "Mautic did not confirm the requested Contact Point "
                        "Group adjustment."
                    )
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )

        return Response(
            {
                "mautic_contact_id": str(mautic_contact_id),
                "group_id": after_normalized["group_id"],
                "group_name": after_normalized["group_name"],
                "group_description": after_normalized["group_description"],
                "operation": operation,
                "amount": amount,
                "previous_score": before_score,
                "score": after_normalized["score"],
                "reason": reason,
            },
            status=status.HTTP_200_OK,
        )
