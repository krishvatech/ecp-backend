"""The Marketing Hub Categories manager (see mautic_category_services).

The Subscription List marker category is shown but can be neither renamed nor
deleted, and no new category may take its alias.

As in Mautic, a category that items use cannot be deleted (Mautic itself
refuses); one that only contacts' email preferences refer to is deleted after
the admin confirms, which removes those preferences.
"""

from __future__ import annotations

import hashlib
from typing import Any

from django.core.cache import cache
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .category_segment_services import CONSENT_CATEGORY_ALIAS
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.exceptions import MauticRequestNotSentError
from .mautic.operations import CATEGORY_CREATE, CATEGORY_DELETE, CATEGORY_UPDATE
from .mautic_category_services import (
    BUNDLES,
    COLOR_PATTERN,
    DESCRIPTION_MAX,
    ITEM_LABELS,
    TITLE_MAX,
    alias_for,
    all_categories,
    normalize,
    publish_states,
    truthy,
)
from .mautic_identity_execution import run_interactive_mutation


CREATE_LOCK_SECONDS = 30


def _usage_summary(entry: dict[str, Any] | None) -> dict[str, Any]:
    items = (entry or {}).get("items") or {}
    preferences = sum(int(value) for value in ((entry or {}).get("contact_preferences") or {}).values())
    return {
        "items": sum(int(value) for value in items.values()),
        "by_type": [{"type": ITEM_LABELS.get(table, table), "count": int(count)} for table, count in sorted(items.items()) if count],
        "contact_preferences": preferences,
    }


def _mautic_message(exc: Exception, fallback: str) -> str:
    text = str(exc)
    return text.split("): ", 1)[1] if "): " in text else fallback


def _write_error(exc: Exception, fallback: str) -> Response:
    if isinstance(exc, MauticRequestNotSentError):
        return Response({"detail": "Mautic could not be reached; nothing was changed."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    if isinstance(exc, PermanentMauticError):
        text = str(exc)
        if "HTTP 404" in text:
            return Response({"detail": "Category not found."}, status=status.HTTP_404_NOT_FOUND)
        if "HTTP 403" in text:
            return Response({"detail": "Your Mautic user is not allowed to change categories."}, status=status.HTTP_403_FORBIDDEN)
        if "HTTP 409" in text:
            return Response({"detail": _mautic_message(exc, fallback)}, status=status.HTTP_409_CONFLICT)
        return Response({"detail": _mautic_message(exc, fallback)}, status=status.HTTP_400_BAD_REQUEST)
    return Response({"detail": "Mautic did not confirm the change. Refresh before trying again."}, status=status.HTTP_502_BAD_GATEWAY)


def _parse(data, *, create: bool) -> dict[str, Any]:
    allowed = {"title", "bundle", "description", "color", "isPublished"}
    unknown = sorted(set(data.keys()) - allowed)
    if unknown:
        raise ValueError("Unsupported field(s): " + ", ".join(unknown))
    payload: dict[str, Any] = {}
    if create or "title" in data:
        title = str(data.get("title") or "").strip()
        if not title:
            raise ValueError("Enter a title.")
        if len(title) > TITLE_MAX:
            raise ValueError(f"Use at most {TITLE_MAX} characters for the title.")
        payload["title"] = title
    if create:
        bundle = str(data.get("bundle") or "")
        if bundle not in BUNDLES:
            raise ValueError("Choose what the category is for.")
        payload["bundle"] = bundle
    elif "bundle" in data:
        raise ValueError("A category keeps its type. Create a new category instead.")
    if "description" in data:
        description = str(data.get("description") or "")
        if len(description) > DESCRIPTION_MAX:
            raise ValueError(f"Use at most {DESCRIPTION_MAX} characters for the description.")
        payload["description"] = description
    if "color" in data:
        color = str(data.get("color") or "").strip().lstrip("#")
        if color and not COLOR_PATTERN.match(color):
            raise ValueError("Colour must be a 6-digit hex value such as 4E5D9D.")
        payload["color"] = color
    if "isPublished" in data:
        payload["isPublished"] = 1 if truthy(data.get("isPublished")) else 0
    elif create:
        payload["isPublished"] = 1
    if not create and not payload:
        raise ValueError("Nothing to change.")
    return payload


def _find(category_id) -> dict[str, Any] | None:
    try:
        wanted = int(category_id)
    except (TypeError, ValueError):
        return None
    return next((category for category in all_categories(fresh=True) if category["id"] == wanted), None)


def _current_usage(category_id: int) -> dict[str, Any] | None:
    try:
        return _usage_summary(MauticClient().get_category_overview()["usage"].get(category_id))
    except (TemporaryMauticError, PermanentMauticError):
        return None


def _in_use(usage: dict[str, Any]) -> Response:
    return Response({"detail": "This category is in use. Remove it from these items before deleting it.",
                     "code": "category_in_use", "usage": usage}, status=status.HTTP_409_CONFLICT)


def _with_state(category: dict[str, Any]) -> dict[str, Any]:
    result = normalize(category)
    states = publish_states()
    result["isPublished"] = states.get(result["id"]) if states is not None else None
    return result


class NewsletterAdminMauticCategoryListView(APIView):
    """GET the categories (``?bundle=segment`` adds global ones and leaves out
    the protected marker, for pickers); POST creates one as the admin."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        bundle = str(request.query_params.get("bundle") or "")
        if bundle and bundle not in BUNDLES:
            return Response({"detail": "Unknown category type."}, status=status.HTTP_400_BAD_REQUEST)
        client = MauticClient()
        try:
            overview = client.get_category_overview()
        except (TemporaryMauticError, PermanentMauticError):
            overview = None
        try:
            categories = all_categories(client, published=overview["published"] if overview else None)
        except (TemporaryMauticError, PermanentMauticError):
            return Response({"detail": "Mautic categories could not be read. Try again."}, status=status.HTTP_502_BAD_GATEWAY)
        if bundle:
            # As Mautic's own pickers: published categories of that type or global.
            picker = [category for category in categories if category["bundle"] in (bundle, "global")
                      and not category["protected"] and category["isPublished"] is not False]
            return Response({"count": len(picker), "results": picker})
        for category in categories:
            category["usage"] = _usage_summary(overview["usage"].get(category["id"])) if overview else None
        return Response({"count": len(categories), "results": categories, "bundles": BUNDLES, "usage_available": overview is not None})

    def post(self, request):
        try:
            payload = _parse(request.data, create=True)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        if alias_for(payload["title"]) == CONSENT_CATEGORY_ALIAS:
            return Response({"detail": "This title is reserved for the Subscription List category."}, status=status.HTTP_400_BAD_REQUEST)
        # Two requests for the same title at once (a double-click) would both
        # pass the duplicate check below; only the first may go on.
        lock = "marketing:category-create:" + hashlib.sha256(f'{payload["bundle"]}|{payload["title"].casefold()}'.encode()).hexdigest()
        if not cache.add(lock, 1, timeout=CREATE_LOCK_SECONDS):
            return Response({"detail": "This category is already being created."}, status=status.HTTP_409_CONFLICT)
        try:
            return self._create(request, payload)
        finally:
            cache.delete(lock)

    def _create(self, request, payload):
        try:
            existing = all_categories(fresh=True)
        except (TemporaryMauticError, PermanentMauticError):
            return Response({"detail": "Mautic categories could not be read. Try again."}, status=status.HTTP_502_BAD_GATEWAY)
        if any(category["bundle"] == payload["bundle"] and category["title"].casefold() == payload["title"].casefold()
               for category in existing):
            return Response({"detail": f'A {BUNDLES[payload["bundle"]]} category named "{payload["title"]}" already exists.'},
                            status=status.HTTP_409_CONFLICT)
        try:
            category, error_response = run_interactive_mutation(
                request,
                action=CATEGORY_CREATE,
                resource="category",
                resource_id="",
                mutate=lambda client: client.create_category(payload),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                resource_id_from_result=lambda created: str(created.get("id") or ""),
                detail=f'{payload["bundle"]}: {payload["title"]}'[:250],
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _write_error(exc, "Mautic refused the category.")
        if error_response is not None:
            return error_response
        return Response(_with_state(category), status=status.HTTP_201_CREATED)


class NewsletterAdminMauticCategoryDetailView(APIView):
    """PATCH title/description/colour/published; DELETE an unused category
    (``?confirm=1`` when contacts have email preferences for it)."""

    permission_classes = [HasMarketingHubAccess]

    def _target(self, category_id):
        try:
            category = _find(category_id)
        except (TemporaryMauticError, PermanentMauticError):
            return None, Response({"detail": "Mautic categories could not be read. Try again."}, status=status.HTTP_502_BAD_GATEWAY)
        if category is None:
            return None, Response({"detail": "Category not found."}, status=status.HTTP_404_NOT_FOUND)
        if category["protected"]:
            return None, Response({"detail": "This category marks Subscription List segments and is managed by ECP."},
                                  status=status.HTTP_409_CONFLICT)
        return category, None

    def patch(self, request, category_id):
        category, error = self._target(category_id)
        if error is not None:
            return error
        try:
            payload = _parse(request.data, create=False)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        if "title" in payload and payload["title"].casefold() != category["title"].casefold():
            if any(other["id"] != category["id"] and other["bundle"] == category["bundle"]
                   and other["title"].casefold() == payload["title"].casefold() for other in all_categories(fresh=True)):
                return Response({"detail": f'Another {BUNDLES.get(category["bundle"], category["bundle"])} category is named "{payload["title"]}".'},
                                status=status.HTTP_409_CONFLICT)
        try:
            updated, error_response = run_interactive_mutation(
                request,
                action=CATEGORY_UPDATE,
                resource="category",
                resource_id=str(category["id"]),
                mutate=lambda client: client.update_category(category["id"], payload),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                detail=", ".join(sorted(payload))[:250],
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _write_error(exc, "Mautic refused the change.")
        if error_response is not None:
            return error_response
        return Response(_with_state(updated))

    def delete(self, request, category_id):
        category, error = self._target(category_id)
        if error is not None:
            return error
        usage = _current_usage(category["id"])
        if usage is None:
            return Response({"detail": "Mautic could not say where this category is used, so it was not deleted. Try again."},
                            status=status.HTTP_502_BAD_GATEWAY)
        if usage["items"]:
            return _in_use(usage)
        if usage["contact_preferences"] and str(request.query_params.get("confirm") or "") != "1":
            return Response({"detail": "Contacts have email preferences for this category. Deleting it removes them.",
                             "code": "category_has_preferences", "usage": usage}, status=status.HTTP_409_CONFLICT)
        try:
            _, error_response = run_interactive_mutation(
                request,
                action=CATEGORY_DELETE,
                resource="category",
                resource_id=str(category["id"]),
                mutate=lambda client: client.delete_category(category["id"]),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                detail=f'{category["bundle"]}: {category["title"]}; {usage["items"]} items'[:250],
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            # Mautic refuses to delete a category in use; an item may have
            # started using it a moment ago.
            usage = _current_usage(category["id"])
            if usage is not None and usage["items"]:
                return _in_use(usage)
            return _write_error(exc, "Mautic refused to delete the category.")
        if error_response is not None:
            return error_response
        return Response(status=status.HTTP_204_NO_CONTENT)
