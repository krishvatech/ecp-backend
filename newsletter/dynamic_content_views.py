"""Marketing Hub Dynamic Content endpoints (see dynamic_content_services)."""

from __future__ import annotations

from datetime import datetime, timezone

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .dynamic_content_services import DynamicContentError, bridge_form, duplicate_payload, place_codes, rule_metadata
from .form_views import _public_base_url as mautic_public_base_url
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.operations import DYNAMIC_CONTENT_CREATE, DYNAMIC_CONTENT_DELETE, DYNAMIC_CONTENT_UPDATE
from .mautic_identity_execution import run_interactive_mutation
from .mautic_publish_window import from_mautic

_PROVIDER_ERRORS = (TemporaryMauticError, PermanentMauticError)


def _item_error(exc: DynamicContentError) -> Response:
    body = {"detail": str(exc), "code": exc.code}
    if exc.field:
        body["field"] = exc.field
    return Response(body, status=exc.status_code)


def _provider_error(exc, *, action: str = "read") -> Response:
    message = str(exc)
    if isinstance(exc, PermanentMauticError):
        reason = message.split(": ", 1)[1] if ": " in message else ""
        if "HTTP 404" in message:
            return Response({"detail": "That Dynamic Content item was not found in Mautic.", "code": "dynamic_content_not_found"},
                            status=status.HTTP_404_NOT_FOUND)
        if "HTTP 403" in message:
            return Response({"detail": "Your Mautic user is not allowed to do that with Dynamic Content.", "code": "dynamic_content_forbidden"},
                            status=status.HTTP_403_FORBIDDEN)
        if "HTTP 409" in message:
            return Response({"detail": reason or "This Dynamic Content item is still in use.", "code": "dynamic_content_in_use"},
                            status=status.HTTP_409_CONFLICT)
        if "HTTP 400" in message or "HTTP 422" in message:
            # The bridge or Mautic's own form refused it: show the reason.
            return Response({"detail": reason or "Mautic refused the Dynamic Content item.", "code": "dynamic_content_invalid"},
                            status=status.HTTP_400_BAD_REQUEST)
    if action == "read":
        detail = "Mautic could not be reached. Try again."
    else:
        detail = f"Mautic could not be reached. Nothing was {action}; try again."
    return Response({"detail": detail, "code": "mautic_error"}, status=status.HTTP_502_BAD_GATEWAY)


def _mutation(request, action: str, resource_id, mutate, **kwargs):
    return run_interactive_mutation(
        request,
        action=action,
        resource="dynamic_content",
        resource_id=resource_id,
        mutate=mutate,
        client_factory=MauticClient,
        audit_and_reraise=_PROVIDER_ERRORS,
        **kwargs,
    )


def _is_live(item: dict) -> bool:
    if not item.get("isPublished"):
        return False
    now = datetime.now(timezone.utc)
    start, end = from_mautic(item.get("publishUp")), from_mautic(item.get("publishDown"))
    return not (start and start > now) and not (end and end <= now)


def _detail(item: dict, base: str | None) -> dict:
    return {**item, "isLive": _is_live(item), "place": place_codes(item, base)}


def _created(request, client: MauticClient, data) -> Response:
    try:
        pairs = bridge_form(data, client=client)
    except DynamicContentError as exc:
        return _item_error(exc)
    except _PROVIDER_ERRORS as exc:
        return _provider_error(exc)
    try:
        item, identity_response = _mutation(
            request, DYNAMIC_CONTENT_CREATE, "", lambda c: c.create_dynamic_content(pairs),
            resource_id_from_result=lambda result: result.get("id"),
            detail=str(data.get("name") or "")[:250],
        )
    except _PROVIDER_ERRORS as exc:
        return _provider_error(exc, action="saved")
    if identity_response is not None:
        return identity_response
    return Response(_detail(item, mautic_public_base_url()), status=status.HTTP_201_CREATED)


class NewsletterAdminDynamicContentListCreateView(APIView):
    """GET Dynamic Content items (newest first) with how often each was shown; POST one."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        params = request.query_params
        try:
            page = max(1, int(params.get("page") or 1))
            limit = min(100, max(1, int(params.get("page_size") or 25)))
        except (TypeError, ValueError):
            return Response({"detail": "page and page_size must be numbers.", "code": "invalid_page"}, status=status.HTTP_400_BAD_REQUEST)
        query = {"start": (page - 1) * limit, "limit": limit}
        search = " ".join(str(params.get("search") or "").split())[:200]
        if search:
            query["search"] = search
        if params.get("status") in ("published", "unpublished"):
            query["status"] = params["status"]
        if params.get("mode") in ("rules", "campaign"):
            query["mode"] = params["mode"]
        try:
            data = MauticClient().list_dynamic_contents(**query)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        total = int(data.get("total") or 0)
        return Response({"count": total, "page": page, "page_size": limit, "num_pages": (total + limit - 1) // limit,
                         "results": [{**item, "isLive": _is_live(item)} for item in data["dynamicContents"]]})

    def post(self, request):
        return _created(request, MauticClient(), request.data)


class NewsletterAdminDynamicContentDetailView(APIView):
    """GET one item (with how to place it); PATCH it; DELETE it when no campaign uses it."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, item_id):
        try:
            item = MauticClient().get_dynamic_content(item_id)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        return Response(_detail(item, mautic_public_base_url()))

    def patch(self, request, item_id):
        client = MauticClient()
        try:
            current = client.get_dynamic_content(item_id)
            pairs = bridge_form(request.data, current=current, client=client)
        except DynamicContentError as exc:
            return _item_error(exc)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        try:
            item, identity_response = _mutation(request, DYNAMIC_CONTENT_UPDATE, item_id, lambda c: c.update_dynamic_content(item_id, pairs))
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc, action="saved")
        if identity_response is not None:
            return identity_response
        return Response(_detail(item, mautic_public_base_url()))

    def delete(self, request, item_id):
        try:
            usage = MauticClient().get_dynamic_content_insights(item_id, days=1)["usage"]
        except _PROVIDER_ERRORS as exc:
            # Fail closed: an item whose use cannot be checked is not deleted.
            return _provider_error(exc, action="deleted")
        if usage.get("campaigns"):
            return Response({
                "detail": "This Dynamic Content item is still used by campaign steps. Remove it there first.",
                "code": "dynamic_content_in_use", "usage": usage,
            }, status=status.HTTP_409_CONFLICT)
        try:
            _, identity_response = _mutation(request, DYNAMIC_CONTENT_DELETE, item_id, lambda c: c.delete_dynamic_content(item_id))
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc, action="deleted")
        if identity_response is not None:
            return identity_response
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminDynamicContentDuplicateView(APIView):
    """POST: an unpublished copy with the same content and rules, as the admin's Mautic user."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, item_id):
        client = MauticClient()
        try:
            item = client.get_dynamic_content(item_id)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        return _created(request, client, duplicate_payload(item))


class NewsletterAdminDynamicContentInsightsView(APIView):
    """GET how often it was shown (totals and per day) and where it is used."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, item_id):
        try:
            days = min(365, max(1, int(request.query_params.get("days") or 30)))
        except (TypeError, ValueError):
            return Response({"detail": "days must be a number.", "code": "invalid_days"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            data = MauticClient().get_dynamic_content_insights(item_id, days=days)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        response = Response(data)
        response["Cache-Control"] = "no-store"
        return response


class NewsletterAdminDynamicContentSlotsView(APIView):
    """GET the slots a page can show: those of published rule-based items and
    those campaign "Request dynamic content" steps ask for."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            slots = MauticClient().get_dynamic_content_slots()
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        return Response({"count": len(slots), "results": slots})


class NewsletterAdminDynamicContentRuleMetadataView(APIView):
    """GET the fields and conditions a rule can use (segment metadata narrowed to
    contact fields and what Mautic can check for a visitor)."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            return Response(rule_metadata(MauticClient()))
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
