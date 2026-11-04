"""Marketing Hub Focus Items endpoints (see focus_services)."""

from __future__ import annotations

from datetime import datetime, timezone

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .focus_services import FocusError, bridge_form, duplicate_payload, embed_codes, focus_rows, normalize_focus, preview_document
from .form_views import _public_base_url as mautic_public_base_url
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.operations import FOCUS_CREATE, FOCUS_DELETE, FOCUS_UPDATE
from .mautic_identity_execution import run_interactive_mutation
from .mautic_publish_window import from_mautic

_PROVIDER_ERRORS = (TemporaryMauticError, PermanentMauticError)


def _focus_error(exc: FocusError) -> Response:
    body = {"detail": str(exc), "code": exc.code}
    if exc.field:
        body["field"] = exc.field
    return Response(body, status=exc.status_code)


def _provider_error(exc, *, action: str = "read") -> Response:
    message = str(exc)
    if isinstance(exc, PermanentMauticError):
        reason = message.split(": ", 1)[1] if ": " in message else ""
        if "HTTP 404" in message:
            return Response({"detail": "That Focus Item was not found in Mautic.", "code": "focus_not_found"}, status=status.HTTP_404_NOT_FOUND)
        if "HTTP 403" in message:
            return Response({"detail": "Your Mautic user is not allowed to do that with Focus Items.", "code": "focus_forbidden"},
                            status=status.HTTP_403_FORBIDDEN)
        if "HTTP 409" in message:
            return Response({"detail": reason or "This Focus Item is still in use.", "code": "focus_in_use"}, status=status.HTTP_409_CONFLICT)
        if "HTTP 400" in message or "HTTP 422" in message:
            # The bridge or Mautic's own form refused it: show the reason.
            return Response({"detail": reason or "Mautic refused the Focus Item.", "code": "focus_invalid"}, status=status.HTTP_400_BAD_REQUEST)
    if action == "read":
        detail = "Mautic could not be reached. Try again."
    else:
        detail = f"Mautic could not be reached. Nothing was {action}; try again."
    return Response({"detail": detail, "code": "mautic_error"}, status=status.HTTP_502_BAD_GATEWAY)


def _mutation(request, action: str, resource_id, mutate, **kwargs):
    return run_interactive_mutation(
        request,
        action=action,
        resource="focus",
        resource_id=resource_id,
        mutate=mutate,
        client_factory=MauticClient,
        audit_and_reraise=_PROVIDER_ERRORS,
        **kwargs,
    )


def _is_live(focus: dict) -> bool:
    """Published and inside its publish window: what Mautic's public script requires."""
    if not focus["isPublished"]:
        return False
    now = datetime.now(timezone.utc)
    start, end = from_mautic(focus.get("publishUp")), from_mautic(focus.get("publishDown"))
    return not (start and start > now) and not (end and end <= now)


def _detail(focus: dict, base: str | None) -> dict:
    return {**focus, "isLive": _is_live(focus), "embed": embed_codes(focus["id"], base)}


def _created(request, client: MauticClient, data) -> Response:
    try:
        pairs = bridge_form(data, client=client)
    except FocusError as exc:
        return _focus_error(exc)
    except _PROVIDER_ERRORS as exc:
        return _provider_error(exc)
    try:
        focus, identity_response = _mutation(
            request, FOCUS_CREATE, "", lambda c: c.create_focus_item(pairs),
            resource_id_from_result=lambda result: result.get("id"),
            detail=str(data.get("name") or "")[:250],
        )
    except _PROVIDER_ERRORS as exc:
        return _provider_error(exc, action="saved")
    if identity_response is not None:
        return identity_response
    return Response(_detail(normalize_focus(focus), mautic_public_base_url()), status=status.HTTP_201_CREATED)


class NewsletterAdminFocusListCreateView(APIView):
    """GET Focus Items (newest first) with their views, clicks and submissions; POST one."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        params = request.query_params
        try:
            page = max(1, int(params.get("page") or 1))
            limit = min(100, max(1, int(params.get("page_size") or 25)))
        except (TypeError, ValueError):
            return Response({"detail": "page and page_size must be numbers.", "code": "invalid_page"}, status=status.HTTP_400_BAD_REQUEST)
        search = " ".join(str(params.get("search") or "").split())[:200]
        if params.get("status") in ("published", "unpublished"):
            search = f"{search} is:{params['status']}".strip()
        client = MauticClient()
        try:
            data = client.list_focus_items(start=(page - 1) * limit, limit=limit, orderBy="id", orderByDir="DESC",
                                           **({"search": search} if search else {}))
            rows = focus_rows(data)
            stats = client.get_focus_stats([row["id"] for row in rows])
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        total = int(data.get("total") or 0)
        return Response({
            "count": total, "page": page, "page_size": limit, "num_pages": (total + limit - 1) // limit,
            "results": [{**focus, "isLive": _is_live(focus)} for focus in
                        (normalize_focus(row, stats=stats.get(int(row["id"]))) for row in rows)],
        })

    def post(self, request):
        return _created(request, MauticClient(), request.data)


class NewsletterAdminFocusDetailView(APIView):
    """GET one Focus Item (with its embed code); PATCH it; DELETE it when nothing uses it."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, focus_id):
        try:
            focus = normalize_focus(MauticClient().get_focus_item(focus_id))
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        return Response(_detail(focus, mautic_public_base_url()))

    def patch(self, request, focus_id):
        client = MauticClient()
        try:
            current = normalize_focus(client.get_focus_item(focus_id))
            pairs = bridge_form(request.data, current=current, client=client)
        except FocusError as exc:
            return _focus_error(exc)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        try:
            focus, identity_response = _mutation(request, FOCUS_UPDATE, focus_id, lambda c: c.update_focus_item(focus_id, pairs))
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc, action="saved")
        if identity_response is not None:
            return identity_response
        return Response(_detail(normalize_focus(focus), mautic_public_base_url()))

    def delete(self, request, focus_id):
        try:
            usage = MauticClient().get_focus_insights(focus_id, days=1)["usage"]
        except _PROVIDER_ERRORS as exc:
            # Fail closed: an item whose use cannot be checked is not deleted.
            return _provider_error(exc, action="deleted")
        campaigns, pages = usage.get("campaigns") or [], usage.get("pages") or []
        if campaigns or pages:
            return Response({
                "detail": "This Focus Item is still used. Remove it from these campaigns and landing pages first.",
                "code": "focus_in_use", "usage": {"campaigns": campaigns, "pages": pages},
            }, status=status.HTTP_409_CONFLICT)
        try:
            _, identity_response = _mutation(request, FOCUS_DELETE, focus_id, lambda c: c.delete_focus_item(focus_id))
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc, action="deleted")
        if identity_response is not None:
            return identity_response
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminFocusDuplicateView(APIView):
    """POST: an unpublished copy with the same settings, as the admin's Mautic user."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, focus_id):
        client = MauticClient()
        try:
            focus = normalize_focus(client.get_focus_item(focus_id))
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        if focus["htmlMode"] == "html":
            # Its raw HTML cannot be saved through ECP, so a copy would lose the content.
            return Response({"detail": "This Focus Item uses Mautic's raw HTML mode, so it can only be copied in Mautic.",
                             "code": "focus_raw_html"}, status=status.HTTP_400_BAD_REQUEST)
        return _created(request, client, duplicate_payload(focus))


class NewsletterAdminFocusPreviewView(APIView):
    """POST unsaved settings: Mautic's own rendering, as a document for a sandboxed frame."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request):
        client = MauticClient()
        try:
            html = client.preview_focus_item(bridge_form(request.data, client=client, preview=True))
        except FocusError as exc:
            return _focus_error(exc)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        response = Response({"document": preview_document(html)})
        response["Cache-Control"] = "no-store"
        return response


class NewsletterAdminFocusInsightsView(APIView):
    """GET views, clicks and submissions (totals and per day) and where the Focus Item is used."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, focus_id):
        try:
            days = min(365, max(1, int(request.query_params.get("days") or 30)))
        except (TypeError, ValueError):
            return Response({"detail": "days must be a number.", "code": "invalid_days"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            data = MauticClient().get_focus_insights(focus_id, days=days)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        response = Response(data)
        response["Cache-Control"] = "no-store"
        return response
