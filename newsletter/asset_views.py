"""Marketing Hub assets endpoints (see asset_services)."""

from __future__ import annotations

import re

from django.http import HttpResponse
from rest_framework import status
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .asset_services import AssetError, asset_categories, asset_config, check_remote_url, check_upload, normalize_fields
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.operations import ASSET_CREATE, ASSET_DELETE, ASSET_UPDATE
from .mautic_identity_audit import record_identity_audit
from .mautic_identity_execution import run_interactive_mutation
from .models import MauticIdentityAuditLog

FILE_DOWNLOAD = "asset.file.download"
_PROVIDER_ERRORS = (TemporaryMauticError, PermanentMauticError)
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]")


def _asset_error(exc: AssetError) -> Response:
    body = {"detail": str(exc), "code": exc.code}
    if exc.field:
        body["field"] = exc.field
    return Response(body, status=exc.status_code)


def _provider_error(exc, *, action: str = "read") -> Response:
    message = str(exc)
    if isinstance(exc, PermanentMauticError):
        reason = message.split(": ", 1)[1] if ": " in message else ""
        if "HTTP 404" in message:
            return Response({"detail": "That asset was not found in Mautic.", "code": "asset_not_found"}, status=status.HTTP_404_NOT_FOUND)
        if "HTTP 403" in message:
            return Response({"detail": "Your Mautic user is not allowed to do that with assets.", "code": "asset_forbidden"},
                            status=status.HTTP_403_FORBIDDEN)
        if "HTTP 409" in message:
            return Response({"detail": reason or "That asset has no stored file.", "code": "asset_conflict"}, status=status.HTTP_409_CONFLICT)
        if "HTTP 400" in message or "HTTP 422" in message:
            # The bridge or Mautic's own form refused it: show the reason.
            return Response({"detail": reason or "Mautic refused the asset.", "code": "asset_invalid"}, status=status.HTTP_400_BAD_REQUEST)
    if action == "read":
        detail = "Mautic could not be reached. Try again."
    else:
        detail = f"Mautic could not be reached. Nothing was {action}; try again."
    return Response({"detail": detail, "code": "mautic_error"}, status=status.HTTP_502_BAD_GATEWAY)


def _mutation(request, action: str, resource_id, mutate, **kwargs):
    return run_interactive_mutation(
        request,
        action=action,
        resource="asset",
        resource_id=resource_id,
        mutate=mutate,
        client_factory=MauticClient,
        audit_and_reraise=_PROVIDER_ERRORS,
        **kwargs,
    )


def _file_and_link(request, config, *, creating: bool):
    """(upload tuple or None, remote url): one of them on create, at most one on update."""
    upload = request.FILES.get("file")
    remote = str(request.data.get("remoteUrl") or "").strip() if hasattr(request.data, "get") else ""
    if upload and remote:
        raise AssetError("Upload a file or enter a link, not both.", field="file")
    if creating and not upload and not remote:
        raise AssetError("Upload a file or enter a link to a remote file.", field="file")
    if upload:
        check_upload(upload.name, upload.size, config)
        return (upload.name, upload.read(), upload.content_type or "application/octet-stream"), ""
    if remote:
        return None, check_remote_url(remote)
    return None, ""


class NewsletterAdminAssetMetadataView(APIView):
    """Upload limits (Mautic's allowed extensions and max size) and asset categories."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        client = MauticClient()
        try:
            config = asset_config(client)
            categories = asset_categories(client)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        return Response({**config, "categories": categories})


class NewsletterAdminAssetListCreateView(APIView):
    permission_classes = [HasMarketingHubAccess]
    parser_classes = [MultiPartParser, JSONParser]

    def get(self, request):
        params = request.query_params
        try:
            page = max(1, int(params.get("page") or 1))
            limit = min(100, max(1, int(params.get("page_size") or 25)))
        except (TypeError, ValueError):
            return Response({"detail": "page and page_size must be numbers.", "code": "invalid_page"}, status=status.HTTP_400_BAD_REQUEST)
        query = {"page": page, "limit": limit}
        if params.get("search"):
            query["search"] = str(params["search"])[:200]
        if params.get("status") in ("published", "unpublished"):
            query["status"] = params["status"]
        try:
            data = MauticClient().list_assets(**query)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        total = int(data.get("total") or 0)
        return Response({"count": total, "page": page, "page_size": limit, "num_pages": (total + limit - 1) // limit,
                         "results": data["assets"]})

    def post(self, request):
        client = MauticClient()
        try:
            config = asset_config(client)
            fields = normalize_fields(request.data, creating=True, categories=asset_categories(client))
            upload, remote = _file_and_link(request, config, creating=True)
        except AssetError as exc:
            return _asset_error(exc)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)

        try:
            asset, identity_response = _mutation(
                request, ASSET_CREATE, "", lambda c: c.create_asset(fields, upload=upload, remote_url=remote),
                resource_id_from_result=lambda result: result.get("id"),
                detail=("remote link" if remote else f"upload .{upload[0].rsplit('.', 1)[-1].lower()}")[:250],
            )
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc, action="saved")
        if identity_response is not None:
            return identity_response
        return Response(asset, status=status.HTTP_201_CREATED)


class NewsletterAdminAssetDetailView(APIView):
    """GET one asset; PATCH its details and optionally a new file or link; DELETE it (and its file)."""

    permission_classes = [HasMarketingHubAccess]
    parser_classes = [MultiPartParser, JSONParser]

    def get(self, request, asset_id):
        try:
            return Response(MauticClient().get_asset(asset_id))
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)

    def patch(self, request, asset_id):
        client = MauticClient()
        try:
            config = asset_config(client)
            fields = normalize_fields(request.data, creating=False, categories=asset_categories(client))
            upload, remote = _file_and_link(request, config, creating=False)
        except AssetError as exc:
            return _asset_error(exc)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        if not fields and not upload and not remote:
            return Response({"detail": "Nothing to change.", "code": "no_changes"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            asset, identity_response = _mutation(
                request, ASSET_UPDATE, asset_id, lambda c: c.update_asset(asset_id, fields, upload=upload, remote_url=remote),
                detail="file replaced" if upload or remote else "",
            )
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc, action="saved")
        if identity_response is not None:
            return identity_response
        return Response(asset)

    def delete(self, request, asset_id):
        try:
            _, identity_response = _mutation(request, ASSET_DELETE, asset_id, lambda c: c.delete_asset(asset_id))
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc, action="deleted")
        if identity_response is not None:
            return identity_response
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminAssetDownloadsView(APIView):
    """Download totals, a daily series and the most recent downloads (contact, source)."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, asset_id):
        params = request.query_params
        try:
            query = {
                "days": min(365, max(1, int(params.get("days") or 30))),
                "page": max(1, int(params.get("page") or 1)),
                "limit": min(100, max(1, int(params.get("page_size") or 25))),
            }
        except (TypeError, ValueError):
            return Response({"detail": "days, page and page_size must be numbers.", "code": "invalid_page"},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            data = MauticClient().get_asset_downloads(asset_id, **query)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        response = Response(data)
        response["Cache-Control"] = "no-store"
        return response


class NewsletterAdminAssetFileView(APIView):
    """The stored file for the admin, as an attachment. Not counted as a download in Mautic; audited."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, asset_id):
        client = MauticClient()
        try:
            asset = client.get_asset(asset_id)
            upstream = client.get_asset_file(asset_id)
        except _PROVIDER_ERRORS as exc:
            return _provider_error(exc)
        name = _SAFE_NAME.sub("_", str(asset.get("originalFileName") or f"asset-{asset_id}"))[:150] or f"asset-{asset_id}"
        record_identity_audit(
            action=FILE_DOWNLOAD,
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            actor=request.user,
            resource="asset",
            resource_id=str(asset_id),
            detail=name[:250],
        )
        response = HttpResponse(upstream.content, content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{name}"'
        response["Cache-Control"] = "no-store"
        response["X-Content-Type-Options"] = "nosniff"
        return response
