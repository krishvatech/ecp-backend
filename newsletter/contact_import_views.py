"""Marketing Hub CSV contact import endpoints.

Preview and validate are read-only. Start queues the approved rows on
Mautic's native import queue as the acting administrator's own Mautic user;
status, history and row errors are read back from Mautic and only ever shown
to the administrator whose Mautic user created the import.
"""

from __future__ import annotations

import logging

from django.core.cache import cache
from rest_framework import status
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from . import contact_import_services as import_services
from .contact_import_services import (
    ContactImportError,
    ContactImportUnavailable,
    build_preview,
    mapping_targets,
    normalize_import,
    normalize_import_errors,
    parse_csv,
    parse_mapping,
    parse_options,
    read_upload,
    sign_validation,
    start_import,
    validate_import,
    validation_payload,
    verify_validation,
)
from .marketing_permissions import HasMarketingHubAccess
from .mautic import PermanentMauticError, TemporaryMauticError
from .mautic.operations import CONTACT_IMPORT_CREATE
from .mautic_identity_execution import run_interactive_mutation
from .models import MauticUserConnection
from .provider_errors import provider_error_response

logger = logging.getLogger(__name__)

START_LOCK_SECONDS = 120


def _import_error(exc: ContactImportError):
    return Response(exc.as_payload(), status=status.HTTP_400_BAD_REQUEST)


def _provider_error(exc):
    return provider_error_response(exc, context="Mautic contact import request failed.")


def _actor_mautic_user_id(user):
    connection = (
        MauticUserConnection.objects.filter(
            user_id=user.pk,
            is_active=True,
            status=MauticUserConnection.Status.ACTIVE,
        )
        .only("mautic_user_id")
        .first()
    )
    return connection.mautic_user_id if connection is not None else None


def _page_params(request, default_size=25, max_size=100):
    try:
        page = max(1, int(request.query_params.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = int(request.query_params.get("page_size", default_size))
    except (TypeError, ValueError):
        page_size = default_size
    page_size = max(1, min(page_size, max_size))
    return page, page_size


def _parse_request_file(request):
    filename, raw = read_upload(request.FILES.get("file"))
    return parse_csv(filename, raw)


class NewsletterAdminContactImportFieldsView(APIView):
    """Mapping destinations, from live Mautic contact field metadata."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            targets = mapping_targets(import_services.client_for_reads())
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response(
            {
                "results": targets,
                "limits": {
                    "max_rows": import_services.max_rows(),
                    "max_bytes": import_services.max_bytes(),
                },
                "options": {
                    "existing_modes": list(import_services.EXISTING_MODES),
                    "tag_separators": list(import_services.TAG_SEPARATORS),
                },
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminContactImportPreviewView(APIView):
    """Parse an uploaded CSV and return its structure and a capped sample."""

    permission_classes = [HasMarketingHubAccess]
    parser_classes = [MultiPartParser]

    def post(self, request):
        try:
            parsed = _parse_request_file(request)
            targets = mapping_targets(import_services.client_for_reads())
        except ContactImportError as exc:
            return _import_error(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response(build_preview(parsed, targets), status=status.HTTP_200_OK)


class NewsletterAdminContactImportValidateView(APIView):
    """Validate every row against the mapping and current Mautic data."""

    permission_classes = [HasMarketingHubAccess]
    parser_classes = [MultiPartParser]

    def post(self, request):
        try:
            parsed = _parse_request_file(request)
            mapping = parse_mapping(request.data.get("mapping"))
            options = parse_options(request.data.get("options"))
            result = validate_import(
                parsed,
                mapping,
                options,
                client=import_services.client_for_reads(),
            )
        except ContactImportError as exc:
            return _import_error(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)

        payload = validation_payload(result)
        payload["validation_token"] = sign_validation(request.user, parsed, mapping, options)
        payload["token_max_age_seconds"] = import_services.TOKEN_MAX_AGE_SECONDS
        logger.info(
            "Contact import validated",
            extra={
                "ecp_user_id": request.user.pk,
                "total_rows": result.summary.get("total_rows"),
                "to_import": result.summary.get("to_import"),
            },
        )
        return Response(payload, status=status.HTTP_200_OK)


class NewsletterAdminContactImportStartView(APIView):
    """Queue a validated import on Mautic's native import queue.

    Requires the token from Validate for the same file, mapping and options,
    an explicit confirmation, and per-user Mautic execution. The whole file is
    validated again; repeating Start with the same token never queues a
    second import (the bridge returns the first one).
    """

    permission_classes = [HasMarketingHubAccess]
    parser_classes = [MultiPartParser]

    def post(self, request):
        if str(request.data.get("confirm", "")).strip().lower() not in ("true", "1", "yes"):
            return Response(
                {"detail": "Confirm the import summary before starting.", "code": "confirmation_required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            parsed = _parse_request_file(request)
            mapping = parse_mapping(request.data.get("mapping"))
            options = parse_options(request.data.get("options"))
            claims = verify_validation(
                request.data.get("validation_token"), request.user, parsed, mapping, options
            )
            result = validate_import(
                parsed,
                mapping,
                options,
                client=import_services.client_for_reads(),
            )
        except ContactImportError as exc:
            return _import_error(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)

        if not result.rows:
            return Response(
                {
                    "detail": "No rows are left to import after revalidation.",
                    "code": "nothing_to_import",
                    "validation": validation_payload(result),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        key = import_services.idempotency_key(claims)
        lock_key = f"newsletter:contact-import:start:{key}"
        try:
            locked = cache.add(lock_key, request.user.pk, START_LOCK_SECONDS)
        except Exception:
            # The bridge's idempotency key is the durable guard; the cache
            # lock only turns a concurrent double-click into a clear message.
            locked = True
        if not locked:
            return Response(
                {"detail": "This import is already being started.", "code": "start_in_progress"},
                status=status.HTTP_409_CONFLICT,
            )

        try:
            outcome, identity_response = run_interactive_mutation(
                request,
                action=CONTACT_IMPORT_CREATE,
                resource="contact_import",
                resource_id=key[:16],
                mutate=lambda client: start_import(client, result, claims),
                client_factory=import_services.MauticClient,
                audit_and_reraise=(PermanentMauticError, TemporaryMauticError),
            )
        except ContactImportUnavailable as exc:
            return Response(
                {"detail": str(exc), "code": "per_user_execution_required"},
                status=status.HTTP_409_CONFLICT,
            )
        except ContactImportError as exc:
            return _import_error(exc)
        except TemporaryMauticError:
            return Response(
                {
                    "detail": (
                        "Mautic did not confirm the import. It may still have been queued: "
                        "check Import history before trying again. Retrying Start with this "
                        "validation never queues the same import twice."
                    ),
                    "code": "outcome_unknown",
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )
        except PermanentMauticError as exc:
            return _provider_error(exc)
        finally:
            try:
                cache.delete(lock_key)
            except Exception:
                pass
        if identity_response is not None:
            return identity_response

        contact_import, duplicate = outcome
        logger.info(
            "Contact import queued",
            extra={
                "ecp_user_id": request.user.pk,
                "mautic_import_id": contact_import.get("id"),
                "rows_sent": len(result.rows),
                "duplicate": duplicate,
            },
        )
        return Response(
            {
                "import": normalize_import(contact_import),
                "duplicate": duplicate,
                "validation": validation_payload(result),
            },
            status=status.HTTP_200_OK if duplicate else status.HTTP_201_CREATED,
        )


class NewsletterAdminContactImportListView(APIView):
    """The acting administrator's own ECP imports, newest first."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        mautic_user_id = _actor_mautic_user_id(request.user)
        if not mautic_user_id:
            return Response({"count": 0, "page": 1, "page_size": 0, "results": []})
        page, page_size = _page_params(request, default_size=10, max_size=50)
        try:
            data = import_services.client_for_reads().list_contact_imports(
                created_by=mautic_user_id,
                limit=page_size,
                start=(page - 1) * page_size,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)

        results = [
            normalize_import(item)
            for item in data.get("imports", [])
            if isinstance(item, dict) and item.get("created_by") == mautic_user_id
        ]
        return Response(
            {
                "count": int(data.get("total") or 0),
                "page": page,
                "page_size": page_size,
                "results": results,
            },
            status=status.HTTP_200_OK,
        )


def _owned_import(request, import_id):
    """The import, or None when it does not exist or belongs to someone else.

    Both cases return the same 404 so import IDs cannot be probed.
    """
    mautic_user_id = _actor_mautic_user_id(request.user)
    if not mautic_user_id:
        return None
    contact_import = import_services.client_for_reads().get_contact_import(import_id)
    if contact_import.get("created_by") != mautic_user_id:
        return None
    return contact_import


class NewsletterAdminContactImportDetailView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request, import_id):
        try:
            contact_import = _owned_import(request, import_id)
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                contact_import = None
            else:
                return _provider_error(exc)
        except TemporaryMauticError as exc:
            return _provider_error(exc)
        if contact_import is None:
            return Response({"detail": "Import not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(normalize_import(contact_import), status=status.HTTP_200_OK)


class NewsletterAdminContactImportErrorsView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request, import_id):
        page, page_size = _page_params(request)
        try:
            contact_import = _owned_import(request, import_id)
            if contact_import is None:
                return Response({"detail": "Import not found."}, status=status.HTTP_404_NOT_FOUND)
            data = import_services.client_for_reads().list_contact_import_errors(
                import_id,
                limit=page_size,
                start=(page - 1) * page_size,
            )
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                return Response({"detail": "Import not found."}, status=status.HTTP_404_NOT_FOUND)
            return _provider_error(exc)
        except TemporaryMauticError as exc:
            return _provider_error(exc)

        payload = normalize_import_errors(data)
        payload.update({"page": page, "page_size": page_size})
        return Response(payload, status=status.HTTP_200_OK)
