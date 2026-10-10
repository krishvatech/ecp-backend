"""Marketing Hub bulk delete of Mautic contacts (prepare, then confirm in batches).

Only Marketing Hub administrators reach these views, every plan belongs to the
administrator who prepared it, and each batch's provider delete runs through
the existing identity-attributed mutation helper, so it is executed as that
administrator's Mautic user and audited.
"""

from __future__ import annotations

from rest_framework import status
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from . import contact_delete_services as delete_services
from .contact_delete_services import ContactDeleteError, plan_payload
from .contact_import_services import ContactImportError, parse_csv, read_upload
from .marketing_permissions import HasMarketingHubAccess
from .mautic import PermanentMauticError, TemporaryMauticError
from .mautic.operations import CONTACT_DELETE
from .mautic_identity_execution import run_interactive_mutation
from .provider_errors import provider_error_response


def _error(exc: ContactDeleteError):
    return Response({"detail": str(exc), "code": exc.code}, status=exc.status)


def _provider_error(exc):
    return provider_error_response(exc, context="Mautic contact lookup failed. Nothing was deleted.")


class NewsletterAdminContactDeletePrepareView(APIView):
    """Build a deletion plan. Never deletes anything."""

    permission_classes = [HasMarketingHubAccess]
    parser_classes = [JSONParser, MultiPartParser]

    def post(self, request):
        mode = str(request.data.get("mode") or "").strip()
        try:
            if mode == "selected":
                plan = delete_services.prepare_selected(request.user, request.data.get("contact_ids"))
            elif mode == "csv":
                filename, raw = read_upload(request.FILES.get("file"))
                parsed = parse_csv(filename, raw)
                plan = delete_services.prepare_csv(
                    request.user, parsed, email_column=str(request.data.get("email_column") or "").strip()
                )
            else:
                return Response(
                    {"detail": "mode must be 'selected' or 'csv'.", "code": "invalid_mode"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except ContactImportError as exc:
            return Response(exc.as_payload(), status=status.HTTP_400_BAD_REQUEST)
        except ContactDeleteError as exc:
            return _error(exc)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response(plan_payload(plan), status=status.HTTP_201_CREATED)


class NewsletterAdminContactDeleteDetailView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request, plan_id):
        try:
            return Response(plan_payload(delete_services.load_plan(request.user, plan_id)))
        except ContactDeleteError as exc:
            return _error(exc)


class NewsletterAdminContactDeleteExecuteView(APIView):
    """Delete the next batch of a confirmed plan (call until it is finished)."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, plan_id):
        def run_delete(ids):
            return run_interactive_mutation(
                request,
                action=CONTACT_DELETE,
                resource="contact_bulk_delete",
                resource_id=str(plan_id)[:16],
                mutate=lambda client: client.delete_contacts_batch(ids),
                client_factory=delete_services.MauticClient,
                audit_and_reraise=(PermanentMauticError, TemporaryMauticError),
            )

        try:
            plan, identity_response = delete_services.execute_next_batch(
                request.user, plan_id, request.data.get("confirm_count"), run_delete=run_delete
            )
        except ContactDeleteError as exc:
            return _error(exc)
        except TemporaryMauticError:
            return Response(
                {
                    "detail": "Mautic did not answer for this batch. Retry: contacts already deleted are "
                    "counted as already gone, and no other contact can be affected.",
                    "code": "retry",
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )
        except PermanentMauticError as exc:
            return _provider_error(exc)
        if identity_response is not None:
            return identity_response
        return Response(plan_payload(plan))


class NewsletterAdminContactDeleteCancelView(APIView):
    """Stop a plan before its next batch. Contacts already deleted stay deleted."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, plan_id):
        try:
            return Response(plan_payload(delete_services.cancel(request.user, plan_id)))
        except ContactDeleteError as exc:
            return _error(exc)
