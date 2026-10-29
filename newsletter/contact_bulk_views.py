"""Marketing Hub contact bulk actions and owner choices (see contact_bulk_services)."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import marketing_cache
from .contact_bulk_services import (
    BulkActionAbort,
    BulkActionError,
    list_owner_choices,
    parse_bulk_request,
    run_bulk_action,
)
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic_identity_execution import run_interactive_mutation


def _provider_error(exc) -> Response:
    if isinstance(exc, PermanentMauticError) and "HTTP 404" in str(exc):
        return Response({"detail": "That segment, campaign or user was not found in Mautic.", "code": "target_not_found"},
                        status=status.HTTP_404_NOT_FOUND)
    return Response({"detail": "Mautic could not be reached. Nothing more was changed; try again.", "code": "mautic_error"},
                    status=status.HTTP_502_BAD_GATEWAY)


class NewsletterAdminContactBulkActionView(APIView):
    """Segment, campaign, owner or Do Not Contact changes for up to 100 ticked contacts."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request):
        try:
            options = parse_bulk_request(request.data)
        except BulkActionError as exc:
            return Response({"detail": str(exc), "code": exc.code}, status=exc.status_code)

        def run_mutation(operation, resource, resource_id, fn):
            # One fresh, single-use assertion and one audit row per contact.
            return run_interactive_mutation(
                request,
                action=operation,
                resource=resource,
                resource_id=resource_id,
                mutate=fn,
                client_factory=MauticClient,
            )

        try:
            data = run_bulk_action(options, run_mutation=run_mutation)
        except BulkActionError as exc:
            return Response({"detail": str(exc), "code": exc.code}, status=exc.status_code)
        except BulkActionAbort as exc:
            return exc.response
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response(data)


class NewsletterAdminContactOwnersView(APIView):
    """Active Mautic users a contact can be owned by."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            owners = marketing_cache.cached_value(
                "contact-owners", [], lambda: list_owner_choices(MauticClient()), ttl=marketing_cache.reference_ttl()
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response({"count": len(owners), "results": owners})


class NewsletterAdminContactCampaignsView(APIView):
    """Every Campaign a contact is in, published or not. Changes go through bulk/."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, mautic_contact_id):
        contact_id = str(mautic_contact_id or "").strip()
        if not contact_id.isdigit():
            return Response({"detail": "Contact must be a Mautic contact id.", "code": "invalid_contact"},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            rows = MauticClient().get_contact_campaigns(contact_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            if isinstance(exc, PermanentMauticError) and "HTTP 404" in str(exc):
                return Response({"detail": "That contact was not found in Mautic.", "code": "contact_not_found"},
                                status=status.HTTP_404_NOT_FOUND)
            return _provider_error(exc)
        results = [
            {
                "id": str(row["id"]),
                "name": str(row.get("name") or ""),
                "published": bool(row.get("published")),
                "manually_added": bool(row.get("manuallyAdded")),
                "date_added": row.get("dateAdded"),
            }
            for row in rows
        ]
        return Response({"count": len(results), "results": results})
