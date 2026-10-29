"""Marketing Hub contact merge (see contact_merge_services)."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .contact_merge_services import MergeError, merge_preview, run_merge
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.operations import CONTACT_MERGE
from .mautic_identity_execution import run_interactive_mutation


def _provider_error(exc) -> Response:
    message = str(exc)
    if isinstance(exc, PermanentMauticError) and "HTTP 404" in message:
        return Response({"detail": "That contact was not found in Mautic.", "code": "contact_not_found"},
                        status=status.HTTP_404_NOT_FOUND)
    if isinstance(exc, PermanentMauticError) and "HTTP 409" in message:
        if "Subscription List" in message:
            return Response({"detail": "The contact to merge away is subscribed to a Subscription List the kept contact "
                                       "is not. Subscriptions are consent and cannot move between contacts.",
                             "code": "subscription_list_conflict"}, status=status.HTTP_409_CONFLICT)
        return Response({"detail": "One of the contacts is being edited in Mautic. Try again later.", "code": "contact_locked"},
                        status=status.HTTP_409_CONFLICT)
    return Response({"detail": "Mautic could not be reached. Nothing was merged; try again.", "code": "mautic_error"},
                    status=status.HTTP_502_BAD_GATEWAY)


class NewsletterAdminContactMergeView(APIView):
    """GET previews merging ?other_contact_id= into this contact; POST merges it."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, mautic_contact_id):
        try:
            return Response(merge_preview(mautic_contact_id, request.query_params.get("other_contact_id")))
        except MergeError as exc:
            return Response({"detail": str(exc), "code": exc.code}, status=exc.status_code)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)

    def post(self, request, mautic_contact_id):
        other = request.data.get("other_contact_id") if isinstance(request.data, dict) else None

        def run_mutation(fn):
            return run_interactive_mutation(
                request,
                action=CONTACT_MERGE,
                resource="contact",
                resource_id=f"{mautic_contact_id}:{other}",
                mutate=fn,
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
            )

        try:
            data = run_merge(mautic_contact_id, other, run_mutation=run_mutation)
        except MergeError as exc:
            return Response({"detail": str(exc), "code": exc.code}, status=exc.status_code)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        if "identity_response" in data:
            return data["identity_response"]
        return Response(data)
