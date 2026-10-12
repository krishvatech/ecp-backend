"""Marketing Hub permanent delete of a Subscription List.

Separate from ``DELETE /admin/categories/<slug>/``, which stays Deactivate.
GET is a read-only preflight for the confirmation dialog; POST performs the
deletion (see ``category_delete_services`` for the lifecycle). The Mautic
segment delete runs through the identity-attributed mutation helper, so it is
executed as the acting administrator's Mautic user and audited.
"""

from __future__ import annotations

from django.conf import settings
from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import category_delete_services as delete_services
from .category_delete_services import CategoryDeleteError
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.operations import SEGMENT_DELETE
from .mautic_identity_execution import run_interactive_mutation
from .models import NewsletterCategory


def _mautic_enabled():
    return bool(getattr(settings, "MAUTIC_SYNC_ENABLED", False))


def _get_category(slug):
    try:
        return NewsletterCategory.objects.get(slug=slug)
    except NewsletterCategory.DoesNotExist:
        raise Http404


def _current_state(category):
    return (
        NewsletterCategory.objects.filter(pk=category.pk)
        .values_list("deletion_state", flat=True)
        .first()
    )


def _provider_failure(exc, category):
    temporary = isinstance(exc, TemporaryMauticError)
    return Response(
        {
            "detail": (
                str(exc)
                or "Mautic could not complete the Subscription List deletion."
            ),
            "code": "mautic_unavailable" if temporary else "mautic_rejected",
            "deletion_state": _current_state(category),
            "retryable": True,
        },
        status=(
            status.HTTP_503_SERVICE_UNAVAILABLE
            if temporary
            else status.HTTP_502_BAD_GATEWAY
        ),
    )


class NewsletterAdminCategoryDeleteView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request, slug):
        category = _get_category(slug)
        if category.is_deleted:
            raise Http404
        try:
            report = delete_services.check_category(
                category, mautic_enabled=_mautic_enabled()
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_failure(exc, category)
        return Response(report, status=status.HTTP_200_OK)

    def post(self, request, slug):
        category = _get_category(slug)
        if category.is_deleted:
            return Response(
                delete_services.deletion_payload(category, already_deleted=True),
                status=status.HTTP_200_OK,
            )

        try:
            if not delete_services.acquire_lock(category):
                return Response(
                    {
                        "detail": "This Subscription List is already being deleted.",
                        "code": "deletion_in_progress",
                    },
                    status=status.HTTP_409_CONFLICT,
                )
        except CategoryDeleteError as exc:
            return Response(exc.as_payload(), status=exc.status)

        try:
            return self._delete(request, category)
        except CategoryDeleteError as exc:
            return Response(exc.as_payload(), status=exc.status)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_failure(exc, category)
        finally:
            delete_services.release_lock(category)

    def _delete(self, request, category):
        report = delete_services.check_category(
            category, mautic_enabled=_mautic_enabled()
        )
        delete_services.raise_if_blocked(report)

        segment_id = report["mautic_segment_id"]
        already_missing = bool(report["mautic_segment_missing"])

        if segment_id and not already_missing:
            def delete_segment(client):
                delete_services.begin_deletion(category, actor=request.user)
                return delete_services.delete_remote_segment(client, segment_id)

            already_missing, identity_response = run_interactive_mutation(
                request,
                action=SEGMENT_DELETE,
                resource="newsletter_category",
                resource_id=category.slug,
                mutate=delete_segment,
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
            )
            if identity_response is not None:
                return identity_response
        else:
            delete_services.begin_deletion(category, actor=request.user)

        deleted = delete_services.finish_deletion(category)
        return Response(
            delete_services.deletion_payload(
                deleted,
                segment_already_missing=already_missing,
                warnings=report["warnings"],
            ),
            status=status.HTTP_200_OK,
        )
