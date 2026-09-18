"""Staff-only admin endpoints for native Mautic companies and their contacts."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from . import company_services
from .company_services import (
    add_admin_company_contact,
    create_admin_company,
    delete_admin_company,
    get_admin_company,
    list_admin_companies,
    list_admin_company_contacts,
    remove_admin_company_contact,
    update_admin_company,
)
from .mautic import PermanentMauticError, TemporaryMauticError
from .mautic.operations import (
    COMPANY_CONTACT_ADD,
    COMPANY_CONTACT_REMOVE,
    COMPANY_CREATE,
    COMPANY_DELETE,
    COMPANY_UPDATE,
)
from .mautic_identity_execution import run_interactive_mutation
from .provider_errors import provider_error_response


DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100


def _paging(request):
    try:
        page = max(1, int(request.query_params.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = int(request.query_params.get("page_size", DEFAULT_PAGE_SIZE))
    except (TypeError, ValueError):
        page_size = DEFAULT_PAGE_SIZE
    return page, max(1, min(page_size, MAX_PAGE_SIZE))


def _company_error(exc):
    return provider_error_response(exc, context="Mautic company operation failed.")


class NewsletterAdminCompanyListCreateView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        page, page_size = _paging(request)
        try:
            data = list_admin_companies(
                page=page,
                page_size=page_size,
                search=request.query_params.get("search", ""),
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _company_error(exc)

        return Response(data, status=status.HTTP_200_OK)

    def post(self, request):
        try:
            data, identity_response = run_interactive_mutation(
                request,
                action=COMPANY_CREATE,
                resource="company",
                mutate=lambda client: create_admin_company(
                    request.data,
                    client=client,
                ),
                client_factory=company_services.MauticClient,
            )
            if identity_response is not None:
                return identity_response
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _company_error(exc)

        return Response(data, status=status.HTTP_201_CREATED)


class NewsletterAdminCompanyDetailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, company_id):
        try:
            data = get_admin_company(company_id)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _company_error(exc)

        return Response(data, status=status.HTTP_200_OK)

    def patch(self, request, company_id):
        try:
            data, identity_response = run_interactive_mutation(
                request,
                action=COMPANY_UPDATE,
                resource="company",
                resource_id=company_id,
                mutate=lambda client: update_admin_company(
                    company_id,
                    request.data,
                    client=client,
                ),
                client_factory=company_services.MauticClient,
            )
            if identity_response is not None:
                return identity_response
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _company_error(exc)

        return Response(data, status=status.HTTP_200_OK)

    def delete(self, request, company_id):
        try:
            data, identity_response = run_interactive_mutation(
                request,
                action=COMPANY_DELETE,
                resource="company",
                resource_id=company_id,
                mutate=lambda client: delete_admin_company(
                    company_id,
                    client=client,
                ),
                client_factory=company_services.MauticClient,
            )
            if identity_response is not None:
                return identity_response
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _company_error(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminCompanyContactsView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, company_id):
        page, page_size = _paging(request)
        try:
            data = list_admin_company_contacts(
                company_id,
                page=page,
                page_size=page_size,
                search=request.query_params.get("search", ""),
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _company_error(exc)

        return Response(data, status=status.HTTP_200_OK)

    def post(self, request, company_id):
        try:
            contact_id = request.data.get("contact_id")
            data, identity_response = run_interactive_mutation(
                request,
                action=COMPANY_CONTACT_ADD,
                resource="company_contact",
                resource_id=f"{company_id}:{contact_id or ''}",
                mutate=lambda client: add_admin_company_contact(
                    company_id,
                    contact_id,
                    client=client,
                ),
                client_factory=company_services.MauticClient,
            )
            if identity_response is not None:
                return identity_response
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _company_error(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminCompanyContactDetailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def delete(self, request, company_id, contact_id):
        try:
            data, identity_response = run_interactive_mutation(
                request,
                action=COMPANY_CONTACT_REMOVE,
                resource="company_contact",
                resource_id=f"{company_id}:{contact_id}",
                mutate=lambda client: remove_admin_company_contact(
                    company_id,
                    contact_id,
                    client=client,
                ),
                client_factory=company_services.MauticClient,
            )
            if identity_response is not None:
                return identity_response
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _company_error(exc)

        return Response(data, status=status.HTTP_200_OK)
