"""Staff-only admin endpoints for native Mautic custom field definitions."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from .field_services import (
    ProtectedMauticFieldError,
    create_admin_field,
    delete_admin_field,
    get_admin_field,
    list_admin_field_choices,
    list_admin_field_types,
    list_admin_fields,
    update_admin_field,
)
from .mautic import PermanentMauticError, TemporaryMauticError
from .provider_errors import provider_error_response


def _field_error(exc):
    return provider_error_response(exc, context="Mautic field operation failed.")


def _protected_response(exc):
    return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)


def _as_bool(value) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


class NewsletterAdminFieldListCreateView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, field_object):
        try:
            data = list_admin_fields(
                field_object,
                search=request.query_params.get("search", ""),
                published_only=_as_bool(request.query_params.get("published_only")),
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _field_error(exc)

        return Response(data, status=status.HTTP_200_OK)

    def post(self, request, field_object):
        try:
            data = create_admin_field(field_object, request.data)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _field_error(exc)

        return Response(data, status=status.HTTP_201_CREATED)


class NewsletterAdminFieldDetailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, field_object, field_id):
        try:
            data = get_admin_field(field_object, field_id)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _field_error(exc)

        return Response(data, status=status.HTTP_200_OK)

    def patch(self, request, field_object, field_id):
        try:
            data = update_admin_field(field_object, field_id, request.data)
        except ProtectedMauticFieldError as exc:
            return _protected_response(exc)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _field_error(exc)

        return Response(data, status=status.HTTP_200_OK)

    def delete(self, request, field_object, field_id):
        try:
            data = delete_admin_field(field_object, field_id)
        except ProtectedMauticFieldError as exc:
            return _protected_response(exc)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _field_error(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminFieldTypesView(APIView):
    """Publish the Mautic-owned field type registry used by the ECP field builder."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            data = list_admin_field_types()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _field_error(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminFieldChoicesView(APIView):
    """Serve Mautic's bundled country/region/timezone/locale option lists."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, field_type):
        try:
            data = list_admin_field_choices(field_type)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _field_error(exc)

        return Response(data, status=status.HTTP_200_OK)
