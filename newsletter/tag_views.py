"""Staff-only admin endpoints for native Mautic tags."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from .mautic import PermanentMauticError, TemporaryMauticError
from .provider_errors import provider_error_response
from .tag_services import (
    create_admin_tag,
    delete_admin_tag,
    get_admin_tag,
    list_admin_tag_directory,
    update_admin_tag,
)


def _tag_error(exc):
    return provider_error_response(exc, context="Mautic tag operation failed.")


class NewsletterAdminTagDirectoryView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            page = max(1, int(request.query_params.get("page", 1)))
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(request.query_params.get("page_size", 25))
        except (TypeError, ValueError):
            page_size = 25

        try:
            data = list_admin_tag_directory(
                page=page,
                page_size=page_size,
                search=request.query_params.get("search", ""),
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _tag_error(exc)

        return Response(data, status=status.HTTP_200_OK)

    def post(self, request):
        try:
            data = create_admin_tag(request.data)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _tag_error(exc)

        return Response(data, status=status.HTTP_201_CREATED)


class NewsletterAdminTagDetailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, tag_id):
        try:
            data = get_admin_tag(tag_id)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _tag_error(exc)

        return Response(data, status=status.HTTP_200_OK)

    def patch(self, request, tag_id):
        try:
            data = update_admin_tag(tag_id, request.data)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _tag_error(exc)

        return Response(data, status=status.HTTP_200_OK)

    def delete(self, request, tag_id):
        try:
            data = delete_admin_tag(tag_id)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            # Mautic refuses to delete a tag that is still applied to contacts; that
            # provider failure is surfaced rather than forced.
            return _tag_error(exc)

        return Response(data, status=status.HTTP_200_OK)
