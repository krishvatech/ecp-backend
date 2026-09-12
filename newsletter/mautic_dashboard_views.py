"""Staff-only Marketing Hub dashboard endpoint."""

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from .mautic_dashboard_services import get_dashboard_data


class NewsletterAdminDashboardView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            data = get_dashboard_data(request.query_params)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(data, status=status.HTTP_200_OK)
