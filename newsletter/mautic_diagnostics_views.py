"""Staff-only Marketing Hub diagnostics endpoints."""

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from .mautic_diagnostics_services import get_mautic_diagnostics


class NewsletterAdminMauticDiagnosticsView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        return Response(get_mautic_diagnostics(request), status=status.HTTP_200_OK)
