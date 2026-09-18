"""Superuser-only Marketing Hub diagnostics endpoints.

Deliberately does NOT require an active Mautic mapping: an administrator needs
these to diagnose why a mapping is missing or broken in the first place.
"""

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsSuperuser

from .mautic_diagnostics_services import get_mautic_diagnostics


class NewsletterAdminMauticDiagnosticsView(APIView):
    permission_classes = [IsSuperuser]

    def get(self, request):
        return Response(get_mautic_diagnostics(request), status=status.HTTP_200_OK)
