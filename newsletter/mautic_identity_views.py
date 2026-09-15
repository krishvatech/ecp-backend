"""Staff-only Marketing Hub Mautic identity-connection endpoints."""

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from .mautic_identity_services import get_mautic_identity_connection_status


class NewsletterAdminMauticIdentityStatusView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        return Response(
            get_mautic_identity_connection_status(request.user),
            status=status.HTTP_200_OK,
        )
