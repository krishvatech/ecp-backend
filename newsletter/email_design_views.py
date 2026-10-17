from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .email_design_services import EmailDesignCompileError, compile_marketing_mjml
from .marketing_permissions import HasMarketingHubAccess


class NewsletterAdminEmailDesignCompileView(APIView):
    """Compile visual-editor MJML to email HTML for a Template or Broadcast.

    Read-only with respect to Mautic and ECP data: nothing is stored, synced,
    published or sent, so no Mautic identity assertion is involved.
    """

    permission_classes = [HasMarketingHubAccess]

    def post(self, request):
        data = request.data if isinstance(request.data, dict) else {}
        try:
            result = compile_marketing_mjml(data.get("mjml"))
        except EmailDesignCompileError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(result, status=status.HTTP_200_OK)
