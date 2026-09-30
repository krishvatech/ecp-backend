"""Staff-only Marketing Hub dashboard endpoint."""

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import marketing_cache
from .marketing_permissions import HasMarketingHubAccess

from .mautic_dashboard_services import get_dashboard_data


def _all_sections_ok(data) -> bool:
    """Sections degrade to "unavailable" instead of failing the request, so a
    partial dashboard must not be cached."""
    return all(
        value.get("status") == "ok"
        for value in data.values()
        if isinstance(value, dict)
    )


class NewsletterAdminDashboardView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            return marketing_cache.cached_response(
                request,
                "dashboard",
                lambda: get_dashboard_data(request.query_params),
                ttl=marketing_cache.dashboard_ttl(),
                cacheable=_all_sections_ok,
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
