"""Staff-only Mautic-backed Marketing Analytics endpoints."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import marketing_cache
from .marketing_permissions import HasMarketingHubAccess

from .mautic import PermanentMauticError, TemporaryMauticError
from .mautic_analytics_services import (
    get_contact_analytics,
    get_overview_analytics,
    list_campaign_analytics,
    list_email_analytics,
    list_segment_analytics,
    parse_date_range,
)
from .provider_errors import provider_error_response


def _provider_error(exc):
    return provider_error_response(exc, context="Mautic analytics operation failed.")


def _date_range_or_response(request):
    try:
        return parse_date_range(request.query_params)
    except ValueError as exc:
        return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)


class NewsletterAdminAnalyticsOverviewView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        date_range = _date_range_or_response(request)
        if isinstance(date_range, Response):
            return date_range
        try:
            return marketing_cache.cached_response(
                request,
                "analytics-overview",
                lambda: get_overview_analytics(date_range),
                ttl=marketing_cache.analytics_ttl(),
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)


class NewsletterAdminAnalyticsCampaignsView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            return marketing_cache.cached_response(
                request,
                "analytics-campaigns",
                lambda: list_campaign_analytics(request.query_params),
                ttl=marketing_cache.analytics_ttl(),
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)


class NewsletterAdminAnalyticsEmailsView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            return marketing_cache.cached_response(
                request,
                "analytics-emails",
                lambda: list_email_analytics(request.query_params),
                ttl=marketing_cache.analytics_ttl(),
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)


class NewsletterAdminAnalyticsContactsView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        date_range = _date_range_or_response(request)
        if isinstance(date_range, Response):
            return date_range
        try:
            return marketing_cache.cached_response(
                request,
                "analytics-contacts",
                lambda: get_contact_analytics(date_range),
                ttl=marketing_cache.analytics_ttl(),
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)


class NewsletterAdminAnalyticsSegmentsView(APIView):
    permission_classes = [HasMarketingHubAccess]

    def get(self, request):
        try:
            return marketing_cache.cached_response(
                request,
                "analytics-segments",
                lambda: list_segment_analytics(request.query_params),
                ttl=marketing_cache.analytics_ttl(),
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
