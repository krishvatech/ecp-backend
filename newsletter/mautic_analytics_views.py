"""Staff-only Mautic-backed Marketing Analytics endpoints."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

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
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        date_range = _date_range_or_response(request)
        if isinstance(date_range, Response):
            return date_range
        try:
            data = get_overview_analytics(date_range)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminAnalyticsCampaignsView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            data = list_campaign_analytics(request.query_params)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminAnalyticsEmailsView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            data = list_email_analytics(request.query_params)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminAnalyticsContactsView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        date_range = _date_range_or_response(request)
        if isinstance(date_range, Response):
            return date_range
        try:
            data = get_contact_analytics(date_range)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminAnalyticsSegmentsView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            data = list_segment_analytics(request.query_params)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response(data, status=status.HTTP_200_OK)
