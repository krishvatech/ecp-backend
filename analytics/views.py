"""
Views for the analytics app.

Provides list-only access to daily metrics aggregated by organization
and event.  Results can be filtered by organization, event, and a
date range.  Only authenticated users with staff or organization
admin privileges may query analytics.
"""
from __future__ import annotations

import datetime
from django.db.models import Q
from rest_framework import generics, permissions
from rest_framework.exceptions import PermissionDenied
from .models import MetricDaily
from .serializers import MetricDailySerializer


class MetricDailyListView(generics.ListAPIView):
    """List daily metrics, filtered by organization/event and date range."""

    serializer_class = MetricDailySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # Base queryset
        qs = MetricDaily.objects.all().select_related("organization", "event")
        # Filter by organization
        org_id = self.request.query_params.get("organization")
        if org_id:
            qs = qs.filter(organization_id=org_id)
            # RBAC: only staff, superusers or admins of that org can view
            if not (
                user.is_staff
                or user.is_superuser
                or user.organizations.filter(id=org_id).exists()
                or user.owned_organizations.filter(id=org_id).exists()
            ):
                raise PermissionDenied("You do not have permission to view analytics for this organization.")
        else:
            # If no organization filter, limit to orgs the user belongs to unless staff
            if not (user.is_staff or user.is_superuser):
                org_ids = list(user.organizations.values_list("id", flat=True))
                org_ids += list(user.owned_organizations.values_list("id", flat=True))
                qs = qs.filter(organization_id__in=org_ids)
        # Filter by event
        event_id = self.request.query_params.get("event")
        if event_id:
            qs = qs.filter(event_id=event_id)
        # Date range filters
        start_date = self.request.query_params.get("start")
        end_date = self.request.query_params.get("end")
        if start_date:
            try:
                start_dt = datetime.datetime.strptime(start_date, "%Y-%m-%d").date()
                qs = qs.filter(date__gte=start_dt)
            except ValueError:
                pass
        if end_date:
            try:
                end_dt = datetime.datetime.strptime(end_date, "%Y-%m-%d").date()
                qs = qs.filter(date__lte=end_dt)
            except ValueError:
                pass
        qs = qs.order_by("-date")
        return qs
