"""
URL configuration for the analytics app.

This module defines the endpoint for listing daily metrics.  Include
under ``/api/analytics/`` in the project-level URL config.
"""
from django.urls import path
from .views import MetricDailyListView


urlpatterns = [
    path("daily/", MetricDailyListView.as_view(), name="analytics-daily-list"),
]
