"""
URL configuration for the integrations app.

Provides routes to manage integration configurations and to test
connections to external services.  Include this module under
``/api/integrations/`` at the project level.
"""
from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import IntegrationConfigViewSet, TestConnectionView


router = DefaultRouter()
router.register(r"configs", IntegrationConfigViewSet, basename="integrationconfig")

urlpatterns = [
    *router.urls,
    path("test-connection/", TestConnectionView.as_view(), name="integration-test-connection"),
]
