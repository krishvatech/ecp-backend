"""
URL configuration for the events & community platform backend.

All API endpoints are registered under the `/api/` prefix via DRF's router.
Authentication endpoints are nested under `/api/auth/`.
"""
from django.contrib import admin
from django.urls import include, path
from rest_framework.routers import DefaultRouter

from users.views import UserViewSet, RegisterView
from organizations.views import OrganizationViewSet
from events.views import EventViewSet

# Create a default router and register our viewsets
router = DefaultRouter()
router.register(r"users", UserViewSet, basename="user")
router.register(r"organizations", OrganizationViewSet, basename="organization")
router.register(r"events", EventViewSet, basename="event")

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include(router.urls)),
    # Auth endpoints (JWT and register)
    path("api/auth/", include("users.urls")),
]