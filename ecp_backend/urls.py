"""
URL configuration for the events & community platform backend.

All API endpoints are registered under the `/api/` prefix via DRF's router.
Authentication endpoints are nested under `/api/auth/`.
"""

from django.contrib import admin
from django.urls import include, path
from rest_framework.routers import DefaultRouter

from users.views import UserViewSet, RegisterView,LinkedInAuthURL, LinkedInCallback
from organizations.views import OrganizationViewSet
from events.views import EventViewSet
from realtime.urls import urlpatterns as realtime_urls

# drf-spectacular views
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)

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

    # OpenAPI schema
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path(
        "api/redoc/",
        SpectacularRedocView.as_view(url_name="schema"),
        name="redoc",
    ),
    path("api/auth/linkedin/url/", LinkedInAuthURL.as_view(), name="linkedin_auth_url"),
    path("api/auth/linkedin/callback/", LinkedInCallback.as_view(), name="linkedin_callback"),
    # Realtime endpoints (stream token issuance)
    path("api/", include((realtime_urls, "realtime"), namespace="realtime")),
]
