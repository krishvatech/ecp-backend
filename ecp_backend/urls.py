"""
URL configuration for the events & community platform backend.
All API endpoints are registered under the `/api/` prefix via DRF's router.
Authentication endpoints are nested under `/api/auth/`.
"""

from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView         
from rest_framework.routers import DefaultRouter
from drf_spectacular.views import (
    SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
)
from django.conf import settings
from django.conf.urls.static import static

from realtime.urls import urlpatterns as realtime_urls
from users.views import UserViewSet, RegisterView, LinkedInAuthURL, LinkedInCallback
from community.views import CommunityViewSet
from events.views import EventViewSet
from ecp_backend.views import index
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)



router = DefaultRouter()
router.register(r"users", UserViewSet, basename="user")
router.register(r"community", CommunityViewSet, basename="community")
router.register(r"events", EventViewSet, basename="event")

urlpatterns = [
    path("", index, name="index"),
    path("admin/", admin.site.urls),

    path("api/", RedirectView.as_view(pattern_name="swagger-ui", permanent=False)),

    #  Swagger/Redoc
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    path("api/", include(router.urls)),

    # Auth endpoints
    path("api/auth/", include("users.urls")),
    path("api/", include("orders.urls")),
    path("api/messaging/", include("messaging.urls")),
    path('api/interactions/', include('interactions.urls')),
    path("api/", include((realtime_urls, "realtime"), namespace="realtime")),
    
    path("api/", include("events.urls")), 
    path('api/', include('groups.urls')),
    path("api/", include("friends.urls")),
    path("api/", include("community.urls")), 
    
    path("api/content/", include("content.urls")),
    path("api/activity/", include("activity_feed.urls")),
    
    path("api/auth/linkedin/url/", LinkedInAuthURL.as_view(), name="linkedin_auth_url"),
    path("api/auth/linkedin/callback/", LinkedInCallback.as_view(), name="linkedin_callback"),
    
]

if settings.DEBUG:
    # Only serve MEDIA_URL via Django if it's a local path (avoid trying to serve S3)
    if getattr(settings, "MEDIA_URL", "").startswith("/"):
        urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

    # Serve local-only preview images (Event.preview_image) in dev
    if hasattr(settings, "PREVIEW_MEDIA_URL") and hasattr(settings, "PREVIEW_MEDIA_ROOT"):
        urlpatterns += static(settings.PREVIEW_MEDIA_URL, document_root=settings.PREVIEW_MEDIA_ROOT)