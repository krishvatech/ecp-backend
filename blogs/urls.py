"""
URL patterns for the blogs app, included under ``/api/blogs/``.

``admin/`` routes are listed before the public ``<slug>/`` route, and
``admin`` is a reserved post slug, so the two surfaces cannot collide.
"""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from .views import (
    BlogCategoryAdminViewSet,
    BlogPostAdminViewSet,
    BlogPostViewSet,
    BlogTagAdminViewSet,
)

app_name = "blogs"

admin_router = SimpleRouter()
admin_router.register(r"categories", BlogCategoryAdminViewSet, basename="admin-category")
admin_router.register(r"tags", BlogTagAdminViewSet, basename="admin-tag")
admin_router.register(r"", BlogPostAdminViewSet, basename="admin-post")

public_router = SimpleRouter()
public_router.register(r"", BlogPostViewSet, basename="post")

urlpatterns = [
    path("admin/", include(admin_router.urls)),
] + public_router.urls
