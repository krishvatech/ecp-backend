"""
URL patterns for the blogs app, included under ``/api/blogs/``.

``admin/`` routes are listed before the public ``<slug>/`` route, and
``admin`` is a reserved post slug, so the two surfaces cannot collide.
"""
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from .public_sections import PublicSectionPostViewSet
from .views import (
    BlogCategoryAdminViewSet,
    BlogPostAdminViewSet,
    BlogPostViewSet,
    BlogTagAdminViewSet,
    BlogWordPressImportViewSet,
)

app_name = "blogs"

admin_router = SimpleRouter()
admin_router.register(r"categories", BlogCategoryAdminViewSet, basename="admin-category")
admin_router.register(r"tags", BlogTagAdminViewSet, basename="admin-tag")
admin_router.register(r"wordpress-import", BlogWordPressImportViewSet, basename="admin-wordpress-import")
admin_router.register(r"", BlogPostAdminViewSet, basename="admin-post")

public_router = SimpleRouter()
public_router.register(r"", BlogPostViewSet, basename="post")

section_list = PublicSectionPostViewSet.as_view({"get": "list"})
section_detail = PublicSectionPostViewSet.as_view({"get": "retrieve"})

urlpatterns = [
    path("admin/", include(admin_router.urls)),
    # Public website sections (anonymous): In The News and M&A Publications (blogs/public_sections.py).
    path("public/<slug:section>/", section_list, name="public-section-list"),
    path("public/<slug:section>/<slug:slug>/", section_detail, name="public-section-detail"),
] + public_router.urls
