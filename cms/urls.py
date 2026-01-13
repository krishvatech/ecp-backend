from django.urls import path
from .api import CmsPageBySlugView, ProfileLayoutView

urlpatterns = [
    path("pages/<slug:slug>/", CmsPageBySlugView.as_view(), name="cms_page_by_slug"),
    path("profile-layout/", ProfileLayoutView.as_view(), name="profile_layout"),
]
