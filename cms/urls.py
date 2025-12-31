from django.urls import path
from .api import CmsPageBySlugView

urlpatterns = [
    path("pages/<slug:slug>/", CmsPageBySlugView.as_view(), name="cms_page_by_slug"),
]
