from django.urls import path
from .api import (
    CmsPageBySlugView,
    EmailTemplateDetailView,
    EmailTemplateListView,
    EmailTemplatePreviewView,
    EmailTemplateResetView,
    EmailTemplateSendTestView,
    ProfileLayoutView,
)
from .contact import ContactSubmissionView
from .public_pages import CmsPublicPageByPathView

urlpatterns = [
    path("pages/<slug:slug>/", CmsPageBySlugView.as_view(), name="cms_page_by_slug"),
    # Public website: resolve a complete relative path within the configured Wagtail Site,
    # e.g. GET /api/cms/public/pages/by-path/?path=/privacy-policy/
    path("public/pages/by-path/", CmsPublicPageByPathView.as_view(), name="cms_public_page_by_path"),
    # e.g. POST /api/cms/public/contact/ (Contact Us enquiries; e-mailed, not stored)
    path("public/contact/", ContactSubmissionView.as_view(), name="cms_public_contact"),
    path("profile-layout/", ProfileLayoutView.as_view(), name="profile_layout"),
    path("email-templates/", EmailTemplateListView.as_view(), name="cms_email_template_list"),
    path("email-templates/<slug:template_key>/", EmailTemplateDetailView.as_view(), name="cms_email_template_detail"),
    path("email-templates/<slug:template_key>/preview/", EmailTemplatePreviewView.as_view(), name="cms_email_template_preview"),
    path("email-templates/<slug:template_key>/send-test/", EmailTemplateSendTestView.as_view(), name="cms_email_template_send_test"),
    path("email-templates/<slug:template_key>/reset/", EmailTemplateResetView.as_view(), name="cms_email_template_reset"),
]
