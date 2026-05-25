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

urlpatterns = [
    path("pages/<slug:slug>/", CmsPageBySlugView.as_view(), name="cms_page_by_slug"),
    path("profile-layout/", ProfileLayoutView.as_view(), name="profile_layout"),
    path("email-templates/", EmailTemplateListView.as_view(), name="cms_email_template_list"),
    path("email-templates/<slug:template_key>/", EmailTemplateDetailView.as_view(), name="cms_email_template_detail"),
    path("email-templates/<slug:template_key>/preview/", EmailTemplatePreviewView.as_view(), name="cms_email_template_preview"),
    path("email-templates/<slug:template_key>/send-test/", EmailTemplateSendTestView.as_view(), name="cms_email_template_send_test"),
    path("email-templates/<slug:template_key>/reset/", EmailTemplateResetView.as_view(), name="cms_email_template_reset"),
]
