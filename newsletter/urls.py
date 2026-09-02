from django.urls import path

from .admin_views import (
    NewsletterAdminCampaignDetailView,
    NewsletterAdminCampaignListCreateView,
    NewsletterAdminCampaignPreviewView,
    NewsletterAdminCampaignSendView,
    NewsletterAdminCampaignSyncView,
    NewsletterAdminCampaignTestEmailView,
    NewsletterAdminCategoryListView,
)
from .views import NewsletterPreferencesView


urlpatterns = [
    path(
        "newsletter/preferences/",
        NewsletterPreferencesView.as_view(),
        name="newsletter-preferences",
    ),
    path(
        "newsletter/admin/campaigns/",
        NewsletterAdminCampaignListCreateView.as_view(),
        name="newsletter-admin-campaign-list",
    ),
    path(
        "newsletter/admin/campaigns/<uuid:uuid>/",
        NewsletterAdminCampaignDetailView.as_view(),
        name="newsletter-admin-campaign-detail",
    ),
    path(
        "newsletter/admin/campaigns/<uuid:uuid>/preview/",
        NewsletterAdminCampaignPreviewView.as_view(),
        name="newsletter-admin-campaign-preview",
    ),
    path(
        "newsletter/admin/campaigns/<uuid:uuid>/test-email/",
        NewsletterAdminCampaignTestEmailView.as_view(),
        name="newsletter-admin-campaign-test-email",
    ),
    path(
        "newsletter/admin/campaigns/<uuid:uuid>/sync/",
        NewsletterAdminCampaignSyncView.as_view(),
        name="newsletter-admin-campaign-sync",
    ),
    path(
        "newsletter/admin/campaigns/<uuid:uuid>/send/",
        NewsletterAdminCampaignSendView.as_view(),
        name="newsletter-admin-campaign-send",
    ),
    path(
        "newsletter/admin/categories/",
        NewsletterAdminCategoryListView.as_view(),
        name="newsletter-admin-category-list",
    ),
]
