from django.urls import path

from .admin_views import (
    NewsletterAdminCampaignDetailView,
    NewsletterAdminCampaignListCreateView,
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
        "newsletter/admin/categories/",
        NewsletterAdminCategoryListView.as_view(),
        name="newsletter-admin-category-list",
    ),
]
