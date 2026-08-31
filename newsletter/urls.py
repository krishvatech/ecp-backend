from django.urls import path

from .views import NewsletterPreferencesView


urlpatterns = [
    path(
        "newsletter/preferences/",
        NewsletterPreferencesView.as_view(),
        name="newsletter-preferences",
    ),
]
