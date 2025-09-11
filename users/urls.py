"""
Authentication and registration endpoints for the users app.

This module exposes JWT obtain/refresh views and a custom registration
endpoint.
"""
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import RegisterView


urlpatterns = [
    # Obtain a pair of JWT tokens (access + refresh)
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # Register a new user
    path("register/", RegisterView.as_view({"post": "create"}), name="register"),
]