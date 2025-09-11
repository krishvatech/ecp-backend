"""
Authentication and registration endpoints for the users app.

This module exposes JWT obtain/refresh views and a custom registration
endpoint.
"""
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import RegisterView,ChangePasswordView


urlpatterns = [
    # Obtain a pair of JWT tokens (access + refresh)
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("login/", TokenObtainPairView.as_view(), name="login"),
    path("register/", RegisterView.as_view({"post": "create"}), name="register"),
    path("password/change/", ChangePasswordView.as_view(), name="password_change"),
]
