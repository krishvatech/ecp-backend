"""
Authentication and registration endpoints for the users app.

This module exposes JWT obtain/refresh views and a custom registration
endpoint. Login is via email + password only.
"""
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegisterView,
    ChangePasswordView,
    ForgotPasswordView,
    ResetPasswordView,
    EmailTokenObtainPairView,
    LogoutView
)

urlpatterns = [
    # Email + password login (returns refresh + access)
    path("login/", EmailTokenObtainPairView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),

    # Also allow obtaining tokens at /token/
    path("token/", EmailTokenObtainPairView.as_view(), name="token_obtain_pair_email"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    # Registration & password flows
    path("register/", RegisterView.as_view(), name="auth_register"),
    path("password/change/", ChangePasswordView.as_view(), name="password_change"),
    path("password/forgot/", ForgotPasswordView.as_view(), name="password_forgot"),
    path("password/reset/", ResetPasswordView.as_view(), name="password_reset"),
]
