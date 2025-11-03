"""
Authentication and registration endpoints for the users app.

This module exposes JWT obtain/refresh views and a custom registration
endpoint. Login is via email + password only.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegisterView,
    ChangePasswordView,
    ForgotPasswordView,
    ResetPasswordView,
    EmailTokenObtainPairView,
    LogoutView,
    SessionLoginView, SessionLogoutView, SessionMeView, CSRFCookieView,
    # NEW:
    MeEducationViewSet, MeExperienceViewSet, MeProfileView,
)

# ---- NEW: Router for logged-in user's Education & Experience ----
router = DefaultRouter()
router.register(r"me/educations", MeEducationViewSet, basename="me-educations")
router.register(r"me/experiences", MeExperienceViewSet, basename="me-experiences")

urlpatterns = [
    # Email + password login (returns refresh + access)
    path("login/", EmailTokenObtainPairView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),

    # Also allow obtaining tokens at /token/
    path("token/", EmailTokenObtainPairView.as_view(), name="token_obtain_pair_email"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    # Registration & password flows
    path("register/", RegisterView.as_view(), name="register"),
    path("password/change/", ChangePasswordView.as_view(), name="password_change"),
    path("password/forgot/", ForgotPasswordView.as_view(), name="password_forgot"),
    path("password/reset/", ResetPasswordView.as_view(), name="password_reset"),

    # Session auth helpers
    path("session/csrf/", CSRFCookieView.as_view(), name="session_csrf"),
    path("session/login/", SessionLoginView.as_view(), name="session_login"),
    path("session/logout/", SessionLogoutView.as_view(), name="session_logout"),
    path("session/me/", SessionMeView.as_view(), name="session_me"),

    # ---- NEW: compact profile view (returns both lists) ----
    path("me/profile/", MeProfileView.as_view(), name="me-profile"),

    # ---- NEW: include router endpoints ----
    # /api/users/me/educations/  (GET, POST)
    # /api/users/me/educations/<id>/  (GET, PUT, PATCH, DELETE)
    # /api/users/me/experiences/ ... same
    path("", include(router.urls)),
]