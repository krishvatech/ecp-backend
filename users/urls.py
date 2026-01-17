"""
Authentication and registration endpoints for the users app.

This module exposes JWT obtain/refresh views and a custom registration
endpoint. Login is via email + password only.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .cognito_bootstrap import CognitoBootstrapView
from .views import WagtailSessionFromCognitoView, WagtailLogoutView, SaleorDashboardAuthorizeView, SaleorDashboardSsoView
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
    StaffUserViewSet,AdminNameChangeRequestViewSet,
    MeEducationDocumentViewSet,
    DiditWebhookView,
    MeSkillViewSet,
    EscoSkillSearchView,
    MeLanguageViewSet,
    MeLanguageCertificateViewSet,
    IsoLanguageSearchView,
    MeTrainingViewSet, MeCertificationViewSet, MeMembershipViewSet,
    GeoCitySearchView, AuthUsersMeView,

)

# ---- NEW: Router for logged-in user's Education & Experience ----
router = DefaultRouter()
router.register(r"me/educations", MeEducationViewSet, basename="me-educations")
router.register(r"me/experiences", MeExperienceViewSet, basename="me-experiences")
router.register(r"me/skills", MeSkillViewSet, basename="me-skills")
router.register(r"me/education-documents", MeEducationDocumentViewSet, basename="me-education-documents")
router.register(r"me/languages", MeLanguageViewSet, basename="me-languages")
router.register(r"me/language-certificates", MeLanguageCertificateViewSet, basename="me-language-certificates")
router.register(r"me/trainings", MeTrainingViewSet, basename="me-trainings")
router.register(r"me/certifications", MeCertificationViewSet, basename="me-certifications")
router.register(r"me/memberships", MeMembershipViewSet, basename="me-memberships")
router.register(r"admin/users", StaffUserViewSet, basename="admin-users")
router.register(r"admin/name-requests", AdminNameChangeRequestViewSet, basename="admin-name-requests")

urlpatterns = [
    # Email + password login (returns refresh + access)
    path("login/", EmailTokenObtainPairView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("wagtail/session/", WagtailSessionFromCognitoView.as_view(), name="wagtail-session"),
    path("wagtail/logout/", WagtailLogoutView.as_view(), name="wagtail-logout"),
    path("saleor/dashboard/", SaleorDashboardAuthorizeView.as_view(), name="saleor-dashboard"),
    path("saleor/sso/", SaleorDashboardSsoView.as_view(), name="saleor-sso"),

    # Also allow obtaining tokens at /token/
    path("token/", EmailTokenObtainPairView.as_view(), name="token_obtain_pair_email"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    # Registration & password flows
    path("register/", RegisterView.as_view(), name="register"),
    path("cognito/bootstrap/", CognitoBootstrapView.as_view(), name="cognito-bootstrap"),
    path("password/change/", ChangePasswordView.as_view(), name="password_change"),
    path("password/forgot/", ForgotPasswordView.as_view(), name="password_forgot"),
    path("password/reset/", ResetPasswordView.as_view(), name="password_reset"),

    # Session auth helpers
    path("session/csrf/", CSRFCookieView.as_view(), name="session_csrf"),
    path("session/login/", SessionLoginView.as_view(), name="session_login"),
    path("session/logout/", SessionLogoutView.as_view(), name="session_logout"),
    path("session/me/", SessionMeView.as_view(), name="session_me"),
    path("users/me/", AuthUsersMeView.as_view(), name="auth-users-me"),

    # ---- NEW: compact profile view (returns both lists) ----
    path("me/profile/", MeProfileView.as_view(), name="me-profile"),
    path("didit/webhook/", DiditWebhookView.as_view(), name="didit-webhook"),
    path("skills/search/", EscoSkillSearchView.as_view(), name="esco-skill-search"),
    path("languages/search/", IsoLanguageSearchView.as_view(), name="iso-language-search"),
    path("cities/search/", GeoCitySearchView.as_view(), name="geonames-city-search"),
    path("", include(router.urls)),
]
