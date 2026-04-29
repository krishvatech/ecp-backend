"""
Authentication and registration endpoints for the users app.

This module exposes JWT obtain/refresh views and a custom registration
endpoint. Login is via email + password only.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .cognito_bootstrap import CognitoBootstrapView
from .views import WagtailSessionFromCognitoView, WagtailLogoutView, SaleorDashboardAuthorizeView, SaleorDashboardSsoView, MagicLinkAuthView
from .views import (
    RegisterView,
    CheckEmailExistsView,
    AdminMergeDuplicateUsersView,
    ChangePasswordView,
    ForgotPasswordView,
    ResetPasswordView,
    EmailTokenObtainPairView,
    LogoutView,
    SessionLoginView, SessionLogoutView, SessionMeView, CSRFCookieView,
    # NEW:
    MeEducationViewSet, MeExperienceViewSet, MeProfileView,
    StaffUserViewSet,AdminNameChangeRequestViewSet, AdminKYCViewSet,
    MeEducationDocumentViewSet,
    MeTrainingDocumentViewSet,
    MeMembershipDocumentViewSet,
    DiditWebhookView,
    MeSkillViewSet,
    EscoSkillSearchView,
    MeLanguageViewSet,
    MeLanguageCertificateViewSet,
    IsoLanguageSearchView,
    MeTrainingViewSet, MeCertificationViewSet, MeMembershipViewSet,
    MeCertificationDocumentViewSet,
    GeoCitySearchView, AuthUsersMeView,
    AdminUserProfileView, AdminUserAvatarView, AdminEducationViewSet,
    AdminExperienceViewSet, AdminTrainingViewSet, AdminCertificationViewSet,
    AdminMembershipViewSet, AdminSkillViewSet, AdminLanguageViewSet,
    AdminEducationDocumentViewSet, AdminTrainingDocumentViewSet,
    AdminCertificationDocumentViewSet, AdminMembershipDocumentViewSet,
    AdminLanguageCertificateViewSet, AdminUserWordPressSyncView,
    # Email alias views
    AddEmailAliasView,
    VerifyEmailAliasView,
    ListEmailAliasView,
    RemoveEmailAliasView,
    SaleorConnectionStatusView,
    SaleorConnectionStartView,
    SaleorConnectionCallbackView,
    SaleorConnectionDisconnectView,

)
from .wordpress_webhook import WordPressWebhookView, WordPressUserSyncView, WordPressProfileSyncAuthenticatedView

# ---- NEW: Router for logged-in user's Education & Experience ----
router = DefaultRouter()
router.register(r"me/educations", MeEducationViewSet, basename="me-educations")
router.register(r"me/experiences", MeExperienceViewSet, basename="me-experiences")
router.register(r"me/skills", MeSkillViewSet, basename="me-skills")
router.register(r"me/education-documents", MeEducationDocumentViewSet, basename="me-education-documents")
router.register(r"me/languages", MeLanguageViewSet, basename="me-languages")
router.register(r"me/language-certificates", MeLanguageCertificateViewSet, basename="me-language-certificates")
router.register(r"me/trainings", MeTrainingViewSet, basename="me-trainings")
router.register(r"me/training-documents", MeTrainingDocumentViewSet, basename="me-training-documents")
router.register(r"me/certifications", MeCertificationViewSet, basename="me-certifications")
router.register(r"me/certification-documents", MeCertificationDocumentViewSet, basename="me-certification-documents")
router.register(r"me/memberships", MeMembershipViewSet, basename="me-memberships")
router.register(r"me/membership-documents", MeMembershipDocumentViewSet, basename="me-membership-documents")
router.register(r"admin/users", StaffUserViewSet, basename="admin-users")
router.register(r"admin/name-requests", AdminNameChangeRequestViewSet, basename="admin-name-requests")
router.register(r"admin/kyc", AdminKYCViewSet, basename="admin-kyc")

admin_profile_router = DefaultRouter()
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/educations", AdminEducationViewSet, basename="admin-user-educations")
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/experiences", AdminExperienceViewSet, basename="admin-user-experiences")
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/trainings", AdminTrainingViewSet, basename="admin-user-trainings")
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/certifications", AdminCertificationViewSet, basename="admin-user-certifications")
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/memberships", AdminMembershipViewSet, basename="admin-user-memberships")
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/skills", AdminSkillViewSet, basename="admin-user-skills")
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/languages", AdminLanguageViewSet, basename="admin-user-languages")
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/language-certificates", AdminLanguageCertificateViewSet, basename="admin-user-language-certificates")
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/education-documents", AdminEducationDocumentViewSet, basename="admin-user-education-documents")
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/training-documents", AdminTrainingDocumentViewSet, basename="admin-user-training-documents")
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/certification-documents", AdminCertificationDocumentViewSet, basename="admin-user-certification-documents")
admin_profile_router.register(r"admin/users/(?P<user_id>\d+)/membership-documents", AdminMembershipDocumentViewSet, basename="admin-user-membership-documents")

urlpatterns = [
    # Email + password login (returns refresh + access)
    # path("login/", EmailTokenObtainPairView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("magic-link/", MagicLinkAuthView.as_view(), name="magic-link"),
    path("wagtail/session/", WagtailSessionFromCognitoView.as_view(), name="wagtail-session"),
    path("wagtail/logout/", WagtailLogoutView.as_view(), name="wagtail-logout"),
    path("saleor/dashboard/", SaleorDashboardAuthorizeView.as_view(), name="saleor-dashboard"),
    path("saleor/sso/", SaleorDashboardSsoView.as_view(), name="saleor-sso"),
    path("saleor/status/", SaleorConnectionStatusView.as_view(), name="saleor-status"),
    path("saleor/connect/", SaleorConnectionStartView.as_view(), name="saleor-connect"),
    path("saleor/callback/", SaleorConnectionCallbackView.as_view(), name="saleor-callback"),
    path("saleor/disconnect/", SaleorConnectionDisconnectView.as_view(), name="saleor-disconnect"),

    # Also allow obtaining tokens at /token/
    # path("token/", EmailTokenObtainPairView.as_view(), name="token_obtain_pair_email"),
    # path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    # Registration & password flows
    path("register/", RegisterView.as_view(), name="register"),
    path("check-email/", CheckEmailExistsView.as_view(), name="check-email"),
    path("admin/merge-users/", AdminMergeDuplicateUsersView.as_view(), name="admin-merge-users"),
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
    path("admin/users/<int:user_id>/profile/", AdminUserProfileView.as_view(), name="admin-user-profile"),
    path("admin/users/<int:user_id>/avatar/", AdminUserAvatarView.as_view(), name="admin-user-avatar"),
    path("admin/users/<int:user_id>/sync-profile/", AdminUserWordPressSyncView.as_view(), name="admin-user-sync-profile"),

    # ---- NEW: compact profile view (returns both lists) ----
    path("me/profile/", MeProfileView.as_view(), name="me-profile"),
    path("didit/webhook/", DiditWebhookView.as_view(), name="didit-webhook"),
    path("wordpress/webhook/", WordPressWebhookView.as_view(), name="wordpress-webhook"),
    path("wordpress/sync/", WordPressUserSyncView.as_view(), name="wordpress-sync"),
    path("wordpress/sync-profile/", WordPressProfileSyncAuthenticatedView.as_view(), name="wordpress-sync-profile"),
    path("skills/search/", EscoSkillSearchView.as_view(), name="esco-skill-search"),
    path("languages/search/", IsoLanguageSearchView.as_view(), name="iso-language-search"),
    path("cities/search/", GeoCitySearchView.as_view(), name="geonames-city-search"),

    # Email alias management
    path("users/me/email-aliases/", AddEmailAliasView.as_view(), name="add-email-alias"),
    path("users/me/email-aliases/verify/", VerifyEmailAliasView.as_view(), name="verify-email-alias"),
    path("users/me/email-aliases/list/", ListEmailAliasView.as_view(), name="list-email-aliases"),
    path("users/me/email-aliases/<int:alias_id>/", RemoveEmailAliasView.as_view(), name="remove-email-alias"),

    path("", include(router.urls)),
    path("", include(admin_profile_router.urls)),
]
