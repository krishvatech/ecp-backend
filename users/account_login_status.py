"""Public preflight check for blocked local account states.

The frontend authenticates directly with Cognito before falling back to WordPress.
That means Cognito/WordPress error text can hide the authoritative Django account
state.  This read-only endpoint lets the login form stop immediately when a
platform administrator has deactivated the account.
"""
from django.contrib.auth.models import User
from django.db.models import Q
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import CognitoIdentity, UserEmailAlias, UserProfile


DEACTIVATED_MESSAGE = (
    "This account has been deactivated by an administrator. Please contact support."
)

_STATUS_MESSAGES = {
    UserProfile.PROFILE_STATUS_DELETED: (
        "account_deleted",
        DEACTIVATED_MESSAGE,
    ),
    UserProfile.PROFILE_STATUS_SUSPENDED: (
        "account_suspended",
        "Your account has been suspended. Please contact support for assistance.",
    ),
    UserProfile.PROFILE_STATUS_FAKE: (
        "account_disabled",
        "This account has been disabled due to policy violations.",
    ),
    UserProfile.PROFILE_STATUS_DECEASED: (
        "account_memorialized",
        "This account has been memorialized.",
    ),
}


def _find_user(identifier: str):
    normalized = (identifier or "").strip()
    if not normalized:
        return None

    user = (
        User.objects.select_related("profile")
        .filter(Q(email__iexact=normalized) | Q(username__iexact=normalized))
        .order_by("id")
        .first()
    )
    if user:
        return user

    alias = (
        UserEmailAlias.objects.select_related("user__profile")
        .filter(email__iexact=normalized, verified=True, is_active=True)
        .order_by("id")
        .first()
    )
    if alias:
        return alias.user

    identity = (
        CognitoIdentity.objects.select_related("user__profile")
        .filter(email__iexact=normalized, email_verified=True)
        .order_by("id")
        .first()
    )
    return identity.user if identity else None


def blocked_account_payload(user):
    """Return a stable blocked-account payload, or ``None`` when login may continue."""
    if user is None:
        return None

    profile = getattr(user, "profile", None)
    profile_status = getattr(profile, "profile_status", "")

    if profile_status in _STATUS_MESSAGES:
        code, detail = _STATUS_MESSAGES[profile_status]
        return {
            "can_login": False,
            "detail": detail,
            "error": detail,
            "code": code,
            "profile_status": profile_status,
        }

    if not user.is_active:
        return {
            "can_login": False,
            "detail": DEACTIVATED_MESSAGE,
            "error": DEACTIVATED_MESSAGE,
            "code": "account_inactive",
            "profile_status": profile_status or "inactive",
        }

    return None


class AccountLoginStatusView(APIView):
    """Return a terminal status only when the local account is access-blocked.

    Active and unknown identifiers intentionally receive the same success payload,
    so this endpoint does not become a general account-discovery API.
    """

    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        identifier = str(request.data.get("identifier") or request.data.get("email") or "").strip()
        if not identifier:
            response = Response(
                {"detail": "Email or username is required.", "code": "identifier_required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
            response["Cache-Control"] = "no-store"
            return response

        blocked_payload = blocked_account_payload(_find_user(identifier))
        if blocked_payload:
            response = Response(blocked_payload, status=status.HTTP_403_FORBIDDEN)
        else:
            response = Response({"can_login": True}, status=status.HTTP_200_OK)

        response["Cache-Control"] = "no-store"
        return response
