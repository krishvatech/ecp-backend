"""
Views for the users app.

Provides endpoints to list and retrieve user information, update the
authenticated user via a custom `me` action, and register new users.
"""
from django.contrib.auth.models import User
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import update_session_auth_hash
from django.conf import settings
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import generics, status, permissions
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
import os, time, json, base64, secrets, requests
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
from django.conf import settings
from django.shortcuts import redirect
from django.utils.crypto import get_random_string
from rest_framework_simplejwt.tokens import RefreshToken
from .models import LinkedInAccount

from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q
from .filters import UserFilter

from .serializers import (
    UserSerializer,
    EmailTokenObtainPairSerializer,
    RegisterSerializer,
    ChangePasswordSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
)

LINKEDIN_AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
LINKEDIN_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
API_ME = "https://api.linkedin.com/v2/me"
API_EMAIL = "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"
OIDC_USERINFO = "https://api.linkedin.com/v2/userinfo"  # if using OIDC product

def _state_cookie():
    return get_random_string(32)

class UserViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet
    ):
    """
    ViewSet for listing and retrieving users. Anonymous users must
    authenticate via JWT to access these endpoints.  A custom `me`
    action allows the current authenticated user to view or update
    their own profile.
    """
    queryset = User.objects.all().order_by("id")
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    # enable advanced search via django-filter
    filter_backends = [DjangoFilterBackend]
    filterset_class = UserFilter

    def get_queryset(self):
        """
        Determine the base queryset for the user directory.

        Staff and superusers can view all users.  Non‑staff users may only
        see themselves and other users who share an organization with
        them (either as members or as owners).  This method returns a
        queryset filtered accordingly.
        """
        qs = super().get_queryset().select_related("profile").prefetch_related(
            "organizations", "owned_organizations"
        )
        user = self.request.user
        if not user.is_authenticated:
            return qs.none()
        if user.is_staff or user.is_superuser:
            return qs
        org_ids = set(user.organizations.values_list("id", flat=True))
        org_ids.update(user.owned_organizations.values_list("id", flat=True))
        if not org_ids:
            return qs.filter(id=user.id)
        return qs.filter(
            Q(id=user.id)
            | Q(organizations__id__in=org_ids)
            | Q(owned_organizations__id__in=org_ids)
        ).distinct()
    
    @action(detail=False, methods=["get", "put"], url_path="me")
    def me(self, request):
        user = request.user

        if request.method == "GET":
            return Response(UserSerializer(user).data)

        # Build a mutable copy and collapse dotted profile keys (from HTML form)
        data = request.data.copy()
        profile = {}

        # If JSON sent {"profile": {...}}, keep it
        if isinstance(data.get("profile"), dict):
            profile.update(data["profile"])

        # Also handle HTML form dotted keys: profile.full_name, profile.timezone, profile.bio
        for k in list(data.keys()):
            if k.startswith("profile."):
                subkey = k.split(".", 1)[1]
                profile[subkey] = data.pop(k)

        if profile:
            data["profile"] = profile

        # ✅ Use serializer so validations run
        serializer = UserSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)


class RegisterView(APIView):
    """Register a new user (email + password + optional profile)."""
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer 

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)

class EmailTokenObtainPairView(TokenObtainPairView):
    """
    Obtain JWT tokens using email + password.
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = EmailTokenObtainPairSerializer


class ChangePasswordView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangePasswordSerializer   # <- enables HTML form

    def post(self, request):
        serializer = self.get_serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        user = request.user
        old_password = serializer.validated_data["old_password"]
        new_password = serializer.validated_data["new_password"]

        if not user.check_password(old_password):
            return Response(
                {"old_password": ["Old password is incorrect."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(new_password)
        user.save()
        return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)



class ForgotPasswordView(generics.GenericAPIView):
    """POST { "email": "user@example.com" }"""
    permission_classes = [permissions.AllowAny]
    serializer_class = ForgotPasswordSerializer   # <- enables HTML form

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]  # may be None (we don't leak)
        if user:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_link = f"{settings.FRONTEND_RESET_PASSWORD_URL}?uid={uid}&token={token}"
            send_mail(
                subject="Reset your password",
                message=f"Open this link to set a new password:\n{reset_link}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )

        return Response(
            {"detail": "If that email exists, we've sent a reset link."},
            status=status.HTTP_200_OK,
        )


class ResetPasswordView(generics.GenericAPIView):
    """POST { "uid": "...", "token": "...", "new_password": "...", "confirm_new_password": "..." }"""
    permission_classes = [permissions.AllowAny]
    serializer_class = ResetPasswordSerializer   # <- enables HTML form

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)
    
    
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_205_RESET_CONTENT)
        except KeyError:
            return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError:
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        
class LinkedInAuthURL(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        state = _state_cookie()
        request.session["li_oauth_state"] = state
        params = {
            "response_type": "code",
            "client_id": settings.LINKEDIN_CLIENT_ID,
            "redirect_uri": settings.LINKEDIN_REDIRECT_URI,
            "state": state,
            "scope": " ".join(settings.LINKEDIN_SCOPES),
        }
        return Response({"authorization_url": f"{LINKEDIN_AUTH_URL}?{urlencode(params)}"})

class LinkedInCallback(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        if "error" in request.query_params:
            return Response({"error": request.query_params.get("error_description", "denied")}, status=400)
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code or state != request.session.get("li_oauth_state"):
            return Response({"error": "invalid_state_or_code"}, status=400)

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.LINKEDIN_REDIRECT_URI,
            "client_id": settings.LINKEDIN_CLIENT_ID,
            "client_secret": settings.LINKEDIN_CLIENT_SECRET,
        }
        tok = requests.post(LINKEDIN_TOKEN_URL, data=data, timeout=15)
        if tok.status_code != 200:
            return Response({"error": "token_exchange_failed", "detail": tok.text}, status=400)
        t = tok.json()  # {access_token, expires_in, ...}
        access_token = t["access_token"]
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(t.get("expires_in", 0)))

        # Fetch profile (lite)
        headers = {"Authorization": f"Bearer {access_token}"}
        if "openid" in settings.LINKEDIN_SCOPES or "profile" in settings.LINKEDIN_SCOPES:
            # ✅ OIDC path (works with: openid profile email)
            resp = requests.get(OIDC_USERINFO, headers=headers, timeout=15)
            if resp.status_code != 200:
                return Response({"error": "userinfo_fetch_failed", "detail": resp.text}, status=400)

            uj = resp.json()
            linkedin_id = uj.get("sub")
            email = uj.get("email") or ""

            # Build a lite 'me' dict so downstream code keeps working
            mej = {
                "id": linkedin_id,
                "localizedFirstName": uj.get("given_name", ""),
                "localizedLastName": uj.get("family_name", ""),
                "localizedHeadline": "",
                "profilePicture": {"displayImage": uj.get("picture", "")},
            }

        else:
            # Classic fallback (requires r_liteprofile + r_emailaddress)
            me = requests.get(API_ME, headers=headers, timeout=15)
            if me.status_code != 200:
                return Response({"error": "profile_fetch_failed", "detail": me.text}, status=400)
            mej = me.json()
            email = ""
            er = requests.get(API_EMAIL, headers=headers, timeout=15)
            if er.status_code == 200:
                try:
                    email = er.json()["elements"][0]["handle~"]["emailAddress"]
                except Exception:
                    email = ""


        # Resolve or create a local user by email (or create a placeholder)
        from django.contrib.auth.models import User
        if email:
            user, _ = User.objects.get_or_create(username=email, defaults={"email": email})
        else:
            # fallback: use linkedin id for username
            lid = mej.get("id")
            user, _ = User.objects.get_or_create(username=f"li_{lid}")

        # Upsert LinkedIn account link
        acc, _ = LinkedInAccount.objects.get_or_create(user=user, defaults={"linkedin_id": mej.get("id")})
        acc.linkedin_id = mej.get("id", acc.linkedin_id)
        acc.access_token = access_token
        acc.expires_at = expires_at
        # map a few lite fields
        acc.email = email or acc.email
        # headline & picture may require projections/products; keep best-effort
        acc.raw_profile_json = mej
        acc.save()

        # Issue your own JWT for the user so frontend can proceed
        refresh = RefreshToken.for_user(user)
        return Response({"access": str(refresh.access_token), "refresh": str(refresh)})