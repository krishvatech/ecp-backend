"""
Views for the users app.

Provides endpoints to list and retrieve user information, update the
authenticated user via a custom `me` action, and register new users.
"""
from django.contrib.auth.models import User
from rest_framework import status
from django.template.loader import render_to_string
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework import mixins, permissions, status, viewsets, filters
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import update_session_auth_hash
from django.http import HttpResponse
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
from django.utils import timezone as django_timezone
from urllib.parse import urlencode
from django.conf import settings
from django.shortcuts import get_object_or_404, redirect
from django.utils.crypto import get_random_string
from rest_framework_simplejwt.tokens import RefreshToken
from .models import LinkedInAccount,EscoSkill
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.contrib.auth import login as django_login, logout as django_logout
from django.contrib.auth import get_user_model
from .serializers import StaffUserSerializer, UserRosterSerializer
from .serializers import PublicProfileSerializer
from .models import Education, Experience,UserProfile,NameChangeRequest, UserSkill, UserLanguage, IsoLanguage, LanguageCertificate, ProfileTraining, ProfileCertification, ProfileMembership
from .serializers import EducationSerializer, ExperienceSerializer,NameChangeRequestSerializer, ProfileTrainingSerializer, ProfileCertificationSerializer, ProfileMembershipSerializer
from .models import EducationDocument
from .serializers import EducationDocumentSerializer
from .esco_client import search_skills
from .didit_client import (
    create_initial_kyc_session, 
    create_name_change_kyc_session, 
    verify_webhook_signature,
    get_session_details
)
from .serializers import (
    UserSerializer,
    EmailTokenObtainPairSerializer,
    RegisterSerializer,
    ChangePasswordSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    UserSkillSerializer,
    LanguageCertificateSerializer,
    UserLanguageSerializer
    
)
import logging

logger = logging.getLogger(__name__)
LINKEDIN_AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
LINKEDIN_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
API_ME = "https://api.linkedin.com/v2/me"
API_EMAIL = "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"
OIDC_USERINFO = "https://api.linkedin.com/v2/userinfo"  # if using OIDC product

# Google OAuth2 endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

UserModel = get_user_model()

class IsSuperuser(permissions.BasePermission):
    """
    Restrict access to owner-level operations.
    Only Django superusers (is_superuser=True) are allowed.
    """
    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        return bool(user and user.is_authenticated and user.is_superuser)


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

    def get_queryset(self):
        """
        Determine the base queryset for the user directory.

        Staff and superusers can view all users.  Non‑staff users may only
        see themselves and other users who share an community with
        them (either as members or as owners).  This method returns a
        queryset filtered accordingly.
        """
        qs = super().get_queryset().select_related("profile").prefetch_related(
            "community", "owned_community"
        )
        user = self.request.user
        if not user.is_authenticated:
            return qs.none()
        if user.is_staff or user.is_superuser:
            return qs
        org_ids = set(user.community.values_list("id", flat=True))
        org_ids.update(user.owned_community.values_list("id", flat=True))
        if not org_ids:
            return qs.filter(id=user.id)
        return qs.filter(
            Q(id=user.id)
            | Q(community__id__in=org_ids)
            | Q(owned_community__id__in=org_ids)
        ).distinct()
    
    @action(detail=False, methods=["get", "put", "patch"], url_path="me")
    def me(self, request):
        user = request.user

        if request.method == "GET":
            return Response(UserSerializer(user, context={"request": request}).data)

        data = request.data.copy()
        profile = {}

        data.pop("first_name", None)
        data.pop("last_name", None)

        if isinstance(data.get("profile"), dict):
            profile.update(data["profile"])

        for k in list(data.keys()):
            if k.startswith("profile."):
                subkey = k.split(".", 1)[1]
                profile[subkey] = data.pop(k)

        if profile:
            data["profile"] = profile

        serializer = UserSerializer(
            user,
            data=data,
            partial=(request.method == "PATCH"),
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=["post"], url_path="me/avatar")
    def upload_avatar(self, request):
        """
        Accepts multipart/form-data with key 'avatar' OR 'user_image'.
        Saves to request.user.profile.user_image and returns the URL.
        """
        file = request.FILES.get("avatar") or request.FILES.get("user_image")
        if not file:
            return Response({"detail": "avatar (file) is required"}, status=status.HTTP_400_BAD_REQUEST)

        profile = getattr(request.user, "profile", None)
        if profile is None:
            return Response({"detail": "Profile not found"}, status=status.HTTP_404_NOT_FOUND)

        profile.user_image = file
        profile.save(update_fields=["user_image"])

        # send back absolute URL
        data = {
            "user_image": profile.user_image.name,
            "user_image_url": request.build_absolute_uri(profile.user_image.url),
        }
        return Response(data, status=status.HTTP_200_OK)
    

    @action(detail=True, methods=["get"], permission_classes=[AllowAny], url_path="profile")
    def public_profile(self, request, pk=None):
        try:
            target = UserModel.objects.select_related("profile").get(pk=pk)
        except UserModel.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)

        exps = (Experience.objects
                .filter(user=target)
                .order_by("-currently_work_here", "-end_date", "-start_date", "-id"))
        edus = (Education.objects
                .filter(user=target)
                .order_by("-end_date", "-start_date", "-id"))
        trainings = ProfileTraining.objects.filter(user=target).order_by("-currently_ongoing", "-end_date", "-start_date", "-id")
        certs = ProfileCertification.objects.filter(user=target).order_by("-issue_date", "-id")
        mems = ProfileMembership.objects.filter(user=target).order_by("-ongoing", "-end_date", "-start_date", "-id")

        payload = {
            "user": target,
            "profile": getattr(target, "profile", None),
            "experiences": list(exps),
            "educations": list(edus),
            "trainings": list(trainings),
            "certifications": list(certs),
            "memberships": list(mems),
        }

        data = PublicProfileSerializer(payload, context={"request": request}).data
        return Response(data)
    
    @action(detail=False, methods=["get"], permission_classes=[permissions.IsAuthenticated], url_path="filters")
    def filters(self, request):
        """
        Return distinct values for filters from the entire database.
        """
        # Helper to get distinct, non-empty values from a model field
        def get_distinct(model, field):
            return (
                model.objects
                .exclude(**{f"{field}__exact": ""})   # Exclude empty strings
                .exclude(**{f"{field}__isnull": True}) # Exclude NULLs
                .values_list(field, flat=True)
                .distinct()
                .order_by(field)
            )

        # 1. Company from Experience model (community_name)
        companies = get_distinct(Experience, "community_name")

        # 2. Job Title from Experience model (position)
        titles = get_distinct(Experience, "position")

        # 3. Industry from Experience model
        industries = get_distinct(Experience, "industry")

        # 4. Company Size from Experience model
        sizes = get_distinct(Experience, "number_of_employees")
        
        # 5. Location from UserProfile model
        locations = get_distinct(UserProfile, "location")

        return Response({
            "companies": list(companies),
            "titles": list(titles),
            "industries": list(industries),
            "sizes": list(sizes),
            "locations": list(locations),
        })


   # users/views.py  (inside UserViewSet)
    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated], url_path="roster")
    def roster(self, request):
        qs = (
            UserModel.objects
            .filter(is_superuser=False)
            .all()
            .exclude(id=request.user.id)
            .select_related("profile") 
            .prefetch_related("experiences")   # NEW: so serializer is fast
            .order_by("first_name", "last_name")[:500]
        )
        data = UserRosterSerializer(qs, many=True, context={"request": request}).data
        return Response(data)

    @action(detail=False, methods=["post"], url_path="me/name-change-request")
    def create_name_change_request(self, request):
        """
        Create a legal name change request (First / Middle / Last) with a reason
        (e.g. Marriage / Divorce / Legal change).
        """
        serializer = NameChangeRequestSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        obj = serializer.save()
        return Response(
            NameChangeRequestSerializer(obj).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=False, methods=["get"], url_path="me/name-change-requests")
    def list_name_change_requests(self, request):
        """
        List all name change requests by the current user.
        """
        qs = NameChangeRequest.objects.filter(user=request.user).order_by("-created_at")
        serializer = NameChangeRequestSerializer(qs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=["post"], url_path="me/start-kyc")
    def start_kyc(self, request):
        """
        Initiates the first-time KYC process.
        Returns: { "session_id": "...", "url": "..." }
        """
        user = request.user
        profile = user.profile

        # Optional: Check if already verified
        if profile.kyc_status == UserProfile.KYC_STATUS_APPROVED:
             return Response({"detail": "KYC already verified."}, status=400)

        try:
            session_id, url = create_initial_kyc_session(user, request=request)
            
            # Store session ID
            profile.kyc_last_session_id = session_id
            profile.kyc_status = UserProfile.KYC_STATUS_PENDING
            profile.save()
            
            return Response({"session_id": session_id, "url": url}, status=200)
        except Exception as e:
            logger.error(f"Failed to start KYC: {e}")
            return Response({"detail": "Failed to create verification session."}, status=503)

    @action(detail=False, methods=["post"], url_path="me/name-change-request")
    def create_name_change_request(self, request):
        """
        Create a name change request AND immediately start a Didit session for it.
        """
        serializer = NameChangeRequestSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        name_req = serializer.save()

        # --- Start Didit Session for this request ---
        try:
            session_id, url = create_name_change_kyc_session(name_req, request=request)
            
            name_req.didit_session_id = session_id
            name_req.didit_status = NameChangeRequest.DIDIT_STATUS_PENDING
            name_req.save()
            
            # Return normal data + KYC URL
            data = NameChangeRequestSerializer(name_req).data
            data["kyc_url"] = url 
            
            return Response(data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            # If Didit fails, we might want to delete the request or return partial success
            logger.error(f"Failed to start Name Change KYC: {e}")
            # Optional: name_req.delete() if you want atomic behavior
            return Response(
                {"detail": "Request created but failed to start verification session."}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # ✅ Welcome email (non-blocking)
        try:
            frontend_app_url = os.getenv("FRONTEND_APP_URL", "http://localhost:5173")

            ctx = {
                "app_name": "IMAA Connect",  # TODO: change to your brand name
                "first_name": (user.first_name or user.username or "there"),
                "email": user.email,
                "login_url": f"{frontend_app_url}/signin",
                "support_email": settings.DEFAULT_FROM_EMAIL,  # or your support email
            }

            text_body = render_to_string("emails/welcome.txt", ctx)
            html_body = render_to_string("emails/welcome.html", ctx)

            send_mail(
                subject=f"Welcome to {ctx['app_name']}",
                message=text_body,
                from_email=settings.DEFAULT_FROM_EMAIL,  # ✅ same sender as forgot password
                recipient_list=[user.email],
                html_message=html_body,
                fail_silently=False,
            )
        except Exception as e:
            logger.warning(f"Welcome email failed for {getattr(user,'email',None)}: {e}")


        # issue JWT (simplejwt)
        refresh = RefreshToken.for_user(user)
        payload = serializer.data
        payload.update({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        })
        return Response(payload, status=status.HTTP_201_CREATED)

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
        # ✅ Password changed alert email (non-blocking)
        try:
            frontend_app_url = os.getenv("FRONTEND_APP_URL", "http://localhost:5173")
            changed_at = django_timezone.localtime(django_timezone.now()).strftime("%d %b %Y, %I:%M %p %Z")

            ctx = {
                "app_name": "IMAA Connect",  # TODO: change brand
                "first_name": (user.first_name or user.username or "there"),
                "email": user.email,
                "changed_at": changed_at,
                "forgot_password_url": f"{frontend_app_url}/forgot-password",
                "support_email": settings.DEFAULT_FROM_EMAIL,
            }

            text_body = render_to_string("emails/password_changed.txt", ctx)
            html_body = render_to_string("emails/password_changed.html", ctx)

            send_mail(
                subject=f"Your {ctx['app_name']} password was changed",
                message=text_body,
                from_email=settings.DEFAULT_FROM_EMAIL,  # ✅ same sender as forgot password
                recipient_list=[user.email],
                html_message=html_body,
                fail_silently=False,
            )
        except Exception as e:
            logger.warning(f"Password-changed alert email failed for {getattr(user,'email',None)}: {e}")

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
        # ✅ Password changed alert email (non-blocking)
        try:
            frontend_app_url = os.getenv("FRONTEND_APP_URL", "http://localhost:5173")
            changed_at = django_timezone.localtime(django_timezone.now()).strftime("%d %b %Y, %I:%M %p %Z")

            ctx = {
                "app_name": "IMAA Connect",  # TODO: change brand
                "first_name": (user.first_name or user.username or "there"),
                "email": user.email,
                "changed_at": changed_at,
                "forgot_password_url": f"{frontend_app_url}/forgot-password",
                "support_email": settings.DEFAULT_FROM_EMAIL,
            }

            text_body = render_to_string("emails/password_changed.txt", ctx)
            html_body = render_to_string("emails/password_changed.html", ctx)

            send_mail(
                subject=f"Your {ctx['app_name']} password was changed",
                message=text_body,
                from_email=settings.DEFAULT_FROM_EMAIL,  # ✅ same sender as forgot password
                recipient_list=[user.email],
                html_message=html_body,
                fail_silently=False,
            )
        except Exception as e:
            logger.warning(f"Password-changed alert email failed for {getattr(user,'email',None)}: {e}")

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
        

class SessionLoginView(APIView):
    """
    Session-based login. Expects JSON: {"email": "...", "password": "..."}
    On success, creates a Django session (cookie-based).
    """
    permission_classes = []  # allow unauthenticated
    authentication_classes = []

    @method_decorator(ensure_csrf_cookie)
    def post(self, request):
        data = request.data or {}
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        if not email or not password:
            return Response({"error": "email and password are required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = UserModel.objects.get(email__iexact=email)
        except UserModel.DoesNotExist:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        if not user.is_active or not user.check_password(password):
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

        django_login(request, user)          # <- creates session
        request.session.cycle_key()          # optional: rotate session id

        from .serializers import UserSerializer
        return Response({"detail": "logged_in", "user": UserSerializer(user).data}, status=status.HTTP_200_OK)


class SessionLogoutView(APIView):
    """Session-based logout. Destroys the user's session cookie."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        django_logout(request)
        return Response({"detail": "logged_out"}, status=status.HTTP_200_OK)


class SessionMeView(APIView):
    """Return the current session-authenticated user (401 if not logged in)."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from .serializers import UserSerializer
        return Response(UserSerializer(request.user).data, status=status.HTTP_200_OK)


class CSRFCookieView(APIView):
    """
    GET to set the CSRF cookie. Call this before POST /session/login from a browser.
    """
    permission_classes = []
    authentication_classes = []

    @method_decorator(ensure_csrf_cookie)
    def get(self, request):
        return Response({"detail": "CSRF cookie set"}, status=status.HTTP_200_OK)


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
        # If user cancelled or LinkedIn returned an error
        if "error" in request.query_params:
            return Response(
                {
                    "error": request.query_params.get("error"),
                    "detail": request.query_params.get(
                        "error_description", "denied"
                    ),
                },
                status=400,
            )

        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code:
            return Response({"error": "missing_code"}, status=400)

        # only enforce state if we have it (avoids dev issues)
        session_state = request.session.get("li_oauth_state")
        if session_state and state != session_state:
            return Response({"error": "invalid_state_or_code"}, status=400)

        # ---- Exchange code -> access token ----
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.LINKEDIN_REDIRECT_URI,
            "client_id": settings.LINKEDIN_CLIENT_ID,
            "client_secret": settings.LINKEDIN_CLIENT_SECRET,
        }

        tok = requests.post(LINKEDIN_TOKEN_URL, data=data, timeout=15)
        if tok.status_code != 200:
            return Response(
                {"error": "token_exchange_failed", "detail": tok.text},
                status=400,
            )

        t = tok.json()
        access_token = t.get("access_token")
        if not access_token:
            return Response({"error": "no_access_token"}, status=400)

        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=int(t.get("expires_in", 0) or 0)
        )

        headers = {"Authorization": f"Bearer {access_token}"}

        uj = {}
        mej = {}
        email = ""
        picture_url = ""
        linkedin_profile_url = ""

        # ---- Fetch profile via OIDC or classic REST ----
        try:
            if "openid" in settings.LINKEDIN_SCOPES or "profile" in settings.LINKEDIN_SCOPES:
                # ✅ OIDC userinfo: id, name, picture, email
                resp = requests.get(OIDC_USERINFO, headers=headers, timeout=15)
                if resp.status_code != 200:
                    return Response(
                        {
                            "error": "userinfo_fetch_failed",
                            "detail": resp.text,
                        },
                        status=400,
                    )

                uj = resp.json()
                linkedin_id = uj.get("sub")
                email = uj.get("email") or ""

                # picture
                pic_claim = uj.get("picture")
                if isinstance(pic_claim, str):
                    picture_url = pic_claim
                elif isinstance(pic_claim, dict):
                    picture_url = pic_claim.get("value") or pic_claim.get("url") or ""

                mej = {
                    "id": linkedin_id,
                    "localizedFirstName": uj.get("given_name", ""),
                    "localizedLastName": uj.get("family_name", ""),
                    "localizedHeadline": "",
                    "profilePicture": {"displayImage": picture_url},
                }

                # if they ever include a "profile" claim, use it as URL
                linkedin_profile_url = uj.get("profile") or ""

            else:
                # Classic REST fallback (needs r_liteprofile / r_emailaddress / Profile API)
                me = requests.get(API_ME, headers=headers, timeout=15)
                if me.status_code != 200:
                    return Response(
                        {"error": "profile_fetch_failed", "detail": me.text},
                        status=400,
                    )
                mej = me.json()

                er = requests.get(API_EMAIL, headers=headers, timeout=15)
                if er.status_code == 200:
                    try:
                        email = er.json()["elements"][0]["handle~"]["emailAddress"]
                    except Exception:
                        email = ""

                profile_picture = mej.get("profilePicture") or {}
                if isinstance(profile_picture, dict):
                    display_image = profile_picture.get("displayImage")
                    if isinstance(display_image, str) and display_image.startswith("http"):
                        picture_url = display_image

                # If Profile API gives vanityName, build profile URL
                vanity = mej.get("vanityName")
                if vanity:
                    linkedin_profile_url = f"https://www.linkedin.com/in/{vanity}/"

        except Exception as exc:
            logger.error(f"LinkedIn profile fetch failed: {exc}")

        # ---- Resolve or create local User ----
        from django.contrib.auth.models import User

        if email:
            user, created = User.objects.get_or_create(
                username=email,
                defaults={"email": email},
            )
        else:
            lid = mej.get("id")
            user, created = User.objects.get_or_create(username=f"li_{lid}")

        # ---- Update first_name / last_name from LinkedIn ----
        first_name_li = mej.get("localizedFirstName") or ""
        last_name_li = mej.get("localizedLastName") or ""

        fields_to_update = []
        if first_name_li and user.first_name != first_name_li:
            user.first_name = first_name_li
            fields_to_update.append("first_name")
        if last_name_li and user.last_name != last_name_li:
            user.last_name = last_name_li
            fields_to_update.append("last_name")

        if fields_to_update:
            user.save(update_fields=fields_to_update)

        # ---- Update UserProfile: avatar + links.linkedin ----
        profile = getattr(user, "profile", None)
        if profile:
            updated_fields = []

            # 1) Avatar from LinkedIn picture (only if new user or no avatar yet)
            if picture_url and (created or not profile.user_image):
                try:
                    img_resp = requests.get(picture_url, timeout=10)
                    if img_resp.status_code == 200:
                        from django.core.files.base import ContentFile

                        filename = f"linkedin_avatar_{user.id}.jpg"
                        profile.user_image.save(
                            filename,
                            ContentFile(img_resp.content),
                            save=False,  # we'll call profile.save() below
                        )
                        updated_fields.append("user_image")
                        logger.info(
                            f"Saved LinkedIn profile picture for {email or user.username}"
                        )
                except Exception as e:
                    logger.error(
                        f"Failed to download LinkedIn profile picture for "
                        f"{email or user.username}: {e}"
                    )

            # 2) LinkedIn URL in JSONField links.linkedin
            if linkedin_profile_url:
                links = dict(getattr(profile, "links", {}) or {})
                if links.get("linkedin") != linkedin_profile_url:
                    links["linkedin"] = linkedin_profile_url
                    profile.links = links
                    updated_fields.append("links")

            if updated_fields:
                profile.save(update_fields=updated_fields)

        # ---- Upsert LinkedInAccount link ----
        acc, _ = LinkedInAccount.objects.get_or_create(
            user=user, defaults={"linkedin_id": mej.get("id")}
        )
        acc.linkedin_id = mej.get("id", acc.linkedin_id)
        acc.access_token = access_token
        acc.expires_at = expires_at
        acc.email = email or acc.email
        acc.raw_profile_json = mej
        if picture_url:
            acc.picture_url = picture_url
        if linkedin_profile_url:
            # optional: keep here too if you want
            acc.raw_profile_json["profile_url"] = linkedin_profile_url
        acc.save()

        # ---- Issue JWT and redirect to frontend OAuth callback ----
        refresh = RefreshToken.for_user(user)
        tokens = {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        }
        qs = urlencode(tokens)
        return redirect(f"{settings.FRONTEND_URL}/oauth/callback?{qs}")

    
class GoogleAuthURL(APIView):
    """
    Returns the Google authorization URL so the frontend can redirect.
    GET /api/auth/google/url/
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        state = _state_cookie()
        request.session["google_oauth_state"] = state

        params = {
            "response_type": "code",
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "scope": " ".join(settings.GOOGLE_SCOPES),
            "access_type": "offline",
            "include_granted_scopes": "true",
            "state": state,
            "prompt": "select_account",
        }

        return Response(
            {"authorization_url": f"{GOOGLE_AUTH_URL}?{urlencode(params)}"}
        )


class GoogleCallback(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        # If Google returned an error from consent screen
        if "error" in request.query_params:
            return Response(
                {
                    "error": request.query_params.get("error"),
                    "detail": request.query_params.get("error_description", ""),
                },
                status=400,
            )

        code = request.query_params.get("code")
        if not code:
            return Response({"error": "missing_code"}, status=400)

        # --- Exchange code -> tokens ---
        data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }

        tok = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=15)
        if tok.status_code != 200:
            return Response(
                {"error": "token_exchange_failed", "detail": tok.text},
                status=400,
            )

        t = tok.json()
        access_token = t.get("access_token")
        if not access_token:
            return Response({"error": "no_access_token"}, status=400)

        # --- Get user info from Google ---
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = requests.get(GOOGLE_USERINFO_URL, headers=headers, timeout=15)
        if resp.status_code != 200:
            return Response(
                {"error": "userinfo_fetch_failed", "detail": resp.text},
                status=400,
            )

        info = resp.json()
        email = info.get("email")
        if not email:
            return Response({"error": "no_email"}, status=400)

        first_name = info.get("given_name") or ""
        last_name = info.get("family_name") or ""
        picture_url = info.get("picture")  # Google's picture URL

        from django.contrib.auth.models import User
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "username": email,
                "first_name": first_name,
                "last_name": last_name,
            },
        )

        # --- NEW: Download and save Google Profile Picture ---
        # We check if the user is new (created) OR if they don't have an image yet.
        # We assume 'profile' exists via signals, but use getattr to be safe.
        profile = getattr(user, "profile", None)
        
        if profile and picture_url and (created or not profile.user_image):
            try:
                # Download the image
                img_resp = requests.get(picture_url, timeout=10)
                if img_resp.status_code == 200:
                    from django.core.files.base import ContentFile
                    
                    # Create a filename (e.g., google_avatar_15.jpg)
                    filename = f"google_avatar_{user.id}.jpg"
                    
                    # Save content directly to the ImageField
                    profile.user_image.save(filename, ContentFile(img_resp.content), save=True)
                    logger.info(f"Saved Google profile picture for user {email}")
            except Exception as e:
                logger.error(f"Failed to download Google profile picture for {email}: {e}")

        # Issue JWT and redirect to frontend
        refresh = RefreshToken.for_user(user)
        tokens = {"access": str(refresh.access_token), "refresh": str(refresh)}
        qs = urlencode(tokens)

        return redirect(f"{settings.FRONTEND_URL}/oauth/callback?{qs}")


class MeEducationViewSet(viewsets.ModelViewSet):
    """
    /api/users/me/educations/  (GET list, POST)
    /api/users/me/educations/<id>/  (GET, PUT, PATCH, DELETE)
    Only the logged in user's rows are visible/editable.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = EducationSerializer

    def get_queryset(self):
        return (
            Education.objects
            .filter(user=self.request.user)
            .order_by("-end_date", "-start_date", "-id")
        )

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class MeTrainingViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProfileTrainingSerializer

    def get_queryset(self):
        return ProfileTraining.objects.filter(user=self.request.user).order_by(
            "-currently_ongoing", "-end_date", "-start_date", "-id"
        )

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class MeCertificationViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProfileCertificationSerializer

    def get_queryset(self):
        return ProfileCertification.objects.filter(user=self.request.user).order_by("-issue_date", "-id")

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class MeMembershipViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProfileMembershipSerializer

    def get_queryset(self):
        return ProfileMembership.objects.filter(user=self.request.user).order_by(
            "-ongoing", "-end_date", "-start_date", "-id"
        )

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class MeExperienceViewSet(viewsets.ModelViewSet):
    """
    /api/users/me/experiences/  (GET list, POST)
    /api/users/me/experiences/<id>/  (GET, PUT, PATCH, DELETE)
    Only the logged in user's rows are visible/editable.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ExperienceSerializer

    def get_queryset(self):
        return (
            Experience.objects
            .filter(user=self.request.user)
            .order_by("-currently_work_here", "-end_date", "-start_date", "-id")
        )

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class MeProfileView(APIView):
    """
    Compact payload for your Profile page preview:
    /api/users/me/profile/
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        edus = EducationSerializer(
            Education.objects.filter(user=request.user).order_by("-end_date", "-start_date", "-id"),
            many=True,
        ).data
        exps = ExperienceSerializer(
            Experience.objects.filter(user=request.user).order_by("-currently_work_here", "-end_date", "-start_date", "-id"),
            many=True,
        ).data

        trainings = ProfileTrainingSerializer(
            ProfileTraining.objects.filter(user=request.user).order_by("-currently_ongoing", "-end_date", "-start_date", "-id"),
            many=True
        ).data

        certifications = ProfileCertificationSerializer(
            ProfileCertification.objects.filter(user=request.user).order_by("-issue_date", "-id"),
            many=True
        ).data

        memberships = ProfileMembershipSerializer(
            ProfileMembership.objects.filter(user=request.user).order_by("-ongoing", "-end_date", "-start_date", "-id"),
            many=True
        ).data


        return Response({
        "educations": edus,
        "experiences": exps,
        "trainings": trainings,
        "certifications": certifications,
        "memberships": memberships,
    })

    
class StaffUserViewSet(viewsets.ModelViewSet):
    """
    /api/admin/users/                 GET list (search/order/paginate)
    /api/admin/users/{id}/            GET retrieve
    /api/admin/users/{id}/            PATCH { "is_staff": true|false }
    /api/admin/users/bulk-set-staff/  POST { "ids":[...], "is_staff": true|false }
    """
    queryset = User.objects.all().order_by("-date_joined")
    serializer_class = StaffUserSerializer
    permission_classes = [IsSuperuser]
    http_method_names = ["get", "patch", "post"]

    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["username", "first_name", "last_name", "email"]
    ordering_fields = ["date_joined", "last_login", "username", "email"]
    
   # users/views.py  -> inside class StaffUserViewSet
    def get_queryset(self):
        qs = super().get_queryset()
        cid  = self.request.query_params.get("community_id")
        slug = self.request.query_params.get("community_slug")

        if cid or slug:
            filt = Q()
            if cid:
                filt |= Q(community__id=cid)            # 👈 use community__, not memberships__
            if slug:
                filt |= Q(community__slug=slug)         # 👈 use community__, not memberships__
            qs = qs.filter(filt).distinct()

        return qs

    def partial_update(self, request, *args, **kwargs):
        user = self.get_object()

        # Non-superusers cannot modify a superuser
        if user.is_superuser and not request.user.is_superuser:
            return Response({"detail": "You cannot modify a superuser."},
                            status=status.HTTP_403_FORBIDDEN)

        # Only allow toggling is_staff
        if "is_staff" not in request.data:
            return Response({"detail": "Only 'is_staff' can be updated."},
                            status=status.HTTP_400_BAD_REQUEST)

        ser = self.get_serializer(user, data={"is_staff": request.data["is_staff"]}, partial=True)
        ser.is_valid(raise_exception=True)
        self.perform_update(ser)
        return Response(ser.data)

    @action(detail=False, methods=["post"], url_path="bulk-set-staff")
    def bulk_set_staff(self, request):
        ids = request.data.get("ids", [])
        is_staff = request.data.get("is_staff", None)
        if not isinstance(ids, list) or is_staff is None:
            return Response({"detail": "Provide 'ids' (list) and 'is_staff' (bool)."},
                            status=status.HTTP_400_BAD_REQUEST)

        qs = User.objects.filter(id__in=ids)
        # Block superusers unless caller is superuser
        if not request.user.is_superuser:
            qs = qs.filter(is_superuser=False)

        updated = qs.update(is_staff=bool(is_staff))
        return Response({"updated": updated})
    
    
class AdminNameChangeRequestViewSet(viewsets.ModelViewSet):
    """
    Admin endpoint to list all requests and approve/reject them.
    GET /api/users/admin/name-requests/?status=pending
    POST /api/users/admin/name-requests/{id}/decide/
    """
    
    queryset = NameChangeRequest.objects.all().order_by("-created_at")
    serializer_class = NameChangeRequestSerializer
    permission_classes = [IsSuperuser] # Limit to admins
    http_method_names = ['get', 'post', 'head', 'options']
    
    # Enable filtering by status
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter] 
    filterset_fields = ['status']
    
    search_fields = [
        'user__username', 
        'user__email', 
        'new_first_name', 
        'new_last_name', 
        'old_first_name', 
        'old_last_name'
    ]
    ordering_fields = ['created_at', 'status']

    @action(detail=True, methods=["post"])
    def decide(self, request, pk=None):
        name_req = self.get_object()
        new_status = request.data.get("status")
        admin_note = request.data.get("admin_note", "")

        if new_status not in ["approved", "rejected"]:
            return Response({"detail": "Invalid status. Must be 'approved' or 'rejected'."}, status=400)

        if name_req.status != "pending":
            return Response({"detail": "Request has already been processed."}, status=400)

        # Apply changes if approved
        if new_status == "approved":
            user = name_req.user
            profile = user.profile

            # 1. Update Auth User (First/Last)
            if name_req.new_first_name:
                user.first_name = name_req.new_first_name
            if name_req.new_last_name:
                user.last_name = name_req.new_last_name
            user.save()

            # 2. Update Profile (Middle)
            if name_req.new_middle_name is not None:
                profile.middle_name = name_req.new_middle_name
            
            # 3. Recalculate Full Name
            parts = [user.first_name, profile.middle_name, user.last_name]
            profile.full_name = " ".join([p for p in parts if p]).strip()
            profile.save()

        # Update Request Record
        name_req.status = new_status
        name_req.admin_note = admin_note
        name_req.decided_at = django_timezone.now()
        name_req.decided_by = request.user
        name_req.save()

        return Response(NameChangeRequestSerializer(name_req).data)


class MeEducationDocumentViewSet(viewsets.ModelViewSet):
    """
    Manage documents for the authenticated user's education entries.
    Endpoints:
      POST /api/users/me/education-documents/ (Requires 'education' ID and 'file')
      DELETE /api/users/me/education-documents/<id>/
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = EducationDocumentSerializer
    parser_classes = [MultiPartParser, FormParser] # Required for file uploads

    def get_queryset(self):
        # Only show documents belonging to the user's education entries
        return EducationDocument.objects.filter(education__user=self.request.user)

    def perform_create(self, serializer):
        # Security check: Ensure the education ID belongs to the current user
        education_id = self.request.data.get('education')
        education = generics.get_object_or_404(Education, id=education_id, user=self.request.user)
        serializer.save(education=education)

import re
import unicodedata

_STOP_TOKENS = {
    "mr", "mrs", "ms", "dr", "prof",
    "jr", "sr", "ii", "iii", "iv",
}

def _name_tokens(name: str) -> list[str]:
    if not name:
        return []
    name = name.replace(",", " ")
    name = unicodedata.normalize("NFKD", name)
    name = "".join(ch for ch in name if not unicodedata.combining(ch))
    name = name.lower()
    name = re.sub(r"[^a-z\s]", " ", name)
    name = re.sub(r"\s+", " ", name).strip()
    toks = [t for t in name.split(" ") if t and t not in _STOP_TOKENS]
    return toks

def _token_matches(pt: str, id_tokens: list[str]) -> bool:
    """Match token with exact / initial / prefix rules."""
    if not pt:
        return False

    # exact
    if pt in id_tokens:
        return True

    # initial: "r" matches "rahul"
    if len(pt) == 1:
        return any(t.startswith(pt) for t in id_tokens)

    # allow prefix match for short-form vs full-form (alex vs alexander)
    # keep it conservative: only if token length >= 3
    if len(pt) >= 3:
        return any(t.startswith(pt) or pt.startswith(t) for t in id_tokens if len(t) >= 3)

    return False

def linkedin_style_name_match(profile_display_name: str, id_full_name: str) -> tuple[bool, dict]:
    """
    LinkedIn-like: require PROFILE FIRST token + PROFILE LAST token to match ID tokens.
    Order doesn't matter. Middle names can be extra/missing.
    """
    p = _name_tokens(profile_display_name)
    d = _name_tokens(id_full_name)

    debug = {
        "profile_tokens": p,
        "id_tokens": d,
        "matched_profile_tokens": [],
        "missing_profile_tokens": [],
        "reason": "",
    }

    if len(p) < 2 or len(d) < 2:
        debug["reason"] = "insufficient_tokens"
        return False, debug

    p_first = p[0]
    p_last = p[-1]

    first_ok = _token_matches(p_first, d)
    last_ok = _token_matches(p_last, d)

    for tok in p:
        if _token_matches(tok, d):
            debug["matched_profile_tokens"].append(tok)
        else:
            debug["missing_profile_tokens"].append(tok)

    if first_ok and last_ok:
        debug["reason"] = "pass"
        return True, debug

    # If you want STRICT LinkedIn-like behavior: mismatch => fail
    debug["reason"] = "name_mismatch"
    return False, debug


def best_linkedin_match(profile_candidates: list[str], id_candidates: list[str]) -> tuple[bool, dict]:
    """
    Try multiple variants (normal + swapped), return best pass or best debug.
    """
    best_debug = None
    for p in profile_candidates:
        for i in id_candidates:
            ok, dbg = linkedin_style_name_match(p, i)
            dbg["profile_candidate"] = p
            dbg["id_candidate"] = i
            if ok:
                return True, dbg
            # keep last debug (or you can keep the one with most matched tokens)
            if not best_debug or len(dbg.get("matched_profile_tokens", [])) > len(best_debug.get("matched_profile_tokens", [])):
                best_debug = dbg
    return False, best_debug or {"reason": "no_candidates"}


class DiditWebhookView(APIView):
    """
    Receives callbacks from Didit.
    Verifies signature and updates UserProfile or NameChangeRequest.
    """
    permission_classes = [AllowAny]
    authentication_classes = [] # Disable auth for webhooks

    def get(self, request, *args, **kwargs):
        # This is the browser callback, not a signed webhook.
        verification_session_id = request.query_params.get("verificationSessionId")
        status_text = request.query_params.get("status")

        # Optional: you could call get_session_details(verification_session_id)
        # here and update the profile as a fallback, but webhooks are preferred.

        return HttpResponse(
            "Verification complete. You can close this tab and return to the app.",
            content_type="text/plain",
            status=200,
        )
    
    def post(self, request):
        # 1. Verify Signature
        if not verify_webhook_signature(request):
            logger.warning("Didit Webhook: Invalid signature")
            return Response({"detail": "Invalid signature"}, status=403)

        payload = request.data
        session_id = payload.get("session_id")
        status_text = payload.get("status") # e.g. "Approved", "Declined"
        decision = payload.get("decision", {}) # Can contain "risk", "details", etc.
        vendor_data = payload.get("vendor_data", "")

        logger.info(f"Didit Webhook received: {session_id} - {status_text} - {vendor_data}")

        # 2. Determine Request Type (Initial KYC vs Name Change)
        if vendor_data.startswith("kyc_initial:"):
            return self.handle_initial_kyc(payload, session_id, status_text, vendor_data)
        
        elif vendor_data.startswith("kyc_namechange:"):
            return self.handle_name_change(payload, session_id, status_text, vendor_data)

        # Fallback: Try to find by session_id lookup if vendor_data is missing/mangled
        return self.handle_fallback_lookup(payload, session_id, status_text)

    def handle_initial_kyc(self, payload, session_id, status_text, vendor_data):
        user_id = vendor_data.split(":")[1]
        try:
            profile = UserProfile.objects.get(user__id=user_id)
        except UserProfile.DoesNotExist:
            return Response({"detail": "User not found"}, status=404)

        # store payload always
        profile.kyc_didit_raw_payload = payload
        profile.kyc_didit_last_webhook_at = django_timezone.now()
        profile.kyc_last_session_id = session_id

        # If Didit says NOT approved, just map and exit (no name check)
        status_map = {
            "Approved": UserProfile.KYC_STATUS_APPROVED,
            "Declined": UserProfile.KYC_STATUS_DECLINED,
            "Review": UserProfile.KYC_STATUS_REVIEW,
            "Pending": UserProfile.KYC_STATUS_PENDING,
        }

        if status_text != "Approved":
            profile.kyc_status = status_map.get(status_text, UserProfile.KYC_STATUS_PENDING)
            if status_text == "Declined":
                profile.kyc_decline_reason = UserProfile.KYC_DECLINE_REASON_OTHER
                profile.legal_name_locked = False
                profile.legal_name_verified_at = None
            profile.save()
            return Response({"status": "processed_initial_kyc"})

        # --------------------------
        # Didit Approved => now do LinkedIn-style name match
        # --------------------------
        user = profile.user

        # Profile display candidates (normal + swapped)
        profile_candidates = []
        if profile.full_name:
            profile_candidates.append(profile.full_name.strip())

        display_from_user = f"{user.first_name} {user.last_name}".strip()
        if display_from_user:
            profile_candidates.append(display_from_user)

        swapped_from_user = f"{user.last_name} {user.first_name}".strip()
        if swapped_from_user and swapped_from_user != display_from_user:
            profile_candidates.append(swapped_from_user)

        # ID name candidates
        decision = payload.get("decision") or {}
        idv = decision.get("id_verification") or {}

        id_full = (idv.get("full_name") or "").strip()
        id_first = (idv.get("first_name") or "").strip()
        id_last = (idv.get("last_name") or "").strip()

        id_candidates = []
        if id_full:
            id_candidates.append(id_full)

        combined = f"{id_first} {id_last}".strip()
        if combined:
            id_candidates.append(combined)

        swapped = f"{id_last} {id_first}".strip()
        if swapped and swapped != combined:
            id_candidates.append(swapped)

        ok, debug = best_linkedin_match(profile_candidates, id_candidates)

        if ok:
            profile.kyc_status = UserProfile.KYC_STATUS_APPROVED
            profile.kyc_decline_reason = None
            profile.legal_name_locked = True
            profile.legal_name_verified_at = django_timezone.now()
        else:
            # LinkedIn-style: no badge if mismatch
            profile.kyc_status = UserProfile.KYC_STATUS_DECLINED  # or REVIEW if you prefer manual admin review
            profile.kyc_decline_reason = UserProfile.KYC_DECLINE_REASON_NAME_MISMATCH
            profile.legal_name_locked = False
            profile.legal_name_verified_at = None

            # Optional: log debug to server logs
            logger.info("[KYC NAME MATCH FAIL] user=%s debug=%s", user_id, debug)

        profile.save()
        return Response({"status": "processed_initial_kyc"})


    def handle_name_change(self, payload, session_id, status_text, vendor_data):
        request_id = vendor_data.split(":")[1]
        try:
            ncr = NameChangeRequest.objects.get(id=request_id)
        except NameChangeRequest.DoesNotExist:
            return Response({"detail": "Request not found"}, status=404)

        status_map = {
            "Approved": NameChangeRequest.DIDIT_STATUS_APPROVED,
            "Declined": NameChangeRequest.DIDIT_STATUS_DECLINED,
            "Review": NameChangeRequest.DIDIT_STATUS_REVIEW,
            "Pending": NameChangeRequest.DIDIT_STATUS_PENDING,
        }

        ncr.didit_status = status_map.get(status_text, NameChangeRequest.DIDIT_STATUS_PENDING)
        ncr.didit_raw_payload = payload

        # Always store session id too (safe)
        ncr.didit_session_id = session_id or ncr.didit_session_id

        # If request already processed, just ack webhook (idempotent)
        if ncr.status != NameChangeRequest.STATUS_PENDING:
            ncr.save()
            return Response({"status": "name_change_already_processed"})

        # Only do auto-approve check when Didit is Approved
        if status_text == "Approved":
            # 1) Extract ID name candidates from payload (same style as initial KYC)
            decision = payload.get("decision") or {}
            idv = decision.get("id_verification") or {}

            id_full = (idv.get("full_name") or "").strip()
            id_first = (idv.get("first_name") or "").strip()
            id_last = (idv.get("last_name") or "").strip()

            # Save extracted doc names for admin review
            ncr.doc_full_name = id_full
            ncr.doc_first_name = id_first
            ncr.doc_last_name = id_last

            id_candidates = []
            if id_full:
                id_candidates.append(id_full)

            combined = f"{id_first} {id_last}".strip()
            if combined:
                id_candidates.append(combined)

            swapped = f"{id_last} {id_first}".strip()
            if swapped and swapped != combined:
                id_candidates.append(swapped)

            # 2) Build requested-name candidates (new name)
            req_full = " ".join([ncr.new_first_name, ncr.new_middle_name, ncr.new_last_name]).strip()
            req_simple = f"{ncr.new_first_name} {ncr.new_last_name}".strip()
            req_swapped = f"{ncr.new_last_name} {ncr.new_first_name}".strip()

            req_candidates = []
            if req_full:
                req_candidates.append(req_full)
            if req_simple and req_simple != req_full:
                req_candidates.append(req_simple)
            if req_swapped and req_swapped not in req_candidates:
                req_candidates.append(req_swapped)

            # 3) Run your existing matcher
            ok, debug = best_linkedin_match(req_candidates, id_candidates)

            ncr.name_match_passed = bool(ok)
            ncr.name_match_debug = debug or {}
            ncr.auto_approved = bool(ok)

            if ok:
                # ✅ AUTO-APPROVE: apply same logic as Admin decide()
                user = ncr.user
                profile = user.profile

                if ncr.new_first_name:
                    user.first_name = ncr.new_first_name
                if ncr.new_last_name:
                    user.last_name = ncr.new_last_name
                user.save()

                if ncr.new_middle_name is not None:
                    profile.middle_name = ncr.new_middle_name

                parts = [user.first_name, profile.middle_name, user.last_name]
                profile.full_name = " ".join([p for p in parts if p]).strip()
                profile.save()

                # Mark request approved
                ncr.status = NameChangeRequest.STATUS_APPROVED
                ncr.decided_at = django_timezone.now()
                ncr.decided_by = None
                ncr.admin_note = "Auto-approved (Didit Approved + name match passed)."
            else:
                # ❌ mismatch => admin review
                ncr.admin_note = "Didit Approved but name mismatch. Manual admin review required."

        
        # If Didit Approves, we move Admin Status to PENDING (Ready for Admin Review)
        # If Didit Declines, we might auto-reject or keep as PENDING for manual override.
        # Flow guide says: "At this point, the request is marked as Pending Admin Review"
        
        ncr.save()
        return Response({"status": "processed_name_change"})

    def handle_fallback_lookup(self, payload, session_id, status_text):
        # Try finding a NameChangeRequest first
        ncr = NameChangeRequest.objects.filter(didit_session_id=session_id).first()
        if ncr:
            vendor_data = f"kyc_namechange:{ncr.id}"
            return self.handle_name_change(payload, session_id, status_text, vendor_data)
        
        # Try finding a UserProfile
        profile = UserProfile.objects.filter(kyc_last_session_id=session_id).first()
        if profile:
            vendor_data = f"kyc_initial:{profile.user.id}"
            return self.handle_initial_kyc(payload, session_id, status_text, vendor_data)
            
        return Response({"detail": "Session not matched"}, status=200) # 200 to ack Didit
   

class EscoSkillSearchView(APIView):
    """
    GET /api/users/skills/search/?q=python
    If 'q' is provided: Search ESCO API.
    If 'q' is empty: Return suggestions from local DB.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        q = request.query_params.get("q", "").strip()

        # ---------------------------------------------------------
        # CASE 1: Empty Query -> Return Local DB Skills
        # ---------------------------------------------------------
        if not q:
            # Fetch, for example, the first 50 skills from your DB.
            # You can order by usage count or alphabetical if preferred.
            local_skills = EscoSkill.objects.all().order_by("preferred_label")[:50]
            
            results = [
                {
                    "uri": skill.uri, 
                    "label": skill.preferred_label
                }
                for skill in local_skills
            ]
            return Response({"results": results})

        # ---------------------------------------------------------
        # CASE 2: Query Present -> Search External ESCO API
        # ---------------------------------------------------------
        language = request.query_params.get("lang", "en")
        
        # ... (Keep existing logging and external API call logic) ...
        logger.info(
            "[ESCO] Frontend skill search: user=%s q=%r lang=%s",
            getattr(request.user, "id", None),
            q,
            language,
        )

        raw_results = search_skills(q, language=language, limit=10)

        results = []
        for item in raw_results:
            uri = item.get("uri") or item.get("id")
            label = item.get("preferredLabel") or item.get("title")
            if not uri or not label:
                continue
            results.append({
                "uri": uri,
                "label": label,
            })

        return Response({"results": results})

    
class MeSkillViewSet(viewsets.ModelViewSet):
    """
    /api/users/me/skills/  (GET list, POST)
    /api/users/me/skills/<id>/  (GET, PUT, PATCH, DELETE)
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSkillSerializer

    def get_queryset(self):
        return (
            UserSkill.objects
            .select_related("skill")
            .filter(user=self.request.user)
            .order_by("-proficiency_level", "-updated_at")
        )

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        logger.info(
            "[MeSkillViewSet.list] Returning %d skills for user=%s",
            qs.count(),
            getattr(request.user, "id", None),
        )
        return super().list(request, *args, **kwargs)

    def perform_create(self, serializer):
        serializer.save()



class IsoLanguageSearchView(APIView):
    """
    GET /api/users/languages/search/?q=english
    Local autocomplete (DB-backed).
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        q = request.query_params.get("q", "").strip()
        if not q:
            return Response({"results": []})

        qs = IsoLanguage.objects.filter(
            Q(english_name__icontains=q) |
            Q(native_name__icontains=q) |
            Q(iso_639_1__icontains=q) |
            Q(iso_639_3__icontains=q)
        ).order_by("english_name")[:20]

        results = [
            {
                "iso_639_1": l.iso_639_1,
                "iso_639_3": l.iso_639_3,
                "label": l.english_name,
                "native_name": l.native_name,
            }
            for l in qs
        ]
        return Response({"results": results})


class MeLanguageViewSet(viewsets.ModelViewSet):
    """
    /api/users/me/languages/
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserLanguageSerializer

    def get_queryset(self):
        return (
            UserLanguage.objects
            .select_related("language")
            .prefetch_related("certificates")
            .filter(user=self.request.user)
            .order_by("-proficiency_cefr", "-updated_at")
        )

    def perform_create(self, serializer):
        serializer.save()


class MeLanguageCertificateViewSet(viewsets.ModelViewSet):
    """
    /api/users/me/language-certificates/
    Upload files for language proof.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = LanguageCertificateSerializer
    parser_classes = [MultiPartParser, FormParser]

    def get_queryset(self):
        return (
            LanguageCertificate.objects
            .select_related("user_language", "user_language__language")
            .filter(user_language__user=self.request.user)
            .order_by("-uploaded_at")
        )

    def perform_create(self, serializer):
        ul_id = self.request.data.get("user_language")
        ul = get_object_or_404(UserLanguage, id=ul_id, user=self.request.user)

        f = self.request.FILES.get("file")
        filename = f.name if f else ""

        serializer.save(user_language=ul, filename=filename)