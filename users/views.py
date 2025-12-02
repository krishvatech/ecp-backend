"""
Views for the users app.

Provides endpoints to list and retrieve user information, update the
authenticated user via a custom `me` action, and register new users.
"""
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework import mixins, permissions, status, viewsets, filters
from rest_framework.permissions import IsAuthenticated, AllowAny
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
from django.utils import timezone as django_timezone
from urllib.parse import urlencode
from django.conf import settings
from django.shortcuts import redirect
from django.utils.crypto import get_random_string
from rest_framework_simplejwt.tokens import RefreshToken
from .models import LinkedInAccount
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.contrib.auth import login as django_login, logout as django_logout
from django.contrib.auth import get_user_model
from .serializers import StaffUserSerializer, UserRosterSerializer
from .serializers import PublicProfileSerializer
from .models import Education, Experience,UserProfile,NameChangeRequest
from .serializers import EducationSerializer, ExperienceSerializer,NameChangeRequestSerializer
from .models import EducationDocument
from .serializers import EducationDocumentSerializer

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

        payload = {
            "user": target,
            "profile": getattr(target, "profile", None),
            "experiences": list(exps),
            "educations": list(edus),
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

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

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

        return Response({
            "educations": edus,
            "experiences": exps,
            # add more sections later if needed (skills, links, etc.)
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