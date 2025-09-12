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


from .serializers import (
    UserSerializer,
    EmailTokenObtainPairSerializer,
    RegisterSerializer,
    ChangePasswordSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
)


class UserViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet
):
    """
    ViewSet for listing and retrieving users. Anonymous users must
    authenticate via JWT to access these endpoints. A custom `me`
    action allows the current authenticated user to view or update
    their own profile.
    """
    queryset = User.objects.all().order_by("id")
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

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