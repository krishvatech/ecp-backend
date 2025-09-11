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
from .serializers import UserSerializer, RegisterSerializer, ChangePasswordSerializer


class UserViewSet(mixins.ListModelMixin,
                  mixins.RetrieveModelMixin,
                  viewsets.GenericViewSet):
    """
    ViewSet for listing and retrieving users.  Anonymous users must
    authenticate via JWT to access these endpoints.  A custom `me`
    action allows the current authenticated user to view or update
    their own profile.
    """
    queryset = User.objects.all().order_by("id")
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=["get", "put"], url_path="me")
    def me(self, request):
        """Retrieve or update the authenticated user's information."""
        user = request.user
        if request.method == "GET":
            return Response(UserSerializer(user).data)

        # For PUT requests, update selected fields on user and profile
        data = request.data
        if "profile" in data:
            profile = user.profile
            for key, value in data["profile"].items():
                setattr(profile, key, value)
            profile.save()
        if "email" in data:
            user.email = data["email"]
            user.save()
        return Response(UserSerializer(user).data)


class RegisterView(viewsets.ViewSet):
    """ViewSet for user registration."""
    permission_classes = [permissions.AllowAny]

    def create(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
    
    
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        user = request.user
        old_password = serializer.validated_data["old_password"]
        new_password = serializer.validated_data["new_password"]

        if not user.check_password(old_password):
            return Response({"old_password": ["Old password is incorrect."]},
                            status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)  # hashes automatically
        user.save()

        # Keep the user’s session valid if they use session auth (optional)
        update_session_auth_hash(request, user)

        # If you want to force re-login for JWT, you can ask client to discard tokens.
        return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)
    
    