"""
Views for the users app.

Provides endpoints to list and retrieve user information, update the
authenticated user via a custom `me` action, and register new users.
"""
from django.contrib.auth.models import User
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .serializers import UserSerializer, RegisterSerializer


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