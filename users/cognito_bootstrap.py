from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.contrib.auth import get_user_model
from .models import UserProfile

User = get_user_model()


class CognitoBootstrapView(APIView):
    """
    Writes DB fields from frontend signup form payload.
    Requires Authorization: Bearer <Cognito JWT>
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user  # created by CognitoJWTAuthentication if not exists
        data = request.data or {}

        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip().lower()
        first_name = (data.get("firstName") or data.get("first_name") or "").strip()
        last_name = (data.get("lastName") or data.get("last_name") or "").strip()

        # Safety: don't allow spoofing someone else's identity
        if email and user.email and email != (user.email or "").lower():
            return Response({"detail": "email_mismatch"}, status=status.HTTP_400_BAD_REQUEST)

        # Apply form values (write directly; does not touch serializer rules)
        update_fields = []
        if username and user.username != username:
            user.username = username
            update_fields.append("username")

        if email and user.email != email:
            user.email = email
            update_fields.append("email")

        if first_name and user.first_name != first_name:
            user.first_name = first_name
            update_fields.append("first_name")

        if last_name and user.last_name != last_name:
            user.last_name = last_name
            update_fields.append("last_name")

        if update_fields:
            user.save(update_fields=update_fields)

        # Ensure profile exists + initialize activity time
        profile, _ = UserProfile.objects.get_or_create(user=user)
        if not profile.last_activity_at:
            profile.last_activity_at = timezone.now()
            profile.save(update_fields=["last_activity_at"])

        return Response({"detail": "ok"}, status=status.HTTP_200_OK)
