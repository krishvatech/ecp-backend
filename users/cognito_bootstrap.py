from django.utils import timezone
import pytz
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.contrib.auth import get_user_model
from users.models import UserProfile

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
        company = (data.get("company") or "").strip()
        job_title = (data.get("job_title") or data.get("jobTitle") or "").strip()
        # Country / Region. Event application submission requires a non-empty
        # profile.location (lead-gen validation), so a newly registered guest
        # applicant must be able to seed it at bootstrap time. Accept both the
        # snake_case and camelCase spellings the frontend may send.
        location = (data.get("location") or data.get("country") or "").strip()

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

        user.last_login = timezone.now()
        update_fields.append("last_login")

        if update_fields:
            user.save(update_fields=update_fields)

        # Ensure profile exists + initialize activity time
        profile, _ = UserProfile.objects.get_or_create(user=user)

        profile_update_fields = []

        # Set full_name from user's first_name + last_name
        full_name = f"{user.first_name} {user.last_name}".strip()
        if full_name and profile.full_name != full_name:
            profile.full_name = full_name
            profile_update_fields.append("full_name")

        if profile.company != company:
            profile.company = company
            profile_update_fields.append("company")

        if profile.job_title != job_title:
            profile.job_title = job_title
            profile_update_fields.append("job_title")

        # Only fill location when a value is supplied and the profile does not
        # already have one, mirroring the "initialize missing fields" intent of
        # bootstrap. This never clears or overwrites an existing location.
        if location and not (profile.location or "").strip():
            profile.location = location[:255]
            profile_update_fields.append("location")

        tz = (data.get("timezone") or "").strip()
        if tz and tz in pytz.all_timezones and profile.timezone != tz:
            profile.timezone = tz
            profile_update_fields.append("timezone")

        if not profile.last_activity_at:
            profile.last_activity_at = timezone.now()
            profile_update_fields.append("last_activity_at")

        if profile_update_fields:
            profile.save(update_fields=profile_update_fields)

        return Response({"detail": "ok"}, status=status.HTTP_200_OK)
