from django.utils import timezone
import pytz
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.contrib.auth import get_user_model
from users.models import UserProfile
from users.cognito_auth import _is_placeholder_name

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

        # Names only fill an empty/placeholder value. Social login calls this on
        # every sign-in with the provider's name, which must not revert an
        # admin rename or approved name change.
        names_changed = False
        if first_name and _is_placeholder_name(user.first_name, user.email, user.username):
            user.first_name = first_name
            update_fields.append("first_name")
            names_changed = True

        if last_name and _is_placeholder_name(user.last_name, user.email, user.username):
            user.last_name = last_name
            update_fields.append("last_name")
            names_changed = True

        user.last_login = timezone.now()
        update_fields.append("last_login")

        if update_fields:
            user.save(update_fields=update_fields)

        # Ensure profile exists + initialize activity time
        profile, _ = UserProfile.objects.get_or_create(user=user)

        profile_update_fields = []

        # Set full_name from first + middle + last only when names were just
        # filled or full_name is still empty.
        parts = [user.first_name, profile.middle_name, user.last_name]
        full_name = " ".join([p.strip() for p in parts if p and p.strip()])
        if full_name and (names_changed or not (profile.full_name or "").strip()) and profile.full_name != full_name:
            profile.full_name = full_name
            profile_update_fields.append("full_name")

        # Only apply supplied values; social login sends neither, and must not
        # wipe an existing company/job title.
        if company and profile.company != company:
            profile.company = company
            profile_update_fields.append("company")

        if job_title and profile.job_title != job_title:
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
