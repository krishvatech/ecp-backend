"""
Guest Attendee API Views

This module provides endpoints for guest (unauthenticated) event participation:
- GuestJoinView: Request email verification via OTP for event access
- GuestVerifyOTPView: Verify OTP and receive guest JWT token
- ResendGuestOTPView: Resend OTP if expired
- GuestRegisterView: Convert guest session to registered Cognito account
"""

import uuid
import jwt
import logging
import random
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError, PermissionDenied
from .models import Event, GuestAttendee, GuestEmailOTP
from .guest_auth import GuestPrincipal

logger = logging.getLogger(__name__)


def generate_otp_code():
    """Generate a random 6-digit numeric OTP."""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


def send_guest_otp(event, email, guest_name, max_attempts=5, rate_limit_seconds=60):
    """
    Send an OTP code to a guest's email for event access verification.

    Args:
        event: Event instance
        email: Guest's email address
        guest_name: Guest's first name
        max_attempts: Max OTP generation attempts before rate limiting
        rate_limit_seconds: Seconds to wait before resending

    Returns:
        dict: {
            "success": bool,
            "message": str,
            "otp_required": bool (for API response),
            "seconds_remaining": int (if rate limited)
        }
    """
    from users.email_utils import send_guest_otp_email

    # Check if there's a recent valid OTP
    recent_otps = GuestEmailOTP.objects.filter(
        event=event,
        email=email,
        used_at__isnull=True
    ).order_by('-created_at')

    if recent_otps.exists():
        latest = recent_otps.first()
        time_since_created = timezone.now() - latest.created_at

        # Rate limit: only allow resend after rate_limit_seconds
        if time_since_created.total_seconds() < rate_limit_seconds:
            seconds_remaining = int(rate_limit_seconds - time_since_created.total_seconds())
            return {
                "success": False,
                "message": f"OTP already sent. Please wait {seconds_remaining} seconds before requesting another.",
                "otp_required": True,
                "seconds_remaining": seconds_remaining,
            }

        # If latest OTP is still valid (not expired), return it instead of creating new one
        if latest.is_valid:
            return {
                "success": True,
                "message": f"OTP sent to {email}",
                "otp_required": True,
            }

    # Generate new OTP
    otp_code = generate_otp_code()
    expires_at = timezone.now() + timedelta(minutes=10)

    otp = GuestEmailOTP.objects.create(
        email=email,
        event=event,
        code=otp_code,
        expires_at=expires_at,
    )

    # Send OTP via email
    email_sent = send_guest_otp_email(
        to_email=email,
        guest_name=guest_name,
        otp_code=otp_code,
        event_title=event.title
    )

    if email_sent:
        logger.info(f"[GuestOTP] Sent OTP {otp_code} to {email} for event {event.id}")
        return {
            "success": True,
            "message": f"Verification code sent to {email}",
            "otp_required": True,
        }
    else:
        # Email send failed - delete the OTP record
        otp.delete()
        logger.error(f"[GuestOTP] Failed to send OTP email to {email}")
        return {
            "success": False,
            "message": "Failed to send verification code. Please try again.",
            "otp_required": False,
        }


class GuestJoinView(APIView):
    """
    POST /api/events/{event_id}/guest-join/

    Initiate guest event access by requesting email verification.
    Sends a 6-digit OTP code to the provided email address.
    Guest must verify OTP via /guest-verify-otp/ before receiving JWT token.

    Request body:
    {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "job_title": "Software Engineer",  # optional
        "company_name": "Acme Corp"  # optional
    }

    Response (200 OK):
    {
        "otp_required": true,
        "message": "Verification code sent to john@example.com"
    }

    Response (429 Too Many Requests - if rate limited):
    {
        "otp_required": true,
        "message": "OTP already sent. Please wait 45 seconds before requesting another.",
        "seconds_remaining": 45
    }

    Error responses:
    - 400: Missing required fields or validation error
    - 404: Event not found
    - 409: Email already has registered account for this event
    """

    permission_classes = [AllowAny]
    authentication_classes = []  # No auth required to join as guest

    def post(self, request, pk=None):
        """Handle guest join request - send OTP to email."""
        logger.info(f"[GuestJoin] POST request received for event {pk}")
        logger.info(f"[GuestJoin] Request data: {request.data}")

        # 1. Validate and get event
        try:
            event = Event.objects.get(pk=pk)
            logger.info(f"[GuestJoin] ✅ Event found: {event.title} (ID: {event.id})")
        except Event.DoesNotExist:
            logger.warning(f"[GuestJoin] ❌ Event not found: {pk}")
            return Response(
                {"error": "Event not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 2. Extract and validate request data
        first_name = request.data.get("first_name", "").strip()
        last_name = request.data.get("last_name", "").strip()
        email = request.data.get("email", "").strip().lower()
        job_title = request.data.get("job_title", "").strip()
        company_name = request.data.get("company_name", "").strip()

        # Validate required fields
        if not first_name:
            return Response(
                {"error": "first_name is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not last_name:
            return Response(
                {"error": "last_name is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not email:
            return Response(
                {"error": "email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 3. Check if email already has CONVERTED account for this event
        existing = GuestAttendee.objects.filter(event=event, email=email).first()
        if existing and existing.converted_at:
            logger.info(
                f"Guest join attempt for already-registered email {email} "
                f"on event {event.id}"
            )
            return Response({
                "error": "account_exists",
                "message": "You have already registered. Please sign in."
            }, status=status.HTTP_409_CONFLICT)

        # 4. Create or update GuestAttendee (without verified status yet)
        if existing:
            # Update profile info for existing guest
            existing.first_name = first_name
            existing.last_name = last_name
            existing.job_title = job_title
            existing.company = company_name
            # Keep guests in waiting-room state when policy is enabled, unless already admitted
            if event.waiting_room_enabled and existing.current_location != "main_room":
                existing.current_location = "waiting_room"
            existing.save(update_fields=["first_name", "last_name", "job_title", "company", "current_location"])
            guest = existing
            logger.info(f"Updated profile for existing guest {email} on event {event.id}")
        else:
            # Create new guest attendee (not verified yet)
            initial_location = "waiting_room" if event.waiting_room_enabled else "main_room"
            guest = GuestAttendee(
                event=event,
                email=email,
                first_name=first_name,
                last_name=last_name,
                job_title=job_title,
                company=company_name,
                current_location=initial_location,
                email_verified=False,
            )
            guest.save()
            logger.info(f"Created new guest attendee {email} for event {event.id}")

        # 5. Send OTP to email
        otp_result = send_guest_otp(event, email, first_name)

        if not otp_result["success"]:
            # Email send failed or rate limited
            if otp_result.get("seconds_remaining"):
                return Response(
                    otp_result,
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            return Response(
                {"error": otp_result["message"]},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Return success - OTP sent
        return Response(otp_result, status=status.HTTP_200_OK)


class GuestVerifyOTPView(APIView):
    """
    POST /api/events/{event_id}/guest-verify-otp/

    Verify the OTP code sent to guest's email and receive guest JWT token.

    Request body:
    {
        "email": "john@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "otp_code": "123456",
        "job_title": "Software Engineer",  # optional
        "company": "Acme Corp"  # optional
    }

    Response (201 Created):
    {
        "token": "<jwt_token>",
        "guest_id": 7,
        "name": "John Doe",
        "email": "john@example.com",
        "company": "Acme Corp",
        "job_title": "Software Engineer",
        "event_id": 42,
        "expires_at": "2026-03-14T10:00:00Z"
    }

    Error responses:
    - 400: Invalid OTP or other validation error
    - 404: Event not found
    - 409: Email already has registered account
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, pk=None):
        """Handle OTP verification and JWT token issuance."""
        logger.info(f"[GuestVerifyOTP] POST request for event {pk}")

        # 1. Validate and get event
        try:
            event = Event.objects.get(pk=pk)
        except Event.DoesNotExist:
            logger.warning(f"[GuestVerifyOTP] Event not found: {pk}")
            return Response(
                {"error": "Event not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 2. Extract and validate request data
        email = request.data.get("email", "").strip().lower()
        otp_code = request.data.get("otp_code", "").strip()
        first_name = request.data.get("first_name", "").strip()
        last_name = request.data.get("last_name", "").strip()
        job_title = request.data.get("job_title", "").strip()
        company = request.data.get("company", "").strip()

        if not email or not otp_code:
            return Response(
                {"error": "email and otp_code are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 3. Find and validate OTP
        otp = GuestEmailOTP.objects.filter(
            event=event,
            email=email,
            code=otp_code,
            used_at__isnull=True
        ).order_by('-created_at').first()

        if not otp:
            logger.warning(f"[GuestVerifyOTP] Invalid OTP for {email} on event {event.id}")
            return Response(
                {"error": "Invalid verification code."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if OTP is expired
        if otp.is_expired:
            logger.warning(f"[GuestVerifyOTP] Expired OTP for {email}")
            return Response(
                {"error": "Verification code has expired. Please request a new one."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if OTP is still valid (not used)
        if not otp.is_valid:
            logger.warning(f"[GuestVerifyOTP] Already-used OTP for {email}")
            return Response(
                {"error": "Verification code has already been used."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 4. Mark OTP as used
        otp.mark_as_used()
        logger.info(f"[GuestVerifyOTP] OTP verified for {email}")

        # 5. Check if email already has CONVERTED account for this event
        existing = GuestAttendee.objects.filter(event=event, email=email).first()
        if existing and existing.converted_at:
            logger.info(f"Email {email} has already registered account for event {event.id}")
            return Response({
                "error": "account_exists",
                "message": "You have already registered. Please sign in."
            }, status=status.HTTP_409_CONFLICT)

        # 6. Create or update GuestAttendee with verified status
        jti = str(uuid.uuid4())
        ttl_hours = getattr(settings, "GUEST_JWT_TTL_HOURS", 24)
        expires_at = timezone.now() + timedelta(hours=ttl_hours)

        if existing:
            # Update existing guest with verified status
            existing.first_name = first_name or existing.first_name
            existing.last_name = last_name or existing.last_name
            existing.job_title = job_title or existing.job_title
            existing.company = company or existing.company
            existing.token_jti = jti
            existing.expires_at = expires_at
            existing.email_verified = True
            existing.save()
            guest = existing
            logger.info(f"Updated existing guest {email} with verified status")
        else:
            # Create new guest attendee with verified status
            initial_location = "waiting_room" if event.waiting_room_enabled else "main_room"
            guest = GuestAttendee(
                event=event,
                email=email,
                first_name=first_name,
                last_name=last_name,
                job_title=job_title,
                company=company,
                token_jti=jti,
                expires_at=expires_at,
                current_location=initial_location,
                email_verified=True,
            )
            guest.save()
            logger.info(f"Created new verified guest {email}")

        # 7. Issue JWT token
        payload = {
            "token_type": "guest",
            "guest_id": guest.id,
            "event_id": event.id,
            "jti": jti,
            "exp": expires_at,
        }

        secret = getattr(settings, "GUEST_JWT_SECRET", settings.SECRET_KEY)
        token = jwt.encode(payload, secret, algorithm="HS256")

        return Response({
            "token": token,
            "guest_id": guest.id,
            "name": guest.get_display_name(),
            "email": guest.email,
            "company": guest.company,
            "job_title": guest.job_title,
            "event_id": event.id,
            "expires_at": expires_at.isoformat(),
        }, status=status.HTTP_201_CREATED)


class ResendGuestOTPView(APIView):
    """
    POST /api/events/{event_id}/guest-resend-otp/

    Resend a verification code if the previous one expired.
    Rate-limited to 1 resend per 60 seconds per email per event.

    Request body:
    {
        "email": "john@example.com",
        "first_name": "John"  # optional, for personalization
    }

    Response (200 OK):
    {
        "otp_required": true,
        "message": "Verification code sent to john@example.com"
    }

    Response (429 Too Many Requests - if rate limited):
    {
        "otp_required": true,
        "message": "Please wait 45 seconds before requesting another code.",
        "seconds_remaining": 45
    }

    Error responses:
    - 400: Missing email field
    - 404: Event not found
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, pk=None):
        """Handle OTP resend request."""
        logger.info(f"[GuestResendOTP] POST request for event {pk}")

        # 1. Validate and get event
        try:
            event = Event.objects.get(pk=pk)
        except Event.DoesNotExist:
            logger.warning(f"[GuestResendOTP] Event not found: {pk}")
            return Response(
                {"error": "Event not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 2. Extract email
        email = request.data.get("email", "").strip().lower()
        first_name = request.data.get("first_name", "").strip()

        if not email:
            return Response(
                {"error": "email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 3. Invalidate all prior unused OTPs for this email/event
        GuestEmailOTP.objects.filter(
            event=event,
            email=email,
            used_at__isnull=True
        ).update(used_at=timezone.now())

        # 4. Send new OTP
        otp_result = send_guest_otp(event, email, first_name)

        if not otp_result["success"]:
            if otp_result.get("seconds_remaining"):
                return Response(
                    otp_result,
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            return Response(
                {"error": otp_result["message"]},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(otp_result, status=status.HTTP_200_OK)


class GuestRegisterView(APIView):
    """
    POST /api/auth/guest-register/

    Convert a guest session to a registered user account.
    Requires authentication with a valid guest JWT token.

    Request body:
    {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "password": "SecurePassword123!",
    }

    Response (200 OK):
    {
        "message": "Verification email sent to john@example.com...",
        "email": "john@example.com"
    }

    Error responses:
    - 403: Only guests can use this endpoint
    - 400: Invalid password or validation error
    """

    def post(self, request):
        """Handle guest account registration."""

        # 1. Verify request.user is a guest (via GuestJWTAuthentication)
        if not getattr(request.user, "is_guest", False):
            logger.warning(
                f"Non-guest user attempted guest-register: {request.user}"
            )
            return Response(
                {"error": "Only guests can use this endpoint."},
                status=status.HTTP_403_FORBIDDEN
            )

        guest = request.user.guest

        # 2. Validate core fields
        first_name = request.data.get("first_name", "").strip()
        last_name = request.data.get("last_name", "").strip()
        email = request.data.get("email", "").strip().lower()
        password = request.data.get("password", "").strip()

        if not first_name:
            return Response(
                {"error": "first_name is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not last_name:
            return Response(
                {"error": "last_name is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not email:
            return Response(
                {"error": "email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not password:
            return Response(
                {"error": "password is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if len(password) < 8:
            return Response(
                {"error": "Password must be at least 8 characters."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Keep guest record synchronized with submitted data before conversion
        guest.first_name = first_name
        guest.last_name = last_name
        guest.email = email
        guest.save(update_fields=["first_name", "last_name", "email"])

        try:
            # 4. Trigger signup and create Django User
            from users.cognito_auth import create_cognito_user_from_guest
            from users.email_utils import link_guest_history_to_user

            user = create_cognito_user_from_guest(
                guest=guest,
                password=password,
                first_name=first_name,
                last_name=last_name,
                email=email,
            )

            # 5. Mark guest as converted (revoke JWT)
            guest.converted_user = user
            guest.converted_at = timezone.now()
            guest.save()

            # 6. Link all guest history for this email to the new user
            link_guest_history_to_user(user, email)

            logger.info(
                f"Guest {guest.email} converted to registered user {user.id}"
            )

            return Response({
                "message": (
                    f"Verification email sent to {guest.email}. "
                    "Click the link to activate your account."
                ),
                "email": guest.email,
            })

        except Exception as e:
            logger.error(f"Error registering guest {guest.email}: {str(e)}")
            return Response(
                {"error": f"Registration failed: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


class GuestRegisterLinkView(APIView):
    """
    POST /api/auth/guest-register/link/

    Link an already-created registered user account to the current guest session.
    Used by the frontend after Cognito code verification succeeds.
    """

    def post(self, request):
        if not getattr(request.user, "is_guest", False):
            return Response(
                {"error": "Only guests can use this endpoint."},
                status=status.HTTP_403_FORBIDDEN,
            )

        email = (request.data.get("email") or "").strip().lower()
        if not email:
            return Response(
                {"error": "email is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from django.contrib.auth import get_user_model
        User = get_user_model()

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            return Response(
                {"error": "Registered user not found for this email."},
                status=status.HTTP_404_NOT_FOUND,
            )

        guest = request.user.guest
        if guest.email.strip().lower() != email:
            return Response(
                {"error": "Email does not match the current guest session."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        guest.converted_user = user
        if guest.converted_at is None:
            guest.converted_at = timezone.now()
        guest.save(update_fields=["converted_user", "converted_at"])

        # Link all guest history for this email to the registered user
        from users.email_utils import link_guest_history_to_user
        link_guest_history_to_user(user, email)

        # Sync guest profile fields to UserProfile (job_title, company, full_name)
        profile_data = {"job_title": "", "company": "", "full_name": ""}
        try:
            from users.models import UserProfile
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile_update_fields = []

            if guest.job_title and not profile.job_title:
                profile.job_title = guest.job_title
                profile_update_fields.append("job_title")

            if guest.company and not profile.company:
                profile.company = guest.company
                profile_update_fields.append("company")

            # Ensure full_name is populated (often blank on first Cognito login)
            full_name = f"{user.first_name} {user.last_name}".strip()
            if full_name and not profile.full_name:
                profile.full_name = full_name
                profile_update_fields.append("full_name")

            if profile_update_fields:
                profile.save(update_fields=profile_update_fields)
                logger.info(
                    f"[GuestRegisterLink] Synced profile fields {profile_update_fields} "
                    f"from guest {guest.id} to user {user.id}"
                )

            # Prepare response with synced profile data
            profile_data = {
                "job_title": profile.job_title,
                "company": profile.company,
                "full_name": profile.full_name,
            }
        except Exception as e:
            logger.warning(f"[GuestRegisterLink] Profile sync failed for user {user.id}: {e}")
            # Non-fatal: continue without profile sync

        return Response(
            {
                "message": "Guest account linked successfully.",
                "email": email,
                "profile": profile_data,
            },
            status=status.HTTP_200_OK,
        )


class GuestProfileDetailView(APIView):
    """
    GET /api/events/{event_id}/guests/{guest_id}/profile/

    Allow hosts/staff to view a specific guest's profile information.
    Requires authentication with a valid host/staff token.
    """

    def get(self, request, event_id=None, guest_id=None):
        """Fetch a guest's profile details."""
        try:
            event = Event.objects.get(pk=event_id)
        except Event.DoesNotExist:
            return Response(
                {"error": "Event not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        try:
            guest = GuestAttendee.objects.get(pk=guest_id, event=event)
        except GuestAttendee.DoesNotExist:
            return Response(
                {"error": "Guest not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        return Response({
            "guest": {
                "id": guest.id,
                "first_name": guest.first_name,
                "last_name": guest.last_name,
                "email": guest.email,
                "company": guest.company,
                "job_title": guest.job_title,
                "name": guest.get_display_name()
            }
        }, status=status.HTTP_200_OK)


class GuestProfileUpdateView(APIView):
    """
    GET /api/events/{event_id}/guest-profile/
    PATCH /api/events/{event_id}/guest-profile/

    Allow guests to view and update their profile information during a live event.
    Requires authentication with a valid guest JWT token.

    GET Response (200 OK):
    {
        "guest": {
            "id": 7,
            "first_name": "John",
            "last_name": "Doe",
            "email": "john@example.com",
            "company": "Acme Corp",
            "job_title": "Software Engineer",
            "name": "John Doe"
        }
    }

    PATCH Request body:
    {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "company": "Acme Corp",
        "job_title": "Software Engineer"
    }

    PATCH Response (200 OK):
    {
        "message": "Profile updated successfully",
        "guest": {
            "id": 7,
            "first_name": "John",
            "last_name": "Doe",
            "email": "john@example.com",
            "company": "Acme Corp",
            "job_title": "Software Engineer",
            "name": "John Doe"
        }
    }

    Error responses:
    - 403: Only guests can use this endpoint
    - 404: Event or guest not found
    - 400: Invalid data
    """

    def get(self, request, pk=None):
        """Handle guest profile fetch request."""

        # 1. Verify request.user is a guest
        if not getattr(request.user, "is_guest", False):
            logger.warning(
                f"Non-guest user attempted guest profile fetch: {request.user}"
            )
            return Response(
                {"error": "Only guests can use this endpoint."},
                status=status.HTTP_403_FORBIDDEN
            )

        # 2. Get event and guest
        try:
            event = Event.objects.get(pk=pk)
        except Event.DoesNotExist:
            return Response(
                {"error": "Event not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        guest = request.user.guest
        if guest.event_id != event.id:
            logger.warning(
                f"Guest {guest.id} attempted to fetch profile for different event {event.id}"
            )
            return Response(
                {"error": "Guest does not belong to this event."},
                status=status.HTTP_403_FORBIDDEN
            )

        # 3. Return guest profile
        return Response({
            "guest": {
                "id": guest.id,
                "first_name": guest.first_name,
                "last_name": guest.last_name,
                "email": guest.email,
                "company": guest.company,
                "job_title": guest.job_title,
                "name": guest.get_display_name()
            }
        }, status=status.HTTP_200_OK)

    def patch(self, request, pk=None):
        """Handle guest profile update request."""

        # 1. Verify request.user is a guest
        if not getattr(request.user, "is_guest", False):
            logger.warning(
                f"Non-guest user attempted guest profile update: {request.user}"
            )
            return Response(
                {"error": "Only guests can use this endpoint."},
                status=status.HTTP_403_FORBIDDEN
            )

        # 2. Get event and guest
        try:
            event = Event.objects.get(pk=pk)
        except Event.DoesNotExist:
            return Response(
                {"error": "Event not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        guest = request.user.guest
        if guest.event_id != event.id:
            logger.warning(
                f"Guest {guest.id} attempted to update profile for different event {event.id}"
            )
            return Response(
                {"error": "Guest does not belong to this event."},
                status=status.HTTP_403_FORBIDDEN
            )

        # 3. Extract and validate request data
        first_name = request.data.get("first_name", "").strip()
        last_name = request.data.get("last_name", "").strip()
        email = request.data.get("email", "").strip().lower()
        company = request.data.get("company", "").strip()
        job_title = request.data.get("job_title", "").strip()

        # Validate required fields
        if not first_name:
            return Response(
                {"error": "first_name is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not last_name:
            return Response(
                {"error": "last_name is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not email:
            return Response(
                {"error": "email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 4. Check if new email conflicts with another guest (but allow same email for this guest)
        if email != guest.email:
            existing = GuestAttendee.objects.filter(
                event=event,
                email=email
            ).exclude(id=guest.id).first()
            if existing:
                return Response(
                    {"error": "Email already in use by another guest in this event."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # 5. Update guest record
        guest.first_name = first_name
        guest.last_name = last_name
        guest.email = email
        guest.company = company
        guest.job_title = job_title
        guest.save()

        logger.info(f"Guest {guest.id} updated profile for event {event.id}")

        # ✅ Trigger WebSocket update to notify other participants of profile change
        try:
            from asgiref.sync import async_to_sync
            from channels.layers import get_channel_layer
            channel_layer = get_channel_layer()
            group_name = f"event_{event.id}"

            # Send update message to WebSocket group with full profile data
            async_to_sync(channel_layer.group_send)(
                group_name,
                {
                    "type": "guest_profile_updated",
                    "guest_id": guest.id,
                    "event_id": event.id,
                    "participant_id": f"guest_{guest.id}",
                    "first_name": guest.first_name,
                    "last_name": guest.last_name,
                    "email": guest.email,
                    "company": guest.company,
                    "job_title": guest.job_title,
                    "name": guest.get_display_name(),
                }
            )
            logger.info(f"Broadcast guest profile update for guest {guest.id} to event {event.id}")
        except Exception as e:
            logger.warning(f"Failed to broadcast guest profile update: {str(e)}")

        return Response({
            "message": "Profile updated successfully",
            "guest": {
                "id": guest.id,
                "first_name": guest.first_name,
                "last_name": guest.last_name,
                "email": guest.email,
                "company": guest.company,
                "job_title": guest.job_title,
                "name": guest.get_display_name()
            }
        }, status=status.HTTP_200_OK)
