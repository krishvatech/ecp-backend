"""
Guest Attendee API Views

This module provides endpoints for guest (unauthenticated) event participation:
- GuestJoinView: Allow visitors to join events without registration
- GuestRegisterView: Convert guest session to registered Cognito account
"""

import uuid
import jwt
import logging
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError, PermissionDenied
from .models import Event, GuestAttendee
from .guest_auth import GuestPrincipal

logger = logging.getLogger(__name__)


class GuestJoinView(APIView):
    """
    POST /api/events/{event_id}/guest-join/

    Allow unauthenticated users to join an event as guests.
    Returns a short-lived JWT token for guest session.

    Request body:
    {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "job_title": "Software Engineer"  # optional
    }

    Response (201 Created):
    {
        "token": "<jwt_token>",
        "guest_id": 7,
        "name": "John Doe",
        "email": "john@example.com",
        "event_id": 42,
        "expires_at": "2026-03-14T10:00:00Z"
    }

    Error responses:
    - 400: Missing required fields
    - 404: Event not found
    - 409: Email already has registered account for this event
    """

    permission_classes = [AllowAny]
    authentication_classes = []  # No auth required to join as guest

    def post(self, request, pk=None):
        """Handle guest join request."""

        # 1. Validate and get event
        try:
            event = Event.objects.get(pk=pk)
        except Event.DoesNotExist:
            logger.warning(f"Guest join attempt for non-existent event: {pk}")
            return Response(
                {"error": "Event not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 2. Extract and validate request data
        first_name = request.data.get("first_name", "").strip()
        last_name = request.data.get("last_name", "").strip()
        email = request.data.get("email", "").strip().lower()
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

        # 4. Create or update GuestAttendee
        jti = str(uuid.uuid4())
        ttl_hours = getattr(settings, "GUEST_JWT_TTL_HOURS", 24)
        expires_at = timezone.now() + timedelta(hours=ttl_hours)

        if existing:
            # Re-issue token for existing guest
            existing.first_name = first_name
            existing.last_name = last_name
            existing.job_title = job_title
            existing.token_jti = jti
            existing.expires_at = expires_at
            # Keep guests in waiting-room state when policy is enabled, unless already admitted.
            if event.waiting_room_enabled and existing.current_location != "main_room":
                existing.current_location = "waiting_room"
            existing.save()
            guest = existing
            logger.info(f"Re-issued guest token for {email} on event {event.id}")
        else:
            # Create new guest attendee
            initial_location = "waiting_room" if event.waiting_room_enabled else "main_room"
            guest = GuestAttendee(
                event=event,
                email=email,
                first_name=first_name,
                last_name=last_name,
                job_title=job_title,
                token_jti=jti,
                expires_at=expires_at,
                current_location=initial_location,
            )
            guest.save()
            logger.info(f"Created new guest attendee {email} for event {event.id}")

        # 5. Issue JWT token
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
            "event_id": event.id,
            "expires_at": expires_at.isoformat(),
        }, status=status.HTTP_201_CREATED)


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

        return Response(
            {"message": "Guest account linked successfully.", "email": email},
            status=status.HTTP_200_OK,
        )


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
