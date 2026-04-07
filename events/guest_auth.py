"""
Guest JWT Authentication

This module implements JWT-based authentication for guest attendees who join
events without creating a full account. Guest tokens are HS256-signed with
Django's SECRET_KEY and have a short expiration (default 24 hours).

The GuestJWTAuthentication class is designed to be used in DRF's auth chain
BEFORE CognitoJWTAuthentication, so it can detect and process guest tokens
without interfering with Cognito tokens.
"""

import jwt
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed


class GuestPrincipal:
    """
    Lightweight proxy object that wraps a GuestAttendee instance
    and provides the minimum interface DRF and views expect from request.user.

    This allows guest sessions to coexist with registered user sessions
    without requiring a full Django User account.
    """

    is_authenticated = True
    is_guest = True
    is_anonymous = False
    is_active = True
    is_staff = False
    is_superuser = False
    id = 0  # Guest is not a Django User; keep a non-null numeric sentinel

    def __init__(self, guest):
        """
        Args:
            guest: GuestAttendee model instance
        """
        self.guest = guest
        self.email = guest.email
        self.username = f"guest_{guest.id}"
        self.pk = 0

    def get_full_name(self):
        """Return guest's display name."""
        return self.guest.get_display_name()

    def has_perm(self, *args, **kwargs):
        """Guests have no permissions."""
        return False

    def has_module_perms(self, *args, **kwargs):
        """Guests have no module permissions."""
        return False

    def __str__(self):
        return f"Guest: {self.get_full_name()}"

    def __int__(self):
        """
        Defensive compatibility for code paths that accidentally pass request.user
        into ORM filters expecting a numeric User FK.
        """
        return 0


class GuestJWTAuthentication(BaseAuthentication):
    """
    DRF BaseAuthentication subclass for guest JWT tokens.

    Process:
    1. Extract Bearer token from Authorization header
    2. Peek at token (no signature check) to check token_type == "guest"
    3. If not guest token, return None (pass to next auth class)
    4. If guest token, verify HS256 signature with Django SECRET_KEY
    5. Validate expiration and token_jti in database
    6. Return (GuestPrincipal, token)

    This authenticator should be placed BEFORE CognitoJWTAuthentication
    in REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'] to catch guest tokens
    before Cognito tries to process them.
    """

    def authenticate(self, request):
        """
        Authenticate the request if it contains a valid guest JWT.

        Args:
            request: DRF Request object

        Returns:
            Tuple of (GuestPrincipal, token) if valid guest JWT
            None if no bearer token or token is not guest type
            Raises AuthenticationFailed for invalid guest tokens

        Raises:
            AuthenticationFailed: if guest token is invalid, expired, or revoked
        """
        token = self._extract_bearer(request)
        if not token:
            return None

        # Peek at token without verification to check if it's a guest token
        try:
            unverified = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False}
            )
        except Exception:
            # Not a valid JWT at all, let other auth classes handle it
            return None

        # Only process if this is a guest token
        if unverified.get("token_type") != "guest":
            return None  # Pass to CognitoJWTAuthentication

        # This is a guest token, verify its signature and claims
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Guest session has expired.")
        except jwt.InvalidTokenError as e:
            raise AuthenticationFailed(f"Invalid guest token: {str(e)}")

        # Validate in database
        try:
            from .models import GuestAttendee
            guest = GuestAttendee.objects.get(
                id=payload["guest_id"],
                token_jti=payload["jti"]
            )
        except GuestAttendee.DoesNotExist:
            raise AuthenticationFailed("Guest session not found or has been revoked.")

        # Check if guest has converted to registered user (revocation check)
        if guest.converted_at is not None:
            raise AuthenticationFailed(
                "You have already registered. Please sign in with your account."
            )

        # Check if guest is banned
        if guest.is_banned:
            raise AuthenticationFailed("You have been banned from this event.")

        # Success
        return (GuestPrincipal(guest), token)

    @staticmethod
    def _extract_bearer(request):
        """
        Extract Bearer token from Authorization header.

        Args:
            request: DRF Request object

        Returns:
            Token string (without "Bearer " prefix) or None
        """
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if header.lower().startswith("bearer "):
            return header[7:].strip()
        return None
