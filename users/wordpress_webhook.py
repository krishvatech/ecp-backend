"""
WordPress webhook endpoint handler.

Receives and processes user sync events from WordPress IMAA.
Validates webhook signatures and triggers profile sync.
"""
import json
import logging
import boto3
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.contrib.auth.models import User
from .wordpress_api import get_wordpress_client
from .wordpress_sync import get_profile_sync_service
from .email_utils import update_cognito_user_email
from .serializers import UserProfileSerializer

logger = logging.getLogger(__name__)


def get_cognito_tokens_admin(username: str) -> dict:
    """
    Get Cognito tokens using Admin API with stored temporary password.
    Used to auto-authenticate users after WordPress sync.

    Returns dict with access_token, id_token, refresh_token or empty dict on failure
    """
    try:
        from django.contrib.auth.models import User

        region = getattr(settings, "COGNITO_REGION", "") or ""
        pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "") or ""
        client_id = getattr(settings, "COGNITO_CLIENT_ID", "") or ""

        if not region or not pool_id or not client_id:
            logger.warning("Cognito not fully configured for admin auth")
            return {}

        # Get the temporary password from user profile
        try:
            user = User.objects.get(username=username)
            temp_password = user.profile.cognito_temp_password
        except (User.DoesNotExist, AttributeError):
            logger.error(f"User {username} not found or has no temp password")
            return {}

        if not temp_password:
            logger.error(f"No temporary password stored for user {username}")
            return {}

        client = boto3.client("cognito-idp", region_name=region)

        # Use admin_initiate_auth with PASSWORD parameter
        response = client.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_NO_SRP_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": temp_password,
            }
        )

        tokens = response.get("AuthenticationResult", {})
        logger.info(f"Got Cognito tokens for user {username} via admin auth")

        return {
            "access_token": tokens.get("AccessToken", ""),
            "id_token": tokens.get("IdToken", ""),
            "refresh_token": tokens.get("RefreshToken", ""),
        }

    except Exception as e:
        logger.error(f"Failed to get Cognito tokens for {username}: {str(e)}")
        return {}


class WordPressWebhookView(APIView):
    """Handle incoming WordPress webhooks for user sync."""

    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
        Handle WordPress webhook POST request.

        Expected payload:
        {
            "event": "user_created|user_updated|user_deleted",
            "timestamp": "2024-03-09T12:00:00Z",
            "user_id": 123,
            "id": 123,
            "email": "user@example.com",
            "name": "User Name",
            "username": "username",
            "description": "User bio",
            "avatar_urls": {
                "96": "https://example.com/avatar.jpg"
            }
        }
        """
        try:
            signature = request.headers.get("X-Webhook-Signature", "")

            # Get raw request body for signature validation (preserves exact payload)
            payload_str = request.body.decode('utf-8')
            payload = request.data

            # Validate webhook signature using raw body
            wp_client = get_wordpress_client()

            if not wp_client.validate_webhook_secret(payload_str, signature):
                logger.warning("Invalid WordPress webhook signature")
                return Response(
                    {"error": "Invalid signature"},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Extract event and user data
            event = payload.get("event")
            if not event:
                logger.warning("Missing event in WordPress webhook")
                return Response(
                    {"error": "Missing event"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Trigger profile sync
            sync_service = get_profile_sync_service()
            success = sync_service.handle_wordpress_webhook(event, payload)

            if success:
                logger.info(f"Processed WordPress webhook: {event}")
                return Response(
                    {"status": "success", "event": event},
                    status=status.HTTP_200_OK
                )
            else:
                logger.error(f"Failed to process WordPress webhook: {event}")
                return Response(
                    {"error": "Failed to process webhook"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except json.JSONDecodeError:
            logger.error("Invalid JSON in WordPress webhook")
            return Response(
                {"error": "Invalid JSON"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error processing WordPress webhook: {str(e)}", exc_info=True)
            return Response(
                {"error": "Internal error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class WordPressUserSyncView(APIView):
    """Manual trigger for WordPress user sync."""

    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
        Manually sync a user from WordPress.

        Request body:
        {
            "wp_user_id": 123,
            "email": "user@example.com"  # optional, preserves original email from login
        }
        or
        {
            "email": "user@example.com"
        }
        """
        try:
            sync_service = get_profile_sync_service()
            user = None
            created = False
            original_email = request.data.get("email")  # Preserve the original email from login

            if "wp_user_id" in request.data:
                wp_user_id = request.data.get("wp_user_id")
                logger.info(f"Syncing WordPress user by ID: {wp_user_id}")
                wp_user_data = sync_service.wp_client.get_user_by_id(wp_user_id)
                if not wp_user_data:
                    logger.warning(f"WordPress user not found for ID: {wp_user_id}")
                    return Response(
                        {"error": "User not found in WordPress"},
                        status=status.HTTP_404_NOT_FOUND
                    )
                user, created = sync_service.sync_user_from_wordpress(wp_user_data, override_email=original_email)
            elif "email" in request.data:
                email = request.data.get("email")
                logger.info(f"Syncing WordPress user by email: {email}")
                wp_user_data = sync_service.wp_client.get_user_by_email(email)
                if not wp_user_data:
                    logger.warning(f"WordPress user not found for email: {email}")
                    return Response(
                        {"error": "User not found in WordPress"},
                        status=status.HTTP_404_NOT_FOUND
                    )
                user, created = sync_service.sync_user_from_wordpress(wp_user_data, override_email=original_email)
            else:
                logger.warning("Missing wp_user_id or email in request")
                return Response(
                    {"error": "Provide either wp_user_id or email"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not user:
                logger.error(f"Failed to sync user: not found in WordPress")
                return Response(
                    {"error": "User not found in WordPress"},
                    status=status.HTTP_404_NOT_FOUND
                )

            logger.info(f"Successfully synced user {user.id}, created={created}")

            # Get Cognito tokens for the user (auto-authenticate)
            cognito_tokens = get_cognito_tokens_admin(user.username)

            if not cognito_tokens.get("access_token"):
                # Fallback to SimpleJWT if Cognito fails
                logger.warning(f"Failed to get Cognito tokens for {user.username}, using SimpleJWT")
                refresh = RefreshToken.for_user(user)
                cognito_tokens = {
                    "access_token": str(refresh.access_token),
                    "id_token": str(refresh.access_token),
                    "refresh_token": str(refresh),
                }

            return Response(
                {
                    "status": "success",
                    "user_id": user.id,
                    "created": created,
                    "email": user.email,
                    "access_token": cognito_tokens.get("access_token", ""),
                    "id_token": cognito_tokens.get("id_token", ""),
                    "refresh_token": cognito_tokens.get("refresh_token", ""),
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(f"Error in manual sync: {str(e)}", exc_info=True)
            return Response(
                {"error": f"Internal error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class WordPressProfileSyncAuthenticatedView(APIView):
    """Manual profile sync endpoint for authenticated users."""

    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Manually sync the current authenticated user's profile from WordPress.

        Returns the updated profile data.
        """
        try:
            user = request.user
            if not user or not user.is_authenticated:
                return Response(
                    {"error": "User not authenticated"},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            sync_service = get_profile_sync_service()

            # Sync user from WordPress by email (preserve their current email)
            logger.info(f"User {user.id} requesting profile sync from WordPress")
            wp_user_data = sync_service.wp_client.get_user_by_email(user.email)
            if not wp_user_data:
                logger.warning(f"Could not find WordPress user for email: {user.email}")
                return Response(
                    {"error": "Your profile could not be found in WordPress. Please contact support if this is unexpected."},
                    status=status.HTTP_404_NOT_FOUND
                )
            # Sync with override_email to preserve the user's current email in the system
            synced_user, created = sync_service.sync_user_from_wordpress(wp_user_data, override_email=user.email)

            if not synced_user:
                logger.warning(f"Could not sync user {user.id} from WordPress - user not found in WordPress")
                return Response(
                    {"error": "Your profile could not be found in WordPress. Please contact support if this is unexpected."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Return the updated profile data
            profile_serializer = UserProfileSerializer(synced_user.profile)

            logger.info(f"Successfully synced profile for user {user.id} from WordPress")
            return Response(
                {
                    "status": "success",
                    "message": "Profile synced successfully from WordPress",
                    "profile": profile_serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(f"Error syncing profile for user {request.user.id}: {str(e)}", exc_info=True)
            return Response(
                {"error": f"Failed to sync profile: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
