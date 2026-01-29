"""
User Suspension Utilities

This module provides functions to handle user suspension, including:
- Invalidating all active Django sessions for a user
- Blacklisting all outstanding JWT tokens
- Optional Cognito global sign-out
"""

import logging
from typing import Optional

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.utils import timezone

logger = logging.getLogger(__name__)
User = get_user_model()

# Blocked profile statuses that should prevent access
BLOCKED_PROFILE_STATUSES = ("suspended", "fake", "deceased")


def invalidate_user_sessions(user_id: int) -> dict:
    """
    Invalidate all active sessions and tokens for a user.
    Call this when suspending a user to force immediate logout.

    Args:
        user_id: The ID of the user to invalidate sessions for.

    Returns:
        dict: Statistics about what was invalidated.
            - sessions_deleted: Number of Django sessions deleted
            - tokens_blacklisted: Number of JWT tokens blacklisted
    """
    stats = {"sessions_deleted": 0, "tokens_blacklisted": 0}

    # 1. Clear Django sessions (session-based auth)
    # Sessions store user_id in _auth_user_id within session data
    try:
        all_sessions = Session.objects.filter(expire_date__gt=timezone.now())
        for session in all_sessions:
            try:
                data = session.get_decoded()
                if str(data.get("_auth_user_id")) == str(user_id):
                    session.delete()
                    stats["sessions_deleted"] += 1
            except Exception as e:
                # Skip corrupt sessions
                logger.warning(f"Could not decode session {session.session_key}: {e}")
                continue
    except Exception as e:
        logger.error(f"Error clearing sessions for user {user_id}: {e}")

    # 2. Blacklist all outstanding JWT tokens for this user
    try:
        from rest_framework_simplejwt.token_blacklist.models import (
            BlacklistedToken,
            OutstandingToken,
        )

        user = User.objects.filter(id=user_id).first()
        if user:
            outstanding = OutstandingToken.objects.filter(user=user)
            for token in outstanding:
                if not BlacklistedToken.objects.filter(token=token).exists():
                    BlacklistedToken.objects.create(token=token)
                    stats["tokens_blacklisted"] += 1
    except ImportError:
        # Token blacklist app not installed
        logger.warning("rest_framework_simplejwt.token_blacklist not installed")
    except Exception as e:
        logger.error(f"Error blacklisting tokens for user {user_id}: {e}")

    logger.info(
        f"Invalidated sessions for user {user_id}: "
        f"{stats['sessions_deleted']} sessions, {stats['tokens_blacklisted']} tokens"
    )
    return stats


def cognito_global_signout(username: str) -> bool:
    """
    Force sign out a user from all Cognito sessions.
    This invalidates all refresh tokens issued by Cognito.

    Args:
        username: The Cognito username (not email) to sign out.

    Returns:
        bool: True if successful, False otherwise.
    """
    region = getattr(settings, "COGNITO_REGION", None)
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", None)

    if not region or not pool_id:
        logger.warning("Cognito not configured, skipping global signout")
        return False

    try:
        import boto3

        client = boto3.client("cognito-idp", region_name=region)
        client.admin_user_global_sign_out(
            UserPoolId=pool_id,
            Username=username,
        )
        logger.info(f"Cognito global signout successful for user: {username}")
        return True
    except ImportError:
        logger.warning("boto3 not installed, cannot perform Cognito signout")
        return False
    except Exception as e:
        # User might not exist in Cognito or other errors
        logger.warning(f"Cognito global signout failed for {username}: {e}")
        return False


def suspend_user(user_id: int, reason: str = "", performed_by: Optional[int] = None) -> dict:
    """
    Suspend a user and invalidate all their sessions.

    This is a convenience function that:
    1. Sets profile_status to 'suspended'
    2. Records the reason and who performed the action
    3. Invalidates all active sessions and tokens
    4. Optionally signs out from Cognito

    Args:
        user_id: The ID of the user to suspend.
        reason: The reason for suspension.
        performed_by: The ID of the admin who performed the action.

    Returns:
        dict: Result including invalidation stats and success status.
    """
    result = {
        "success": False,
        "user_id": user_id,
        "sessions_invalidated": 0,
        "tokens_blacklisted": 0,
        "cognito_signout": False,
    }

    try:
        user = User.objects.select_related("profile").get(id=user_id)
    except User.DoesNotExist:
        result["error"] = "User not found"
        return result

    profile = getattr(user, "profile", None)
    if not profile:
        result["error"] = "User profile not found"
        return result

    # Update profile status
    profile.profile_status = "suspended"
    profile.profile_status_reason = reason
    profile.profile_status_updated_at = timezone.now()

    if performed_by:
        try:
            admin_user = User.objects.get(id=performed_by)
            profile.profile_status_updated_by = admin_user
        except User.DoesNotExist:
            pass

    profile.save(
        update_fields=[
            "profile_status",
            "profile_status_reason",
            "profile_status_updated_at",
            "profile_status_updated_by",
        ]
    )

    # Invalidate sessions and tokens
    invalidation_stats = invalidate_user_sessions(user_id)
    result["sessions_invalidated"] = invalidation_stats["sessions_deleted"]
    result["tokens_blacklisted"] = invalidation_stats["tokens_blacklisted"]

    # Try Cognito signout (optional, won't fail if it doesn't work)
    result["cognito_signout"] = cognito_global_signout(user.username)

    result["success"] = True
    return result


def reactivate_user(user_id: int, reason: str = "", performed_by: Optional[int] = None) -> dict:
    """
    Reactivate a suspended user.

    This sets profile_status back to 'active'.
    No session invalidation needed - user can log in again.

    Args:
        user_id: The ID of the user to reactivate.
        reason: The reason for reactivation.
        performed_by: The ID of the admin who performed the action.

    Returns:
        dict: Result including success status.
    """
    result = {"success": False, "user_id": user_id}

    try:
        user = User.objects.select_related("profile").get(id=user_id)
    except User.DoesNotExist:
        result["error"] = "User not found"
        return result

    profile = getattr(user, "profile", None)
    if not profile:
        result["error"] = "User profile not found"
        return result

    # Update profile status
    profile.profile_status = "active"
    profile.profile_status_reason = reason
    profile.profile_status_updated_at = timezone.now()

    if performed_by:
        try:
            admin_user = User.objects.get(id=performed_by)
            profile.profile_status_updated_by = admin_user
        except User.DoesNotExist:
            pass

    profile.save(
        update_fields=[
            "profile_status",
            "profile_status_reason",
            "profile_status_updated_at",
            "profile_status_updated_by",
        ]
    )

    result["success"] = True
    return result


def is_user_suspended(user) -> bool:
    """
    Check if a user is suspended (or has another blocked status).

    Args:
        user: The User instance to check.

    Returns:
        bool: True if the user is suspended/blocked, False otherwise.
    """
    if not user or not user.is_authenticated:
        return False

    profile = getattr(user, "profile", None)
    if profile and profile.profile_status in BLOCKED_PROFILE_STATUSES:
        return True

    return False
