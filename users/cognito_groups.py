import logging
import boto3
from django.conf import settings

log = logging.getLogger(__name__)

def sync_staff_group(*, username: str, is_staff: bool) -> None:
    region = getattr(settings, "COGNITO_REGION", "") or ""
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "") or ""
    group = getattr(settings, "COGNITO_STAFF_GROUP", "staff") or "staff"

    if not region or not pool_id:
        log.warning("Cognito not configured; skipping staff sync (missing region/pool_id)")
        return

    try:
        client = boto3.client("cognito-idp", region_name=region)
        if is_staff:
            client.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group)
            log.info("Cognito staff sync: added user=%s to group=%s", username, group)
        else:
            client.admin_remove_user_from_group(UserPoolId=pool_id, Username=username, GroupName=group)
            log.info("Cognito staff sync: removed user=%s from group=%s", username, group)
    except Exception as exc:
        log.warning("Cognito staff sync failed for user=%s group=%s: %s", username, group, exc, exc_info=True)


def add_user_to_speaker_group(*, username: str) -> bool:
    """
    Add a user to the 'speaker' group in Cognito.

    Args:
        username: Cognito username

    Returns:
        bool: True if successful, False otherwise
    """
    region = getattr(settings, "COGNITO_REGION", "") or ""
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "") or ""
    group = "speaker"

    if not region or not pool_id:
        log.warning("Cognito not configured; skipping speaker group sync (missing region/pool_id)")
        return False

    try:
        client = boto3.client("cognito-idp", region_name=region)
        client.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group)
        log.info("Added user=%s to Cognito group=%s", username, group)
        return True
    except Exception as exc:
        return False
    except Exception as exc:
        log.warning("Failed to add user=%s to group=%s: %s", username, group, exc, exc_info=True)
        return False


def add_user_to_group(*, username: str, group_name: str) -> bool:
    """
    Add a user to a specific Cognito group.

    Args:
        username: Cognito username
        group_name: Name of the group to add user to

    Returns:
        bool: True if successful, False otherwise
    """
    region = getattr(settings, "COGNITO_REGION", "") or ""
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "") or ""

    if not region or not pool_id or not group_name:
        log.warning(
            "Cognito sync skipped: missing config (region=%s, pool=%s) or group_name=%s",
            bool(region), bool(pool_id), group_name
        )
        return False

    try:
        client = boto3.client("cognito-idp", region_name=region)
        client.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group_name)
        log.info("Added user=%s to Cognito group=%s", username, group_name)
        return True
    except Exception as exc:
        log.warning("Failed to add user=%s to group=%s: %s", username, group_name, exc, exc_info=True)
        return False


def remove_user_from_group(*, username: str, group_name: str) -> bool:
    """
    Remove a user from a specific Cognito group.

    Args:
        username: Cognito username
        group_name: Name of the group to remove user from

    Returns:
        bool: True if successful, False otherwise
    """
    region = getattr(settings, "COGNITO_REGION", "") or ""
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "") or ""

    if not region or not pool_id or not group_name:
        log.warning(
            "Cognito sync skipped (remove): missing config or group_name=%s", group_name
        )
        return False

    try:
        client = boto3.client("cognito-idp", region_name=region)
        client.admin_remove_user_from_group(UserPoolId=pool_id, Username=username, GroupName=group_name)
        log.info("Removed user=%s from Cognito group=%s", username, group_name)
        return True
    except Exception as exc:
        # If user not in group, it might throw; usually safe to ignore or log warning
        log.warning("Failed to remove user=%s from group=%s: %s", username, group_name, exc)
        return False


