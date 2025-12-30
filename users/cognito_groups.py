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
