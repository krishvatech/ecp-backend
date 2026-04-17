"""
Signals for the users app.

Automatically create or update a `UserProfile` instance whenever a `User`
is created or saved, and add new users to the default community.
"""
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save, pre_delete
from django.db import transaction
from django.dispatch import receiver
from django.apps import apps
from django.utils import timezone
from django.conf import settings
from .models import UserProfile
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
def ensure_profile(sender, instance, created, **kwargs):
    """
    Ensure exactly one UserProfile exists for every User.
    Also, when a new user is created, automatically add them
    to the default community (id = 1).
    """
    was_created = created  # capture for use inside on_commit callback

    def _create():
        # 1) Ensure profile exists
        profile, created_profile = UserProfile.objects.get_or_create(user=instance)

        # Initialize last_activity_at for brand-new profiles
        if created_profile and not profile.last_activity_at:
            profile.last_activity_at = timezone.now()
            profile.save(update_fields=["last_activity_at"])

        # 2) Only on brand-new users, add to default community
        if was_created:
            try:
                Community = apps.get_model("community", "Community")
            except LookupError:
                # community app not ready / not installed
                return

            try:
                default_comm = Community.objects.get(pk=1)  # your default community
            except Community.DoesNotExist:
                # default community not created yet – just skip
                return

            # Use the ManyToMany manager, creates a row in
            # public.community_community_members (community_id=1, user_id=<user.id>)
            default_comm.members.add(instance)

    # Run after the transaction commits so IDs are available
    transaction.on_commit(_create)

    # Link guest history if this is a newly created user with an email that has guest records
    if created and instance.email:
        def _link_guest_history():
            from users.email_utils import link_guest_history_to_user
            try:
                link_guest_history_to_user(instance, instance.email)
            except Exception as e:
                from django.utils import timezone
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to link guest history for user {instance.id}: {e}")

        transaction.on_commit(_link_guest_history)


@receiver(post_save, sender=UserProfile)
def sync_cognito_status(sender, instance, created, **kwargs):
    """
    Sync profile_status changes to Cognito (Enable/Disable user).
    Supported statuses:
      - 'suspended', 'fake', 'deceased' -> Disable user in Cognito
      - 'active', 'under_review' -> Enable user in Cognito
    """
    # 1. Gather Cognito settings
    region = getattr(settings, "COGNITO_REGION", "")
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "")
    if not region or not pool_id:
        return

    # 2. Determine desired Cognito state
    #    True = Enabled, False = Disabled
    BLOCKED_STATUSES = ("suspended", "fake", "deceased")
    should_be_enabled = (instance.profile_status not in BLOCKED_STATUSES)

    # 3. Perform sync in a separate thread or immediately (blocking)
    #    For simplicity/reliability here we do it immediately but inside a try/except.
    #    Ideally this would be a Celery task to avoid blocking the request.
    import boto3
    try:
        client = boto3.client("cognito-idp", region_name=region)
        username = instance.user.username  # Assuming username matches Cognito username

        if should_be_enabled:
            client.admin_enable_user(
                UserPoolId=pool_id,
                Username=username
            )
        else:
            client.admin_disable_user(
                UserPoolId=pool_id,
                Username=username
            )
    except Exception as e:
        # Log failure but don't crash the app
        print(f"Failed to sync Cognito status for {instance.user.username}: {e}")


@receiver(pre_delete, sender=User)
def remove_user_from_cognito(sender, instance, **kwargs):
    """
    Remove user from Cognito when deleted from Django.
    This ensures deleted/merged users can no longer login.
    """
    region = getattr(settings, "COGNITO_REGION", "")
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "")
    if not region or not pool_id:
        return

    try:
        import boto3
        client = boto3.client("cognito-idp", region_name=region)
        username = instance.username

        client.admin_delete_user(
            UserPoolId=pool_id,
            Username=username
        )
        logger.info(f"Removed user {username} (ID: {instance.id}) from Cognito")
    except Exception as e:
        logger.error(f"Failed to remove {instance.username} from Cognito: {e}")


def create_profile_view_notification(sender, instance, created, **kwargs):
    """
    Create a notification when someone views a staff/admin profile.
    Throttled to avoid spam (max 1 notification per viewer per 12 hours).
    """
    if not created:
        return

    from django.utils import timezone
    from datetime import timedelta
    from friends.models import Notification

    viewer = instance.viewer
    target = instance.target_user

    # Check if we already notified target about this viewer in the last 12 hours
    cutoff_time = timezone.now() - timedelta(hours=12)
    existing = Notification.objects.filter(
        recipient=target,
        actor=viewer,
        kind="profile_view",
        created_at__gte=cutoff_time
    ).exists()

    if existing:
        return  # Already notified recently

    # Create the notification
    if instance.is_anonymous:
        if instance.viewer_country:
            title = f"Someone from {instance.viewer_country} viewed your profile."
        else:
            title = "Someone viewed your profile."
    else:
        profile = getattr(viewer, "profile", None)
        name = profile.full_name if profile and profile.full_name else viewer.username
        title = f"{name} viewed your profile."

    Notification.objects.create(
        recipient=target,
        actor=viewer if not instance.is_anonymous else None,
        kind="profile_view",
        title=title,
        data={
            "profile_view_id": instance.id,
            "viewer_id": viewer.id if not instance.is_anonymous else None,
            "is_anonymous": instance.is_anonymous,
        }
    )
