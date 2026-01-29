"""
Signals for the users app.

Automatically create or update a `UserProfile` instance whenever a `User`
is created or saved, and add new users to the default community.
"""
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.db import transaction
from django.dispatch import receiver
from django.apps import apps  
from django.utils import timezone
from django.conf import settings
from .models import UserProfile

User = get_user_model()


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
