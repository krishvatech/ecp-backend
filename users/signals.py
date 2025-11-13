"""
Signals for the users app.

Automatically create or update a `UserProfile` instance whenever a `User`
is created or saved, and add new users to the default community.
"""
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.db import transaction
from django.dispatch import receiver
from django.apps import apps  # <-- NEW
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
        UserProfile.objects.get_or_create(user=instance)

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
