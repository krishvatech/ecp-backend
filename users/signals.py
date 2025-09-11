"""
Signals for the users app.

Automatically create or update a `UserProfile` instance whenever a `User`
is created or saved.
"""
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.db import transaction
from django.dispatch import receiver
from .models import UserProfile

User = get_user_model()

@receiver(post_save, sender=User)
def ensure_profile(sender, instance, created, **kwargs):
    """
    Ensure exactly one UserProfile exists for every User.
    Safe with Admin inline and concurrent creates.
    """
    # If you want to delay profile creation until the user row is fully committed:
    def _create():
        UserProfile.objects.get_or_create(user=instance)
    transaction.on_commit(_create)