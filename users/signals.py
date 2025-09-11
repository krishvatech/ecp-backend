"""
Signals for the users app.

Automatically create or update a `UserProfile` instance whenever a `User`
is created or saved.
"""
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import UserProfile


@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    """Create a corresponding UserProfile for new users."""
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_profile(sender, instance, **kwargs):
    """Ensure that a profile exists and is saved when the user is saved."""
    UserProfile.objects.get_or_create(user=instance)