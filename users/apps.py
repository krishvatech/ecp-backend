from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "users"

    def ready(self) -> None:
        # Import signals to ensure they are registered
        from . import signals  # noqa
        from django.db.models.signals import post_save
        from .models import ProfileView
        post_save.connect(signals.create_profile_view_notification, sender=ProfileView)