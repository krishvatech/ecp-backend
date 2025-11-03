from django.apps import AppConfig


class MessagingConfig(AppConfig):
    """Configuration for the messaging app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "messaging"

    def ready(self) -> None:
        # Import signal handlers
        from . import signals  # noqa: F401
