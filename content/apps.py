from django.apps import AppConfig

class ContentConfig(AppConfig):
    """
    Configuration for the content app.

    The ready() hook imports the signals module to ensure that our
    post‑save hooks are registered when Django starts.
    """
    default_auto_field = "django.db.models.BigAutoField"
    name = "content"

    def ready(self) -> None:
        from . import signals  # ensures signal handlers are registered
