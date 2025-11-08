from django.apps import AppConfig

class EngagementsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "engagements"

    def ready(self):
        # Enable counters by importing signals (keep commented until you add counters on FeedItem).
        # from . import signals  # noqa: F401
        pass
