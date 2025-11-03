# activity_feed/apps.py
from django.apps import AppConfig

class ActivityFeedConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "activity_feed"

    def ready(self):
        # import signals so receivers register
        from . import signals  # noqa
