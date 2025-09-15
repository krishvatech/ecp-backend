from django.apps import AppConfig


class RealtimeConfig(AppConfig):
    """Configuration for the realtime app.

    The realtime app is responsible for integrating with a cloud
    communications platform as a service (CPaaS) provider to generate
    short‑lived tokens for streaming sessions.  This config simply
    registers the app with Django.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "realtime"
