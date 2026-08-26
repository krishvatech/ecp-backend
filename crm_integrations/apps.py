from django.apps import AppConfig


class CRMIntegrationsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "crm_integrations"
    verbose_name = "CRM Integrations"

    def ready(self):
        from . import signals  # noqa: F401
