"""Isolated settings for provider-neutral CRM model tests.

The full project has PostgreSQL-specific migrations, so SQLite cannot migrate
every application. These settings intentionally install only the dependencies
required to exercise the CRM schema and constraints without external services.
"""

SECRET_KEY = "crm-integration-tests-only"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "crm_integrations.apps.CRMIntegrationsConfig",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True

# The production project installs ``users.UserProfile``. This intentionally
# minimal test configuration does not, so ignore only the lazy-sender check.
SILENCED_SYSTEM_CHECKS = ["signals.E001"]
