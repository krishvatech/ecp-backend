"""
Development settings for the events & community platform.

Extends the base settings by enabling debugging and allowing all hosts.  Do
not use these settings in production.
"""
from .base import *  # noqa

# Development toggles
DEBUG = True
ALLOWED_HOSTS = ALLOWED_HOSTS or ["*"]
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"