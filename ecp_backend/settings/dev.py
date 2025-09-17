"""
Development settings for the events & community platform.

Extends the base settings by enabling debugging and allowing all hosts.  Do
not use these settings in production.
"""
from .base import *  # noqa
import os

# Development toggles
DEBUG = True
ALLOWED_HOSTS = ["*", "127.0.0.1", "localhost"]
# (WS doesn't use CSRF, but keeping these aligned helps for HTTP)
CSRF_TRUSTED_ORIGINS = ["http://127.0.0.1:8000","http://localhost:8000"]
LOGGING = {
    "version": 1, "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {
        "channels": {"handlers": ["console"], "level": "DEBUG"},
    },
}