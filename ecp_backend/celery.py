"""
Celery configuration for the events & community platform.

This module defines and exposes a Celery application instance.  Celery
discovers tasks by inspecting any `tasks.py` modules in installed apps.
"""
import os
from celery import Celery

# Set default Django settings for Celery to pick configuration from settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ecp_backend.settings.dev")

app = Celery("ecp_backend")

# Namespacing Celery settings with the "CELERY_" prefix in Django settings
app.config_from_object("django.conf:settings", namespace="CELERY")

# Explicitly list apps for task autodiscovery to ensure networking tasks are found
app.autodiscover_tasks(['events', 'invoicing', 'interactions', 'friends', 'users', 'activity_feed', 'courses', 'content'])