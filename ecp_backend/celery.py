"""
Celery configuration for the events & community platform.

This module defines and exposes a Celery application instance.  Celery
discovers tasks by inspecting any `tasks.py` modules in installed apps.
"""
import os
from celery import Celery

# Set default Django settings for Celery to pick configuration from settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ecp_backend.settings.dev")

celery_app = Celery("ecp_backend")

# Namespacing Celery settings with the "CELERY_" prefix in Django settings
celery_app.config_from_object("django.conf:settings", namespace="CELERY")
celery_app.autodiscover_tasks()