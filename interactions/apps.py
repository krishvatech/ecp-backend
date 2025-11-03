"""
App configuration for the interactions app.

The interactions app encapsulates live Chat and Q&A for events using
Django Channels. No special startup logic is required at this time.
"""

from django.apps import AppConfig


class InteractionsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "interactions"
    verbose_name = "Interactions (Chat & Q&A)"
