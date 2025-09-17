"""
Analytics app package for the events & community platform backend.

The analytics app records metrics about platform activity (messages
sent, resources uploaded, registrations and purchases) on a daily
basis.  Celery tasks increment counters asynchronously to avoid
blocking the user experience.  Data can be queried via the REST
API for reporting.
"""

default_app_config = "analytics.apps.AnalyticsConfig"
