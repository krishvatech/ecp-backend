"""
Production settings for the events & community platform.

Extends the base settings by disabling debug mode, enforcing secure
cookies, and enabling HTTP Strict Transport Security.
"""
import os

from .base import *  # noqa

DEBUG = False

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
SECURE_REDIRECT_EXEMPT = [r"^api/health/?$"]

SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

SESSION_COOKIE_SAMESITE = "None"
CSRF_COOKIE_SAMESITE = "None"

STORAGES = globals().get("STORAGES", {})
STORAGES["staticfiles"] = {
    "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
}

# Live meeting ASG autoscale settings (production defaults)
LIVE_MEETING_ASG_AUTOSCALE_ENABLED = os.getenv(
    "LIVE_MEETING_ASG_AUTOSCALE_ENABLED", "True"
).lower() == "true"

LIVE_MEETING_ASG_NAME = os.getenv("LIVE_MEETING_ASG_NAME", "ecp-backend-asg")
LIVE_MEETING_ASG_REGION = os.getenv("LIVE_MEETING_ASG_REGION", "eu-central-1")

LIVE_MEETING_SAFE_USERS_PER_INSTANCE = int(os.getenv("LIVE_MEETING_SAFE_USERS_PER_INSTANCE", "75"))
LIVE_MEETING_BUFFER_INSTANCES = int(os.getenv("LIVE_MEETING_BUFFER_INSTANCES", "1"))

LIVE_MEETING_ASG_MIN_CAPACITY = int(os.getenv("LIVE_MEETING_ASG_MIN_CAPACITY", "2"))
LIVE_MEETING_ASG_MAX_CAPACITY = int(os.getenv("LIVE_MEETING_ASG_MAX_CAPACITY", "12"))

LIVE_MEETING_PREWARM_MINUTES = int(os.getenv("LIVE_MEETING_PREWARM_MINUTES", "90"))
LIVE_MEETING_HOST_EARLY_START_MINUTES = int(os.getenv("LIVE_MEETING_HOST_EARLY_START_MINUTES", "120"))
LIVE_MEETING_COOLDOWN_MINUTES = int(os.getenv("LIVE_MEETING_COOLDOWN_MINUTES", "60"))

LIVE_MEETING_LATE_REGISTRATION_BUFFER_PERCENT = int(
    os.getenv("LIVE_MEETING_LATE_REGISTRATION_BUFFER_PERCENT", "100")
)
LIVE_MEETING_LATE_REGISTRATION_BUFFER_MIN = int(os.getenv("LIVE_MEETING_LATE_REGISTRATION_BUFFER_MIN", "100"))
