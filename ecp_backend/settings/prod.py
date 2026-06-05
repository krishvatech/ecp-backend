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

# Safe scale-in feature flags (disabled by default; no behavior change yet).
LIVE_MEETING_SAFE_SCALE_IN_ENABLED = os.getenv(
    "LIVE_MEETING_SAFE_SCALE_IN_ENABLED",
    "False",
).lower() == "true"

LIVE_MEETING_SAFE_SCALE_IN_DRY_RUN = os.getenv(
    "LIVE_MEETING_SAFE_SCALE_IN_DRY_RUN",
    "True",
).lower() == "true"

LIVE_MEETING_SCALE_IN_ONE_INSTANCE_AT_A_TIME = os.getenv(
    "LIVE_MEETING_SCALE_IN_ONE_INSTANCE_AT_A_TIME",
    "True",
).lower() == "true"

LIVE_MEETING_DRAIN_IDLE_SECONDS = int(
    os.getenv("LIVE_MEETING_DRAIN_IDLE_SECONDS", "300")
)

LIVE_MEETING_ALB_DRAIN_TIMEOUT_SECONDS = int(
    os.getenv("LIVE_MEETING_ALB_DRAIN_TIMEOUT_SECONDS", "900")
)

LIVE_MEETING_INSTANCE_HEARTBEAT_TTL_SECONDS = int(
    os.getenv("LIVE_MEETING_INSTANCE_HEARTBEAT_TTL_SECONDS", "90")
)

LIVE_MEETING_PREWARM_MINUTES = int(os.getenv("LIVE_MEETING_PREWARM_MINUTES", "90"))
LIVE_MEETING_HOST_EARLY_START_MINUTES = int(os.getenv("LIVE_MEETING_HOST_EARLY_START_MINUTES", "120"))
LIVE_MEETING_COOLDOWN_MINUTES = int(os.getenv("LIVE_MEETING_COOLDOWN_MINUTES", "60"))

LIVE_MEETING_LATE_REGISTRATION_BUFFER_PERCENT = int(
    os.getenv("LIVE_MEETING_LATE_REGISTRATION_BUFFER_PERCENT", "100")
)
LIVE_MEETING_LATE_REGISTRATION_BUFFER_MIN = int(os.getenv("LIVE_MEETING_LATE_REGISTRATION_BUFFER_MIN", "100"))

# WebSocket heartbeat settings for long-running meetings (2-3 hours)
WS_HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("WS_HEARTBEAT_INTERVAL_SECONDS", "25"))
WS_HEARTBEAT_TIMEOUT_SECONDS = int(os.getenv("WS_HEARTBEAT_TIMEOUT_SECONDS", "90"))
DISCONNECT_CLEANUP_GRACE_SECONDS = int(os.getenv("DISCONNECT_CLEANUP_GRACE_SECONDS", "90"))

# Redis presence and location TTL settings (must match or exceed heartbeat timeout)
REDIS_PRESENCE_TTL_SECONDS = int(os.getenv("REDIS_PRESENCE_TTL_SECONDS", "300"))
REDIS_LOCATION_TTL_SECONDS = int(os.getenv("REDIS_LOCATION_TTL_SECONDS", "300"))
REDIS_CONNECTION_COUNT_TTL_SECONDS = int(os.getenv("REDIS_CONNECTION_COUNT_TTL_SECONDS", "360"))
