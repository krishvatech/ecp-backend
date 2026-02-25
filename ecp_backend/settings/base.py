"""
Base settings for the events & community platform backend.

This module defines shared settings across development and production
configurations.  Most values can be overridden via environment
variables defined in `.env`.
"""

import os
from .base import *  # noqa
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv
import logging
from celery.schedules import crontab

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "%(levelname)s %(name)s: %(message)s"
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
    },
    "loggers": {
        # Root logger: everything falls back here
        "": {
            "handlers": ["console"],
            "level": "INFO",  # or "DEBUG" if you want extra detail
        },

        # Users app logs -> console
        "users": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "users.esco_client": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "users.serializers": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "users.views": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        # Events app logging
        "events": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "events.views": {
            "handlers": ["console"],
            "level": "DEBUG",  # ✅ Enable DEBUG to see mood API request details
            "propagate": False,
        },
        "events.consumers": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "events.utils": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

# Root of the project directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(os.path.join(BASE_DIR, ".env"))

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-insecure")
DEBUG = os.getenv("DJANGO_DEBUG", "True") == "True"

DJANGO_ALLOWED_HOSTS = os.getenv(
    "DJANGO_ALLOWED_HOSTS",
    "localhost,127.0.0.1,colligatus.com,www.colligatus.com,63.180.39.182",
)

DATA_UPLOAD_MAX_NUMBER_FIELDS = 10_000
DATA_UPLOAD_MAX_MEMORY_SIZE = 104857600  # 100 MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 104857600  # 100 MB
WAGTAIL_SITE_NAME = "Events & Community - IMAA Connect - CMS"
WAGTAILADMIN_BASE_URL = os.getenv("WAGTAILADMIN_BASE_URL", "http://localhost:8000")
ALLOWED_HOSTS = [h.strip() for h in DJANGO_ALLOWED_HOSTS.split(",") if h.strip()]
EMAIL_BACKEND = os.getenv("EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend")
EMAIL_HOST = os.getenv("EMAIL_HOST", "")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True") == "True"
EMAIL_USE_SSL = os.getenv("EMAIL_USE_SSL", "False") == "True"
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", EMAIL_HOST_USER or "no-reply@example.com")
AGORA_APP_ID = os.getenv("AGORA_APP_ID", "")
AGORA_APP_CERTIFICATE = os.getenv("AGORA_APP_CERTIFICATE", "")
AGORA_TOKEN_EXPIRE_SECS = 7200
# AWS S3 Configuration (load credentials only)
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_STORAGE_BUCKET_NAME = os.getenv("AWS_BUCKET_NAME")
AWS_S3_REGION_NAME = os.getenv("AWS_REGION_NAME")

# Cognito settings
COGNITO_REGION = os.getenv("COGNITO_REGION", "")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID", "")
COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID", "")
COGNITO_STAFF_GROUP = os.getenv("COGNITO_STAFF_GROUP", "staff")
COGNITO_DOMAIN = os.getenv("COGNITO_DOMAIN", "")
COGNITO_SALEOR_CLIENT_ID = os.getenv("COGNITO_SALEOR_CLIENT_ID", "")
COGNITO_SALEOR_REDIRECT_URI = os.getenv("COGNITO_SALEOR_REDIRECT_URI", "")
COGNITO_SALEOR_SCOPES = os.getenv("COGNITO_SALEOR_SCOPES", "openid email profile").split()
SALEOR_SSO_PROMPT = os.getenv("SALEOR_SSO_PROMPT", "none")


AWS_S3_FILE_OVERWRITE = False
AWS_DEFAULT_ACL = None  # let bucket policy handle permissions
AWS_S3_OBJECT_PARAMETERS = {
    "CacheControl": "max-age=86400",
}

# Didit For Identity Verifications
DIDIT_API_KEY = os.getenv("DIDIT_API_KEY", "")
DIDIT_WORKFLOW_ID_KYC = os.getenv("DIDIT_WORKFLOW_ID_KYC", "")
DIDIT_WORKFLOW_ID_NAME_CHANGE = os.getenv("DIDIT_WORKFLOW_ID_NAME_CHANGE", "")
DIDIT_WEBHOOK_SECRET = os.getenv("DIDIT_WEBHOOK_SECRET", "")


# Google Cloud Storage Configuration
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")

# A frontend URL to build the reset link (your React/Next.js page)
FRONTEND_RESET_PASSWORD_URL = os.getenv(
    "FRONTEND_RESET_PASSWORD_URL",
    "http://localhost:3000/reset-password"  # e.g. https://app.example.com/reset-password
)

LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID", "")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET", "")
LINKEDIN_REDIRECT_URI = os.getenv("LINKEDIN_REDIRECT_URI", "")
LINKEDIN_SCOPES = os.getenv("LINKEDIN_SCOPES", "openid profile email").split()
# Google OAuth settings
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "")
GOOGLE_SCOPES = os.getenv(
    "GOOGLE_SCOPES",
    "openid email profile"
).split()
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],   # optional project-level templates/
        "APP_DIRS": True,                   # looks inside each app’s templates/
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Third-party apps
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "rest_framework.authtoken",
    "corsheaders",
    "channels",
    "django_celery_beat",
    "storages",

    # Local apps
    "users",
    "community",
    "events",
    "common",
    "orders",
    "realtime",
    "messaging",
    "interactions",
    "content",
    "activity_feed",
    'groups',
    'friends',
    'engagements',
    "moderation",
    
    "drf_spectacular",
    "drf_spectacular_sidecar",

    "wagtail.contrib.forms",
    "wagtail.contrib.redirects",
    "wagtail.embeds",
    "wagtail.sites",
    "wagtail.users",
    "wagtail.snippets",
    "wagtail.documents",
    "wagtail.images",
    "wagtail.search",
    "wagtail.admin",
    "wagtail",

    "modelcluster",
    "taggit",

    "cms",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",  # must be first for CORS
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "users.middleware.SuspendedUserMiddleware",  # Block suspended users from write operations
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "users.middleware.LastActivityMiddleware",
    "wagtail.contrib.redirects.middleware.RedirectMiddleware",
    "users.middleware.WagtailPlatformAdminOnlyMiddleware",
]

ROOT_URLCONF = "ecp_backend.urls"
ASGI_APPLICATION = "ecp_backend.asgi.application"
WSGI_APPLICATION = None  # Channels-based; no WSGI application needed

_DB_CONN_MAX_AGE = 600 if DEBUG else int(os.getenv("DB_CONN_MAX_AGE", "600"))

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "ecp"),
        "USER": os.getenv("POSTGRES_USER", "ecp"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", "ecp_password"),
        "HOST": os.getenv("POSTGRES_HOST", "localhost"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": _DB_CONN_MAX_AGE,
        "CONN_HEALTH_CHECKS": True,           # validates stale pooled conns
        "OPTIONS": {
            "connect_timeout": 5,    # fail fast instead of hanging
            "options": "-c statement_timeout=30000"  # 30 second query timeout
        },
    }
}

# Redis configuration used for cache, channel layers, and Celery
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Moderation settings
MODERATION_AUTO_REVIEW_THRESHOLD = int(os.getenv("MODERATION_AUTO_REVIEW_THRESHOLD", "3"))

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
        "OPTIONS": {
            "socket_connect_timeout": 5,
            "socket_timeout": 5,
            "socket_keepalive": True,
        },
        "KEY_PREFIX": "ecp",
        "TIMEOUT": 300,  # 5 minute default timeout
    }
}

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {"hosts": [REDIS_URL]},
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
        "OPTIONS": {
            # only compare with email (ignore username), or tweak the list to your needs
            "user_attributes": ("email",),
            # raise threshold (default is 0.7). Higher = less strict
            "max_similarity": 0.8,
        },
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Kolkata"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# Google Cloud Storage Configuration
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
GS_CREDENTIALS = os.getenv("GCS_CREDENTIALS")

# File storage backend selection
if AWS_STORAGE_BUCKET_NAME:
    # Use AWS S3 for media files
    STORAGES = {
        "default": {"BACKEND": "storages.backends.s3boto3.S3Boto3Storage"},
        # keep whatever you already use for staticfiles; whitenoise is common:
        "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
    }
    DEFAULT_FILE_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"
    AWS_S3_CUSTOM_DOMAIN = f"{AWS_STORAGE_BUCKET_NAME}.s3.{AWS_S3_REGION_NAME}.amazonaws.com"
    MEDIA_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/"
    AWS_S3_FILE_OVERWRITE = False
    AWS_DEFAULT_ACL = None
    
elif GCS_BUCKET_NAME:
    # Use Google Cloud Storage for media files
    DEFAULT_FILE_STORAGE = "storages.backends.gcloud.GoogleCloudStorage"
    GS_BUCKET_NAME = GCS_BUCKET_NAME
    MEDIA_URL = f"https://storage.googleapis.com/{GCS_BUCKET_NAME}/"
    
else:
    # Fallback to local file system storage
    DEFAULT_FILE_STORAGE = "django.core.files.storage.FileSystemStorage"
    MEDIA_URL = "/media/"
    MEDIA_ROOT = BASE_DIR / "media"

# Django REST Framework configuration
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "users.cognito_auth.CognitoJWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": os.getenv("DRF_THROTTLE_ANON", "10/min"),
        "user": os.getenv("DRF_THROTTLE_USER", "100/min"),
        "mood": os.getenv("DRF_THROTTLE_MOOD", "30/min"),
    },
    
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
 
    
    "DATETIME_INPUT_FORMATS": [
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",      # 2025-09-13T10:47:00+0530 / +05:30
        "%Y-%m-%dT%H:%M:%S.%f%z",   # 2025-09-13T10:47:00.123+05:30
        "%Y-%m-%dT%H:%M:%S.%fZ",    # 2025-09-13T05:10:47.007Z  <-- what you sent
    ]
    
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Events & Community Platform API",
    "DESCRIPTION": "Django + DRF endpoints for auth, users, community, events, etc.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,  # we’ll expose schema via a separate route
    "SERVE_PERMISSIONS": ["rest_framework.permissions.AllowAny"],
    # Add JWT “Authorize” button in Swagger
    "COMPONENT_SPLIT_REQUEST": True,
    "SECURITY": [{"bearerAuth": []}],
    "COMPONENTS": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        }
    },
}


CSRF_TRUSTED_ORIGINS = [
    o.strip()
    for o in os.getenv("CSRF_TRUSTED_ORIGINS", "").split(",")
    if o.strip()
] + [
    "https://colligatus.com",
    "https://www.colligatus.com",
]


SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# CORS configuration
CORS_ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()
]

# --- Cookies & CSRF 
SESSION_COOKIE_NAME = "ecp_sessionid"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = False        
SESSION_COOKIE_SAMESITE = "Lax"      

CSRF_COOKIE_NAME = "csrftoken"
CSRF_COOKIE_HTTPONLY = False        
CSRF_COOKIE_SECURE = False    

CORS_ALLOW_CREDENTIALS = True
DIDIT_CALLBACK_URL = os.getenv("DIDIT_CALLBACK_URL", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173/")
AUTH_HOME_URL = os.getenv("AUTH_HOME_URL", "/dashboard/")
LOGIN_REDIRECT_URL = AUTH_HOME_URL   
LOGIN_URL = "/login/" 

# Simple JWT configuration; token lifetimes read from environment
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=int(os.getenv("SIMPLE_JWT_ACCESS_LIFETIME_MIN", "15"))),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=int(os.getenv("SIMPLE_JWT_REFRESH_LIFETIME_DAYS", "30"))),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
}

# ============================================================================
# PERFORMANCE OPTIMIZATION SETTINGS
# ============================================================================

# Request timeout settings to prevent hanging
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))  # 30 seconds

# Database connection pooling
# DEBUG mode now uses 600s timeout instead of 0 for better performance with concurrent requests
DATABASE_CONNECT_TIMEOUT = 10
DATABASE_STATEMENT_TIMEOUT = 30000  # 30 seconds

# Celery task timeout to prevent infinite tasks
CELERY_TASK_TIME_LIMIT = 300  # 5 minutes hard limit
CELERY_TASK_SOFT_TIME_LIMIT = 240  # 4 minutes soft limit (allows graceful shutdown)

# Redis connection timeout
REDIS_SOCKET_CONNECT_TIMEOUT = 5
REDIS_SOCKET_TIMEOUT = 5

# Celery configuration
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
CELERY_TIMEZONE = TIME_ZONE
CELERY_BEAT_SCHEDULE = {}

# OPTIMIZATION: Reduced frequency for 100+ concurrent user scalability
CELERY_BEAT_SCHEDULE.update({
    "dispatch_suggestion_digest_local_9am": {
        "task": "friends.tasks.dispatch_suggestion_digest_local_9am",
        "schedule": crontab(minute="*/5"),  # Reduced from every 1 minute to every 5 minutes
    }
})

CELERY_BEAT_SCHEDULE.update({
    "enforce_event_end_conditions": {
        "task": "events.tasks.enforce_event_end_conditions",
        "schedule": crontab(minute="*/5"),  # Reduced from every 1 minute to every 5 minutes
    }
})

# ============================================================================
# MEMORY & CONNECTION MANAGEMENT (100+ Concurrent Users)
# ============================================================================

# Celery configuration for resource management
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000  # Restart worker every 1000 tasks to free memory
CELERY_WORKER_PREFETCH_MULTIPLIER = 1  # Process one task at a time (not 4x the concurrent limit)
CELERY_TASK_TIME_LIMIT = 300  # 5 minute hard limit per task
CELERY_TASK_SOFT_TIME_LIMIT = 240  # 4 minute soft limit (graceful shutdown)

# Django ORM connection management
# Close stale connections after each request
from django.db import connections

def close_old_connections(sender, **kwargs):
    """Close database connections that have been idle."""
    for conn in connections.all():
        conn.close_if_unusable_or_obsolete()

from django.core.signals import request_finished
request_finished.connect(close_old_connections)

# Memory management
import gc
gc.set_debug(0)  # Disable debug (it's expensive)

# Security headers and cookie defaults
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SESSION_COOKIE_SECURE = False  # Should be True in production
CSRF_COOKIE_SECURE = False     # Should be True in production

SALEOR_DASHBOARD_URL = os.getenv("SALEOR_DASHBOARD_URL", "http://127.0.0.1:9001/")
SALEOR_API_URL = os.getenv("SALEOR_API_URL", "http://localhost:8001/graphql/")
SALEOR_APP_TOKEN = os.getenv("SALEOR_APP_TOKEN", "")

# Email Invite Limits
INVITE_EMAILS_MAX_PER_REQUEST = int(os.getenv("INVITE_EMAILS_MAX_PER_REQUEST", "20"))
INVITE_EMAILS_MAX_PER_DAY = int(os.getenv("INVITE_EMAILS_MAX_PER_DAY", "100"))
INVITE_EMAIL_TOKEN_MAX_AGE_SECONDS = int(os.getenv("INVITE_EMAIL_TOKEN_MAX_AGE_SECONDS", str(30 * 24 * 3600)))
