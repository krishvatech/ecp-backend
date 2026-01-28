# ecp_backend/settings/dev.py
from .base import *  # noqa
import os


DEBUG = True
ALLOWED_HOSTS = ALLOWED_HOSTS or ["*"]
CORS_ALLOW_ALL_ORIGINS = True

# ---- FORCE S3 IN DEV IF BUCKET+REGION ARE PRESENT ----
# (Do this unconditionally to rule out any later overrides.)
if AWS_STORAGE_BUCKET_NAME and AWS_S3_REGION_NAME:
    STORAGES = {
        "default": {"BACKEND": "storages.backends.s3boto3.S3Boto3Storage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
    DEFAULT_FILE_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"

    # region-aware S3 domain
    AWS_S3_CUSTOM_DOMAIN = (
        os.getenv("AWS_S3_CUSTOM_DOMAIN")
        or f"{AWS_STORAGE_BUCKET_NAME}.s3.{AWS_S3_REGION_NAME}.amazonaws.com"
    )
    MEDIA_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/"

    # sane defaults
    AWS_S3_FILE_OVERWRITE = False
    AWS_DEFAULT_ACL = None
    AWS_QUERYSTRING_AUTH = False
else:
    # fallback to local only when bucket/region not set
    STORAGES = {
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
    MEDIA_URL = "/media/"
    MEDIA_ROOT = BASE_DIR / "media"
    
PREVIEW_MEDIA_URL = "/media-previews/"
PREVIEW_MEDIA_ROOT = BASE_DIR / "media_previews"

