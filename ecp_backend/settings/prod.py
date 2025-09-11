"""
Production settings for the events & community platform.

Extends the base settings by disabling debug mode, enforcing secure
cookies, and enabling HTTP Strict Transport Security.
"""
from .base import *  # noqa

DEBUG = False

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True

SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True