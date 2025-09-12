"""
Development settings for the events & community platform.

Extends the base settings by enabling debugging and allowing all hosts.  Do
not use these settings in production.
"""
from .base import *  # noqa
import os

# Development toggles
DEBUG = True
ALLOWED_HOSTS = ALLOWED_HOSTS or ["*"]
