"""
Package initializer for the events & community platform backend.

The Celery application is imported here so that shared tasks use
`ecp_backend.celery_app` by default, avoiding duplicate worker setups.
"""
from .celery import app as celery_app  # noqa: F401

__all__ = ["celery_app"]