"""
Content app package for the events & community platform backend.

This package provides a simple resource hub where post‑event materials
(files, external links or videos) can be uploaded and browsed.  It
implements the ``Resource`` model, serializers, views and URL
configuration.  When new resources are created and published the app
emits an activity feed entry via Celery; see ``signals.py``.
"""

default_app_config = "content.apps.ContentConfig"
