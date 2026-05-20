"""
Settings module used ONLY for generating Django migration files locally.

Why this exists:
- `makemigrations` connects to the database to validate migration history.
- If your local Postgres isn't running / has inconsistent history, it can block
  generating new migration files.

This module switches the DB + cache + channel layer to local in-process
backends so `makemigrations` can run without external services.
"""

from .dev import *  # noqa

from pathlib import Path


# Use a local sqlite DB so migration generation does not depend on Postgres.
_MIGRATIONS_DB_PATH = Path("/tmp/ecp_makemigrations.sqlite3")
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(_MIGRATIONS_DB_PATH),
    }
}

# Keep everything in-process; avoids Redis requirements during management cmds.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "ecp-makemigrations",
    }
}

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    }
}

