"""Guards for local-only content commands: refuse unless the process uses this machine's
PostgreSQL database and local file storage (never production settings or a remote bucket).

The dev settings switch the default storage to S3 whenever AWS_BUCKET_NAME is set, so such
commands are run with ``AWS_BUCKET_NAME=`` (empty) to use local media.
"""

from django.conf import settings
from django.core.files.storage import FileSystemStorage, InMemoryStorage, storages
from django.db import connection

LOCAL_DATABASE_HOSTS = ("localhost", "127.0.0.1", "::1", "")  # "" = the local Unix socket
LOCAL_STORAGE_CLASSES = (FileSystemStorage, InMemoryStorage)


def local_environment_problems():
    """Why this process must not write: [] for a local PostgreSQL database and local storage."""
    problems = []
    module = getattr(settings, "SETTINGS_MODULE", "") or ""
    if module.endswith(".prod"):
        problems.append(f"the production settings module is active ({module})")
    db = connection.settings_dict
    if "postgresql" not in db.get("ENGINE", ""):
        problems.append(f"the database engine is {db.get('ENGINE')!r}, not the local PostgreSQL")
    host = (db.get("HOST") or "").strip()
    if host not in LOCAL_DATABASE_HOSTS:
        problems.append(f"the database host is {host!r}, not this machine")
    storage = storages["default"]
    if not isinstance(storage, LOCAL_STORAGE_CLASSES):
        problems.append(
            f"the default file storage is {type(storage).__module__}.{type(storage).__name__}, not local "
            "storage (with the dev settings, run with AWS_BUCKET_NAME= to use local media)"
        )
    return problems


def describe_environment():
    db = connection.settings_dict
    return (
        f"Database: {db.get('NAME')} on {db.get('HOST') or 'local socket'}:{db.get('PORT') or 'default'}; "
        f"file storage: {type(storages['default']).__name__}"
    )
