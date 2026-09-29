"""
Redis response cache for the public Blog reader (``/api/blogs/``).

What is cached (published content only, identical for every reader):
  * list pages   -> ``blogs:v<version>:list:<hash of host + page/page_size/category/tag>``
  * post details -> ``blogs:v<version>:detail:<hash of host + slug>``
Search results are not cached (unbounded key space, low reuse). Admin
endpoints are never cached.

Invalidation is by version: every key embeds ``blogs:version`` and any Blog
write bumps it (see blogs.signals and the WordPress sync), so all older entries
become unreachable at once and expire by TTL. The TTL also bounds staleness for
data we do not watch (author name/avatar) and must stay well below the S3
signed-URL lifetime (1 h by default), because payloads contain media URLs.

The cache is an optimisation only: every call here swallows cache errors and
the caller falls back to the database. After a failure the cache is skipped
for a short cooldown so a Redis outage does not add a socket timeout to every
request.
"""
import hashlib
import logging
import time

from django.conf import settings
from django.core.cache import cache
from django.db import transaction

logger = logging.getLogger(__name__)

VERSION_KEY = "blogs:version"
DEFAULT_TTL_SECONDS = 5 * 60
FAILURE_COOLDOWN_SECONDS = 30

_MISSING = object()
_disabled_until = 0.0


def enabled():
    return getattr(settings, "BLOGS_RESPONSE_CACHE_ENABLED", True)


def ttl():
    return int(getattr(settings, "BLOGS_RESPONSE_CACHE_SECONDS", DEFAULT_TTL_SECONDS))


def _available():
    return time.monotonic() >= _disabled_until


def _failed(operation, exc):
    global _disabled_until
    _disabled_until = time.monotonic() + FAILURE_COOLDOWN_SECONDS
    logger.warning(
        "Blog cache %s failed (%s); serving from the database for %ss",
        operation, exc.__class__.__name__, FAILURE_COOLDOWN_SECONDS,
    )


def reset_failure_state():
    """Forget a previous failure (tests, and after an operator fixes Redis)."""
    global _disabled_until
    _disabled_until = 0.0


def safe_get(key, default=None):
    if not _available():
        return default
    try:
        return cache.get(key, default)
    except Exception as exc:
        _failed("read", exc)
        return default


def safe_set(key, value, timeout):
    if not _available():
        return
    try:
        cache.set(key, value, timeout)
    except Exception as exc:
        _failed("write", exc)


def current_version():
    """The live version, or None when the cache cannot be used."""
    if not _available():
        return None
    try:
        version = cache.get(VERSION_KEY)
        if version is None:
            # Start from a clock value, not 1: if the key is evicted, a restart
            # at 1 could make entries written under an old version live again.
            cache.add(VERSION_KEY, time.time_ns(), timeout=None)
            version = cache.get(VERSION_KEY)
        return version
    except Exception as exc:
        _failed("version read", exc)
        return None


def _bump():
    try:
        cache.incr(VERSION_KEY)
    except ValueError:  # key missing: any fresh value invalidates everything
        cache.add(VERSION_KEY, time.time_ns(), timeout=None)
    except Exception as exc:
        # Never break a write because Redis is down. Entries written before the
        # outage still expire by TTL.
        logger.warning("Blog cache invalidation failed (%s)", exc.__class__.__name__)


def invalidate():
    """Make every cached Blog response stale.

    Bumps now and again after the surrounding transaction commits: the second
    bump drops anything a concurrent reader cached from pre-commit data."""
    _bump()
    transaction.on_commit(_bump)


def _key(version, kind, *parts):
    digest = hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return f"blogs:v{version}:{kind}:{digest}"


LIST_PARAMS = ("page", "page_size", "category", "tag")


def list_key(request, version):
    """Key for a reader list request, or None when it must not be cached."""
    params = request.query_params
    if (params.get("search") or "").strip():
        return None
    # Pagination links are absolute, so the host is part of the response.
    values = [request.get_host()] + [f"{name}={(params.get(name) or '').strip()}" for name in LIST_PARAMS]
    return _key(version, "list", *values)


def detail_key(request, version, slug):
    return _key(version, "detail", request.get_host(), slug)


def cached_response_data(key_func, build):
    """Return (data, hit). `build()` returns response data to cache, or None
    for a response that must not be cached (it is then built on every call)."""
    if not enabled():
        return build(), False
    version = current_version()
    key = key_func(version) if version is not None else None
    if key is None:
        return build(), False
    data = safe_get(key, _MISSING)
    if data is not _MISSING:
        return data, True
    data = build()
    if data is not None:
        safe_set(key, data, ttl())
    return data, False
