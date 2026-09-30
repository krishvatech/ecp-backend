"""
Redis response cache for the Mautic-backed Marketing Hub read pages.

What is cached (identical for every Marketing user, because every Mautic read
uses the shared service account; per-user identity is only asserted on
writes):
  * analytics overview/campaigns/emails/contacts/segments responses
  * stage analytics and the dashboard responses
  * per-email stats summaries, shared by the overview and emails pages
  * Mautic reference data behind the builders and forms (see the
    ``Reference reads`` section): whole provider payloads, so every endpoint,
    search and page that uses one shares a single entry
  * list pages (contacts, segments, tags, stages, companies, points,
    templates, campaigns) via ``cached_get``, for a short TTL
Keys look like ``marketing:v<version>:<name>:<hash of query params>``.

Invalidation is by version: any write to a Marketing Hub admin endpoint bumps
``marketing:version`` (see newsletter.middleware), so every older entry becomes
unreachable at once and expires by TTL. Changes made directly in Mautic, and
sends processed in the background, are bounded by the TTL; ``?refresh=1``
(the pages' Refresh button) bumps the version and rebuilds.

Only successful responses are cached: provider errors propagate to the view,
and a dashboard with an unavailable section is rebuilt on every call.

The cache is an optimisation only: every call here swallows cache errors and
the caller falls back to Mautic. After a failure the cache is skipped for a
short cooldown so a Redis outage does not add a socket timeout to every
request.
"""
import functools
import hashlib
import logging
import time

from django.conf import settings
from django.core.cache import cache
from rest_framework import status
from rest_framework.response import Response

logger = logging.getLogger(__name__)

VERSION_KEY = "marketing:version"
CACHE_HEADER = "X-Marketing-Cache"
DEFAULT_ANALYTICS_TTL_SECONDS = 5 * 60
DEFAULT_DASHBOARD_TTL_SECONDS = 2 * 60
DEFAULT_METADATA_TTL_SECONDS = 15 * 60
DEFAULT_REFERENCE_TTL_SECONDS = 60 * 60
DEFAULT_LIST_TTL_SECONDS = 60
DEFAULT_CONTACT_LIST_TTL_SECONDS = 30
FAILURE_COOLDOWN_SECONDS = 30
REFRESH_PARAM = "refresh"

_MISSING = object()
_disabled_until = 0.0


def enabled():
    return getattr(settings, "MARKETING_RESPONSE_CACHE_ENABLED", True)


def analytics_ttl():
    return int(getattr(settings, "MARKETING_ANALYTICS_CACHE_SECONDS", DEFAULT_ANALYTICS_TTL_SECONDS))


def dashboard_ttl():
    return int(getattr(settings, "MARKETING_DASHBOARD_CACHE_SECONDS", DEFAULT_DASHBOARD_TTL_SECONDS))


def metadata_ttl():
    return int(getattr(settings, "MARKETING_METADATA_CACHE_SECONDS", DEFAULT_METADATA_TTL_SECONDS))


def reference_ttl():
    return int(getattr(settings, "MARKETING_REFERENCE_CACHE_SECONDS", DEFAULT_REFERENCE_TTL_SECONDS))


def list_ttl():
    return int(getattr(settings, "MARKETING_LIST_CACHE_SECONDS", DEFAULT_LIST_TTL_SECONDS))


def contact_list_ttl():
    return int(getattr(settings, "MARKETING_CONTACT_LIST_CACHE_SECONDS", DEFAULT_CONTACT_LIST_TTL_SECONDS))


def _available():
    return time.monotonic() >= _disabled_until


def _failed(operation, exc):
    global _disabled_until
    _disabled_until = time.monotonic() + FAILURE_COOLDOWN_SECONDS
    logger.warning(
        "Marketing cache %s failed (%s); serving from Mautic for %ss",
        operation, exc.__class__.__name__, FAILURE_COOLDOWN_SECONDS,
    )


def reset_failure_state():
    """Forget a previous failure (tests, and after an operator fixes Redis)."""
    global _disabled_until
    _disabled_until = 0.0


def _safe_get(key, default=None):
    if not _available():
        return default
    try:
        return cache.get(key, default)
    except Exception as exc:
        _failed("read", exc)
        return default


def _safe_set(key, value, timeout):
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


def invalidate():
    """Make every cached Marketing Hub response stale.

    Mautic is the source of truth and its writes are done by the time the
    ECP request returns, so one bump after the write is enough."""
    if not enabled():
        return
    try:
        cache.incr(VERSION_KEY)
    except ValueError:  # key missing: any fresh value invalidates everything
        cache.add(VERSION_KEY, time.time_ns(), timeout=None)
    except Exception as exc:
        # Never break a write because Redis is down. Entries written before the
        # outage still expire by TTL.
        logger.warning("Marketing cache invalidation failed (%s)", exc.__class__.__name__)


def _key(version, name, *parts):
    digest = hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return f"marketing:v{version}:{name}:{digest}"


def _param_parts(request):
    params = request.query_params
    return [
        f"{name}={','.join(value.strip() for value in params.getlist(name))}"
        for name in sorted(params.keys())
        if name != REFRESH_PARAM
    ]


def wants_refresh(request):
    value = str(request.query_params.get(REFRESH_PARAM, "") or "").strip().lower()
    return value in {"1", "true", "yes"}


def cached_value(name, parts, build, *, ttl):
    """Return `build()`, cached under `name` + `parts`. Errors from `build()`
    propagate and nothing is cached."""
    if not enabled():
        return build()
    version = current_version()
    if version is None:
        return build()
    key = _key(version, name, *parts)
    value = _safe_get(key, _MISSING)
    if value is not _MISSING:
        return value
    value = build()
    _safe_set(key, value, ttl)
    return value


def _request_key(request, name, *parts):
    """The key for a request (after honouring ``?refresh=1``), or None when the
    cache is off or unavailable."""
    if not enabled():
        return None
    if wants_refresh(request):
        invalidate()
    version = current_version()
    if version is None:
        return None
    return _key(version, name, *parts, *_param_parts(request))


def _hit(data):
    response = Response(data, status=status.HTTP_200_OK)
    response[CACHE_HEADER] = "HIT"
    return response


def cached_response(request, name, build, *, ttl, cacheable=None):
    """A 200 Response for `build()`'s data, served from Redis when possible.

    `cacheable(data)` may veto storing a successful but partial result.
    Provider errors raised by `build()` propagate to the view unchanged."""
    key = _request_key(request, name)
    data = _safe_get(key, _MISSING) if key else _MISSING
    if data is not _MISSING:
        return _hit(data)
    data = build()
    if key and (cacheable is None or cacheable(data)):
        _safe_set(key, data, ttl)
    response = Response(data, status=status.HTTP_200_OK)
    response[CACHE_HEADER] = "MISS"
    return response


def cached_get(name, ttl):
    """Decorate an APIView ``get`` so its 200 responses are cached.

    For views that build their Response inline. Runs after DRF's permission
    checks, keys on the URL kwargs plus query params, and never stores an
    error response. `ttl` is a function so settings are read per request."""
    def decorator(get):
        @functools.wraps(get)
        def wrapper(view, request, *args, **kwargs):
            key = _request_key(request, name, *args, *(f"{k}={v}" for k, v in sorted(kwargs.items())))
            data = _safe_get(key, _MISSING) if key else _MISSING
            if data is not _MISSING:
                return _hit(data)
            response = get(view, request, *args, **kwargs)
            if response.status_code == status.HTTP_200_OK:
                if key:
                    _safe_set(key, response.data, ttl())
                response[CACHE_HEADER] = "MISS"
            return response
        return wrapper
    return decorator


# Reference reads ------------------------------------------------------------
#
# Mautic data that builders and forms load on every open but that rarely
# changes. Each takes the caller's client so tests and identity wiring stay
# with the view. Writes made through ECP invalidate like everything else;
# changes made directly in Mautic are bounded by the TTL.


def field_type_choices(client, field_type):
    """A whole country/region/timezone/locale catalog (the region one is
    ~268 KB); callers search and page it locally."""
    return cached_value(
        "field-type-choices",
        [field_type],
        lambda: client.get_field_type_choices(field_type),
        ttl=reference_ttl(),
    )


def field_type_capabilities(client):
    return cached_value(
        "field-type-capabilities",
        [],
        client.get_field_type_capabilities,
        ttl=reference_ttl(),
    )


def themes(client):
    return cached_value("themes", [], client.list_themes, ttl=reference_ttl())


def point_action_types(client):
    return cached_value(
        "point-action-types",
        [],
        client.list_point_action_types,
        ttl=reference_ttl(),
    )


def point_trigger_event_types(client):
    return cached_value(
        "point-trigger-event-types",
        [],
        client.list_point_trigger_event_types,
        ttl=reference_ttl(),
    )


def contact_fields(client):
    return cached_value(
        "contact-fields",
        [],
        client.list_contact_fields,
        ttl=metadata_ttl(),
    )


def fields(client, field_object, *, limit):
    return cached_value(
        "fields",
        [field_object, limit],
        lambda: client.list_fields(field_object, start=0, limit=limit),
        ttl=metadata_ttl(),
    )


def categories(client, *, limit):
    return cached_value(
        "categories",
        [limit],
        lambda: client.list_categories(start=0, limit=limit),
        ttl=metadata_ttl(),
    )


def segment_filter_metadata(client, search=""):
    # Searches are typed and rarely repeat, so only the full catalog is cached.
    if search:
        return client.get_segment_filter_metadata(search)
    return cached_value(
        "segment-filter-metadata",
        [],
        client.get_segment_filter_metadata,
        ttl=metadata_ttl(),
    )


def campaign_builder_sources(client, *, limit):
    """Builder capabilities plus the segment and form pickers, as one entry."""
    return cached_value(
        "campaign-builder-sources",
        [limit],
        lambda: {
            "capabilities": client.get_campaign_builder_capabilities(),
            "segments": client.list_segments(limit=limit),
            "forms": client.list_forms(limit=limit),
        },
        ttl=metadata_ttl(),
    )
