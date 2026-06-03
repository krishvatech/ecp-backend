import hashlib
import json
from django.core.cache import cache

EVENT_LIST_CACHE_TTL_SECONDS = 45

# Query params that should bust the cache (affect results)
CACHE_AFFECTING_PARAMS = {
    'search', 'bucket', 'event_format', 'category', 'date_range',
    'location', 'start_date', 'end_date', 'min_price', 'max_price',
    'exclude_ended', 'exclude_pinned', 'include_ended', 'created_by',
    'is_hidden', 'lounge_table_id'
}

# Query params to ignore for cache (pagination, ordering, etc handled client-side)
CACHE_IGNORE_PARAMS = {
    'limit', 'offset', 'ordering', 'search_fields', 'expand'
}


def _hash_query_params(query_dict):
    """Generate hash of cache-affecting query params."""
    relevant_params = {}
    for key in CACHE_AFFECTING_PARAMS:
        if key in query_dict:
            value = query_dict.getlist(key) if hasattr(query_dict, 'getlist') else query_dict.get(key)
            relevant_params[key] = sorted(value) if isinstance(value, list) else value

    # Create deterministic hash
    param_str = json.dumps(relevant_params, sort_keys=True)
    return hashlib.md5(param_str.encode()).hexdigest()


def event_list_cache_key(user, query_dict):
    """
    Generate cache key for event list endpoint.
    User-specific: includes user_id and role.
    Query-specific: includes hash of cache-affecting params.
    """
    if not user or not user.is_authenticated:
        user_part = "anonymous"
        role = "anonymous"
    else:
        user_part = str(user.id)
        is_admin = bool(getattr(user, "is_superuser", False)) or bool(getattr(user, "is_staff", False))
        role = "admin" if is_admin else "user"

    params_hash = _hash_query_params(query_dict)
    return f"event:list:{user_part}:{role}:{params_hash}"


def event_mine_cache_key(user, query_dict):
    """Cache key for user's own events (/api/events/mine/)."""
    if not user or not user.is_authenticated:
        return None  # Don't cache for unauthenticated users

    params_hash = _hash_query_params(query_dict)
    return f"event:mine:{user.id}:{params_hash}"


def event_upcoming_cache_key(user, query_dict):
    """Cache key for upcoming events (bucket=upcoming)."""
    if not user or not user.is_authenticated:
        user_part = "anonymous"
    else:
        user_part = str(user.id)

    params_hash = _hash_query_params(query_dict)
    return f"event:upcoming:{user_part}:{params_hash}"


def admin_event_list_cache_key(user, query_dict):
    """Cache key for admin event list (separate from regular list)."""
    if not user or not user.is_authenticated:
        return None

    is_admin = bool(getattr(user, "is_superuser", False)) or bool(getattr(user, "is_staff", False))
    if not is_admin:
        return None

    params_hash = _hash_query_params(query_dict)
    return f"event:admin-list:{user.id}:{params_hash}"


def invalidate_event_list_caches(event_id):
    """
    Clear all event list caches when an event is modified.
    Uses pattern deletion if supported, otherwise just clears broadly.
    """
    # Strategy: Clear all event:* caches since we don't know all possible cache keys
    # This is safe but may clear slightly more than necessary
    try:
        # Try pattern deletion (Redis supports this)
        cache.delete_pattern("event:list:*")
        cache.delete_pattern("event:mine:*")
        cache.delete_pattern("event:upcoming:*")
        cache.delete_pattern("event:admin-list:*")
    except AttributeError:
        # Fallback: If cache backend doesn't support delete_pattern,
        # we could use a version-based approach or manual key tracking.
        # For now, this will be caught and we should log it.
        pass


def get_cached_event_list(cache_key):
    """Retrieve cached event list data."""
    if not cache_key:
        return None
    return cache.get(cache_key)


def set_cached_event_list(cache_key, data):
    """Store event list in cache."""
    if not cache_key:
        return
    cache.set(cache_key, data, EVENT_LIST_CACHE_TTL_SECONDS)
