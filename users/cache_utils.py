import time

from django.core.cache import cache


USER_DETAIL_CACHE_TTL_SECONDS = 15


def request_cache_scope(request):
    try:
        return f"{request.scheme}:{request.get_host()}"
    except Exception:
        return "default"


def request_cache_query(request):
    try:
        return request.META.get("QUERY_STRING", "") or ""
    except Exception:
        return ""


def user_cache_version(user_id):
    key = f"user:{user_id}:detail-version"
    version = cache.get(key)
    if version is None:
        version = 1
        cache.set(key, version, None)
    return version


def bump_user_cache_version(user_id):
    if user_id:
        cache.set(f"user:{user_id}:detail-version", int(time.time() * 1000), None)


def user_me_cache_key(request, user_id):
    return (
        f"user:{user_id}:me:{request_cache_scope(request)}:"
        f"{request_cache_query(request)}:{user_cache_version(user_id)}"
    )


def user_detail_cache_key(request, requester_id, target_id):
    version = user_cache_version(target_id)
    scope = request_cache_scope(request)
    query = request_cache_query(request)
    return f"user:{target_id}:detail:{requester_id}:{scope}:{query}:{version}"
