import os
import base64
import requests
import logging
import hashlib
import json
from functools import wraps
from django.core.cache import cache

logger = logging.getLogger(__name__)

RTK_API_BASE = os.getenv("RTK_API_BASE", "https://api.realtime.cloudflare.com/v2")
# RTK_ORG_ID + RTK_ORG_API_KEY: the RTK org credentials (short hex key from RTK dashboard)
RTK_ORG_ID = os.getenv("RTK_ORG_ID", "")
RTK_ORG_API_KEY = os.getenv("RTK_ORG_API_KEY", "")
# RTK_AUTH_HEADER: pre-encoded "Basic base64(org_id:api_key)" — used as fallback
RTK_AUTH_HEADER = os.getenv("RTK_AUTH_HEADER", "")
RTK_PRESET_HOST = os.getenv("RTK_PRESET_NAME_HOST", os.getenv("RTK_PRESET_NAME", "group_call_host"))
RTK_PRESET_PARTICIPANT = os.getenv("RTK_PRESET_NAME_MEMBER", "group_call_participant")

def _rtk_headers():
    """HTTP headers for RTK REST API (Basic auth: org_id:api_key)."""
    if RTK_ORG_ID and RTK_ORG_API_KEY:
        credentials = f"{RTK_ORG_ID}:{RTK_ORG_API_KEY}"
        auth = "Basic " + base64.b64encode(credentials.encode()).decode()
        logger.error(f"[RTK_DEBUG] Using ORG_ID={RTK_ORG_ID[:8]}... KEY={RTK_ORG_API_KEY[:6]}... auth={auth[:40]}...")
    elif RTK_AUTH_HEADER:
        auth = RTK_AUTH_HEADER
        logger.error(f"[RTK_DEBUG] Using RTK_AUTH_HEADER={RTK_AUTH_HEADER[:40]}...")
    else:
        logger.error(f"[RTK_DEBUG] NO CREDENTIALS FOUND — ORG_ID={repr(RTK_ORG_ID)} AUTH_HEADER={repr(RTK_AUTH_HEADER)}")
        raise RuntimeError(
            "RTK credentials not configured. Set RTK_ORG_ID + RTK_ORG_API_KEY in .env"
        )
    return {
        "Authorization": auth,
        "Content-Type": "application/json",
    }

def create_rtk_meeting(title):
    """Utility to create a RTK meeting and return the meeting ID."""
    payload = {
        "title": title,
        "record_on_start": False,
    }
    try:
        resp = requests.post(f"{RTK_API_BASE}/meetings", headers=_rtk_headers(), json=payload, timeout=30)
        if not resp.ok:
            print(f"RTK ERROR: Create Meeting {resp.status_code} - {resp.text}")
            logger.error(f"RTK ERROR: Create Meeting {resp.status_code} - {resp.text}")
        resp.raise_for_status()
        return resp.json().get("data", {}).get("id")
    except Exception as e:
        logger.error(f"Failed to create RTK meeting: {e}")
        print(f"RTK EXCEPTION (Create Meeting): {e}")
        return None

def add_rtk_participant(meeting_id, user_id, name, preset_name):
    """
    Add a participant to a RTK meeting.
    Returns: (auth_token, error_message)
    """
    url = f"{RTK_API_BASE}/meetings/{meeting_id}/participants"
    payload = {
        "name": name,
        "preset_name": preset_name,
        "custom_participant_id": str(user_id),
    }
    try:
        resp = requests.post(url, headers=_rtk_headers(), json=payload, timeout=30)
        if resp.status_code == 201:
            data = resp.json().get("data", {})
            token = data.get("token")
            logger.info(f"[RTK] Successfully added participant {user_id} to meeting {meeting_id}")
            return token, None
        else:
            error_msg = f"RTK API Error: {resp.status_code} - {resp.text}"
            logger.error(f"RTK add participant failed: {error_msg}")
            print(f"RTK ERROR: Add Participant {error_msg}")
            return None, error_msg
    except Exception as e:
        logger.error(f"RTK add participant exception: {e}")
        print(f"RTK EXCEPTION: {e}")
        return None, str(e)


# ============================================================
# =================== WebSocket Helpers ======================
# ============================================================
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

def send_speed_networking_message(event_id, msg_type, data):
    """
    Broadcast a message to all users in the event.
    """
    try:
        channel_layer = get_channel_layer()
        group_name = f"event_{event_id}"

        # We send a message with 'type' matching the consumer method we want to trigger
        # The consumer method then calls send_json to the client.
        # To map 'speed_networking.session_started' to a method name, Channels replaces '.' with '_'
        # So we need a handler called 'speed_networking_session_started' in the consumer.

        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": msg_type,
                "data": data
            }
        )
    except Exception as e:
        logger.error(f"[BROADCAST] Failed to send {msg_type} message to event_{event_id}: {e}")
        # Don't re-raise - allow the request to continue even if broadcast fails

def send_speed_networking_user_message(user_id, msg_type, data):
    """
    Send a message to a specific user (across all their active connections).
    """
    try:
        channel_layer = get_channel_layer()
        group_name = f"user_{user_id}"
        logger.info(f"[SEND_USER_MSG] Sending '{msg_type}' to group '{group_name}' with data: {data}")

        try:
            async_to_sync(channel_layer.group_send)(
                group_name,
                {
                    "type": msg_type,
                    "data": data
                }
            )
            logger.info(f"[SEND_USER_MSG] ✅ Message sent successfully to {group_name}")
        except Exception as e:
            logger.error(f"[SEND_USER_MSG] ❌ Failed to send message to {group_name}: {e}")
            # Don't re-raise - allow the request to continue even if WebSocket message fails
    except Exception as e:
        logger.error(f"[SEND_USER_MSG] ❌ Outer exception for user {user_id}: {e}")

def send_admission_status_changed(user_id, admission_status):
    """
    ✅ NEW: Notify a user that their admission status has changed.

    This is used to update the frontend in real-time when:
    - Host admits user: "waiting" → "admitted" (button changes "Join Waiting Room" to "Join Live")
    - Host rejects user: "waiting" → "rejected" (button disabled/hidden)

    Endpoint call: send_admission_status_changed(user_id, "admitted")
    Frontend receives: type="admission_status_changed", data={"admission_status": "admitted"}
    """
    send_speed_networking_user_message(user_id, "admission.status_changed", {
        "admission_status": admission_status
    })


# ============================================================
# =================== CACHING UTILITIES ======================
# ============================================================

def get_user_profile_cache_key(user_id, session_id=None):
    """Generate cache key for user profile."""
    if session_id:
        return f"user_profile:{user_id}:session:{session_id}"
    return f"user_profile:{user_id}"


def get_candidates_cache_key(session_id, candidate_ids_hash):
    """Generate cache key for candidate profiles batch."""
    return f"candidates:{session_id}:{candidate_ids_hash}"


def hash_candidate_ids(candidate_ids):
    """Create hash of candidate IDs list for cache key."""
    ids_str = ",".join(map(str, sorted(set(candidate_ids))))
    return hashlib.md5(ids_str.encode()).hexdigest()[:8]


def cache_user_profile(timeout=300):
    """
    Decorator to cache user profile building results.

    Caches for 5 minutes (300 seconds) by default.
    Avoid calling the expensive _build_user_profile_from_skills multiple times.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(user, session=None, queue_entry=None):
            # Generate cache key
            cache_key = get_user_profile_cache_key(user.id, session.id if session else None)

            # Try to get from cache
            cached_profile = cache.get(cache_key)
            if cached_profile is not None:
                logger.debug(f"[CACHE HIT] User profile for user_id={user.id}")
                return cached_profile

            # Not in cache, compute it
            logger.debug(f"[CACHE MISS] Computing profile for user_id={user.id}")
            profile = func(user, session=session, queue_entry=queue_entry)

            # Store in cache
            cache.set(cache_key, profile, timeout)
            return profile

        return wrapper
    return decorator


def invalidate_user_profile_cache(user_id, session_id=None):
    """Invalidate cached user profile when user data changes."""
    cache_key = get_user_profile_cache_key(user_id, session_id)
    cache.delete(cache_key)
    logger.debug(f"[CACHE INVALIDATE] Deleted cache for user_id={user_id}")


def cache_matching_scores(timeout=120):
    """
    Decorator to cache matching score calculations.

    Cache for 2 minutes (120 seconds).
    Useful for find_best_matches when same users are matched repeatedly.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, user, candidate_pool, top_n=5):
            # Create cache key from user ID and candidate IDs
            user_id = user.get('user_id')
            candidate_ids = [c.get('user_id') for c in candidate_pool]
            ids_hash = hash_candidate_ids(candidate_ids)
            cache_key = f"match_scores:{user_id}:{ids_hash}:top{top_n}"

            # Try cache
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"[CACHE HIT] Match scores for user_id={user_id}, top_n={top_n}")
                return cached_result

            # Compute matches
            logger.debug(f"[CACHE MISS] Computing match scores for user_id={user_id}")
            result = func(self, user, candidate_pool, top_n=top_n)

            # Cache result
            cache.set(cache_key, result, timeout)
            return result

        return wrapper
    return decorator
