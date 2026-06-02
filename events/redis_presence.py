"""
Phase 7: Redis-based WebSocket Presence Tracking (NO DB WRITES ON CONNECT/DISCONNECT)

Moves real-time presence and online counts from database to Redis
to eliminate DB writes during WebSocket connect/disconnect storms.

✅ PHASE 7: Uses django_redis.get_redis_connection() for proper Redis set operations
✅ Eliminates ALL database writes on connect/disconnect
✅ Presence stored in Redis only (TTL: 60-120 seconds)
✅ Durable state (joined_live) remains in DB
✅ Optional Celery task syncs summary periodically

Redis Keys:
  event:{event_id}:online_users         - Set of online user IDs (SADD/SMEMBERS/SCARD)
  event:{event_id}:presence:{user_id}   - User presence data (JSON)
  event:{event_id}:location:{user_id}   - User current location (TTL)

TTL: 60-120 seconds (auto-cleanup if disconnect missed)
"""

import json
import logging
from typing import Dict, List, Set, Optional
from django.utils import timezone
from django.conf import settings

# ✅ PHASE 7: Use django_redis for proper Redis client access
try:
    from django_redis import get_redis_connection
    redis_conn = get_redis_connection("default")
except ImportError:
    from django.core.cache import cache
    redis_conn = None

logger = logging.getLogger('events')

# Redis key prefixes
ONLINE_USERS_KEY_PREFIX = "event:{event_id}:online_users"
PRESENCE_KEY_PREFIX = "event:{event_id}:presence:{user_id}"
LOCATION_KEY_PREFIX = "event:{event_id}:location:{user_id}"

# TTL for presence keys (60-120 seconds, auto-cleanup stale entries)
PRESENCE_TTL = 120
LOCATION_TTL = 120


class RedisPresenceManager:
    """Manage WebSocket presence in Redis instead of database."""

    @staticmethod
    def _online_users_key(event_id: int) -> str:
        """Get Redis key for online users set."""
        return ONLINE_USERS_KEY_PREFIX.format(event_id=event_id)

    @staticmethod
    def _presence_key(event_id: int, user_id: int) -> str:
        """Get Redis key for user presence data."""
        return PRESENCE_KEY_PREFIX.format(event_id=event_id, user_id=user_id)

    @staticmethod
    def _location_key(event_id: int, user_id: int) -> str:
        """Get Redis key for user location."""
        return LOCATION_KEY_PREFIX.format(event_id=event_id, user_id=user_id)

    @classmethod
    def _get_redis(cls):
        """Get Redis connection, with fallback to cache."""
        if redis_conn:
            return redis_conn
        # Fallback for non-redis cache backends
        from django.core.cache import cache
        return cache

    @classmethod
    def add_user_online(cls, event_id: int, user_id: int, user_type: str = 'registered',
                       is_guest: bool = False) -> int:
        """
        ✅ PHASE 7: Add user to online set in Redis (NO DB WRITE).

        Args:
            event_id: Event ID
            user_id: User ID
            user_type: 'registered' or 'guest'
            is_guest: Whether user is a guest

        Returns:
            New online count for event
        """
        try:
            online_key = cls._online_users_key(event_id)
            presence_key = cls._presence_key(event_id, user_id)

            r = cls._get_redis()

            # ✅ PHASE 7: Use Redis SADD + EXPIRE (atomic set operation)
            if hasattr(r, 'sadd'):
                r.sadd(online_key, str(user_id))
                r.expire(online_key, PRESENCE_TTL)
            else:
                # Fallback for non-Redis cache
                from django.core.cache import cache
                cache.sadd(online_key, str(user_id))
                cache.expire(online_key, PRESENCE_TTL)

            # Store presence data with TTL
            presence_data = {
                'user_id': user_id,
                'joined_at': timezone.now().isoformat(),
                'user_type': user_type,
                'is_guest': is_guest,
            }

            if hasattr(r, 'setex'):
                r.setex(presence_key, PRESENCE_TTL, json.dumps(presence_data))
            else:
                from django.core.cache import cache
                cache.set(presence_key, json.dumps(presence_data), timeout=PRESENCE_TTL)

            # Get new count
            count = cls.get_online_count(event_id)
            logger.info(f"[REDIS_PRESENCE] User {user_id} joined event {event_id}, online: {count}")

            return count

        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error adding user to online: {e}")
            return -1  # Error signal

    @classmethod
    def remove_user_online(cls, event_id: int, user_id: int) -> int:
        """
        ✅ PHASE 7: Remove user from online set in Redis (NO DB WRITE).

        Args:
            event_id: Event ID
            user_id: User ID

        Returns:
            New online count for event
        """
        try:
            online_key = cls._online_users_key(event_id)
            presence_key = cls._presence_key(event_id, user_id)
            location_key = cls._location_key(event_id, user_id)

            r = cls._get_redis()

            # ✅ PHASE 7: Use Redis SREM (atomic remove operation)
            if hasattr(r, 'srem'):
                r.srem(online_key, str(user_id))
                r.delete(presence_key)
                r.delete(location_key)
            else:
                from django.core.cache import cache
                cache.srem(online_key, str(user_id))
                cache.delete(presence_key)
                cache.delete(location_key)

            # Get new count
            count = cls.get_online_count(event_id)
            logger.info(f"[REDIS_PRESENCE] User {user_id} left event {event_id}, online: {count}")

            return count

        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error removing user from online: {e}")
            return -1  # Error signal

    @classmethod
    def get_online_count(cls, event_id: int) -> int:
        """✅ PHASE 7: Get total online user count from Redis (NO DB QUERY)."""
        try:
            online_key = cls._online_users_key(event_id)
            r = cls._get_redis()

            if hasattr(r, 'scard'):
                count = r.scard(online_key)
            else:
                from django.core.cache import cache
                count = cache.card(online_key)

            return count or 0
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error getting online count: {e}")
            return 0

    @classmethod
    def get_online_users(cls, event_id: int) -> Set[int]:
        """✅ PHASE 7: Get set of online user IDs from Redis (NO DB QUERY)."""
        try:
            online_key = cls._online_users_key(event_id)
            r = cls._get_redis()

            if hasattr(r, 'smembers'):
                users = r.smembers(online_key)
                return {int(uid) for uid in (users or set())}
            else:
                from django.core.cache import cache
                users = cache.smembers(online_key)
                return {int(uid) for uid in (users or set())}
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error getting online users: {e}")
            return set()

    @classmethod
    def set_user_location(cls, event_id: int, user_id: int, location: str) -> bool:
        """
        ✅ PHASE 7: Set user's current location in Redis (NO DB WRITE).

        Args:
            event_id: Event ID
            user_id: User ID
            location: Location (main_room, social_lounge, waiting_room, breakout_room, etc)

        Returns:
            True if successful, False if error
        """
        try:
            location_key = cls._location_key(event_id, user_id)
            r = cls._get_redis()

            if hasattr(r, 'setex'):
                r.setex(location_key, LOCATION_TTL, location)
            else:
                from django.core.cache import cache
                cache.set(location_key, location, timeout=LOCATION_TTL)

            logger.debug(f"[REDIS_PRESENCE] Set location for user {user_id}: {location}")
            return True
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error setting location: {e}")
            return False

    @classmethod
    def get_user_location(cls, event_id: int, user_id: int) -> Optional[str]:
        """✅ PHASE 7: Get user's current location from Redis (NO DB QUERY)."""
        try:
            location_key = cls._location_key(event_id, user_id)
            r = cls._get_redis()

            if hasattr(r, 'get'):
                location = r.get(location_key)
                return location.decode('utf-8') if location else None
            else:
                from django.core.cache import cache
                return cache.get(location_key)
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error getting location: {e}")
            return None

    @classmethod
    def is_user_online(cls, event_id: int, user_id: int) -> bool:
        """✅ PHASE 7: Check if user is currently online in Redis (NO DB QUERY)."""
        try:
            online_key = cls._online_users_key(event_id)
            r = cls._get_redis()

            if hasattr(r, 'sismember'):
                return r.sismember(online_key, str(user_id))
            else:
                from django.core.cache import cache
                return cache.sismember(online_key, str(user_id))
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error checking if online: {e}")
            return False

    @classmethod
    def get_all_online_info(cls, event_id: int) -> List[Dict]:
        """Get info for all online users (user_id, location, presence data)."""
        try:
            users = cls.get_online_users(event_id)
            info = []

            for user_id in users:
                presence_key = cls._presence_key(event_id, user_id)
                presence_data = cache.get(presence_key)

                location = cls.get_user_location(event_id, user_id)

                if presence_data:
                    data = json.loads(presence_data)
                else:
                    data = {'user_id': user_id, 'joined_at': timezone.now().isoformat()}

                data['current_location'] = location
                info.append(data)

            return info

        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error getting all online info: {e}")
            return []

    @classmethod
    def clear_event_presence(cls, event_id: int) -> bool:
        """
        Clear all presence data for an event (e.g., when event ends).

        Args:
            event_id: Event ID

        Returns:
            True if successful
        """
        try:
            online_key = cls._online_users_key(event_id)
            users = cls.get_online_users(event_id)

            # Delete all user presence and location keys
            for user_id in users:
                presence_key = cls._presence_key(event_id, user_id)
                location_key = cls._location_key(event_id, user_id)
                cache.delete(presence_key)
                cache.delete(location_key)

            # Delete online users set
            cache.delete(online_key)

            logger.info(f"[REDIS_PRESENCE] Cleared presence for event {event_id}, was {len(users)} users")
            return True

        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error clearing presence: {e}")
            return False

    @classmethod
    def sync_presence_to_db(cls, event_id: int) -> Dict:
        """
        Periodic task to sync Redis presence summary to database.

        Called by Celery beat to update EventRegistration.is_online
        for admin/reporting purposes.

        Returns:
            Dict with sync stats
        """
        try:
            from events.models import Event, EventRegistration

            online_users = cls.get_online_users(event_id)
            online_count = len(online_users)

            # Update event idle status
            if online_count == 0:
                Event.objects.filter(
                    id=event_id,
                    is_live=True,
                    idle_started_at__isnull=True,
                ).update(idle_started_at=timezone.now())
            else:
                Event.objects.filter(
                    id=event_id,
                    is_live=True,
                    idle_started_at__isnull=False,
                ).update(idle_started_at=None)

            # Batch update registrations
            # Set is_online=True for users in Redis, False for others
            EventRegistration.objects.filter(
                event_id=event_id,
                user_id__in=online_users
            ).update(is_online=True)

            EventRegistration.objects.filter(
                event_id=event_id
            ).exclude(
                user_id__in=online_users
            ).update(is_online=False)

            logger.info(f"[REDIS_PRESENCE] Synced {online_count} online users for event {event_id} to DB")

            return {
                'event_id': event_id,
                'synced_users': online_count,
                'status': 'success'
            }

        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error syncing to DB: {e}")
            return {
                'event_id': event_id,
                'status': 'failed',
                'error': str(e)
            }
