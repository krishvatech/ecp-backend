"""
✅  : Redis-based WebSocket Presence Tracking (NO DB WRITES ON CONNECT/DISCONNECT)

Moves real-time presence and online counts from database to Redis
to eliminate DB writes during WebSocket connect/disconnect storms.

Uses raw redis.Redis client (not django.core.cache) for native SET operations:
  - SADD/SMEMBERS/SCARD/SREM for user tracking
  - SETEX/GET for presence data
  - EXPIRE for TTL management

Redis Keys:
  event:{event_id}:online_users              - Set of online user IDs (no expiry)
  event:{event_id}:presence:{user_id}        - User presence data JSON (with TTL, default 300s)
  event:{event_id}:location:{user_id}        - User current location (with TTL, default 300s)
  event:{event_id}:user:{user_id}:conn_count - Multi-tab connection counter (with TTL, default 360s)

TTL: Configurable via settings (default 300-360s). Set via touch_user_online() heartbeat
for long-running meetings. Individual user presence keys expire, but full online set persists.
"""

import json
import logging
import redis
from typing import Dict, List, Set, Optional
from django.utils import timezone
from django.conf import settings

logger = logging.getLogger('events')

# Redis connection pool (reused across requests)
_redis_conn = None

# TTL for presence and location keys (seconds) - settings-based with defaults
PRESENCE_TTL = int(getattr(settings, "REDIS_PRESENCE_TTL_SECONDS", 300))
LOCATION_TTL = int(getattr(settings, "REDIS_LOCATION_TTL_SECONDS", 300))
CONNECTION_COUNT_TTL = int(getattr(settings, "REDIS_CONNECTION_COUNT_TTL_SECONDS", 360))


def _get_redis_connection():
    """
    Get or create Redis connection using raw redis client.
    Reuses connection pool for efficiency.
    """
    global _redis_conn
    if _redis_conn is None:
        try:
            redis_url = settings.REDIS_URL
            _redis_conn = redis.Redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                socket_keepalive=True,
            )
            # Test connection
            _redis_conn.ping()
            logger.info(f"[REDIS_PRESENCE] Connected to Redis at {redis_url}")
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Failed to connect to Redis: {e}")
            raise
    return _redis_conn


class RedisPresenceManager:
    """✅  : Manage WebSocket presence in Redis instead of database."""

    @staticmethod
    def _online_users_key(event_id: int) -> str:
        """Get Redis key for online users set."""
        return f"event:{event_id}:online_users"

    @staticmethod
    def _presence_key(event_id: int, user_id: int) -> str:
        """Get Redis key for user presence data."""
        return f"event:{event_id}:presence:{user_id}"

    @staticmethod
    def _location_key(event_id: int, user_id: int) -> str:
        """Get Redis key for user location."""
        return f"event:{event_id}:location:{user_id}"

    @staticmethod
    def _connection_count_key(event_id: int, user_id: int) -> str:
        """Get Redis key for user multi-tab connection counter."""
        return f"event:{event_id}:user:{user_id}:conn_count"

    @classmethod
    def add_user_online(cls, event_id: int, user_id: int, user_type: str = 'registered',
                       is_guest: bool = False) -> int:
        """
        ✅  : Add user to online set in Redis (NO DB WRITE).

        Handles multi-tab connections by tracking connection count.

        Args:
            event_id: Event ID
            user_id: User ID
            user_type: 'registered' or 'guest'
            is_guest: Whether user is a guest

        Returns:
            New online count for event
        """
        try:
            r = _get_redis_connection()

            online_key = cls._online_users_key(event_id)
            presence_key = cls._presence_key(event_id, user_id)
            conn_count_key = cls._connection_count_key(event_id, user_id)

            # ✅  : Increment connection count (multi-tab safety)
            # This ensures we don't remove user until all tabs are closed
            r.incr(conn_count_key)
            r.expire(conn_count_key, CONNECTION_COUNT_TTL)

            # ✅  : Add to online set (SADD is idempotent)
            # Note: Do not expire the full event:{event_id}:online_users set on each add,
            # individual user presence is managed per user with touch_user_online()
            r.sadd(online_key, str(user_id))

            # Store presence data with TTL
            presence_data = {
                'user_id': user_id,
                'joined_at': timezone.now().isoformat(),
                'user_type': user_type,
                'is_guest': is_guest,
            }
            r.setex(presence_key, PRESENCE_TTL, json.dumps(presence_data))

            # Get new count
            count = r.scard(online_key)
            logger.info(
                f"[REDIS_PRESENCE] add event={event_id} user={user_id} count={count}"
            )

            return count

        except Exception as e:
            logger.error(
                f"[REDIS_PRESENCE] Error adding user to online event={event_id} user={user_id}: {e}"
            )
            return -1  # Error signal

    @classmethod
    def touch_user_online(cls, event_id: int, user_id: int, location: str | None = None) -> bool:
        """
        ✅  : Refresh user presence without expiring the full online set.

        Used for heartbeat keepalive to extend user presence during long meetings.
        Updates presence timestamp and refreshes TTL without resetting the entire set.

        Args:
            event_id: Event ID
            user_id: User ID
            location: Optional location to update

        Returns:
            True if successful, False if error
        """
        try:
            r = _get_redis_connection()

            online_key = cls._online_users_key(event_id)
            presence_key = cls._presence_key(event_id, user_id)
            conn_count_key = cls._connection_count_key(event_id, user_id)

            # Ensure user is in online set (idempotent)
            r.sadd(online_key, str(user_id))

            # Refresh presence data with new timestamp
            presence_data = {
                "user_id": user_id,
                "last_seen_at": timezone.now().isoformat(),
            }
            r.setex(presence_key, PRESENCE_TTL, json.dumps(presence_data))

            # Refresh connection count TTL
            r.expire(conn_count_key, CONNECTION_COUNT_TTL)

            # Update location if provided
            if location:
                location_key = cls._location_key(event_id, user_id)
                r.setex(location_key, LOCATION_TTL, location)

            logger.debug(
                f"[REDIS_PRESENCE] touch event={event_id} user={user_id}"
            )
            return True

        except Exception as e:
            logger.error(
                f"[REDIS_PRESENCE] touch failed event={event_id} user={user_id} error={e}"
            )
            return False

    @classmethod
    def remove_user_online(cls, event_id: int, user_id: int) -> int:
        """
        ✅  : Remove user from online set in Redis (NO DB WRITE).

        Handles multi-tab connections by checking connection count.

        Args:
            event_id: Event ID
            user_id: User ID

        Returns:
            New online count for event
        """
        try:
            r = _get_redis_connection()

            online_key = cls._online_users_key(event_id)
            presence_key = cls._presence_key(event_id, user_id)
            location_key = cls._location_key(event_id, user_id)
            conn_count_key = cls._connection_count_key(event_id, user_id)

            # ✅  : Decrement connection count
            count = r.decr(conn_count_key)

            # Only remove user when all connections are gone
            if count <= 0:
                # ✅  : Remove from online set (SREM is idempotent)
                r.srem(online_key, str(user_id))

                # Clean up user-specific keys
                r.delete(presence_key)
                r.delete(location_key)
                r.delete(conn_count_key)
            else:
                # Still have open connections (multi-tab case)
                logger.debug(
                    f"[REDIS_PRESENCE] user={user_id} still has {count} connections, not removing"
                )
                r.expire(conn_count_key, CONNECTION_COUNT_TTL)

            # Get new count
            online_count = r.scard(online_key)
            logger.info(
                f"[REDIS_PRESENCE] remove event={event_id} user={user_id} count={online_count}"
            )

            return online_count

        except Exception as e:
            logger.error(
                f"[REDIS_PRESENCE] Error removing user from online event={event_id} user={user_id}: {e}"
            )
            return -1  # Error signal

    @classmethod
    def mark_connection_closed_keep_presence(cls, event_id: int, user_id: int) -> int:
        """
        Decrement this socket/tab connection immediately, but keep the user in
        online_users during disconnect grace.

        Why:
        - WebSocket disconnect should finish fast.
        - User should not disappear immediately if browser reconnects.
        - Celery cleanup will force-remove only after grace if conn_count is still 0.
        """
        try:
            r = _get_redis_connection()

            online_key = cls._online_users_key(event_id)
            presence_key = cls._presence_key(event_id, user_id)
            conn_count_key = cls._connection_count_key(event_id, user_id)

            try:
                count = int(r.decr(conn_count_key))
            except Exception:
                count = 0

            if count <= 0:
                count = 0
                r.setex(conn_count_key, CONNECTION_COUNT_TTL, "0")

            # Keep presence alive during grace window.
            r.sadd(online_key, str(user_id))
            presence_data = {
                "user_id": user_id,
                "last_seen_at": timezone.now().isoformat(),
                "disconnect_grace": True,
            }
            r.setex(presence_key, PRESENCE_TTL, json.dumps(presence_data))

            logger.info(
                "[REDIS_PRESENCE] socket closed keep-presence event=%s user=%s conn_count=%s",
                event_id,
                user_id,
                count,
            )
            return count

        except Exception as e:
            logger.error(
                "[REDIS_PRESENCE] mark_connection_closed_keep_presence failed event=%s user=%s error=%s",
                event_id,
                user_id,
                e,
            )
            return 0

    @classmethod
    def force_remove_user_online(cls, event_id: int, user_id: int) -> int:
        """
        Force-remove user after grace period only.
        Do not decrement again here; the socket count was already decremented
        at disconnect time.
        """
        try:
            r = _get_redis_connection()

            online_key = cls._online_users_key(event_id)
            presence_key = cls._presence_key(event_id, user_id)
            location_key = cls._location_key(event_id, user_id)
            conn_count_key = cls._connection_count_key(event_id, user_id)

            r.srem(online_key, str(user_id))
            r.delete(presence_key)
            r.delete(location_key)
            r.delete(conn_count_key)

            online_count = int(r.scard(online_key) or 0)

            logger.info(
                "[REDIS_PRESENCE] force remove event=%s user=%s online_count=%s",
                event_id,
                user_id,
                online_count,
            )
            return online_count

        except Exception as e:
            logger.error(
                "[REDIS_PRESENCE] force_remove_user_online failed event=%s user=%s error=%s",
                event_id,
                user_id,
                e,
            )
            return -1

    @classmethod
    def get_online_count(cls, event_id: int) -> int:
        """✅  : Get total online user count from Redis (NO DB QUERY)."""
        try:
            r = _get_redis_connection()
            online_key = cls._online_users_key(event_id)
            count = r.scard(online_key)
            return count or 0
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error getting online count event={event_id}: {e}")
            return 0

    @classmethod
    def get_online_users(cls, event_id: int) -> Set[int]:
        """✅  : Get set of online user IDs from Redis (NO DB QUERY)."""
        try:
            r = _get_redis_connection()
            online_key = cls._online_users_key(event_id)
            users = r.smembers(online_key)
            return {int(uid) for uid in (users or set())}
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error getting online users event={event_id}: {e}")
            return set()

    @classmethod
    def set_user_location(cls, event_id: int, user_id: int, location: str) -> bool:
        """
        ✅  : Set user's current location in Redis (NO DB WRITE).

        Also refreshes presence to keep user online during long meetings.

        Args:
            event_id: Event ID
            user_id: User ID
            location: Location (main_room, social_lounge, waiting_room, breakout_room, etc)

        Returns:
            True if successful, False if error
        """
        try:
            r = _get_redis_connection()
            location_key = cls._location_key(event_id, user_id)
            online_key = cls._online_users_key(event_id)

            # ✅  : Set with TTL (no DB write)
            r.setex(location_key, LOCATION_TTL, location)

            # Refresh presence: ensure user is in online set
            r.sadd(online_key, str(user_id))

            logger.debug(
                f"[REDIS_PRESENCE] location event={event_id} user={user_id} location={location}"
            )
            return True
        except Exception as e:
            logger.error(
                f"[REDIS_PRESENCE] Error setting location event={event_id} user={user_id}: {e}"
            )
            return False

    @classmethod
    def get_user_location(cls, event_id: int, user_id: int) -> Optional[str]:
        """✅  : Get user's current location from Redis (NO DB QUERY)."""
        try:
            r = _get_redis_connection()
            location_key = cls._location_key(event_id, user_id)
            location = r.get(location_key)
            return location
        except Exception as e:
            logger.error(
                f"[REDIS_PRESENCE] Error getting location event={event_id} user={user_id}: {e}"
            )
            return None

    @classmethod
    def is_user_online(cls, event_id: int, user_id: int) -> bool:
        """✅  : Check if user is currently online in Redis (NO DB QUERY)."""
        try:
            r = _get_redis_connection()
            online_key = cls._online_users_key(event_id)
            return r.sismember(online_key, str(user_id))
        except Exception as e:
            logger.error(
                f"[REDIS_PRESENCE] Error checking if online event={event_id} user={user_id}: {e}"
            )
            return False

    @classmethod
    def get_connection_count(cls, event_id: int, user_id: int) -> int:
        """✅  : Get number of active connections for user (multi-tab support)."""
        try:
            r = _get_redis_connection()
            conn_count_key = cls._connection_count_key(event_id, user_id)
            count = r.get(conn_count_key)
            return int(count) if count else 0
        except Exception as e:
            logger.error(
                f"[REDIS_PRESENCE] Error getting connection count event={event_id} user={user_id}: {e}"
            )
            return 0

    @classmethod
    def get_all_online_info(cls, event_id: int) -> List[Dict]:
        """Get info for all online users (user_id, location, presence data)."""
        try:
            r = _get_redis_connection()
            users = cls.get_online_users(event_id)
            info = []

            for user_id in users:
                presence_key = cls._presence_key(event_id, user_id)
                presence_data = r.get(presence_key)

                location = cls.get_user_location(event_id, user_id)

                if presence_data:
                    data = json.loads(presence_data)
                else:
                    data = {'user_id': user_id, 'joined_at': timezone.now().isoformat()}

                data['current_location'] = location
                info.append(data)

            return info

        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error getting all online info event={event_id}: {e}")
            return []

    @classmethod
    def clear_event_presence(cls, event_id: int) -> bool:
        """
        ✅  : Clear all presence data for an event (e.g., when event ends).

        Args:
            event_id: Event ID

        Returns:
            True if successful
        """
        try:
            r = _get_redis_connection()
            online_key = cls._online_users_key(event_id)
            users = cls.get_online_users(event_id)

            # Delete all user presence, location, and connection count keys
            for user_id in users:
                presence_key = cls._presence_key(event_id, user_id)
                location_key = cls._location_key(event_id, user_id)
                conn_count_key = cls._connection_count_key(event_id, user_id)
                r.delete(presence_key)
                r.delete(location_key)
                r.delete(conn_count_key)

            # Delete online users set
            r.delete(online_key)

            logger.info(
                f"[REDIS_PRESENCE] Cleared presence for event={event_id}, was {len(users)} users"
            )
            return True

        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error clearing presence event={event_id}: {e}")
            return False

    @classmethod
    def sync_presence_to_db(cls, event_id: int) -> Dict:
        """
        ✅  : Optional periodic task to sync Redis presence summary to database.

        Called by Celery beat (every 5-10 minutes) to update EventRegistration.is_online
        for admin/reporting purposes. NOT called on every connect/disconnect.

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

            logger.info(
                f"[REDIS_PRESENCE] Synced {online_count} online users for event={event_id} to DB"
            )

            return {
                'event_id': event_id,
                'synced_users': online_count,
                'status': 'success'
            }

        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error syncing to DB event={event_id}: {e}")
            return {
                'event_id': event_id,
                'status': 'failed',
                'error': str(e)
            }
