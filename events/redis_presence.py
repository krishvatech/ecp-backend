"""
Phase 6: Redis-based WebSocket Presence Tracking

Moves real-time presence and online counts from database to Redis
to eliminate DB writes during WebSocket connect/disconnect storms.

Redis Keys:
  event:{event_id}:online_users         - Set of online user IDs
  event:{event_id}:presence:{user_id}   - User presence data (JSON)
  event:{event_id}:location:{user_id}   - User current location (TTL)

TTL: 60-120 seconds (auto-cleanup if disconnect missed)
"""

import json
import logging
from typing import Dict, List, Set, Optional
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings

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
    def add_user_online(cls, event_id: int, user_id: int, user_type: str = 'registered',
                       is_guest: bool = False) -> int:
        """
        Add user to online set.

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

            # Add user to online set
            cache.sadd(online_key, str(user_id))
            cache.expire(online_key, PRESENCE_TTL)

            # Store presence data with TTL
            presence_data = {
                'user_id': user_id,
                'joined_at': timezone.now().isoformat(),
                'user_type': user_type,
                'is_guest': is_guest,
            }
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
        Remove user from online set.

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

            # Remove from online set
            cache.srem(online_key, str(user_id))

            # Delete presence data
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
        """Get total online user count for event."""
        try:
            online_key = cls._online_users_key(event_id)
            count = cache.card(online_key)  # Redis SCARD command
            return count or 0
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error getting online count: {e}")
            return 0

    @classmethod
    def get_online_users(cls, event_id: int) -> Set[int]:
        """Get set of online user IDs for event."""
        try:
            online_key = cls._online_users_key(event_id)
            users = cache.smembers(online_key)  # Redis SMEMBERS command
            return {int(uid) for uid in (users or set())}
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error getting online users: {e}")
            return set()

    @classmethod
    def set_user_location(cls, event_id: int, user_id: int, location: str) -> bool:
        """
        Set user's current location.

        Args:
            event_id: Event ID
            user_id: User ID
            location: Location (main_room, social_lounge, waiting_room, breakout_room, etc)

        Returns:
            True if successful, False if error
        """
        try:
            location_key = cls._location_key(event_id, user_id)
            cache.set(location_key, location, timeout=LOCATION_TTL)
            logger.debug(f"[REDIS_PRESENCE] Set location for user {user_id}: {location}")
            return True
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error setting location: {e}")
            return False

    @classmethod
    def get_user_location(cls, event_id: int, user_id: int) -> Optional[str]:
        """Get user's current location from Redis."""
        try:
            location_key = cls._location_key(event_id, user_id)
            location = cache.get(location_key)
            return location
        except Exception as e:
            logger.error(f"[REDIS_PRESENCE] Error getting location: {e}")
            return None

    @classmethod
    def is_user_online(cls, event_id: int, user_id: int) -> bool:
        """Check if user is currently online."""
        try:
            online_key = cls._online_users_key(event_id)
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
