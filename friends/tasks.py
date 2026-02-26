"""
friends/tasks.py

Daily "Suggestion Digest" notification:
- Connections: mutual friends >= 2
- Groups: friends-in-group >= 2
- Send at 9:00 AM Asia/Kolkata via Celery Beat

Creates ONE notification per user per day (skips if already created today).
"""

import logging
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from typing import Optional

from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Count, F, Q
from django.utils import timezone

from friends.models import Friendship, FriendRequest, Notification
from groups.models import Group, GroupMembership
from users.models import UserProfile


User = get_user_model()
logger = logging.getLogger(__name__)

SUGGESTION_DISPATCH_HOUR = 9
SUGGESTION_DISPATCH_WINDOW_MINUTES = 5
SUGGESTION_LOCK_TTL_SECONDS = 48 * 60 * 60


def _my_friend_ids(me_id: int) -> set[int]:
    pairs = Friendship.objects.filter(Q(user1_id=me_id) | Q(user2_id=me_id)).values_list("user1_id", "user2_id")
    out = set()
    for u1, u2 in pairs:
        out.add(u2 if u1 == me_id else u1)
    return out


def _pending_user_ids(me_id: int) -> set[int]:
    pending = FriendRequest.objects.filter(
        status=FriendRequest.PENDING
    ).filter(
        Q(from_user_id=me_id) | Q(to_user_id=me_id)
    ).values_list("from_user_id", "to_user_id")

    out = set()
    for a, b in pending:
        out.add(a)
        out.add(b)
    out.discard(me_id)
    return out


def count_connection_suggestions(me_id: int, mutual_threshold: int = 2) -> int:
    friend_ids = _my_friend_ids(me_id)
    if not friend_ids:
        return 0

    pending_ids = _pending_user_ids(me_id)

    qs = User.objects.filter(
        Q(friends_as_user1__user2_id__in=friend_ids) |
        Q(friends_as_user2__user1_id__in=friend_ids)
    ).exclude(
        id=me_id
    ).exclude(
        id__in=friend_ids
    ).exclude(
        id__in=pending_ids
    ).distinct()

    qs = qs.annotate(
        mutuals_via_u1=Count(
            "friends_as_user1",
            filter=Q(friends_as_user1__user2_id__in=friend_ids),
            distinct=True,
        ),
        mutuals_via_u2=Count(
            "friends_as_user2",
            filter=Q(friends_as_user2__user1_id__in=friend_ids),
            distinct=True,
        ),
    ).annotate(
        mutuals=F("mutuals_via_u1") + F("mutuals_via_u2")
    ).filter(mutuals__gte=mutual_threshold)

    return qs.count()


def count_group_suggestions(me_id: int, friends_in_group_threshold: int = 2) -> int:
    friend_ids = _my_friend_ids(me_id)
    if not friend_ids:
        return 0

    my_group_ids = GroupMembership.objects.filter(user_id=me_id).values_list("group_id", flat=True)

    qs = Group.objects.filter(
        visibility=Group.VISIBILITY_PUBLIC,
        parent__isnull=True,
    ).exclude(
        id__in=my_group_ids
    ).annotate(
        mutuals=Count(
            "memberships",
            filter=Q(
                memberships__status=GroupMembership.STATUS_ACTIVE,
                memberships__user_id__in=friend_ids,
            ),
            distinct=True,
        )
    ).filter(mutuals__gte=friends_in_group_threshold)

    return qs.count()


def _get_timezone_or_default(tz_name: str) -> Optional[ZoneInfo]:
    try:
        return ZoneInfo(tz_name)
    except ZoneInfoNotFoundError:
        fallback = settings.TIME_ZONE or "Asia/Kolkata"
        try:
            logger.warning("Invalid timezone '%s', falling back to '%s'", tz_name, fallback)
            return ZoneInfo(fallback)
        except ZoneInfoNotFoundError:
            logger.warning("Invalid timezone '%s' and fallback '%s'", tz_name, fallback)
            return None


def _local_day_bounds_utc(local_date, tzinfo: ZoneInfo) -> tuple[datetime, datetime]:
    start_local = datetime.combine(local_date, time.min).replace(tzinfo=tzinfo)
    start_utc = start_local.astimezone(timezone.utc)
    end_utc = start_utc + timedelta(days=1)
    return start_utc, end_utc


@shared_task
def dispatch_suggestion_digest_local_9am(
    mutual_threshold: int = 2,
    friends_in_group_threshold: int = 2,
) -> dict:
    now_utc = timezone.now()
    timezones = (
        UserProfile.objects.filter(user__is_active=True)
        .values_list("timezone", flat=True)
        .distinct()
    )

    due_timezones = []
    invalid_timezones = []
    for tz_name in timezones:
        if not tz_name:
            invalid_timezones.append(tz_name)
            continue
        tzinfo = _get_timezone_or_default(tz_name)
        if tzinfo is None:
            invalid_timezones.append(tz_name)
            continue
        local_now = now_utc.astimezone(tzinfo)
        if (
            local_now.hour == SUGGESTION_DISPATCH_HOUR
            and 0 <= local_now.minute < SUGGESTION_DISPATCH_WINDOW_MINUTES
        ):
            due_timezones.append(tz_name)

    for tz_name in due_timezones:
        send_suggestion_digest_for_timezone.delay(
            tz_name,
            mutual_threshold=mutual_threshold,
            friends_in_group_threshold=friends_in_group_threshold,
        )

    if invalid_timezones:
        logger.warning("Skipped invalid timezones for suggestion digest: %s", invalid_timezones)

    return {
        "dispatched": len(due_timezones),
        "invalid_timezones": invalid_timezones,
        "checked_at": now_utc.isoformat(),
    }


@shared_task
def send_suggestion_digest_for_timezone(
    tz_name: str,
    mutual_threshold: int = 2,
    friends_in_group_threshold: int = 2,
) -> dict:
    tzinfo = _get_timezone_or_default(tz_name)
    if tzinfo is None:
        return {"created": 0, "skipped_invalid_tz": True, "timezone": tz_name}

    now_local = timezone.now().astimezone(tzinfo)
    local_date = now_local.date()
    start_utc, end_utc = _local_day_bounds_utc(local_date, tzinfo)

    created = 0
    skipped_already_sent = 0
    skipped_empty = 0
    skipped_locked = 0

    users_qs = (
        User.objects.filter(is_active=True, profile__timezone=tz_name)
        .select_related("profile")
        .only("id", "profile__timezone")
    )

    for u in users_qs.iterator(chunk_size=200):
        lock_key = f"suggestion_digest:{u.id}:{local_date}:{tz_name}"
        if not cache.add(lock_key, "1", timeout=SUGGESTION_LOCK_TTL_SECONDS):
            skipped_locked += 1
            continue

        already = Notification.objects.filter(
            recipient_id=u.id,
            kind="suggestion_digest",
            created_at__gte=start_utc,
            created_at__lt=end_utc,
        ).exists()
        if already:
            skipped_already_sent += 1
            continue

        conn_count = count_connection_suggestions(u.id, mutual_threshold=mutual_threshold)
        group_count = count_group_suggestions(u.id, friends_in_group_threshold=friends_in_group_threshold)

        if conn_count == 0 and group_count == 0:
            skipped_empty += 1
            continue

        parts = []
        if conn_count:
            parts.append(f"{conn_count} new connection suggestions")
        if group_count:
            parts.append(f"{group_count} groups your friends are active in today")

        Notification.objects.create(
            recipient_id=u.id,
            actor=None,
            kind="suggestion_digest",
            title="Daily suggestions",
            description=" - ".join(parts),
            state="info",
            data={
                "connection_count": conn_count,
                "group_count": group_count,
                "mutual_threshold": mutual_threshold,
                "friends_in_group_threshold": friends_in_group_threshold,
                "date": str(local_date),
                "timezone": tz_name,
            },
        )
        created += 1

    return {
        "created": created,
        "skipped_already_sent": skipped_already_sent,
        "skipped_empty": skipped_empty,
        "skipped_locked": skipped_locked,
        "date": str(local_date),
        "timezone": tz_name,
    }


@shared_task
def send_suggestion_digest_daily(mutual_threshold: int = 2, friends_in_group_threshold: int = 2) -> dict:
    """
    Runs daily from Celery Beat.
    Creates Notification(kind='suggestion_digest') for each user if counts > 0.
    """
    today = timezone.localdate()

    created = 0
    skipped_already_sent = 0
    skipped_empty = 0

    users_qs = User.objects.filter(is_active=True).only("id")

    for u in users_qs.iterator(chunk_size=200):
        already = Notification.objects.filter(
            recipient_id=u.id,
            kind="suggestion_digest",
            created_at__date=today,
        ).exists()
        if already:
            skipped_already_sent += 1
            continue

        conn_count = count_connection_suggestions(u.id, mutual_threshold=mutual_threshold)
        group_count = count_group_suggestions(u.id, friends_in_group_threshold=friends_in_group_threshold)

        if conn_count == 0 and group_count == 0:
            skipped_empty += 1
            continue

        parts = []
        if conn_count:
            parts.append(f"{conn_count} new connection suggestions")
        if group_count:
            parts.append(f"{group_count} groups your friends are active in today")

        Notification.objects.create(
            recipient_id=u.id,
            actor=None,
            kind="suggestion_digest",
            title="Daily suggestions",
            description=" • ".join(parts),
            state="info",
            data={
                "connection_count": conn_count,
                "group_count": group_count,
                "mutual_threshold": mutual_threshold,
                "friends_in_group_threshold": friends_in_group_threshold,
                "date": str(today),
            },
        )
        created += 1

    return {
        "created": created,
        "skipped_already_sent": skipped_already_sent,
        "skipped_empty": skipped_empty,
        "date": str(today),
    }
@shared_task
def expire_stale_friend_requests() -> dict:
    """
    Finds PENDING friend requests older than 30 days and EXPERIES (cancels) them.
    Runs daily via Celery Beat.
    """
    days_limit = int(getattr(settings, "FRIEND_REQUEST_WINDOW_DAYS", 30))
    cutoff = timezone.now() - timedelta(days=days_limit)
    
    stale_requests = FriendRequest.objects.filter(
        status=FriendRequest.PENDING,
        created_at__lt=cutoff
    )
    
    count = stale_requests.count()
    expired_ids = []
    
    # We use iterator to handle potentially large numbers of requests
    for fr in stale_requests.iterator():
        fr.cancel()
        expired_ids.append(fr.id)
        
    logger.info(f"Expired {count} stale friend requests.")
    
    return {
        "expired_count": count,
        "expired_ids": expired_ids[:100],  # Return first 100 for logging
        "cutoff": cutoff.isoformat()
    }
