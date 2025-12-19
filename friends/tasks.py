"""
friends/tasks.py

Daily "Suggestion Digest" notification:
- Connections: mutual friends >= 2
- Groups: friends-in-group >= 2
- Send at 9:00 AM Asia/Kolkata via Celery Beat

Creates ONE notification per user per day (skips if already created today).
"""

from celery import shared_task
from django.contrib.auth import get_user_model
from django.db.models import Count, F, Q
from django.utils import timezone

from friends.models import Friendship, FriendRequest, Notification
from groups.models import Group, GroupMembership


User = get_user_model()


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
