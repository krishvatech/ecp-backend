"""Cleanup helpers for breakout-room chat.

Breakout rooms reuse the same LoungeTable rows during an event. Without
clearing their room conversations, messages from an earlier breakout round can
show up when the host starts another breakout round with the same room.
"""

import logging

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)


def soft_delete_breakout_room_chat(event_id: int) -> int:
    """
    Hide chat messages that belong only to breakout-room conversations.

    This does NOT touch:
    - event/public chat conversations
    - private/direct messages
    - group chat
    - social lounge table chat
    - Q&A/questions/replies

    We soft-delete instead of hard-delete so message rows remain available for
    database-level troubleshooting, while normal chat APIs stop returning them
    because MessageViewSet already filters is_deleted=False.
    """
    from messaging.models import Message

    if not event_id:
        return 0

    now = timezone.now()
    with transaction.atomic():
        updated = (
            Message.objects.filter(
                conversation__lounge_table__event_id=event_id,
                conversation__lounge_table__category="BREAKOUT",
                is_deleted=False,
            )
            .update(is_deleted=True, deleted_at=now)
        )

    if updated:
        logger.info(
            "[BREAKOUT_CHAT_CLEANUP] Soft-deleted %s breakout chat message(s) for event=%s",
            updated,
            event_id,
        )
    else:
        logger.info(
            "[BREAKOUT_CHAT_CLEANUP] No breakout chat messages to clear for event=%s",
            event_id,
        )
    return updated
