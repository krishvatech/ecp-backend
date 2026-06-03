"""
Redis utilities for storing chat and Q&A messages before DB persistence.
Messages are saved to Redis immediately for real-time delivery,
then persisted to DB via Celery task in the background.
"""

import json
from uuid import UUID
from django.core.cache import cache
from django.utils import timezone

REDIS_MESSAGE_TTL_SECONDS = 3600  # 1 hour - gives Celery time to persist before expiring


def _serialize_value(obj):
    """Convert Python types to JSON-serializable values."""
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    elif isinstance(obj, (UUID, timezone.datetime)):
        return str(obj)
    elif isinstance(obj, dict):
        return {k: _serialize_value(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_serialize_value(v) for v in obj]
    else:
        return str(obj)


def save_message_to_redis(event_id, message_dict):
    """
    Save chat message to Redis with TTL.

    Args:
        event_id: Event ID
        message_dict: Dict with message data (user_id, content, created_at, uuid, etc)

    Returns:
        uuid: The message UUID (for tracking)
    """
    message_uuid = str(message_dict.get('uuid'))

    # Serialize message data for JSON storage
    serialized_msg = _serialize_value(message_dict)

    # Store message data
    msg_key = f"event_chat:{event_id}:msg:{message_uuid}"
    cache.set(msg_key, json.dumps(serialized_msg), REDIS_MESSAGE_TTL_SECONDS)

    # Add to pending list
    pending_key = f"event_chat:{event_id}:pending"
    try:
        cache.append(pending_key, message_uuid)
    except AttributeError:
        # If cache backend doesn't support append, use a set-based approach
        pending_list = cache.get(pending_key, [])
        if message_uuid not in pending_list:
            pending_list.append(message_uuid)
            cache.set(pending_key, pending_list, REDIS_MESSAGE_TTL_SECONDS)

    return message_uuid


def save_question_to_redis(event_id, question_dict):
    """
    Save Q&A question to Redis with TTL.

    Args:
        event_id: Event ID
        question_dict: Dict with question data (user_id, content, created_at, uuid, etc)

    Returns:
        uuid: The question UUID (for tracking)
    """
    question_uuid = str(question_dict.get('uuid'))

    # Serialize question data
    serialized_q = _serialize_value(question_dict)

    # Store question data
    q_key = f"event_qna:{event_id}:qna:{question_uuid}"
    cache.set(q_key, json.dumps(serialized_q), REDIS_MESSAGE_TTL_SECONDS)

    # Add to pending list
    pending_key = f"event_qna:{event_id}:pending"
    try:
        cache.append(pending_key, question_uuid)
    except AttributeError:
        pending_list = cache.get(pending_key, [])
        if question_uuid not in pending_list:
            pending_list.append(question_uuid)
            cache.set(pending_key, pending_list, REDIS_MESSAGE_TTL_SECONDS)

    return question_uuid


def save_reply_to_redis(event_id, reply_dict):
    """
    Save Q&A reply to Redis with TTL.

    Args:
        event_id: Event ID
        reply_dict: Dict with reply data (user_id, content, question_id, created_at, uuid, etc)

    Returns:
        uuid: The reply UUID (for tracking)
    """
    reply_uuid = str(reply_dict.get('uuid'))

    # Serialize reply data
    serialized_r = _serialize_value(reply_dict)

    # Store reply data
    r_key = f"event_qna:{event_id}:reply:{reply_uuid}"
    cache.set(r_key, json.dumps(serialized_r), REDIS_MESSAGE_TTL_SECONDS)

    # Add to pending list
    pending_key = f"event_qna:{event_id}:pending"
    try:
        cache.append(pending_key, reply_uuid)
    except AttributeError:
        pending_list = cache.get(pending_key, [])
        if reply_uuid not in pending_list:
            pending_list.append(reply_uuid)
            cache.set(pending_key, pending_list, REDIS_MESSAGE_TTL_SECONDS)

    return reply_uuid


def get_message_from_redis(event_id, message_uuid):
    """
    Retrieve message from Redis cache.

    Returns:
        dict: Message data or None if expired/missing
    """
    msg_key = f"event_chat:{event_id}:msg:{message_uuid}"
    cached = cache.get(msg_key)
    if cached:
        try:
            return json.loads(cached)
        except (json.JSONDecodeError, TypeError):
            return cached
    return None


def get_question_from_redis(event_id, question_uuid):
    """
    Retrieve question from Redis cache.

    Returns:
        dict: Question data or None if expired/missing
    """
    q_key = f"event_qna:{event_id}:qna:{question_uuid}"
    cached = cache.get(q_key)
    if cached:
        try:
            return json.loads(cached)
        except (json.JSONDecodeError, TypeError):
            return cached
    return None


def get_reply_from_redis(event_id, reply_uuid):
    """
    Retrieve reply from Redis cache.

    Returns:
        dict: Reply data or None if expired/missing
    """
    r_key = f"event_qna:{event_id}:reply:{reply_uuid}"
    cached = cache.get(r_key)
    if cached:
        try:
            return json.loads(cached)
        except (json.JSONDecodeError, TypeError):
            return cached
    return None


def remove_from_pending(event_id, message_uuid, is_qna=False):
    """
    Remove message from pending list after DB save.
    Called after Celery task completes successfully.

    Args:
        event_id: Event ID
        message_uuid: Message UUID to remove
        is_qna: True if Q&A, False if chat
    """
    if is_qna:
        pending_key = f"event_qna:{event_id}:pending"
    else:
        pending_key = f"event_chat:{event_id}:pending"

    pending_list = cache.get(pending_key, [])
    if message_uuid in pending_list:
        pending_list.remove(message_uuid)
        cache.set(pending_key, pending_list, REDIS_MESSAGE_TTL_SECONDS)


def get_pending_messages(event_id, is_qna=False):
    """
    Get list of messages not yet saved to DB.

    Returns:
        list: UUIDs of pending messages
    """
    if is_qna:
        pending_key = f"event_qna:{event_id}:pending"
    else:
        pending_key = f"event_chat:{event_id}:pending"

    return cache.get(pending_key, [])


def delete_message_from_redis(event_id, message_uuid):
    """
    Delete message from Redis (for moderation/hiding before DB save).

    Args:
        event_id: Event ID
        message_uuid: Message UUID to delete
    """
    msg_key = f"event_chat:{event_id}:msg:{message_uuid}"
    cache.delete(msg_key)
    remove_from_pending(event_id, message_uuid, is_qna=False)


def delete_question_from_redis(event_id, question_uuid):
    """
    Delete question from Redis (for moderation/hiding before DB save).

    Args:
        event_id: Event ID
        question_uuid: Question UUID to delete
    """
    q_key = f"event_qna:{event_id}:qna:{question_uuid}"
    cache.delete(q_key)
    remove_from_pending(event_id, question_uuid, is_qna=True)


def delete_reply_from_redis(event_id, reply_uuid):
    """
    Delete reply from Redis (for moderation/hiding before DB save).

    Args:
        event_id: Event ID
        reply_uuid: Reply UUID to delete
    """
    r_key = f"event_qna:{event_id}:reply:{reply_uuid}"
    cache.delete(r_key)
    remove_from_pending(event_id, reply_uuid, is_qna=True)
