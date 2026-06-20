"""
Signal handlers for the messaging app.

Increment analytics metrics when new messages are created.  Only
dispatch on creation to avoid counting edits or status updates.
Also broadcasts message events to WebSocket groups for real-time updates.
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Message
import logging
import json
from django.utils import timezone

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Message)
def on_message_created(sender, instance: Message, created: bool, **kwargs) -> None:
    """
    On creation: increment metric AND broadcast to WebSocket.
    On update: broadcast edit event to WebSocket.
    """
    if created:
        logger.debug(f"[Signal] Message created: id={instance.id}, conversation_id={instance.conversation_id}, body_len={len(instance.body)}")

        try:
            from analytics.tasks import increment_metric  # local import

            # Messages are not associated with an event or community
            increment_metric.delay(
                metric_name="message_count",
                org_id=None,
                event_id=None,
                value=1,
            )
        except Exception:
            pass

        # Broadcast new message to WebSocket subscribers
        _broadcast_message_event(instance, event_type="message.created")

        # For direct messages, also notify the receiver's already-open live event
        # socket so unread badges update instantly without adding HTTP polling.
        _broadcast_direct_message_unread(instance)
    else:
        # Broadcast edit event to WebSocket subscribers (if body was changed)
        if instance.is_edited or instance.is_deleted:
            event_type = "message.deleted" if instance.is_deleted else "message.edited"
            logger.debug(f"[Signal] Message {event_type}: id={instance.id}, conversation_id={instance.conversation_id}")
            _broadcast_message_event(instance, event_type=event_type)


def _broadcast_message_event(message: Message, event_type: str = "message.created") -> None:
    """
    Broadcast a message event to the appropriate WebSocket group using Redis Channel Layer.

    Groups: messaging_conversation_{conversation_id} (one safe group per conversation)
    Events: message.created, message.edited, message.deleted

    All conversation types (DM, event, lounge, group) use the same shared group.
    This ensures all connected WebSocket clients for a conversation receive real-time updates.
    """
    from .serializers import MessageSerializer
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer

    try:
        conversation = message.conversation
        group_name = f"messaging_conversation_{conversation.id}"

        logger.debug(f"[Broadcast] Broadcasting {event_type} to group {group_name}, msg_id={message.id}")

        # Serialize message
        try:
            serializer = MessageSerializer(message)
            message_data = serializer.data
            logger.debug(f"[Broadcast] Serialized message successfully")
        except Exception as e:
            logger.error(f"[Broadcast] Failed to serialize message: {e}", exc_info=True)
            raise

        # Get channel layer
        channel_layer = get_channel_layer()
        if channel_layer is None:
            logger.error(f"[Broadcast] Channel layer is None! Redis may not be configured.")
            return

        # Broadcast via Django Channels (use underscore format for type field)
        event_type_underscore = event_type.replace(".", "_")
        payload = {
            "type": event_type_underscore,
            "message": message_data,
        }

        logger.debug(f"[Broadcast] Calling group_send to {group_name} with event type {event_type_underscore}")
        async_to_sync(channel_layer.group_send)(group_name, payload)
        logger.debug(f"[Broadcast] Successfully broadcasted {event_type} to {group_name}: msg_id={message.id}")

    except Exception as e:
        logger.exception(f"[Broadcast] ❌ Failed to broadcast message event: {e}")


def _broadcast_direct_message_unread(message: Message) -> None:
    """
    Send a lightweight unread notification for 1:1 direct messages.

    This intentionally reuses the receiver's user_{id} event websocket group
    that LiveMeetingPage already keeps open. It avoids new polling and avoids
    serializing/sending the full message payload to every live participant.
    """
    try:
        conversation = message.conversation

        # Only 1:1 DM conversations have user1/user2 and no event/group/lounge.
        if (
            not conversation.user1_id
            or not conversation.user2_id
            or conversation.group_id
            or conversation.event_id
            or getattr(conversation, "lounge_table_id", None)
        ):
            return

        sender_id = message.sender_id
        if not sender_id:
            return

        if sender_id == conversation.user1_id:
            recipient_id = conversation.user2_id
        elif sender_id == conversation.user2_id:
            recipient_id = conversation.user1_id
        else:
            return

        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer

        channel_layer = get_channel_layer()
        if channel_layer is None:
            return

        payload = {
            "type": "private_message_unread",
            "conversation_id": conversation.id,
            "message_id": message.id,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "event_id": message.event_id,
            "created_at": message.created_at.isoformat() if message.created_at else timezone.now().isoformat(),
        }

        async_to_sync(channel_layer.group_send)(f"user_{recipient_id}", payload)
    except Exception:
        logger.exception(
            "[Broadcast] Failed to send direct-message unread notification for msg_id=%s",
            getattr(message, "id", None),
        )
