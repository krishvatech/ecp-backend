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
        logger.info(f"[Signal] Message created: id={instance.id}, conversation_id={instance.conversation_id}, body_len={len(instance.body)}")

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
    else:
        # Broadcast edit event to WebSocket subscribers (if body was changed)
        if instance.is_edited or instance.is_deleted:
            event_type = "message.deleted" if instance.is_deleted else "message.edited"
            logger.info(f"[Signal] Message {event_type}: id={instance.id}, conversation_id={instance.conversation_id}")
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

        logger.info(f"[Broadcast] Broadcasting {event_type} to group {group_name}, msg_id={message.id}")

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

        logger.info(f"[Broadcast] Calling group_send to {group_name} with event type {event_type_underscore}")
        async_to_sync(channel_layer.group_send)(group_name, payload)
        logger.info(f"[Broadcast] ✅ Successfully broadcasted {event_type} to {group_name}: msg_id={message.id}")

    except Exception as e:
        logger.exception(f"[Broadcast] ❌ Failed to broadcast message event: {e}")
