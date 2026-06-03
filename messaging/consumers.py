"""
Channels consumers for messaging.

Two consumers handle WebSocket connections:

1. DirectMessageConsumer (legacy, for 1-to-1 conversations)
   - Path: ws/messaging/<conversation_id>/
   - Handles 1-to-1 direct messages

2. ConversationConsumer (new, for event/lounge/group chats)
   - Path: ws/messaging/conversations/<conversation_id>/
   - Handles event chats, lounge room chats, and group chats
   - Bridges REST API messages to WebSocket subscribers
   - Receives broadcast from signal handler when messages are created via REST API
"""
from __future__ import annotations

from typing import Any
import logging

from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async

from .models import Conversation, Message
from .serializers import MessageSerializer

logger = logging.getLogger(__name__)


class DirectMessageConsumer(AsyncJsonWebsocketConsumer):
    """Realtime WebSocket consumer for 1‑to‑1 conversations."""

    async def connect(self) -> None:
        conv_id = self.scope["url_route"]["kwargs"]["conversation_id"]
        self.conversation_id = int(conv_id)
        self.group_name = f"conversation_{self.conversation_id}"
        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            logger.warning("WS[DM] rejected: anonymous user conv_id=%s", self.conversation_id)
            await self.close(code=4401)
            return
        if not await self._is_participant(user.id, self.conversation_id):
            logger.warning("WS[DM] rejected: user %s not participant in conv %s", user.id, self.conversation_id)
            await self.close(code=4403)
            return
        await self.accept()
        await self.channel_layer.group_add(self.group_name, self.channel_name)

    async def disconnect(self, code: int) -> None:
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content: dict[str, Any], **kwargs: Any) -> None:
        event_type = content.get("type")
        if event_type == "message.send":
            await self._handle_send(content)
        elif event_type == "message.edit":
            await self._handle_edit(content)
        elif event_type == "message.delete":
            await self._handle_delete(content)

    async def _handle_send(self, content: dict[str, Any]) -> None:
        user = self.scope["user"]
        body = content.get("body") or ""
        attachments = content.get("attachments") or []
        if not body and not attachments:
            return
        message = await database_sync_to_async(self._create_message)(
            user.id, self.conversation_id, body, attachments
        )
        serializer = MessageSerializer(message)
        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "message.created",
                "message": serializer.data,
            },
        )

    async def message_created(self, event: dict[str, Any]) -> None:
        await self.send_json({"type": "message.created", "message": event["message"]})

    async def message_edited(self, event: dict[str, Any]) -> None:
        await self.send_json({"type": "message.edited", "message": event["message"]})

    async def message_deleted(self, event: dict[str, Any]) -> None:
        await self.send_json({"type": "message.deleted", "message": event["message"]})

    async def _handle_edit(self, content: dict[str, Any]) -> None:
        user = self.scope["user"]
        message_id = content.get("message_id")
        new_body = content.get("body") or ""
        if not message_id or not new_body.strip():
            return
        message = await database_sync_to_async(self._update_message)(
            user.id, message_id, self.conversation_id, new_body
        )
        if message:
            serializer = MessageSerializer(message)
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "message.edited",
                    "message": serializer.data,
                },
            )

    async def _handle_delete(self, content: dict[str, Any]) -> None:
        user = self.scope["user"]
        message_id = content.get("message_id")
        if not message_id:
            return
        message = await database_sync_to_async(self._delete_message)(
            user.id, message_id, self.conversation_id
        )
        if message:
            serializer = MessageSerializer(message)
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "message.deleted",
                    "message": serializer.data,
                },
            )

    # ---------- sync helper methods ----------
    def _create_message(self, user_id: int, conv_id: int, body: str, attachments: list) -> Message:
        msg = Message.objects.create(
            conversation_id=conv_id,
            sender_id=user_id,
            body=body,
            attachments=attachments,
        )
        return msg

    def _update_message(self, user_id: int, message_id: int, conv_id: int, new_body: str) -> Message | None:
        try:
            msg = Message.objects.get(id=message_id, conversation_id=conv_id)
            # Only sender can edit their own message
            if msg.sender_id != user_id:
                return None
            from django.utils import timezone
            msg.body = new_body
            msg.is_edited = True
            msg.edited_at = timezone.now()
            msg.save(update_fields=["body", "is_edited", "edited_at"])
            return msg
        except Message.DoesNotExist:
            return None

    def _delete_message(self, user_id: int, message_id: int, conv_id: int) -> Message | None:
        try:
            msg = Message.objects.get(id=message_id, conversation_id=conv_id)
            # Only sender can delete their own message
            if msg.sender_id != user_id:
                return None
            from django.utils import timezone
            msg.is_deleted = True
            msg.deleted_at = timezone.now()
            msg.body = "This message was deleted"
            msg.save()
            return msg
        except Message.DoesNotExist:
            return None

    async def _is_participant(self, user_id: int, conv_id: int) -> bool:
        try:
            conv = await database_sync_to_async(Conversation.objects.get)(pk=conv_id)
        except Conversation.DoesNotExist:
            return False
        return user_id in (conv.user1_id, conv.user2_id)


class ConversationConsumer(AsyncJsonWebsocketConsumer):
    """
    Real-time WebSocket consumer for all conversations (DM, event, lounge, group).

    Connects to shared Redis channel layer group: messaging_conversation_{conversation_id}
    Receives broadcast events from REST API via signal handlers:
    - message.created: new message
    - message.edited: message edited
    - message.deleted: message deleted

    Path: ws/messaging/conversations/<conversation_id>/
    Authentication: JWT token via JWTAuthMiddleware
    """

    async def connect(self) -> None:
        conv_id = self.scope["url_route"]["kwargs"]["conversation_id"]
        self.conversation_id = int(conv_id)

        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            logger.warning("WS[Conv] rejected: anonymous user conv_id=%s", self.conversation_id)
            await self.close(code=4401)
            return

        # Verify user has access to this conversation
        if not await self._user_can_view(user.id, self.conversation_id):
            logger.warning(
                "WS[Conv] rejected: user %s not member of conv %s",
                user.id,
                self.conversation_id,
            )
            await self.close(code=4403)
            return

        # Shared group name for all conversation types
        self.group_name = f"messaging_conversation_{self.conversation_id}"

        await self.accept()

        # Subscribe to Redis channel for this conversation
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        logger.info(
            f"[WS Conv] User {user.id} connected to {self.group_name} for conv {self.conversation_id}"
        )

    async def disconnect(self, code: int) -> None:
        if hasattr(self, "group_name") and self.group_name:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def message_created(self, event: dict[str, Any]) -> None:
        """Handle broadcast from signal when message is created via REST API."""
        await self.send_json({"type": "message.created", "message": event["message"]})

    async def message_edited(self, event: dict[str, Any]) -> None:
        """Handle broadcast from signal when message is edited."""
        await self.send_json({"type": "message.edited", "message": event["message"]})

    async def message_deleted(self, event: dict[str, Any]) -> None:
        """Handle broadcast from signal when message is deleted."""
        await self.send_json({"type": "message.deleted", "message": event["message"]})

    async def _user_can_view(self, user_id: int, conv_id: int) -> bool:
        """Check if user has permission to view this conversation."""
        try:
            conv = await database_sync_to_async(Conversation.objects.get)(pk=conv_id)
            user = await database_sync_to_async(lambda: self.scope["user"])()
            return conv.user_can_view(user)
        except Conversation.DoesNotExist:
            return False
