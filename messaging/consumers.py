"""
Channels consumer for direct messaging.

This asynchronous consumer handles WebSocket connections for a single
conversation.  It authenticates the user via the JWTAuthMiddleware
stack, validates membership in the conversation, and relays messages
between participants in real time.  Clients send ``message.send``
events and receive ``message.created`` events.
"""
from __future__ import annotations

from typing import Any

from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async

from .models import Conversation, Message
from .serializers import MessageSerializer


class DirectMessageConsumer(AsyncJsonWebsocketConsumer):
    """Realtime WebSocket consumer for 1‑to‑1 conversations."""

    async def connect(self) -> None:
        conv_id = self.scope["url_route"]["kwargs"]["conversation_id"]
        self.conversation_id = int(conv_id)
        self.group_name = f"conversation_{self.conversation_id}"
        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            await self.close()
            return
        if not await self._is_participant(user.id, self.conversation_id):
            await self.close()
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

    # ---------- sync helper methods ----------
    def _create_message(self, user_id: int, conv_id: int, body: str, attachments: list) -> Message:
        msg = Message.objects.create(
            conversation_id=conv_id,
            sender_id=user_id,
            body=body,
            attachments=attachments,
        )
        return msg

    async def _is_participant(self, user_id: int, conv_id: int) -> bool:
        try:
            conv = await database_sync_to_async(Conversation.objects.get)(pk=conv_id)
        except Conversation.DoesNotExist:
            return False
        return user_id in (conv.user1_id, conv.user2_id)
