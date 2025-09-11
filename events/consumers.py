"""
WebSocket consumer for the events app.

Clients connect to a specific event channel using the URL pattern
`ws/events/<event_id>/`.  Upon connection, they join a group named
`event_<event_id>`.  Messages received are broadcast to all group
members.  Authentication is handled via the JWT middleware.
"""
from channels.generic.websocket import AsyncJsonWebsocketConsumer


class EventConsumer(AsyncJsonWebsocketConsumer):
    """Consumer to handle real-time communication within an event."""

    async def connect(self) -> None:
        user = self.scope.get("user")
        if not user or user.is_anonymous:
            # Close connection if no valid user is present
            await self.close(code=4401)
            return
        self.event_id = self.scope["url_route"]["kwargs"]["event_id"]
        self.group_name = f"event_{self.event_id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        await self.send_json({"type": "welcome", "event_id": self.event_id})

    async def disconnect(self, code: int) -> None:
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content: dict, **kwargs) -> None:
        # Broadcast any received message to the group
        await self.channel_layer.group_send(
            self.group_name,
            {"type": "broadcast.message", "payload": content},
        )

    async def broadcast_message(self, event: dict) -> None:
        # Send the payload to WebSocket client
        await self.send_json({"type": "message", "data": event["payload"]})