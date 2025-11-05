# activity_feed/consumers.py
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from urllib.parse import parse_qs

class LiveFeedConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        qs = parse_qs((self.scope.get("query_string") or b"").decode())
        community_id = (qs.get("community_id", ["public"])[0]) or "public"
        self.group_name = f"livefeed_{community_id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    # use: channel_layer.group_send(group, {"type": "broadcast.json", "text": "<json>"})
    async def broadcast_json(self, event):
        await self.send(text_data=event["text"])
