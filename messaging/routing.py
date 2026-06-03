"""
WebSocket routing for the messaging app.

Exposes WebSocket URLs for messaging functionality:
1. ws/messaging/<conversation_id>/ - Legacy 1-to-1 direct message consumer
2. ws/messaging/conversations/<conversation_id>/ - Event/lounge/group conversation consumer

The JWT authentication middleware will enforce that only authenticated users
may connect and each consumer verifies conversation membership.
"""
from django.urls import re_path

from .consumers import DirectMessageConsumer, ConversationConsumer


websocket_urlpatterns = [
    # Legacy 1-to-1 direct message consumer
    re_path(r"^ws/messaging/(?P<conversation_id>\d+)/$", DirectMessageConsumer.as_asgi()),

    # New event/lounge/group conversation consumer (bridges REST API to WebSocket)
    re_path(r"^ws/messaging/conversations/(?P<conversation_id>\d+)/$", ConversationConsumer.as_asgi()),
]
