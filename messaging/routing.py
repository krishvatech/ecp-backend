"""
WebSocket routing for the messaging app.

Exposes a single URL for 1‑to‑1 conversation channels.  The JWT
authentication middleware will enforce that only authenticated users
may connect and the consumer itself verifies conversation
membership.
"""
from django.urls import re_path

from .consumers import DirectMessageConsumer


websocket_urlpatterns = [
    re_path(r"^ws/messaging/(?P<conversation_id>\d+)/$", DirectMessageConsumer.as_asgi()),
]
