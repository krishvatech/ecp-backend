"""
Project-level Channels routing configuration.

This module defines the URL routes for all WebSocket connections.  It
wraps the routes with a custom JWT authentication middleware stack.
"""
from events.routing import websocket_urlpatterns as events_ws
from messaging.routing import websocket_urlpatterns as messaging_ws
from interactions.routing import websocket_urlpatterns as interactions_ws

websocket_urlpatterns = [
    *events_ws,
    *messaging_ws,
    *interactions_ws,
]