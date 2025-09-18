"""
Project-level Channels routing configuration.

This module defines the URL routes for all WebSocket connections.  It
wraps the routes with a custom JWT authentication middleware stack.
"""
from ecp_backend.events.routing import websocket_urlpatterns as events_ws
from ecp_backend.interactions.routing import websocket_urlpatterns as interactions_ws
from messaging.routing import websocket_urlpatterns as messaging_ws

# Compose the websocket routes for the project.  Additional apps can extend
# this list by importing and concatenating their own websocket patterns.

# Combine event and interactions websocket patterns
websocket_urlpatterns = [
    *events_ws,
    *interactions_ws,
    *messaging_ws,
]