"""
Project-level Channels routing configuration.

This module defines the URL routes for all WebSocket connections.  It
wraps the routes with a custom JWT authentication middleware stack.
"""
from common.channels_jwt_auth import JWTAuthMiddlewareStack
from events.routing import websocket_urlpatterns as events_ws
from events.routing import websocket_urlpatterns as events_ws
from interactions.routing import websocket_urlpatterns as interactions_ws

# Compose the websocket routes for the project.  Additional apps can extend
# this list by importing and concatenating their own websocket patterns.

# Combine event and interactions websocket patterns
websocket_urlpatterns = JWTAuthMiddlewareStack(
    [
        *events_ws,
        *interactions_ws,
    ]
)