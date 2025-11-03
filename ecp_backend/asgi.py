"""
ASGI entry point for Django Channels.
This file configures both HTTP and WebSocket protocols by composing the
Django ASGI application and Channels routing.  The default settings
module is set to the development configuration.
"""

import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ecp_backend.settings")
django.setup()

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from events.routing import websocket_urlpatterns as events_ws
from messaging.routing import websocket_urlpatterns as messaging_ws   
from interactions.routing import websocket_urlpatterns as interactions_ws
from common.channels_jwt_auth import JWTAuthMiddlewareStack

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AllowedHostsOriginValidator(
        JWTAuthMiddlewareStack(
            URLRouter([
                *events_ws,
                *interactions_ws,
                *messaging_ws,   
            ])
        )
    ),
})