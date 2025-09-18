"""
ASGI entry point for Django Channels.

This file configures both HTTP and WebSocket protocols by composing the
Django ASGI application and Channels routing.  The default settings
module is set to the development configuration.
"""
import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ecp_backend.settings.dev")

# Init Django before importing apps that touch models/auth
django.setup()

from django.core.asgi import get_asgi_application
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter

from common.querystring_jwt import QueryStringJWTAuthMiddleware  # ✅ new middleware
from ecp_backend.routing import websocket_urlpatterns             # ✅ your WS routes

django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": QueryStringJWTAuthMiddleware(  # ✅ reads ?token=...
        AuthMiddlewareStack(                    # keep cookie/session auth if any
            URLRouter(websocket_urlpatterns)    # use project-level routes
        )
    ),
})
