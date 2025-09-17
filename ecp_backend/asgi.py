"""
ASGI entry point for Django Channels.

This file configures both HTTP and WebSocket protocols by composing the
Django ASGI application and Channels routing.  The default settings
module is set to the development configuration.
"""
# ecp_backend/asgi.py
# ecp_backend/asgi.py
import os
import django
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

# Ensure settings are set
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ecp_backend.settings.dev")

# --- initialize Django BEFORE importing anything that touches auth models
django.setup()

# Create the HTTP app (ensures apps are ready)
django_asgi_app = get_asgi_application()

# Now safe to import
from common.channels_jwt_auth import JWTAuthMiddlewareStack
from ecp_backend.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": JWTAuthMiddlewareStack(
        URLRouter(websocket_urlpatterns)
    ),
})
