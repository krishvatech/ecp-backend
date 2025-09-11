"""
ASGI entry point for Django Channels.

This file configures both HTTP and WebSocket protocols by composing the
Django ASGI application and Channels routing.  The default settings
module is set to the development configuration.
"""
import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ecp_backend.settings.dev")

# Initialize Django ASGI application first so that models are ready
django_asgi_app = get_asgi_application()

# Lazy import of websocket patterns to avoid triggering model imports too early
from ecp_backend.routing import websocket_urlpatterns  # noqa: E402

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": URLRouter(websocket_urlpatterns),
})