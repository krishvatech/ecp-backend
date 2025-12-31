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
from django.conf import settings
from django.core.asgi import get_asgi_application
from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator

from events.routing import websocket_urlpatterns as events_ws
from messaging.routing import websocket_urlpatterns as messaging_ws
from interactions.routing import websocket_urlpatterns as interactions_ws
from common.channels_jwt_auth import JWTAuthMiddlewareStack

django_asgi_app = get_asgi_application()

# ✅ IMPORTANT: Serve /static/ when using uvicorn in DEBUG mode
if settings.DEBUG:
    django_asgi_app = ASGIStaticFilesHandler(django_asgi_app)

application = ProtocolTypeRouter({
    "http": django_asgi_app,
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