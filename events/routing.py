"""
WebSocket routing for the events app.

Defines the URL patterns used to connect WebSocket clients to the
`EventConsumer`.  The `<int:event_id>` parameter identifies the event.
"""
from django.urls import path
from .consumers import EventConsumer


websocket_urlpatterns = [
    path("ws/events/<int:event_id>/", EventConsumer.as_asgi()),
]