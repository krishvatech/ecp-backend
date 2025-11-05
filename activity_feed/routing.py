# activity_feed/routing.py
from django.urls import re_path
from .consumers import LiveFeedConsumer

websocket_urlpatterns = [
    re_path(r"^ws/livefeed/$", LiveFeedConsumer.as_asgi()),
]
