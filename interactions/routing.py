from django.urls import path
from .consumers import ChatConsumer, QnAConsumer

# Websocket paths for chat and Q&A; included in root router
websocket_urlpatterns = [
    path("ws/events/<int:event_id>/chat/", ChatConsumer.as_asgi(), name="chat"),
    path("ws/events/<int:event_id>/qna/", QnAConsumer.as_asgi(), name="qna"),
]
