"""
URL configuration for the messaging app.

Defines REST endpoints for conversations and nested message resources.
These routes are included under the ``/api/messaging/`` prefix at the
project level.
"""
from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import ConversationViewSet, MessageViewSet, MarkMessageReadView

router = DefaultRouter()
router.register(r"conversations", ConversationViewSet, basename="conversation")

urlpatterns = [
    *router.urls,
    # Nested message routes (list + create)
    path(
        "conversations/<int:conversation_id>/messages/",
        MessageViewSet.as_view({"get": "list", "post": "create"}),
        name="conversation-messages",
    ),
    # Mark a message as read
    path(
        "messages/<int:pk>/read/",
        MarkMessageReadView.as_view(),
        name="message-read",
    ),
]
