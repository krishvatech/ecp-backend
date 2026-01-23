# apps/messaging/urls.py
"""
URL configuration for the messaging app.

Defines REST endpoints for conversations and nested message resources.
These routes are included under the ``/api/messaging/`` prefix at the
project level.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import ConversationViewSet, MessageViewSet, MarkMessageReadView

app_name = "messaging"

router = DefaultRouter()
router.register(r"conversations", ConversationViewSet, basename="conversation")

urlpatterns = [
    # router routes (list/create/retrieve on /conversations/)
    path("", include(router.urls)),

    # nested messages under a conversation
    path(
        "conversations/<int:conversation_id>/messages/",
        MessageViewSet.as_view({"get": "list", "post": "create"}),
        name="conversation-messages",
    ),

    # mark a single message as read
    path(
        "conversations/<int:conversation_id>/messages/<int:pk>/",
        MessageViewSet.as_view({"get": "retrieve", "delete": "destroy", "patch": "partial_update", "put": "update"}),
        name="conversation-message-detail",
    ),
    path(
        "conversations/<int:conversation_id>/messages/<int:pk>/flag/",
        MessageViewSet.as_view({"post": "flag"}),
        name="conversation-message-flag",
    ),
    
    path(
        "conversations/<int:conversation_id>/messages/<int:pk>/download-attachment/",
        MessageViewSet.as_view({"get": "download_attachment"}),
        name="conversation-message-download-attachment",
    ),
    path("messages/<int:pk>/read/", MarkMessageReadView.as_view(), name="message-read"),
]

