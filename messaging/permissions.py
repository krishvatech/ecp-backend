"""
Custom permission classes for the messaging app.

These permissions enforce that only participants of a conversation may
access DM resources. Group rooms (is_group=True) are open to any
authenticated user by default.
"""
from rest_framework.permissions import BasePermission
from django.core.exceptions import ObjectDoesNotExist

from .models import Conversation


class IsConversationParticipant(BasePermission):
    """Allow access only to participants of a conversation; allow all for group."""

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        conversation_id = view.kwargs.get("conversation_id")
        if conversation_id is not None:
            try:
                conv = Conversation.objects.get(pk=conversation_id)
            except ObjectDoesNotExist:
                return False
            if conv.is_group:
                return True
            return user.id in (conv.user1_id, conv.user2_id)
        return True

    def has_object_permission(self, request, view, obj):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if hasattr(obj, "is_group") and obj.is_group:
            return True
        if hasattr(obj, "user1_id") and hasattr(obj, "user2_id"):
            return user.id in (obj.user1_id, obj.user2_id)
        elif hasattr(obj, "conversation"):
            conv = obj.conversation
            if conv.is_group:
                return True
            return user.id in (conv.user1_id, conv.user2_id)
        return False
