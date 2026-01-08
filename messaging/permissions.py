"""
Custom permission classes for the messaging app.

Rules:
- DM conversations: only the two participants can access.
- Group/Event conversations: any authenticated user can access.
"""
from typing import Optional
from rest_framework.permissions import BasePermission
from django.core.exceptions import ObjectDoesNotExist

from .models import Conversation
from typing import Optional
from .models import Conversation

KWARG_KEYS = ("conversation_id", "conversation_pk", "pk", "id")

def _is_group_conv(conv: Conversation) -> bool:
    # Treat either the flag or FK as a “group chat”.
    return bool(getattr(conv, "is_group", False) or getattr(conv, "group_id", None))

def _is_event_conv(conv: Conversation) -> bool:
    # Treat either the flag or FK as an “event chat”.
    return bool(getattr(conv, "is_event_group", False) or getattr(conv, "event_id", None))

def _is_dm_conv(conv: Conversation) -> bool:
    # DM = not group/event. (Your schema enforces mutual exclusivity.)
    return not (_is_group_conv(conv) or _is_event_conv(conv))

def _get_conversation_from_kwargs(view) -> Optional[Conversation]:
    conv_id = None
    for k in KWARG_KEYS:
        v = view.kwargs.get(k)
        if v is not None:
            conv_id = v
            break
    if not conv_id:
        return None
    try:
        return Conversation.objects.get(pk=conv_id)
    except Conversation.DoesNotExist:
        return None


class IsConversationParticipant(BasePermission):
    """
    Allow access only to participants of a DM conversation.
    Allow access to any authenticated user for Group/Event conversations.
    """

    def _conv_from_view(self, view) -> Optional[Conversation]:
        return _get_conversation_from_kwargs(view)

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        conv = self._conv_from_view(view)
        if conv is None:
            # Endpoints without a specific conversation id in URL can pass here
            # and will be handled by object-level checks or the view itself.
            return True

        # Group/Event rooms → any authenticated user may access
        return conv.user_can_view(user)

    def has_object_permission(self, request, view, obj):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        conv = obj if isinstance(obj, Conversation) else getattr(obj, "conversation", None)

        if conv is None:
            # Infer shape from loose fields (rare)
            uid1 = getattr(obj, "user1_id", None)
            uid2 = getattr(obj, "user2_id", None)
            gid = getattr(obj, "group_id", None)
            eid = getattr(obj, "event_id", None)

            if gid is not None and eid is None:
                return True
            if eid is not None and gid is None:
                return True
            if gid is None and eid is None and (uid1 is not None or uid2 is not None):
                return user.id in (uid1, uid2)
            return False

        return conv.user_can_view(user)
