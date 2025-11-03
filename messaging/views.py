"""
Views for the messaging app.

Expose RESTful endpoints for creating and listing conversations and
their messages. Authentication is required for all endpoints.
This version supports:
 - Direct (1:1) conversations
 - Group rooms (e.g., per-event) via POST /conversations/ensure-group/
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework import viewsets, mixins, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, ValidationError, PermissionDenied
from rest_framework.generics import GenericAPIView

from .models import Conversation, Message
from .serializers import ConversationSerializer, MessageSerializer
from .permissions import IsConversationParticipant


User = get_user_model()


class ConversationViewSet(viewsets.ViewSet):
    """ViewSet for listing, creating and retrieving conversations."""

    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self, request):
        user = request.user
        # Include DMs the user is in + all group rooms
        qs = Conversation.objects.filter(Q(user1=user) | Q(user2=user) | Q(is_group=True))
        qs = qs.select_related("user1__profile", "user2__profile").prefetch_related("messages")
        qs = qs.order_by("-updated_at")
        q = request.query_params.get("q")
        if q:
            q = q.strip()
            other_user1 = (
                (Q(user1__first_name__icontains=q)
                 | Q(user1__last_name__icontains=q)
                 | Q(user1__profile__full_name__icontains=q)
                 | Q(user1__profile__company__icontains=q))
                & ~Q(user1=user)
            )
            other_user2 = (
                (Q(user2__first_name__icontains=q)
                 | Q(user2__last_name__icontains=q)
                 | Q(user2__profile__full_name__icontains=q)
                 | Q(user2__profile__company__icontains=q))
                & ~Q(user2=user)
            )
            qs = qs.filter(other_user1 | other_user2 | Q(is_group=True, title__icontains=q))
        return qs

    def list(self, request):
        qs = self.get_queryset(request)
        serializer = ConversationSerializer(qs, many=True, context={"request": request})
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        user = request.user
        try:
            conv = Conversation.objects.select_related("user1", "user2").get(pk=pk)
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")
        if not conv.is_group and user.id not in (conv.user1_id, conv.user2_id):
            raise PermissionDenied("You are not a participant of this conversation.")
        serializer = ConversationSerializer(conv, context={"request": request})
        return Response(serializer.data)

    def create(self, request):
        """Create or return an existing conversation between the requesting user and a recipient."""
        user = request.user
        recipient_id = request.data.get("recipient_id")
        if not recipient_id:
            raise ValidationError({"recipient_id": "This field is required."})
        try:
            recipient_id = int(recipient_id)
        except (TypeError, ValueError):
            raise ValidationError({"recipient_id": "Invalid recipient ID."})
        if recipient_id == user.id:
            raise ValidationError({"recipient_id": "Cannot start a conversation with yourself."})
        try:
            recipient = User.objects.get(pk=recipient_id)
        except User.DoesNotExist:
            raise ValidationError({"recipient_id": "Recipient not found."})
        user_ids = sorted([user.id, recipient_id])
        conv, created = Conversation.objects.get_or_create(
            user1_id=user_ids[0], user2_id=user_ids[1], is_group=False
        )
        serializer = ConversationSerializer(conv, context={"request": request})
        status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        return Response(serializer.data, status=status_code)

    # --- NEW: ensure or return a per-event group room by room_key ---
    @action(detail=False, methods=["post"], url_path="ensure-group")
    def ensure_group(self, request):
        """
        Upsert a shared room by room_key, e.g., room_key="event:85".
        Body: { "room_key": "event:<event_id>", "title": "<event name>" }
        """
        room_key = request.data.get("room_key")
        title = request.data.get("title", "")
        if not room_key:
            raise ValidationError({"room_key": "This field is required."})

        conv, created = Conversation.objects.get_or_create(
            room_key=room_key,
            defaults={
                "is_group": True,
                "title": title,
                "created_by": request.user if request.user.is_authenticated else None,
            },
        )
        # if it existed but wasn't flagged as group, fix it
        if not conv.is_group:
            conv.is_group = True
            if title and not conv.title:
                conv.title = title
            conv.save(update_fields=["is_group", "title"])

        serializer = ConversationSerializer(conv, context={"request": request})
        return Response(serializer.data, status=status.HTTP_200_OK)


class MessageViewSet(mixins.ListModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    """ViewSet for listing and creating messages within a conversation."""

    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated, IsConversationParticipant]

    def get_queryset(self):
        conv_id = self.kwargs.get("conversation_id")
        user = self.request.user
        try:
            conv = Conversation.objects.get(pk=conv_id)
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")
        if not conv.is_group and user.id not in (conv.user1_id, conv.user2_id):
            raise PermissionDenied("You are not a participant of this conversation.")
        # return oldest-first for chat scrolling in FE (FE can reverse if desired)
        return (
            Message.objects
            .filter(conversation=conv, is_hidden=False, is_deleted=False)
            .select_related("sender")
            .order_by("created_at")
        )
    def perform_create(self, serializer):
        conv_id = self.kwargs.get("conversation_id")
        try:
            conv = Conversation.objects.get(pk=conv_id)
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")
        user = self.request.user
        if not conv.is_group and user.id not in (conv.user1_id, conv.user2_id):
            raise PermissionDenied("You are not a participant of this conversation.")
        serializer.save(conversation=conv, sender=user)


class MarkMessageReadView(GenericAPIView):
    """
    Endpoint to mark a message as read. Only the recipient can mark a
    message as read for DMs; for group rooms, any authenticated user
    can mark (global flag).
    """

    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated, IsConversationParticipant]

    def post(self, request, pk):
        try:
            msg = Message.objects.select_related("conversation").get(pk=pk)
        except Message.DoesNotExist:
            raise NotFound("Message not found.")
        user = request.user
        conv = msg.conversation
        if not conv.is_group and user.id not in (conv.user1_id, conv.user2_id):
            raise PermissionDenied("You are not a participant of this conversation.")
        if msg.sender_id == user.id:
            raise PermissionDenied("You cannot mark your own message as read.")
        if not msg.is_read:
            msg.is_read = True
            msg.save(update_fields=["is_read"])
        serializer = MessageSerializer(msg)
        return Response(serializer.data)
