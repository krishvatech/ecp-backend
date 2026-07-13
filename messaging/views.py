"""
Views for the messaging app.

Expose RESTful endpoints for creating and listing conversations and
their messages. Authentication is required for all endpoints.
This version supports:
 - Direct (1:1) conversations
 - Group rooms (e.g., per-event) via POST /conversations/ensure-group/
"""
from __future__ import annotations
from django.conf import settings
from django.core.cache import cache
from django.db import models
from django.contrib.auth import get_user_model
from django.db.models import Q, Prefetch, Exists, OuterRef, Subquery, Count, Value, IntegerField
from django.db.models.functions import Coalesce
from rest_framework import viewsets, mixins, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, ValidationError, PermissionDenied, Throttled
from rest_framework.generics import GenericAPIView
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from rest_framework.throttling import UserRateThrottle
from django.core.files.storage import default_storage
from django.http import FileResponse, Http404
from django.http import FileResponse
from urllib.parse import urlparse


from .models import Conversation, Message, MessageReadReceipt, ConversationPinnedMessage, ConversationPin, MessageFlag
from .serializers import ConversationSerializer, MessageSerializer,ConversationPinnedMessageOutSerializer
from .permissions import IsConversationParticipant
from .access import user_can_access_event_chat
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from events.models import Event, EventRegistration, EventParticipant, NetworkingMeeting
from friends.models import Friendship
from rest_framework.exceptions import PermissionDenied
import logging
from common.live_metrics import live_metric_incr

logger = logging.getLogger(__name__)

User = get_user_model()


class LiveChatMessageRateThrottle(UserRateThrottle):
    """Per-user live chat send limit. Config: DRF_THROTTLE_LIVE_CHAT_MESSAGE."""
    scope = "live_chat_message"


def _cache_window_limited(key: str, *, limit: int, window_seconds: int) -> tuple[bool, int]:
    """
    Small Redis/cache fixed-window limiter used for room-level burst protection.
    Returns (limited, current_count).
    """
    limit = max(1, int(limit))
    window_seconds = max(1, int(window_seconds))
    try:
        if cache.add(key, 1, timeout=window_seconds):
            return False, 1
        current = cache.incr(key)
        return current > limit, current
    except Exception:
        # Do not break chat if Redis/cache has a temporary issue.
        logger.warning("[LiveChatRate] cache limiter failed for key=%s", key, exc_info=True)
        return False, 0


class ConversationViewSet(viewsets.ViewSet):
    """ViewSet for listing, creating and retrieving conversations."""

    permission_classes = [permissions.IsAuthenticated]

    @staticmethod
    def _is_guest_user(user) -> bool:
        return bool(getattr(user, "is_guest", False))

    def _deny_guest(self, request):
        if self._is_guest_user(request.user):
            raise PermissionDenied("Messaging is unavailable for guest users.")


    def _event_live_dm_allowed(self, *, user, recipient_id, event_id) -> bool:
        """
        Allow 1:1 private chat from Live Meeting participants panel.

        Existing global DM rule stays unchanged:
        - friends can always message
        - accepted networking meeting can message

        This helper only opens DM when the request is scoped to a real event and
        both users are allowed participants/staff for that same event.
        """
        if not event_id:
            return False

        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            return False

        try:
            event = Event.objects.select_related("community").get(pk=event_id)
            recipient = User.objects.get(pk=recipient_id)
        except (Event.DoesNotExist, User.DoesNotExist):
            return False

        return (
            user_can_access_event_chat(user, event=event)
            and user_can_access_event_chat(recipient, event=event)
        )

    def get_queryset(self, request):
        user = request.user
        if self._is_guest_user(user):
            guest = getattr(user, "guest", None)
            if not guest:
                return Conversation.objects.none()
            guest_filter = Q(event_id=guest.event_id)
            if guest.lounge_table_id:
                guest_filter |= Q(lounge_table_id=guest.lounge_table_id)
            qs = Conversation.objects.filter(guest_filter).select_related(
                "event",
                "lounge_table",
            )
            return qs.order_by("-updated_at")

        from groups.models import GroupMembership
        from events.models import LoungeParticipant

        # Groups where this user is a member (same logic as /groups/joined-groups/)
        member_statuses = [
            GroupMembership.STATUS_ACTIVE,
            GroupMembership.STATUS_PENDING,
        ]
        member_group_ids = GroupMembership.objects.filter(
            user=user,
            status__in=member_statuses,
            group__is_deleted=False,
        ).values_list("group_id", flat=True)

        # Events where this user is registered or created the event
        registered_event_ids = EventRegistration.objects.filter(
            user_id=user.id,
            status="registered",
            attendee_status="confirmed",
            is_banned=False,
        ).values_list("event_id", flat=True)
        created_event_ids = Event.objects.filter(
            created_by_id=user.id
        ).values_list("id", flat=True)
        allowed_event_ids = list(set(registered_event_ids) | set(created_event_ids))

        lounge_table_ids = LoungeParticipant.objects.filter(
            user_id=user.id
        ).values_list("table_id", flat=True)

        # Include:
        # - DMs I'm in
        # - Group rooms ONLY where I'm a member
        # - Event rooms ONLY where I'm registered or the creator
        # - Lounge rooms ONLY where I'm seated
        qs = Conversation.objects.filter(
            Q(user1=user)
            | Q(user2=user)
            | Q(group_id__in=member_group_ids)
            | Q(event_id__in=allowed_event_ids)
            | Q(lounge_table_id__in=lounge_table_ids)
        ).filter(
            Q(group__isnull=True) | Q(group__is_deleted=False)
        )

        qs = qs.select_related(
            "user1__profile",
            "user2__profile",
            "group",
            "event",
            "lounge_table",
        )

        is_pinned_subquery = ConversationPin.objects.filter(
            conversation=OuterRef('pk'),
            user=user,
        )
        latest_message_subquery = Message.objects.filter(
            conversation_id=OuterRef("pk"),
            is_hidden=False,
            is_deleted=False,
        ).order_by("-id")

        # IMPORTANT:
        # Do not calculate unread_count with a filtered Count over
        # messages__read_receipts. In event/group chats a message can have read
        # receipts from many users. A joined row for another user can make
        # `~Q(messages__read_receipts__user_id=user.id)` true even when the
        # current user has already read the message, so the red unread dot stays
        # visible after reading. Count unread messages in an isolated Message
        # subquery using exclude(read_receipts__user_id=user.id), matching the
        # mark-all-read semantics.
        unread_messages_subquery = (
            Message.objects
            .filter(
                conversation_id=OuterRef("pk"),
                is_hidden=False,
                is_deleted=False,
            )
            .exclude(sender_id=user.id)
            .exclude(read_receipts__user_id=user.id)
            .values("conversation_id")
            .annotate(total=Count("id", distinct=True))
            .values("total")[:1]
        )

        qs = qs.annotate(
            is_pinned=Exists(is_pinned_subquery),
            last_message_body_annotated=Subquery(latest_message_subquery.values("body")[:1]),
            unread_count_annotated=Coalesce(
                Subquery(unread_messages_subquery, output_field=IntegerField()),
                Value(0),
            ),
        )

        # Ordering: Pinned first (True > False), then by updated_at
        qs = qs.order_by("-is_pinned", "-updated_at")

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
            qs = qs.filter(
                other_user1
                | other_user2
                | Q(group__isnull=False, title__icontains=q)
                | Q(event__isnull=False, title__icontains=q)
                | Q(group__name__icontains=q)
                | Q(event__title__icontains=q)
                | Q(lounge_table__name__icontains=q)
            )
        return qs


    @staticmethod
    def _parse_page_params(request, *, default_limit=50, max_limit=100):
        try:
            limit = int(request.query_params.get("limit", default_limit))
        except (TypeError, ValueError):
            limit = default_limit
        try:
            offset = int(request.query_params.get("offset", 0))
        except (TypeError, ValueError):
            offset = 0
        return max(1, min(limit, max_limit)), max(0, offset)

    @action(detail=False, methods=["get"], url_path="unread-count")
    def unread_count(self, request):
        """Return only the current user's total unread message count.

        This is intentionally much lighter than the full conversations list and is
        safe for sidebar/dashboard badges during high-traffic redirects.
        """
        user = request.user
        user_id = getattr(user, "id", None)
        if not user_id:
            return Response({"unread_count": 0})

        cache_key = f"messaging:unread-count:{user_id}"
        cached_count = cache.get(cache_key)
        if cached_count is not None:
            return Response({"unread_count": int(cached_count)})

        if self._is_guest_user(user):
            guest = getattr(user, "guest", None)
            if not guest:
                return Response({"unread_count": 0})

            conversation_filter = Q(conversation__event_id=guest.event_id)
            if getattr(guest, "lounge_table_id", None):
                conversation_filter |= Q(conversation__lounge_table_id=guest.lounge_table_id)
        else:
            from groups.models import GroupMembership
            from events.models import LoungeParticipant

            member_statuses = [
                GroupMembership.STATUS_ACTIVE,
                GroupMembership.STATUS_PENDING,
            ]
            member_group_ids = GroupMembership.objects.filter(
                user_id=user_id,
                status__in=member_statuses,
                group__is_deleted=False,
            ).values("group_id")
            registered_event_ids = EventRegistration.objects.filter(
                user_id=user_id,
                status="registered",
                attendee_status="confirmed",
                is_banned=False,
            ).values("event_id")
            created_event_ids = Event.objects.filter(created_by_id=user_id).values("id")
            lounge_table_ids = LoungeParticipant.objects.filter(user_id=user_id).values("table_id")

            conversation_filter = (
                Q(conversation__user1_id=user_id) |
                Q(conversation__user2_id=user_id) |
                Q(conversation__group_id__in=member_group_ids) |
                Q(conversation__event_id__in=registered_event_ids) |
                Q(conversation__event_id__in=created_event_ids) |
                Q(conversation__lounge_table_id__in=lounge_table_ids)
            )

        unread_count = Message.objects.filter(
            conversation_filter,
            is_hidden=False,
            is_deleted=False,
        ).filter(
            Q(conversation__group__isnull=True) | Q(conversation__group__is_deleted=False)
        ).exclude(
            sender_id=user_id,
        ).exclude(
            read_receipts__user_id=user_id,
        ).distinct().count()

        cache.set(cache_key, unread_count, 15)
        return Response({"unread_count": unread_count})

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset(request)
        limit, offset = self._parse_page_params(request, default_limit=50, max_limit=100)
        serializer = ConversationSerializer(qs[offset: offset + limit], many=True, context={"request": request})
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        obj = get_object_or_404(self.get_queryset(request), pk=kwargs["pk"])
        serializer = ConversationSerializer(obj, context={"request": request})
        return Response(serializer.data)

    def create(self, request):
        """
        Create or return an existing conversation.
        Supports:
        - DM:          {recipient_id}
        - Group chat:  {group: <group_id>}
        - Event chat:  {event: <event_id>}
        """
        user = request.user
        self._deny_guest(request)
        event_id = request.data.get("event")
        group_id = request.data.get("group")
        recipient_id = request.data.get("recipient_id")

        # --- Event chat ---
        if event_id is not None:
            from events.models import Event
            try:
                event_id = int(event_id)
            except (TypeError, ValueError):
                raise ValidationError({"event": "Invalid event id."})
            event = get_object_or_404(Event.objects.select_related("community"), pk=event_id)
            if not user_can_access_event_chat(user, event=event):
                raise PermissionDenied("You are not allowed to access this event chat.")

            # One row per event chat
            conv, created = Conversation.objects.get_or_create(
                event=event,
                defaults={
                    "created_by": user,
                    "title": event.title,
                },
            )

            # Backfill/normalize (legacy rows)
            changed = False
            if conv.event_id != event.id:
                conv.event = event
                changed = True
            if not conv.title:
                conv.title = event.title
                changed = True
            if changed:
                conv.save(update_fields=["event", "title"])

            ser = ConversationSerializer(conv, context={"request": request})
            return Response(ser.data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

        # --- Group chat ---
        if group_id is not None:
            from groups.models import Group
            from groups.models import GroupMembership
            try:
                group_id = int(group_id)
            except (TypeError, ValueError):
                raise ValidationError({"group": "Invalid group id."})
            group = get_object_or_404(Group, pk=group_id)
            is_group_member = GroupMembership.objects.filter(
                group_id=group.id,
                user_id=user.id,
                status__in=[GroupMembership.STATUS_ACTIVE, GroupMembership.STATUS_PENDING],
            ).exists()
            if not is_group_member:
                raise PermissionDenied("You are not a member of this group.")

            conv, created = Conversation.objects.get_or_create(
                group=group,
                defaults={
                    "created_by": user,
                    "title": group.name,
                },
            )
            changed = False
            if conv.group_id != group.id:
                conv.group = group
                changed = True
            if not conv.title:
                conv.title = group.name
                changed = True
            if changed:
                conv.save(update_fields=["group", "title"])

            ser = ConversationSerializer(conv, context={"request": request})
            return Response(ser.data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

        # --- DM (existing behavior) ---
        if not recipient_id:
            raise ValidationError({"recipient_id": "This field is required when 'event' and 'group' are not provided."})
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

        # Generate a nice title like "Alice ↔ Bob"
        me_name = user.get_full_name() or user.username or f"User {user.id}"
        other_name = recipient.get_full_name() or recipient.username or f"User {recipient.id}"
        dm_title = f"{me_name} ↔ {other_name}"

        conv, created = Conversation.objects.get_or_create(
            user1_id=user_ids[0],
            user2_id=user_ids[1],
            defaults={
                "created_by": user,
                "title": dm_title,
            },
        )

        # Backfill title for old rows that might have NULL / empty title
        if not conv.title:
            conv.title = dm_title
            conv.save(update_fields=["title"])

        serializer = ConversationSerializer(conv, context={"request": request})
        status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        return Response(serializer.data, status=status_code)

    @action(detail=True, methods=["post"], url_path="toggle-pin")
    def toggle_pin(self, request, pk=None):
        """Toggle the pinned status of a conversation for the current user."""
        try:
            conv = Conversation.objects.get(pk=pk)
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")

        # Ensure participation
        if not conv.user_can_view(request.user):
            raise PermissionDenied("You are not a participant.")
            
        # ---------------------------------------------------------------

        pin_obj, created = ConversationPin.objects.get_or_create(
            conversation=conv, user=request.user
        )

        if not created:
            # If it existed, delete it (Unpin)
            pin_obj.delete()
            pinned = False
        else:
            pinned = True

        return Response({"is_pinned": pinned, "conversation_id": conv.id})

    # --- NEW: ensure or return a per-event group room by room_key ---
    @action(detail=False, methods=["post"], url_path="ensure-group")
    def ensure_group(self, request):
        """
        Ensure a group conversation exists and is linked to the actual Group row.

        Accepts ANY of (in body OR query params):
        - group: <group_id>          # numeric id
        - group: "<slug>"            # slug
        - group_slug: "<slug>"
        - slug: "<slug>"
        - room_key: "group:<id|slug>"

        If a real Group cannot be found but room_key is present,
        we fall back to a room_key-only conversation instead of 400.
        """
        from groups.models import Group

        # ---- read from body and query string ----
        data = request.data
        params = request.query_params

        group_ident = (
            data.get("group")
            or data.get("group_slug")
            or data.get("slug")
            or params.get("group")
            or params.get("group_slug")
            or params.get("slug")
        )

        room_key = (data.get("room_key") or params.get("room_key") or "").strip()
        title = (data.get("title") or params.get("title") or "").strip()

        # If only room_key is provided, try to parse "group:<something>"
        if not group_ident and room_key.startswith("group:"):
            try:
                group_ident = room_key.split(":", 1)[1]
            except Exception:
                group_ident = None

        group = None

        # ---- resolve group by id or slug (if we have something) ----
        if group_ident:
            # 1) try numeric id
            try:
                group_id = int(group_ident)
            except (TypeError, ValueError):
                group_id = None

            if group_id is not None:
                try:
                    group = Group.objects.get(pk=group_id)
                except Group.DoesNotExist:
                    group = None  # fail gracefully

            # 2) if still not found, try slug
            if group is None:
                try:
                    group = Group.objects.get(slug=str(group_ident))
                except Group.DoesNotExist:
                    group = None  # still gracefully ignore

            # Do not fall back to a room_key-only conversation when the
            # identifier belongs to a retained soft-deleted group.
            deleted_group_exists = Group.all_objects.filter(
                Q(pk=group_id) if group_id is not None else Q(slug=str(group_ident)),
                is_deleted=True,
            ).exists()
            if group is None and deleted_group_exists:
                raise ValidationError({"group": "This group has been deleted and is no longer available."})

        # ---- if no group and no room_key at all, *then* complain ----
        if not group and not room_key:
            raise ValidationError(
                {"group": "Provide group (id/slug) or room_key like 'group:<id>'."}
            )

        # ---- if we have a real Group, bind conversation to it ----
        if group:
            # canonical room_key for group
            if not room_key:
                room_key = f"group:{group.id}"

            conv, created = Conversation.objects.get_or_create(
                group=group,
                defaults={
                    "created_by": request.user,
                    "title": title or group.name,
                    "room_key": room_key,
                },
            )

            changed = False
            update_fields = []

            if conv.group_id != group.id:
                conv.group = group
                changed = True
                update_fields.append("group")

            if not conv.title:
                conv.title = title or group.name
                changed = True
                update_fields.append("title")

            if room_key and conv.room_key != room_key:
                conv.room_key = room_key
                changed = True
                update_fields.append("room_key")

            if changed:
                conv.save(update_fields=update_fields)

        else:
            # ---- no Group found, but we *do* have room_key → legacy behavior ----
            conv, created = Conversation.objects.get_or_create(
                room_key=room_key,
                defaults={
                    "created_by": request.user,
                    "title": title,
                },
            )

        serializer = ConversationSerializer(conv, context={"request": request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=["post"], url_path="pin-message")
    def pin_message(self, request, pk=None):
        """
        POST /api/messaging/conversations/{id}/pin-message
        Body: { "message_id": <pk>, "scope": "global" | "private" }
        """
        try:
            conv = Conversation.objects.get(pk=pk)
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")

        user = request.user
        if not conv.user_can_view(user):
            raise PermissionDenied("You are not a participant of this conversation.")

        mid = request.data.get("message_id")
        requested_scope = request.data.get("scope", "global") 

        if not mid:
            return Response({"detail": "message_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Determine Final Scope
        final_scope = requested_scope

        # 1. GROUP Chat Logic
        if conv.group_id:
            if requested_scope == 'global':
                from groups.models import GroupMembership
                # Check if user is admin/moderator/owner
                is_group_staff = GroupMembership.objects.filter(
                    group_id=conv.group_id,
                    user=user,
                    status=GroupMembership.STATUS_ACTIVE,
                    role__in=["admin", "moderator", "owner"] 
                ).exists()
                
                if not is_group_staff:
                    final_scope = 'private'

        # 2. EVENT Chat Logic
        elif conv.event_id:
            if requested_scope == 'global':
                from events.models import Event
                # Check if user is the Creator
                is_creator = Event.objects.filter(pk=conv.event_id, created_by=user).exists()
                
                if not is_creator:
                    final_scope = 'private'

        # 3. DM (Direct Message) Logic - 👇 NEW ADDITION
        else:
            # If it's not a Group and not an Event, it's a DM.
            # DMs are ALWAYS private.
            final_scope = 'private'

        try:
            msg = Message.objects.get(
                pk=mid,
                conversation=conv,
                is_hidden=False,
                is_deleted=False,
            )
        except Message.DoesNotExist:
            return Response({"detail": "Message not found in this conversation."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Save using update_or_create with the calculated scope
        pin, created = ConversationPinnedMessage.objects.update_or_create(
            conversation=conv,
            message=msg,
            pinned_by=user, 
            defaults={
                "scope": final_scope,
                "pinned_at": timezone.now()
            },
        )

        data = ConversationPinnedMessageOutSerializer(pin, context={"request": request}).data
        return Response({"ok": True, "pin": data}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="unpin-message")
    def unpin_message(self, request, pk=None):
        try:
            conv = Conversation.objects.get(pk=pk)
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")

        user = request.user
        if not conv.user_can_view(user):
            raise PermissionDenied("You are not a participant.")

        mid = request.data.get("message_id")
        if not mid:
            return Response({"detail": "message_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        # 🗑️ Logic: Only delete pins created by THIS user.
        # (If an admin wants to unpin a global message someone else made, 
        # you would need extra logic here, but this is the safest baseline).
        deleted, _ = ConversationPinnedMessage.objects.filter(
            conversation=conv,
            message_id=mid,
            pinned_by=user 
        ).delete()

        return Response({"ok": True, "deleted": bool(deleted)}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["get"], url_path="pinned-messages")
    def pinned_messages(self, request, pk=None):
        try:
            conv = Conversation.objects.get(pk=pk)
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")

        user = request.user
        if not conv.user_can_view(user):
            raise PermissionDenied("You are not a participant.")

        # 🔍 Logic: Show if Scope is Global OR if I pinned it myself
        qs = (
            ConversationPinnedMessage.objects
            .filter(conversation=conv)
            .filter(Q(scope='global') | Q(pinned_by=user)) 
            .select_related("message__sender__profile", "pinned_by")
            .order_by("-pinned_at")
        )

        data = ConversationPinnedMessageOutSerializer(qs, many=True, context={"request": request}).data
        return Response(data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="ensure-direct")
    def ensure_direct(self, request):
        """
        Ensure a direct (1:1) conversation exists between the current user
        and the recipient.

        Messaging permission:
        - Users who are friends can always message
        - Non-friends can message only if they have an accepted Event Companion
          networking meeting together

        Accepts any of:
        - {"recipient_id": <user_id>, "meeting_id": <networking_meeting_id>}
        - {"user_id": <user_id>}
        - {"user": <user_id>}
        - {"id": <user_id>}
        """
        from rest_framework.exceptions import ValidationError

        self._deny_guest(request)
        user = request.user

        recipient_id = (
            request.data.get("recipient_id")
            or request.data.get("user_id")
            or request.data.get("user")
            or request.data.get("id")
        )

        if not recipient_id:
            raise ValidationError({"recipient_id": "This field is required."})

        try:
            recipient_id = int(recipient_id)
        except (TypeError, ValueError):
            raise ValidationError({"recipient_id": "Invalid recipient ID."})

        if recipient_id == user.id:
            raise ValidationError(
                {"recipient_id": "Cannot start a conversation with yourself."}
            )

        try:
            recipient = User.objects.get(pk=recipient_id)
        except User.DoesNotExist:
            raise ValidationError({"recipient_id": "Recipient not found."})

        # --- Check messaging permission ---
        are_friends = Friendship.are_friends(user.id, recipient_id)

        if not are_friends:
            # Non-friends can message from Live Meeting only when both users
            # belong to the same event. The frontend must send event_id for this
            # path, so normal platform DM privacy remains unchanged.
            event_id = (
                request.data.get("event_id")
                or request.data.get("live_event_id")
                or request.data.get("event")
            )
            if self._event_live_dm_allowed(
                user=user,
                recipient_id=recipient_id,
                event_id=event_id,
            ):
                meeting_id = None
            else:
                # Non-friends outside Live Meeting must have an accepted networking meeting.
                meeting_id = request.data.get("meeting_id")

                if not meeting_id:
                    raise PermissionDenied(
                        "You can only message this user after a confirmed 1:1 meeting or inside the same live event."
                    )

            if meeting_id:
                try:
                    meeting_id = int(meeting_id)
                except (TypeError, ValueError):
                    raise ValidationError({"meeting_id": "Invalid meeting ID."})

                # Validate meeting exists, is accepted, and includes both users
                try:
                    meeting = NetworkingMeeting.objects.get(
                        pk=meeting_id,
                        status="accepted"
                    )
                except NetworkingMeeting.DoesNotExist:
                    raise PermissionDenied(
                        "Meeting not found or not accepted."
                    )

                # Validate current user is one side and recipient is the other
                current_user_is_requester = (
                    meeting.requester.user_id == user.id
                )
                current_user_is_recipient = (
                    meeting.recipient.user_id == user.id
                )
                recipient_is_requester = (
                    meeting.requester.user_id == recipient_id
                )
                recipient_is_recipient = (
                    meeting.recipient.user_id == recipient_id
                )

                is_valid_meeting = (
                    (current_user_is_requester and recipient_is_recipient) or
                    (current_user_is_recipient and recipient_is_requester)
                )

                if not is_valid_meeting:
                    raise PermissionDenied(
                        "This meeting does not involve both users."
                    )

        user_ids = sorted([user.id, recipient_id])

        me_name = user.get_full_name() or user.username or f"User {user.id}"
        other_name = recipient.get_full_name() or recipient.username or f"User {recipient.id}"
        dm_title = f"{me_name} ↔ {other_name}"

        conv, created = Conversation.objects.get_or_create(
            user1_id=user_ids[0],
            user2_id=user_ids[1],
            defaults={
                "created_by": user,
                "title": dm_title,
            },
        )

        if not conv.title:
            conv.title = dm_title
            conv.save(update_fields=["title"])

        serializer = ConversationSerializer(conv, context={"request": request})
        status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        return Response(serializer.data, status=status_code)

    
    # views.py  (inside ConversationViewSet)
    @action(detail=False, methods=["get"], url_path="chat-groups")
    def chat_groups(self, request):
        """
        Return groups where the current user is an ACTIVE member.
        This ensures private groups the user is in are shown.
        """
        self._deny_guest(request)
        from groups.models import GroupMembership

        mems = (GroupMembership.objects
                .select_related("group")
                .filter(user=request.user, status=GroupMembership.STATUS_ACTIVE))  # active only

        out = []
        for gm in mems:
            g = gm.group
            avatar = ""
            ci = getattr(g, "cover_image", None)
            if ci:
                avatar = getattr(ci, "url", "") or ""
            out.append({"id": g.id, "name": g.name, "avatar": avatar})
        return Response(out, status=status.HTTP_200_OK)


    
    @action(detail=False, methods=["post"], url_path="ensure-event")
    def ensure_event(self, request):
        """
        Upsert an event chat. Accepts:
        { "event": <event_id>, "title": "..." }
        or legacy:
        { "room_key": "event:<id>", "title": "..." }
        Guarantees Conversation.event_id is set.
        """
        from events.models import Event

        title = (request.data.get("title") or "").strip()
        event_id = request.data.get("event")
        room_key = (request.data.get("room_key") or "").strip()

        # Parse event id from room_key if needed
        if not event_id and room_key.startswith("event:"):
            try:
                event_id = int(room_key.split(":", 1)[1])
            except Exception:
                event_id = None

        if not event_id:
            raise ValidationError({"event": "Provide event (id) or room_key like 'event:<id>'."})

        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            raise ValidationError({"event": "Invalid event id."})

        event = get_object_or_404(Event.objects.select_related("community"), pk=event_id)
        if self._is_guest_user(request.user):
            guest = getattr(request.user, "guest", None)
            if not guest or guest.event_id != event.id:
                raise PermissionDenied("Guest session is not valid for this event.")
        elif not user_can_access_event_chat(request.user, event=event):
            raise PermissionDenied("You are not allowed to access this event chat.")

        # One conversation per event
        conv, created = Conversation.objects.get_or_create(
            event=event,
            defaults={
                "created_by": None if self._is_guest_user(request.user) else request.user,
                "title": title or event.title,
            },
        )

        # Backfill/normalize
        changed = False
        if conv.event_id != event.id:
            conv.event = event
            changed = True
        if not conv.title:
            conv.title = title or event.title
            changed = True
        if room_key and not conv.room_key:
            conv.room_key = room_key
            changed = True

        if changed:
            conv.save(update_fields=["event", "title", "room_key"])

        serializer = ConversationSerializer(conv, context={"request": request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="ensure-lounge")
    def ensure_lounge(self, request):
        """
        Upsert a lounge table chat. Accepts:
        { "table_id": <lounge_table_id>, "title": "..." }
        """
        from events.models import LoungeTable, LoungeParticipant

        table_id = request.data.get("table_id") or request.data.get("table")
        title = (request.data.get("title") or "").strip()

        if not table_id:
            raise ValidationError({"table_id": "Provide a lounge table id."})

        try:
            table_id = int(table_id)
        except (TypeError, ValueError):
            raise ValidationError({"table_id": "Invalid lounge table id."})

        table = get_object_or_404(LoungeTable, pk=table_id)
        if self._is_guest_user(request.user):
            guest = getattr(request.user, "guest", None)
            if not guest or guest.event_id != table.event_id:
                raise PermissionDenied("Guest session is not valid for this room.")

        if self._is_guest_user(request.user):
            guest = getattr(request.user, "guest", None)
            is_seated = bool(guest and guest.lounge_table_id == table.id)
        else:
            is_seated = LoungeParticipant.objects.filter(
                table_id=table.id,
                user_id=request.user.id,
            ).exists()
        if not is_seated:
            raise PermissionDenied("You are not seated in this room.")

        conv, created = Conversation.objects.get_or_create(
            lounge_table=table,
            defaults={
                "created_by": None if self._is_guest_user(request.user) else request.user,
                "title": title or table.name,
            },
        )

        changed = False
        update_fields = []
        if not conv.title:
            conv.title = title or table.name
            changed = True
            update_fields.append("title")
        if changed:
            conv.save(update_fields=update_fields)

        serializer = ConversationSerializer(conv, context={"request": request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    
    # views.py  (inside ConversationViewSet)

    @action(detail=True, methods=["get"], url_path="members")
    def members(self, request, pk=None):
        """
        Return participants for this conversation.

        - DM: 2 users (user1, user2)
        - Group/Event: try group membership; fallback to message senders + creator
        """
        try:
            conv = (Conversation.objects
                    .select_related("user1__profile", "user2__profile")
                    .get(pk=pk))
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")

        def as_member(u, role=""):
            if not u:
                return None
            prof = getattr(u, "profile", None)
            name = (getattr(prof, "full_name", "") or u.get_full_name() or u.username).strip()

            # --- avatar resolution ---
            avatar = ""
            # primary: your profile image field
            if prof:
                img = getattr(prof, "user_image", None) or getattr(prof, "avatar", None)
                if img:
                    try:
                        avatar = getattr(img, "url", "") or str(img)
                    except Exception:
                        avatar = str(img) if img else ""

            # fallback: LinkedIn picture if present
            if not avatar:
                li = getattr(u, "linkedin", None)
                if li:
                    avatar = getattr(li, "picture_url", "") or ""

            return {
                "id": u.id,
                "name": name or f"User {u.id}",
                "avatar": avatar,
                "role": role,
                "is_you": (u.id == request.user.id),
            }

        members = []

        if conv.group_id is None and conv.event_id is None and getattr(conv, "lounge_table_id", None) is None:
            # Direct message
            for u in (conv.user1, conv.user2):
                m = as_member(u)
                if m:
                    members.append(m)
        elif getattr(conv, "lounge_table_id", None):
            try:
                from events.models import LoungeParticipant, GuestAttendee

                qs = (
                    LoungeParticipant.objects
                    .select_related("user__profile")
                    .filter(table_id=conv.lounge_table_id)
                    .order_by("joined_at", "user__id")
                )[:200]
                for lp in qs:
                    m = as_member(lp.user, "Member")
                    if m:
                        members.append(m)
                guest_qs = GuestAttendee.objects.filter(
                    lounge_table_id=conv.lounge_table_id
                ).order_by("id")[:200]
                for g in guest_qs:
                    members.append({
                        "id": f"guest_{g.id}",
                        "name": g.get_display_name(),
                        "avatar": "",
                        "role": "Guest",
                        "is_you": bool(getattr(request.user, "is_guest", False) and getattr(request.user, "guest", None) and request.user.guest.id == g.id),
                    })
            except Exception:
                pass
        else:
            added = False
            try:
                from groups.models import GroupMembership
                group_id = conv.group_id
                if not group_id and conv.room_key and conv.room_key.startswith("group:"):
                    try:
                        group_id = int(conv.room_key.split(":", 1)[1])
                    except Exception:
                        group_id = None

                if group_id:
                    qs = (GroupMembership.objects
                        .select_related("user__profile")
                        .filter(group_id=group_id)
                        .order_by("role", "user__id"))[:200]
                    role_title = {"owner": "Owner", "admin": "Admin", "moderator": "Moderator", "member": "Member"}
                    for gm in qs:
                        m = as_member(gm.user, role_title.get(getattr(gm, "role", ""), ""))
                        if m: members.append(m)
                    added = bool(members)
            except Exception:
                pass

            # ✅ NEW: Event attendees/hosts
            if not added and getattr(conv, "is_event_group", False) and conv.event_id:
                try:
                    from events.models import Event, EventRegistration
                    # Pull everyone who registered for this event, newest first (cap 200)
                    regs = (
                        EventRegistration.objects
                        .select_related("user__profile")
                        .filter(event_id=conv.event_id)
                        .order_by("-registered_at")[:200]   # <-- use registered_at (your field)
                    )

                    for r in regs:
                        m = as_member(r.user, "Attendee")
                        if m:
                            members.append(m)
                    added = bool(members)

                    # Always include the host/organizers at the top (no duplicates)
                    ev = Event.objects.select_related("created_by__profile").get(pk=conv.event_id)
                    if hasattr(ev, "organizers"):
                        for u in ev.organizers.all():
                            mm = as_member(u, "Organizer")
                            if mm and all(x["id"] != mm["id"] for x in members):
                                members.insert(0, mm)
                    if getattr(ev, "created_by_id", None):
                        host = as_member(ev.created_by, "Host")
                        if host and all(x["id"] != host["id"] for x in members):
                            members.insert(0, host)

                except Exception:
                    # Fallback: at least show host/organizers if registrations query fails
                    try:
                        from events.models import Event
                        ev = Event.objects.select_related("created_by__profile").get(pk=conv.event_id)
                        if hasattr(ev, "organizers"):
                            for u in ev.organizers.all():
                                mm = as_member(u, "Organizer")
                                if mm:
                                    members.append(mm)
                        if getattr(ev, "created_by_id", None):
                            host = as_member(ev.created_by, "Host")
                            if host and all(x["id"] != host["id"] for x in members):
                                members.insert(0, host)
                        added = bool(members)
                    except Exception:
                        pass

            # Fallback: distinct message senders + creator (existing code continues)
            if not added:
                sender_ids = (Message.objects
                            .filter(conversation=conv, is_hidden=False, is_deleted=False)
                            .values_list("sender_id", flat=True)
                            .distinct())[:200]
                for u in User.objects.filter(id__in=list(sender_ids)).select_related("profile"):
                    m = as_member(u)
                    if m: members.append(m)
                if conv.created_by_id and all(x["id"] != conv.created_by_id for x in members):
                    m = as_member(conv.created_by, role="Owner")
                    if m: members.insert(0, m)

        return Response(members, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=["post"], url_path="mark-all-read")
    def mark_all_read(self, request, pk=None):
        try:
            conv = Conversation.objects.get(pk=pk)
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")

        user = request.user
        if self._is_guest_user(user):
            return Response({"ok": True, "marked": 0, "skipped": "guest"}, status=status.HTTP_200_OK)
        if not conv.user_can_view(user):
            raise PermissionDenied("You are not a participant of this conversation.")

        # unread = messages not mine and without my receipt
        qs = (
            Message.objects
            .filter(conversation=conv, is_hidden=False, is_deleted=False)
            .exclude(sender_id=user.id)
            .exclude(read_receipts__user_id=user.id)
            .only("id")
        )

        to_create = [
            MessageReadReceipt(message_id=m.id, user_id=user.id, read_at=timezone.now())
            for m in qs
        ]
        MessageReadReceipt.objects.bulk_create(to_create, ignore_conflicts=True)

        return Response({"ok": True, "marked": len(to_create)}, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=["get"], url_path="chat-events")
    def chat_events(self, request):
        """
        Return events the current user is associated with (created or registered).
        Kept simple to match MessagesPage.jsx.normalizeEvents().
        """
        user = request.user
        if self._is_guest_user(user):
            guest = getattr(user, "guest", None)
            if not guest:
                return Response([], status=status.HTTP_200_OK)
            try:
                ev = Event.objects.get(pk=guest.event_id)
            except Event.DoesNotExist:
                return Response([], status=status.HTTP_200_OK)
            return Response([{
                "id": ev.id,
                "title": getattr(ev, "title", "") or getattr(ev, "name", "") or f"Event #{ev.id}",
                "cover_image": getattr(ev, "cover_image", "") or getattr(ev, "banner", "") or "",
                "event": {"id": ev.id, "title": getattr(ev, "title", "") or getattr(ev, "name", ""), "end_time": ev.end_time, "status": ev.status},
                "end_time": ev.end_time,
                "status": ev.status,
            }], status=status.HTTP_200_OK)
        out = []

        # registrations (cap to 200)
        regs = (EventRegistration.objects
                .select_related("event")
                .filter(user_id=user.id)
                .order_by("-registered_at")[:200])
        for r in regs:
            ev = r.event
            out.append({
                "id": ev.id,
                "title": getattr(ev, "title", "") or getattr(ev, "name", "") or f"Event #{ev.id}",
                "cover_image": getattr(ev, "cover_image", "") or getattr(ev, "banner", "") or "",
                "event": {"id": ev.id, "title": getattr(ev, "title", "") or getattr(ev, "name", ""), "end_time": ev.end_time, "status": ev.status},
                "end_time": ev.end_time,
                "status": ev.status,
            })

        # events created by me (if not already present)
        mine = Event.objects.filter(created_by_id=user.id)[:200]
        seen = {x["id"] for x in out}
        for ev in mine:
            if ev.id in seen:
                continue
            out.append({
                "id": ev.id,
                "title": getattr(ev, "title", "") or getattr(ev, "name", "") or f"Event #{ev.id}",
                "cover_image": getattr(ev, "cover_image", "") or getattr(ev, "banner", "") or "",
                "event": {"id": ev.id, "title": getattr(ev, "title", "") or getattr(ev, "name", ""), "end_time": ev.end_time, "status": ev.status},
                "end_time": ev.end_time,
                "status": ev.status,
            })

        return Response(out, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=["get"], url_path="staff-list")
    def staff_list(self, request):
        """
        Internal staff-messaging helper:
        Return all active staff + owners (superusers) with
        presence info from UserProfile (is_online, last_activity_at).
        Only staff/owners can access this endpoint.
        """
        user = request.user
        if not (user.is_staff or user.is_superuser):
            logger.warning(
                "staff-list forbidden for user=%s (id=%s, is_staff=%s, is_superuser=%s)",
                getattr(user, "username", "anon"),
                getattr(user, "id", None),
                getattr(user, "is_staff", None),
                getattr(user, "is_superuser", None),
            )
            raise PermissionDenied("Staff messaging is only available to staff users.")

        User = get_user_model()

        qs = (
            User.objects.filter(is_active=True)
            .filter(models.Q(is_staff=True) | models.Q(is_superuser=True))
            .select_related("profile")
            .order_by("first_name", "last_name", "id")
        )

        out = []
        for u in qs:
            prof = getattr(u, "profile", None)

            # fallback full name
            full_name = (
                (getattr(prof, "full_name", "") or "").strip()
                or u.get_full_name()
                or u.username
                or u.email
            ).strip()

            # Avatar resolution (same logic as before)
            avatar = ""
            if prof:
                img = getattr(prof, "user_image", None) or getattr(prof, "avatar", None)
                if img:
                    try:
                        avatar = getattr(img, "url", "") or str(img)
                    except Exception:
                        avatar = str(img) if img else ""
            if not avatar:
                li = getattr(u, "linkedin", None)
                if li:
                    avatar = getattr(li, "picture_url", "") or ""

            # ✅ NEW: embed mini profile with presence info
            profile_payload = None
            if prof is not None:
                profile_payload = {
                    "full_name": prof.full_name or full_name,
                    "job_title": prof.job_title or "",
                    "headline": prof.headline or "",
                    "company": prof.company or "",
                    "location": prof.location or "",
                    "last_activity_at": prof.last_activity_at,
                    "is_online": getattr(prof, "is_online", False),
                }

            out.append(
                {
                    "id": u.id,
                    "first_name": u.first_name,
                    "last_name": u.last_name,
                    "username": u.username,
                    "email": u.email,
                    "display_name": full_name,
                    "avatar_url": avatar,
                    "is_staff": u.is_staff,
                    "is_superuser": u.is_superuser,
                    "profile": profile_payload,   # ✅ IMPORTANT
                }
            )

        return Response(out, status=status.HTTP_200_OK)

    
# messaging/views.py

class MessageViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated, IsConversationParticipant]

    def get_throttles(self):
        # Only throttle message creation. Listing/history must keep the normal
        # global DRF throttles, otherwise users can hit send limits simply by
        # reading chat history.
        if getattr(self, "action", None) == "create":
            self.throttle_classes = [LiveChatMessageRateThrottle]
        return super().get_throttles()

    parser_classes = (JSONParser, FormParser, MultiPartParser)

    @staticmethod
    def _is_guest_user(user) -> bool:
        return bool(getattr(user, "is_guest", False))

    @staticmethod
    def _parse_positive_int(value, default, *, max_value=None):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        parsed = max(1, parsed)
        if max_value is not None:
            parsed = min(parsed, max_value)
        return parsed

    @staticmethod
    def _wants_cursor_response(request) -> bool:
        raw = str(request.query_params.get("cursor", "")).lower()
        return raw in {"1", "true", "yes"}

    def _get_conversation_id(self):
        # Accept common kwarg names from DRF-Nested or custom routers
        conv_id = (
            self.kwargs.get("conversation_pk")
            or self.kwargs.get("conversation_id")
            or self.request.query_params.get("conversation")
        )
        if not conv_id:
            raise ValidationError({"conversation": "Missing conversation id in URL."})
        try:
            return int(conv_id)
        except (TypeError, ValueError):
            raise ValidationError({"conversation": "Invalid conversation id."})

    def get_queryset(self):
        conv_id = self._get_conversation_id()  # robust across routers
        my_receipts = Prefetch(
            "read_receipts",
            queryset=MessageReadReceipt.objects.filter(user_id=self.request.user.id),
            to_attr="my_receipts",
        )

        pinned_subq = ConversationPinnedMessage.objects.filter(message_id=OuterRef("id"))

        return (
            Message.objects
            .filter(conversation_id=conv_id, is_hidden=False, is_deleted=False)
            .annotate(is_pinned=Exists(pinned_subq))   # 👈 add this
            .select_related("sender__profile", "guest_sender", "event")
            .prefetch_related(my_receipts)
            .order_by("created_at")
        )

    
    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()

        limit = self._parse_positive_int(
            request.query_params.get("limit"),
            default=10,
            max_value=50,
        )

        before_id = request.query_params.get("before_id")
        after_id = request.query_params.get("after_id")

        if after_id:
            after_id = self._parse_positive_int(after_id, default=0)
            rows = list(qs.filter(id__gt=after_id).order_by("id")[:limit])
            has_more = False
        else:
            if before_id:
                before_id = self._parse_positive_int(before_id, default=0)
                qs = qs.filter(id__lt=before_id)

            rows = list(qs.order_by("-id")[: limit + 1])
            has_more = len(rows) > limit
            rows = rows[:limit]
            rows.reverse()

        serializer = self.get_serializer(rows, many=True)
        data = serializer.data

        if not self._wants_cursor_response(request):
            return Response(data)

        return Response({
            "results": data,
            "has_more": has_more,
            "oldest_id": rows[0].id if rows else None,
            "newest_id": rows[-1].id if rows else None,
            "next_before_id": rows[0].id if has_more and rows else None,
        })

    def create(self, request, *args, **kwargs):
        # 1. Resolve Conversation & Permissions
        conv_id = self._get_conversation_id()
        try:
            conv = Conversation.objects.select_related("lounge_table__event").get(pk=conv_id)
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")
        
        user = request.user
        if not conv.user_can_view(user):
            raise PermissionDenied("You are not a participant of this conversation.")

        # Breakout tables are reused between rounds. Once all breakouts are
        # ended, do not allow a stale room-chat request to create a new message
        # after cleanup. This check applies only to BREAKOUT room chats; public
        # chat, private chat, group chat, and normal Social Lounge chat are not
        # affected.
        lounge_table = getattr(conv, "lounge_table", None)
        if lounge_table is not None and getattr(lounge_table, "category", None) == "BREAKOUT":
            event = getattr(lounge_table, "event", None)
            if not event or not getattr(event, "breakout_rooms_active", False):
                return Response(
                    {"detail": "Breakout room chat is closed."},
                    status=status.HTTP_409_CONFLICT,
                )
        # DM Access Check
        if (conv.group_id is None and conv.event_id is None and getattr(conv, "lounge_table_id", None) is None) and user.id not in (conv.user1_id, conv.user2_id):
            raise PermissionDenied("You are not a participant of this conversation.")

        # Room/conversation-level burst protection. Per-user DRF throttling is
        # not enough when many users send at the same moment during a live
        # meeting. This keeps one noisy room/conversation from creating a
        # DB/Redis broadcast spike while still allowing normal discussion.
        is_direct_message = (
            conv.group_id is None
            and conv.event_id is None
            and getattr(conv, "lounge_table_id", None) is None
        )
        if is_direct_message or conv.lounge_table_id or conv.event_id or conv.group_id:
            window = int(getattr(settings, "LIVE_CHAT_ROOM_RATE_WINDOW_SECONDS", 10))
            if is_direct_message:
                limit = int(getattr(settings, "LIVE_DM_CHAT_BURST_LIMIT", 12))
                scope = f"dm:{conv.id}"
            elif conv.lounge_table_id:
                limit = int(getattr(settings, "LIVE_ROOM_CHAT_BURST_LIMIT", 25))
                scope = f"lounge:{conv.lounge_table_id}"
            elif conv.event_id:
                limit = int(getattr(settings, "LIVE_EVENT_CHAT_BURST_LIMIT", 80))
                scope = f"event:{conv.event_id}"
            else:
                limit = int(getattr(settings, "LIVE_GROUP_CHAT_BURST_LIMIT", 40))
                scope = f"group:{conv.group_id}"

            limited, count = _cache_window_limited(
                f"live-chat-burst:{scope}", limit=limit, window_seconds=window
            )
            if limited:
                raise Throttled(wait=window, detail="Chat is very busy. Please try again in a few seconds.")

        # 2. Extract Data
        body_text = request.data.get("body", "")
        raw_event_id = request.data.get("event_id")
        # Get raw files from FormData (React sends 'attachments')
        files = request.FILES.getlist('attachments') 

        if not body_text and not files:
             return Response({"detail": "Empty message"}, status=status.HTTP_400_BAD_REQUEST)

        message_event = None
        if raw_event_id not in (None, "", "null"):
            try:
                message_event_id = int(raw_event_id)
            except (TypeError, ValueError):
                raise ValidationError({"event_id": "Invalid event id."})

            message_event = get_object_or_404(Event.objects.select_related("community"), pk=message_event_id)
            if not user_can_access_event_chat(user, event=message_event):
                raise PermissionDenied("You are not allowed to attach this event context.")

        # If frontend did not pass event_id, infer it from the conversation.
        # This keeps public and breakout chat messages tied to the event for metrics/debugging
        # without changing public/private/breakout conversation storage behavior.
        if message_event is None:
            if getattr(conv, "event_id", None):
                message_event = conv.event
            elif getattr(conv, "lounge_table_id", None):
                message_event = getattr(conv.lounge_table, "event", None)

        # 3. Upload Files to S3 Manually
        import uuid
        uploaded_attachments = []
        
        for file_obj in files:
            # Generate unique filename: uuid-filename.ext
            ext = file_obj.name.split('.')[-1] if '.' in file_obj.name else 'bin'
            filename = f"{uuid.uuid4()}.{ext}"
            file_path = f"chat-attachments/{conv_id}/{filename}"
            
            # Save to S3 (uses default_storage from settings)
            saved_path = default_storage.save(file_path, file_obj)
            file_url = default_storage.url(saved_path)
            
            # Create the JSON object for your ArrayField
            uploaded_attachments.append({
                "url": file_url,
                "path": saved_path,  
                "name": file_obj.name,
                "type": file_obj.content_type,
                "size": file_obj.size
            })

        # 4. Create Message Object
        # We manually create the object to bypass Serializer validation 
        # (Serializer expects JSON for attachments, but we received Files)
        if self._is_guest_user(user):
            message = Message.objects.create(
                conversation=conv,
                sender=None,
                guest_sender=getattr(user, "guest", None),
                body=body_text,
                attachments=uploaded_attachments,
                event=message_event,
            )
        else:
            message = Message.objects.create(
                conversation=conv,
                sender=user,
                body=body_text,
                attachments=uploaded_attachments,
                event=message_event,
            )

        live_metric_incr("chat_message_created", event_id=getattr(message_event, "id", None) or getattr(conv, "event_id", None))

        # 5. Return Response
        serializer = self.get_serializer(message)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def get_object(self):
        conv_id = self._get_conversation_id()
        obj = get_object_or_404(
            Message.objects.select_related("conversation", "sender__profile", "guest_sender", "event"),
            pk=self.kwargs.get(self.lookup_field),
            conversation_id=conv_id,
            is_hidden=False,
            is_deleted=False,
        )
        self.check_object_permissions(self.request, obj)
        return obj

    def _is_host_for_conversation(self, user, conv: Conversation) -> bool:
        if getattr(user, "is_staff", False) or getattr(user, "is_superuser", False):
            return True
        try:
            if conv.event_id:
                return getattr(conv.event, "created_by_id", None) == user.id
            if conv.lounge_table_id:
                event = getattr(conv.lounge_table, "event", None)
                return getattr(event, "created_by_id", None) == user.id
            if conv.group_id:
                return getattr(conv.group, "owner_id", None) == user.id
        except Exception:
            return False
        return False

    def _can_moderate_message(self, user, msg: Message) -> bool:
        if not user or not getattr(user, "is_authenticated", False):
            return False
        if getattr(user, "is_guest", False):
            guest = getattr(user, "guest", None)
            if guest and msg.guest_sender_id == guest.id:
                return True
        if msg.sender_id == user.id:
            return True
        conv = getattr(msg, "conversation", None)
        return bool(conv and self._is_host_for_conversation(user, conv))

    def update(self, request, *args, **kwargs):
        msg = self.get_object()
        if not self._can_moderate_message(request.user, msg):
            raise PermissionDenied("Not allowed to edit this message.")
        body = request.data.get("body", "")
        if not str(body).strip():
            return Response({"detail": "Empty message"}, status=status.HTTP_400_BAD_REQUEST)
        msg.body = body
        msg.is_edited = True
        msg.edited_at = timezone.now()
        msg.save(update_fields=["body", "is_edited", "edited_at"])
        serializer = self.get_serializer(msg)
        return Response(serializer.data)

    def partial_update(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def perform_destroy(self, instance):
        if not self._can_moderate_message(self.request.user, instance):
            raise PermissionDenied("Not allowed to delete this message.")
        instance.is_deleted = True
        instance.deleted_at = timezone.now()
        instance.body = "This message was deleted"
        instance.save()
        # The record remains in DB with placeholder body so conversation thread is readable

    @action(detail=True, methods=["post"], url_path="flag")
    def flag(self, request, *args, **kwargs):
        msg = self.get_object()
        user = request.user
        MessageFlag.objects.get_or_create(message=msg, user=user)
        return Response({"ok": True})
    
    @action(detail=True, methods=["get"], url_path="download-attachment")
    def download_attachment(self, request, *args, **kwargs):
        """
        Download one of this message's attachments as a file.

        Expects query param ?index=0,1,...
        URL (nested): /api/messaging/conversations/<cid>/messages/<mid>/download-attachment/?index=0
        """
        # Uses nested router conversation_pk + pk
        message = self.get_object()

        # Which attachment index?
        try:
            idx = int(request.query_params.get("index", 0))
        except (TypeError, ValueError):
            raise NotFound("Invalid attachment index.")

        attachments = message.attachments or []
        if idx < 0 or idx >= len(attachments):
            raise NotFound("Attachment not found.")

        att = attachments[idx]
        url = att.get("url")
        if not url:
            raise NotFound("Attachment URL missing.")

        # Convert S3 URL → storage path: /chat-attachments/... → chat-attachments/...
        parsed = urlparse(url)
        storage_path = parsed.path.lstrip("/")

        # Make sure file exists in storage
        if not default_storage.exists(storage_path):
            raise NotFound("File not found.")

        # Open & stream as attachment
        file_obj = default_storage.open(storage_path, "rb")
        filename = att.get("name") or storage_path.rsplit("/", 1)[-1]
        content_type = att.get("type") or "application/octet-stream"

        response = FileResponse(file_obj, as_attachment=True, filename=filename)
        response["Content-Type"] = content_type

        size = att.get("size")
        if size:
            response["Content-Length"] = str(size)

        return response

        
    
class MarkMessageReadView(GenericAPIView):
    permission_classes = [IsAuthenticated, IsConversationParticipant]
    serializer_class = MessageSerializer

    def post(self, request, pk):
        try:
            msg = Message.objects.select_related("conversation").get(pk=pk)
        except Message.DoesNotExist:
            raise NotFound("Message not found.")

        conv = msg.conversation
        user = request.user

        # restrict to conversation's participants
        if not conv.user_can_view(user):
            raise PermissionDenied("You are not a participant of this conversation.")

        if bool(getattr(user, "is_guest", False)):
            return Response({"ok": True, "skipped": "guest"}, status=status.HTTP_200_OK)

        # don't read your own outbound message
        if msg.sender_id == user.id:
            return Response({"ok": True, "skipped": "own-message"}, status=status.HTTP_200_OK)

        MessageReadReceipt.objects.get_or_create(
            message=msg, user=user, defaults={"read_at": timezone.now()}
        )
        return Response({"ok": True}, status=status.HTTP_200_OK)
   
