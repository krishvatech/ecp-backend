"""
Views for the messaging app.

Expose RESTful endpoints for creating and listing conversations and
their messages. Authentication is required for all endpoints.
This version supports:
 - Direct (1:1) conversations
 - Group rooms (e.g., per-event) via POST /conversations/ensure-group/
"""
from __future__ import annotations
from django.db import models
from django.contrib.auth import get_user_model
from django.db.models import Q, Prefetch,Exists, OuterRef
from rest_framework import viewsets, mixins, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, ValidationError, PermissionDenied
from rest_framework.generics import GenericAPIView
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from django.core.files.storage import default_storage
from django.http import FileResponse, Http404
from django.http import FileResponse
from urllib.parse import urlparse


from .models import Conversation, Message, MessageReadReceipt,ConversationPinnedMessage,ConversationPin
from .serializers import ConversationSerializer, MessageSerializer,ConversationPinnedMessageOutSerializer
from .permissions import IsConversationParticipant
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone 
from events.models import Event, EventRegistration
from rest_framework.exceptions import PermissionDenied
import logging

logger = logging.getLogger(__name__)

User = get_user_model()


class ConversationViewSet(viewsets.ViewSet):
    """ViewSet for listing, creating and retrieving conversations."""

    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self, request):
        user = request.user
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
        ).values_list("group_id", flat=True)

        # Events where this user is registered or created the event
        registered_event_ids = EventRegistration.objects.filter(
            user_id=user.id
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
        )

        qs = qs.select_related(
            "user1__profile",
            "user2__profile",
            "group",
            "event",
            "lounge_table",
        ).prefetch_related(
            models.Prefetch(
                "messages",
                queryset=Message.objects.filter(is_hidden=False, is_deleted=False),
            )
        )

        is_pinned_subquery = ConversationPin.objects.filter(
            conversation=OuterRef('pk'), 
            user=user
        )
        qs = qs.annotate(is_pinned=Exists(is_pinned_subquery))
        
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


    def list(self, request, *args, **kwargs):
        qs = self.get_queryset(request)  # <-- use filtered queryset
        serializer = ConversationSerializer(qs, many=True, context={"request": request})
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
            event = get_object_or_404(Event, pk=event_id)
            can_access_event = (
                event.created_by_id == user.id
                or EventRegistration.objects.filter(user_id=user.id, event_id=event.id).exists()
            )
            if not can_access_event:
                raise PermissionDenied("You are not registered for this event.")

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

        Accepts any of:
        - {"recipient_id": <user_id>}   # preferred
        - {"user_id": <user_id>}
        - {"user": <user_id>}
        - {"id": <user_id>}
        """
        from rest_framework.exceptions import ValidationError

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

        event = get_object_or_404(Event, pk=event_id)

        # One conversation per event
        conv, created = Conversation.objects.get_or_create(
            event=event,
            defaults={
                "created_by": request.user if request.user.is_authenticated else None,
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

        is_seated = LoungeParticipant.objects.filter(
            table_id=table.id,
            user_id=request.user.id,
        ).exists()
        if not is_seated:
            raise PermissionDenied("You are not seated in this room.")

        conv, created = Conversation.objects.get_or_create(
            lounge_table=table,
            defaults={
                "created_by": request.user if request.user.is_authenticated else None,
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
                from events.models import LoungeParticipant

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
    mixins.RetrieveModelMixin,   # <-- add
    mixins.DestroyModelMixin,    # <-- add
    viewsets.GenericViewSet,
):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated, IsConversationParticipant]
    
    parser_classes = (JSONParser, FormParser, MultiPartParser)

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
            .select_related("sender__profile")
            .prefetch_related(my_receipts)
            .order_by("created_at")
        )

    
    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        ser = MessageSerializer(qs, many=True, context={"request": request})
        return Response(ser.data)

    def create(self, request, *args, **kwargs):
        # 1. Resolve Conversation & Permissions
        conv_id = self._get_conversation_id()
        try:
            conv = Conversation.objects.get(pk=conv_id)
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")
        
        user = request.user
        # DM Access Check
        if (conv.group_id is None and conv.event_id is None and getattr(conv, "lounge_table_id", None) is None) and user.id not in (conv.user1_id, conv.user2_id):
            raise PermissionDenied("You are not a participant of this conversation.")

        # 2. Extract Data
        body_text = request.data.get("body", "")
        # Get raw files from FormData (React sends 'attachments')
        files = request.FILES.getlist('attachments') 

        if not body_text and not files:
             return Response({"detail": "Empty message"}, status=status.HTTP_400_BAD_REQUEST)

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
        message = Message.objects.create(
            conversation=conv,
            sender=user,
            body=body_text,
            attachments=uploaded_attachments 
        )

        # 5. Return Response
        serializer = self.get_serializer(message)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def get_object(self):
        conv_id = self._get_conversation_id()
        obj = get_object_or_404(
            Message.objects.select_related("conversation", "sender__profile"),
            pk=self.kwargs.get(self.lookup_field),
            conversation_id=conv_id,
            is_hidden=False,
            is_deleted=False,
        )
        self.check_object_permissions(self.request, obj)
        return obj

    def perform_destroy(self, instance):
        instance.is_deleted = True
        from django.utils import timezone
        instance.deleted_at = timezone.now()
        instance.save() 
        # The record remains in DB, but get_queryset() filters it out for users
    
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

        # don't read your own outbound message
        if msg.sender_id == user.id:
            return Response({"ok": True, "skipped": "own-message"}, status=status.HTTP_200_OK)

        MessageReadReceipt.objects.get_or_create(
            message=msg, user=user, defaults={"read_at": timezone.now()}
        )
        return Response({"ok": True}, status=status.HTTP_200_OK)
   
