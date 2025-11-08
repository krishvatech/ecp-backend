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
from django.db.models import Q, Prefetch
from rest_framework import viewsets, mixins, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, ValidationError, PermissionDenied
from rest_framework.generics import GenericAPIView

from .models import Conversation, Message, MessageReadReceipt
from .serializers import ConversationSerializer, MessageSerializer
from .permissions import IsConversationParticipant
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone 
from events.models import Event, EventRegistration

User = get_user_model()


class ConversationViewSet(viewsets.ViewSet):
    """ViewSet for listing, creating and retrieving conversations."""

    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self, request):
        user = request.user
        # Include DMs I’m in + all group/event rooms
        qs = Conversation.objects.filter(
            Q(user1=user) | Q(user2=user) | Q(group__isnull=False) | Q(event__isnull=False)
        )
        qs = qs.select_related("user1__profile", "user2__profile", "group", "event").prefetch_related(
            models.Prefetch("messages", queryset=Message.objects.filter(is_hidden=False, is_deleted=False))
        )
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
            qs = qs.filter(
                other_user1
                | other_user2
                | Q(group__isnull=False, title__icontains=q)
                | Q(event__isnull=False, title__icontains=q)
                # bonus: match actual related names too
                | Q(group__name__icontains=q)
                | Q(event__title__icontains=q)
            )
        return qs


    def list(self, request, *args, **kwargs):
        qs = self.get_queryset(request)  # <-- use filtered queryset
        serializer = ConversationSerializer(qs, many=True, context={"request": request})
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        obj = (Conversation.objects
            .select_related("group", "event", "user1__profile", "user2__profile")
            .get(pk=kwargs["pk"]))
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
            try:
                group_id = int(group_id)
            except (TypeError, ValueError):
                raise ValidationError({"group": "Invalid group id."})
            group = get_object_or_404(Group, pk=group_id)

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
        conv, created = Conversation.objects.get_or_create(
            user1_id=user_ids[0], user2_id=user_ids[1]
        )
        serializer = ConversationSerializer(conv, context={"request": request})
        status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        return Response(serializer.data, status=status_code)


    # --- NEW: ensure or return a per-event group room by room_key ---
    @action(detail=False, methods=["post"], url_path="ensure-group")
    def ensure_group(self, request):
        """
        Ensure a group conversation exists and is linked to the actual Group row.
        Accepts either:
        - {"group": <group_id>}
        - or legacy {"room_key": "group:<id>"} (kept for backward compatibility)
        """
        from groups.models import Group

        group_id = request.data.get("group")
        room_key = request.data.get("room_key") or ""
        title = (request.data.get("title") or "").strip()

        # If only room_key is provided, parse group id from it.
        if not group_id and room_key.startswith("group:"):
            try:
                group_id = int(room_key.split(":", 1)[1])
            except Exception:
                group_id = None

        group = None
        if group_id:
            group = get_object_or_404(Group, pk=int(group_id))

        # Prefer to identify a conversation by the Group FK when available.
        if group:
            conv, created = Conversation.objects.get_or_create(
                group=group,
                defaults={
                    "created_by": request.user,
                    "title": title or group.name,
                },
            )
        else:
            # Fallback: legacy room_key flow
            if not room_key:
                raise ValidationError({"group": "group id (or room_key) is required."})
            conv, created = Conversation.objects.get_or_create(
                room_key=room_key,
                defaults={
                    "created_by": request.user,
                    "title": title,
                },
            )

        # Backfill: if conv was created earlier via room_key, attach the FK now.
        changed = False
        if group and conv.group_id != group.id:
            conv.group = group
            changed = True
        if not conv.title:
            conv.title = title or (group.name if group else "")
            changed = True
        if changed:
            conv.save(update_fields=["group", "title"])

        ser = ConversationSerializer(conv, context={"request": request})
        return Response(ser.data, status=status.HTTP_200_OK)

    
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

        if conv.group_id is None and conv.event_id is None:
            # Direct message
            for u in (conv.user1, conv.user2):
                m = as_member(u)
                if m:
                    members.append(m)
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
                "event": {"id": ev.id, "title": getattr(ev, "title", "") or getattr(ev, "name", "")},
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
                "event": {"id": ev.id, "title": getattr(ev, "title", "") or getattr(ev, "name", "")},
            })

        return Response(out, status=status.HTTP_200_OK)
    
# messaging/views.py

class MessageViewSet(mixins.ListModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated, IsConversationParticipant]

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
            to_attr="my_receipts",   # <- avoid name clash
        )
        return (
            Message.objects
            .filter(conversation_id=conv_id, is_hidden=False, is_deleted=False)
            .select_related("sender__profile")
            .prefetch_related(my_receipts)
            .order_by("created_at")
        )
    
    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        ser = MessageSerializer(qs, many=True, context={"request": request})
        return Response(ser.data)

    def perform_create(self, serializer):
        conv_id = self._get_conversation_id()
        try:
            conv = Conversation.objects.get(pk=conv_id)
        except Conversation.DoesNotExist:
            raise NotFound("Conversation not found.")
        user = self.request.user
        # DM access check (groups/events are open to any authed user by your current logic)
        if (conv.group_id is None and conv.event_id is None) and user.id not in (conv.user1_id, conv.user2_id):
            raise PermissionDenied("You are not a participant of this conversation.")
        serializer.save(conversation=conv, sender=user)



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
