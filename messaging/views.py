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

        # Groups where this user is a member (same logic as /groups/joined-groups/)
        member_statuses = [
            GroupMembership.STATUS_ACTIVE,
            GroupMembership.STATUS_PENDING,
        ]
        member_group_ids = GroupMembership.objects.filter(
            user=user,
            status__in=member_statuses,
        ).values_list("group_id", flat=True)

        # Include:
        # - DMs I'm in
        # - Group rooms ONLY where I'm a member
        # - Event rooms (kept open as before)
        qs = Conversation.objects.filter(
            Q(user1=user)
            | Q(user2=user)
            | Q(group_id__in=member_group_ids)
            | Q(event__isnull=False)
        )

        qs = qs.select_related(
            "user1__profile",
            "user2__profile",
            "group",
            "event",
        ).prefetch_related(
            models.Prefetch(
                "messages",
                queryset=Message.objects.filter(is_hidden=False, is_deleted=False),
            )
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

        conv, created = Conversation.objects.get_or_create(
            user1_id=user_ids[0],
            user2_id=user_ids[1],
        )

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
   