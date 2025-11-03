from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.db.models import Count, Q
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import NotFound
from django.utils import timezone
from urllib.parse import urljoin
from django.db import transaction
from django.core import signing
from django.core.files.storage import default_storage
from rest_framework import status, viewsets, serializers
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from rest_framework.views import APIView

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, inline_serializer, OpenApiParameter, OpenApiExample

from community.models import Community
from .models import Group, GroupMembership, PromotionRequest, GroupPinnedMessage, GroupPoll, GroupPollOption, GroupPollVote
from .permissions import GroupCreateByAdminOnly, is_moderator, can_moderate_content
from .serializers import (
    GroupSerializer,
    GroupMemberOutSerializer,
    CreateFeedPostSerializer,
    FeedItemIdSerializer,
    GroupSettingsSerializer,
    GroupPinnedMessageOutSerializer,
    GroupPollCreateSerializer,
    GroupPollOutSerializer,
    GroupPollVoteInSerializer,
    CreatePollSerializer,
    PromotionRequestCreateSerializer,
    PromotionRequestOutSerializer,
)


class GroupViewSet(viewsets.ModelViewSet):
    """
    Existing:
    - GET   /api/groups/?created_by=me&search=term
    - POST  /api/groups/                  (staff via GroupCreateByAdminOnly)
    - GET   /api/groups/{id-or-slug}/
    - PATCH /api/groups/{id-or-slug}/     (staff or creator)
    - DELETE /api/groups/{id-or-slug}/    (staff or creator)
    - GET   /api/groups/{id-or-slug}/members/
    - POST  /api/groups/{id-or-slug}/add-members/
    - POST  /api/groups/{id-or-slug}/remove-member/
    - GET   /api/groups/mine/

    NEW (Moderator-only features):
    - GET  /api/groups/{id}/moderator/can-i/
    - POST /api/groups/{id}/moderation/create-post/         {content}
    - POST /api/groups/{id}/moderation/delete-post/         {id}
    - POST /api/groups/{id}/moderation/hide-post/           {id}
    - POST /api/groups/{id}/moderation/unhide-post/         {id}
    - POST /api/groups/{id}/moderation/hide-message/        {message_id}
    - POST /api/groups/{id}/moderation/unhide-message/      {message_id}
    - POST /api/groups/{id}/moderation/delete-message/      {message_id}
    - POST /api/groups/{id}/request-promotion/              {reason?}

    Join / Link:
    - POST /api/groups/{id}/join           (handles open/public, approval/public, invite/private, approval/private+token)
    - GET  /api/groups/{id}/join-link      (owner/admin/staff; approval+private only)
    - POST /api/groups/{id}/join-link/rotate (owner/admin/staff; approval+private only)
    """
    JOIN_LINK_MAX_AGE = 7 * 24 * 3600  # 7 days
    serializer_class = GroupSerializer
    parser_classes = [JSONParser, MultiPartParser, FormParser]
    queryset = Group.objects.all()
    lookup_field = "pk"

    def get_permissions(self):
        admin_only = {
            "create", "update", "partial_update", "destroy",
        }
        auth_only = {
            # membership + management
            "mine", "members", "add_members", "remove_member",
            "approve_member_requests", "reject_member_requests", "request_add_members",
            "set_role", "change_role",
            # promotion flow
            "promotion_requests", "approve_promotion_requests", "reject_promotion_requests",
            "request_promotion",
            # moderator content tools
            "moderator_can_i",
            "moderation_create_post", "moderation_delete_post",
            "moderation_hide_post", "moderation_unhide_post",
            "moderation_hide_message", "moderation_unhide_message", "moderation_delete_message",
            # join/link endpoints
            "join", "join_link", "rotate_join_link",
            "settings_message_mode", "can_send",
        }

        if self.action == "create":
            data = getattr(self.request, "data", {}) or {}
            if data.get("parent_id") or data.get("parent"):
                return [IsAuthenticated()]
            return [GroupCreateByAdminOnly()]

        if self.action in admin_only:
            return [GroupCreateByAdminOnly()]
        if self.action in auth_only:
            return [IsAuthenticated()]
        return [IsAuthenticatedOrReadOnly()]

    # ----- join link helpers -----
    def _join_salt(self, group: Group) -> str:
        ts = int(group.updated_at.timestamp()) if group.updated_at else 0
        return f"group-join:{group.pk}:{ts}"

    def _make_join_token(self, group: Group) -> str:
        return signing.dumps({"gid": group.pk}, salt=self._join_salt(group))

    def _validate_join_token(self, token: str, group: Group) -> bool:
        try:
            data = signing.loads(token, max_age=self.JOIN_LINK_MAX_AGE, salt=self._join_salt(group))
            return int(data.get("gid")) == int(group.pk)
        except Exception:
            return False
        
    def _get_message_for_group(self, group, message_id):
        try:
            mid = int(message_id)
        except (TypeError, ValueError):
            return None, "Invalid message_id"

        Message = apps.get_model("messaging", "Message")
        msg = Message.objects.select_related("conversation").filter(pk=mid).first()
        if not msg:
            return None, "Message not found"
        conv = getattr(msg, "conversation", None)
        if not conv or not getattr(conv, "is_group", False) or getattr(conv, "group_id", None) != group.id:
            return None, "Message does not belong to this group"
        return msg, None
    
    def _can_send_message_to_group(self, request, group) -> (bool, str):
        """
        WhatsApp-like rule:
          - owners/admins/moderators/staff always allowed
          - if message_mode=all → ACTIVE members allowed
          - if message_mode=admins_only → members blocked
        """
        user = request.user
        uid = getattr(user, "id", None)
        if not uid or not user.is_authenticated:
            return False, "not_authenticated"

        if (
            getattr(user, "is_staff", False)
            or group.created_by_id == uid
            or getattr(group, "owner_id", None) == uid
            or self._is_admin(uid, group)
            or self._is_moderator(uid, group)
        ):
            return True, "elevated"

        if group.message_mode == Group.MSG_MODE_ALL and self._is_active_member(uid, group):
            return True, "member_allowed"

        return False, "admins_only"
    
    def _ensure_parent_membership_active(self, group: Group, user_id: int):
        if not group.parent_id:
            return
        GroupMembership.objects.get_or_create(
            group=group.parent,
            user_id=user_id,
            defaults={
                "role": GroupMembership.ROLE_MEMBER,
                "status": GroupMembership.STATUS_ACTIVE,   # parent is active once you join a child
            },
        )

    def _is_active_member(self, user_id, group) -> bool:
        return GroupMembership.objects.filter(
            group=group, user_id=user_id, status=GroupMembership.STATUS_ACTIVE
        ).exists()
    
    def _is_owner_admin_or_staff(self, user_id, group: Group) -> bool:
        return bool(
            user_id and (
                group.created_by_id == user_id
                or getattr(group, "owner_id", None) == user_id
                or self._is_admin(user_id, group)
                or getattr(self.request.user, "is_staff", False)
            )
        )

    def _user_short(self, u):
        if not u:
            return None
        name = getattr(u, "get_full_name", lambda: "")() or getattr(u, "username", "") or getattr(u, "email", None)
        return {"id": getattr(u, "id", None), "email": getattr(u, "email", None), "name": name}
    
    @action(detail=True, methods=["get", "post"], url_path="posts", parser_classes=[JSONParser, MultiPartParser, FormParser])
    def posts(self, request, pk=None):
        """
        GET  /api/groups/{id-or-slug}/posts/     -> list posts for the group
        POST /api/groups/{id-or-slug}/posts/     -> create a post (text | image | link | poll | event)
        Data shapes expected by your UI:
        text : {type:"text", text}
        image: {type:"image", text?, image=<file>}
        link : {type:"link",  url, text?}
        poll : {type:"poll",  question, options:[...>=2]}
        event: {type:"event", title, starts_at?, ends_at?, text?}
        """
        group = self.get_object()
        if group.parent_id:
            uid = getattr(request.user, "id", None)
            if not (
                self._can_moderate_any(request, group) or
                (uid and self._is_active_member(uid, group))
            ):
                return Response({"detail": "Only sub-group members can view its posts."}, status=403)
            
        FeedItem = self._get_feeditem_model()
        if not FeedItem:
            return Response({"detail": "activity_feed.FeedItem not installed"}, status=409)

        ct = ContentType.objects.get_for_model(Group)

        # ------- LIST -------
        if request.method.lower() == "get":
            items = (FeedItem.objects
                    .filter(target_content_type=ct, target_object_id=group.id)
                    .order_by("-created_at"))

            out = []
            for it in items:
                meta = it.metadata or {}
                t = (meta.get("type") or "post").lower()
                # Back-compat: our older "post" = simple text
                if t == "post" and "content" in meta:
                    t = "text"

                row = {
                    "id": it.id,
                    "type": t,
                    "created_at": getattr(it, "created_at", None),
                    "created_by": self._user_short(getattr(it, "actor", None)),
                }
                
                row["is_hidden"]  = bool(meta.get("is_hidden"))
                row["is_deleted"] = bool(meta.get("is_deleted"))

                if t == "text":
                    row["text"] = meta.get("text") or meta.get("content") or ""
                elif t == "image":
                    row["text"]  = meta.get("text") or ""
                    row["image"] = meta.get("image")  # URL/path saved below
                elif t == "link":
                    row["text"]  = meta.get("text") or ""
                    row["url"]   = meta.get("url")
                elif t == "poll":
                    row["question"] = meta.get("question") or ""
                    row["options"]  = meta.get("options") or []
                elif t == "event":
                    row["title"]     = meta.get("title") or ""
                    row["starts_at"] = meta.get("starts_at")
                    row["ends_at"]   = meta.get("ends_at")
                    row["text"]      = meta.get("text") or ""
                else:
                    # unknown type: still show raw
                    row.update(meta)

                # hide soft-deleted
                if meta.get("is_deleted"):
                    continue
                out.append(row)

            return Response(out)

        # ------- CREATE -------
        # Only owner/admin/moderator (your helper already knows this)
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        t = (request.data.get("type") or "text").strip().lower()

        meta = {"type": t, "group_id": group.id, "is_hidden": False, "is_deleted": False}

        if t == "text":
            text = (request.data.get("text") or "").strip()
            if not text:
                return Response({"detail": "text is required"}, status=400)
            meta["text"] = text

        elif t == "image":
            f = request.FILES.get("image")
            if not f:
                return Response({"detail": "image file is required"}, status=400)
            # store with default storage, keep URL/path in metadata
            path = default_storage.save(f"feed_images/{f.name}", f)
            try:
                url = default_storage.url(path)
            except Exception:
                url = path
            meta["image"] = url
            cap = (request.data.get("text") or "").strip()
            if cap:
                meta["text"] = cap

        elif t == "link":
            url = (request.data.get("url") or "").strip()
            if not url:
                return Response({"detail": "url is required"}, status=400)
            meta["url"]  = url
            meta["text"] = (request.data.get("text") or "").strip()

        elif t == "poll":
            question = (request.data.get("question") or "").strip()
            options = request.data.get("options") or []
            if not question or not isinstance(options, list) or len([o for o in options if str(o).strip()]) < 2:
                return Response({"detail": "poll requires question and at least two options"}, status=400)
            meta["question"] = question
            meta["options"]  = [str(o).strip() for o in options if str(o).strip()]

        elif t == "event":
            title = (request.data.get("title") or "").strip()
            if not title:
                return Response({"detail": "title is required"}, status=400)
            meta.update({
                "title": title,
                "starts_at": request.data.get("starts_at") or None,
                "ends_at":   request.data.get("ends_at") or None,
                "text": (request.data.get("text") or "").strip(),
            })

        else:
            return Response({"detail": f"Unsupported type '{t}'"}, status=400)

        item = FeedItem.objects.create(
            community=getattr(group, "community", None),
            event=None,
            actor=request.user,
            verb="posted",
            target_content_type=ct,
            target_object_id=group.id,
            metadata=meta,
        )
        return Response({"ok": True, "id": item.id}, status=201)
    
    # ---------- queryset / object helpers ----------
    def get_queryset(self):
        qs = Group.objects.all().annotate(member_count=Count("memberships"))
        created_by = self.request.query_params.get("created_by")
        search = self.request.query_params.get("search")

        if created_by == "me" and self.request.user.is_authenticated:
            qs = qs.filter(created_by=self.request.user)
        if search:
            qs = qs.filter(Q(name__icontains=search) | Q(description__icontains=search))
        return qs

    def get_object(self):
        lookup = self.kwargs.get("pk")
        base = self.get_queryset()
        if lookup is None:
            raise NotFound("Group not specified.")

        if str(lookup).isdigit():
            try:
                return base.get(pk=int(lookup))
            except Group.DoesNotExist:
                try:
                    return base.get(slug=str(lookup))
                except Group.DoesNotExist:
                    raise NotFound(f"Group '{lookup}' not found.")
        else:
            try:
                return base.get(slug=lookup)
            except Group.DoesNotExist:
                try:
                    return base.get(pk=int(lookup))
                except Exception:
                    pass
                raise NotFound(f"Group '{lookup}' not found.")

    # ----- ROLE CHECKS (with STAFF requirement for admin/mod) -----
    def _is_admin(self, user_id, group) -> bool:
        ADMIN = getattr(GroupMembership, "ROLE_ADMIN", "admin")
        # STAFF-ONLY ADMIN/MOD: must be staff
        return GroupMembership.objects.filter(
            group=group, user_id=user_id, role=ADMIN, user__is_staff=True
        ).exists()
    def _is_admin_any(self, user_id, group) -> bool:
        return GroupMembership.objects.filter(
            group=group, user_id=user_id, role=GroupMembership.ROLE_ADMIN
        ).exists()
    
    def _is_moderator(self, user_id, group) -> bool:
        MOD = getattr(GroupMembership, "ROLE_MODERATOR", "moderator")
        # STAFF-ONLY ADMIN/MOD: must be staff
        return GroupMembership.objects.filter(
            group=group, user_id=user_id, role=MOD, user__is_staff=True
        ).exists()

    # ---------- existing helpers ----------
    def _can_manage(self, request, group: Group) -> bool:
        uid = getattr(request.user, "id", None)
        return bool(
            request.user
            and request.user.is_authenticated
            and (
                request.user.is_staff
                or group.created_by_id == uid
                or (hasattr(group, "owner_id") and group.owner_id == uid)
            )
        )

    def _can_set_roles(self, request, group: Group) -> bool:
        uid = getattr(request.user, "id", None)
        return self._can_manage(request, group) or (uid and self._is_admin(uid, group))

    # ---------- create (ADMIN/STAFF only) ----------
    def create(self, request, *args, **kwargs):
        data = request.data
        parent_id = data.get("parent_id") or data.get("parent")
        uid = getattr(request.user, "id", None)

        # SUB-GROUP creation path
        if parent_id:
            try:
                parent = Group.objects.get(pk=int(parent_id))
            except Exception:
                return Response({"detail": "Invalid parent_id"}, status=400)

            # owner/creator OR admin (no staff requirement) OR site staff
            if not (
                self._can_manage(request, parent)        # owner/creator/staff on parent
                or self._is_admin_any(uid, parent)       # admin on parent (even if not staff)
                or getattr(request.user, "is_staff", False)
            ):
                return Response({"detail": "Only parent owner/admin can create sub-groups."}, status=403)

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)

            # force community to match parent
            group = serializer.save(
                created_by=request.user,
                owner=request.user,
                parent=parent,
                community=parent.community,
            )

            # (Optional) ensure the creator is a member of the new sub-group
            GroupMembership.objects.get_or_create(
                group=group, user=request.user,
                defaults={"role": GroupMembership.ROLE_MEMBER, "status": GroupMembership.STATUS_ACTIVE}
            )

            out = self.get_serializer(group)
            headers = self.get_success_headers(out.data)
            return Response(out.data, status=status.HTTP_201_CREATED, headers=headers)

        # TOP-LEVEL creation remains staff-only (your old rule)
        if not request.user.is_staff:
            return Response({"detail": "Only admins can create groups."}, status=403)

        # ... your existing top-level create logic (unchanged) ...
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        owner = request.user
        community_id = request.data.get("community_id") or request.data.get("community")
        community_obj = None

        if community_id:
            try:
                community_obj = Community.objects.get(pk=int(community_id))
            except Exception:
                return Response({"detail": "Invalid community_id"}, status=400)
        if community_obj is None and hasattr(owner, "owned_community"):
            community_obj = owner.owned_community.all().order_by("created_at").first()
        if community_obj is None and hasattr(owner, "community"):
            community_obj = owner.community.all().order_by("created_at").first()

        if community_obj is None:
            return Response({"detail": "No community found for this owner. Pass community_id explicitly."}, status=400)
        group = serializer.save(created_by=owner, owner=owner, community=community_obj)
        out = self.get_serializer(group)
        headers = self.get_success_headers(out.data)
        return Response(out.data, status=status.HTTP_201_CREATED, headers=headers)

    # ---------- update / partial_update (OWNER/ADMIN only) ----------
    def update(self, request, *args, **kwargs):
        group = self.get_object()
        if not self._can_manage(request, group):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        group = self.get_object()
        if not self._can_manage(request, group):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        remove_flag = request.data.get("remove_cover_image") or request.data.get("remove_cover")
        if str(remove_flag).lower() in {"1", "true", "yes"}:
            if getattr(group, "cover_image", None):
                try:
                    group.cover_image.delete(save=False)
                except Exception:
                    pass
                group.cover_image = None
                group.save(update_fields=["cover_image"])
        return super().partial_update(request, *args, **kwargs)

    # ---------- destroy (OWNER/ADMIN only) ----------
    def destroy(self, request, *args, **kwargs):
        group = self.get_object()
        if not self._can_manage(request, group):
            return Response({"detail": "Only owner/admin can delete a group."}, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)

    def perform_create(self, serializer):
        community = serializer.validated_data.get("community")
        if not community:
            community = Community.objects.filter(memberships__user=self.request.user).first()
        if not community:
            from rest_framework.exceptions import ValidationError, PermissionDenied
            raise ValidationError({"community_id": "Provide a community_id or join a community."})
        is_member = Community.objects.filter(
            id=community.id, memberships__user=self.request.user
        ).exists()
        if not is_member:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("You are not a member of this community.")
        group = serializer.save(community=community, created_by=self.request.user)

        FeedItem = getattr(self, "_get_feeditem_model", lambda: None)()
        if FeedItem:
            FeedItem.objects.create(
                community=community,
                event=None,
                actor=self.request.user,
                verb="group_created",
                target_content_type=ContentType.objects.get_for_model(Group),
                target_object_id=group.id,
                metadata={
                    "type": "group_created",
                    "group_id": group.id,
                    "name": group.name,
                    "slug": group.slug,
                },
            )

    @action(detail=False, methods=["get"])
    def mine(self, request):
        qs = self.get_queryset().filter(created_by=request.user)
        page = self.paginate_queryset(qs)
        ser = self.get_serializer(page or qs, many=True)
        return self.get_paginated_response(ser.data) if page is not None else Response(ser.data)

    @action(detail=True, methods=["get"], url_path="members")
    def members(self, request, pk=None):
        group = self.get_object()
        memberships = GroupMembership.objects.filter(group=group).select_related("user")
        return Response(GroupMemberOutSerializer(memberships, many=True).data)

    @action(detail=True, methods=["post"], url_path="add-members")
    def add_members(self, request, pk=None):
        """Owner/admin invites/adds users (explicit add = ACTIVE)."""
        group = self.get_object()
        if not self._can_manage(request, group):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        ids = request.data.get("user_ids") or []
        if not isinstance(ids, list):
            return Response({"detail": "user_ids must be a list of IDs"}, status=status.HTTP_400_BAD_REQUEST)

        default_role   = GroupMembership.ROLE_MEMBER
        STATUS_ACTIVE  = GroupMembership.STATUS_ACTIVE

        for uid in ids:
            try:
                uid = int(uid)
            except Exception:
                continue

            membership, created = GroupMembership.objects.get_or_create(
                group=group,
                user_id=uid,
                defaults={
                    "role": default_role,
                    "status": STATUS_ACTIVE,
                    "invited_by_id": getattr(request.user, "id", None),
                },
            )
            if not created and getattr(membership, "invited_by_id", None) is None:
                GroupMembership.objects.filter(pk=membership.pk).update(invited_by_id=getattr(request.user, "id", None))

        memberships = GroupMembership.objects.filter(group=group).select_related("user")
        if group.parent_id:
            parent = group.parent
            for uid in ids:
                try:
                    uid_int = int(uid)
                except Exception:
                    continue
                GroupMembership.objects.get_or_create(
                    group=parent,
                    user_id=uid_int,
                    defaults={"role": GroupMembership.ROLE_MEMBER, "status": GroupMembership.STATUS_ACTIVE,
                            "invited_by_id": getattr(request.user, "id", None)}
                )
        return Response(GroupMemberOutSerializer(memberships, many=True).data, status=status.HTTP_200_OK)

    @extend_schema(
        request=inline_serializer(
            name='RequestAddMembersBody',
            fields={
                'group_id': serializers.IntegerField(required=False),
                'user_ids': serializers.ListField(child=serializers.IntegerField(), required=False),
                'user_id': serializers.IntegerField(required=False),
            },
        ),
        examples=[
            OpenApiExample('Multiple users', value={'user_ids': [3, 4]}),
            OpenApiExample('Single user', value={'user_id': 3}),
            OpenApiExample('With group_id check', value={'group_id': 1, 'user_ids': [3, 4]}),
        ],
    )
    @action(detail=True, methods=["post"], url_path="request-add-members", parser_classes=[JSONParser])
    def request_add_members(self, request, pk=None):
        """
        Body: {"user_ids":[...]} or {"user_id": 3} (+ optional "group_id")
        Creates/updates memberships with status=PENDING and invited_by=request.user.
        """
        group = self.get_object()
        requester_id = getattr(request.user, "id", None)
        if not (request.user and request.user.is_authenticated and requester_id):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        # allow if owner/admin OR moderator of this group (and moderator must be staff due to _is_moderator)
        if not (self._can_manage(request, group) or self._is_moderator(requester_id, group)):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        body_gid = request.data.get("group_id")
        if body_gid is not None and int(body_gid) != int(group.pk):
            return Response({"detail": "group_id mismatch with URL"}, status=status.HTTP_400_BAD_REQUEST)

        ids = request.data.get("user_ids")
        if ids is None and request.data.get("user_id") is not None:
            ids = [request.data.get("user_id")]
        if not isinstance(ids, list):
            return Response({"detail": "user_ids must be a list (or pass user_id)"},
                            status=status.HTTP_400_BAD_REQUEST)

        default_role = GroupMembership.ROLE_MEMBER
        STATUS_ACTIVE = GroupMembership.STATUS_ACTIVE
        STATUS_PENDING = GroupMembership.STATUS_PENDING

        for uid in ids:
            try:
                uid = int(uid)
            except Exception:
                continue
            membership, created = GroupMembership.objects.get_or_create(
                group=group,
                user_id=uid,
                defaults={"role": default_role, "status": STATUS_PENDING, "invited_by_id": requester_id},
            )
            if not created:
                updates = {}
                if membership.status != STATUS_ACTIVE:
                    updates["status"] = STATUS_PENDING
                if getattr(membership, "invited_by_id", None) is None:
                    updates["invited_by_id"] = requester_id
                if updates:
                    GroupMembership.objects.filter(pk=membership.pk).update(**updates)

        memberships = GroupMembership.objects.filter(group=group).select_related("user")
        return Response(GroupMemberOutSerializer(memberships, many=True).data, status=status.HTTP_200_OK)

    @extend_schema(
        request=inline_serializer(
            name='ApproveMemberRequestsBody',
            fields={'user_ids': serializers.ListField(child=serializers.IntegerField())},
        ),
        examples=[OpenApiExample('Approve two', value={'user_ids': [3, 4]})],
    )
    @action(detail=True, methods=["post"], url_path="approve-member-requests", parser_classes=[JSONParser])
    def approve_member_requests(self, request, pk=None):
        group = self.get_object()
        if not self._can_set_roles(request, group):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        ids = request.data.get("user_ids") or []
        if not isinstance(ids, list):
            return Response({"detail": "user_ids must be a list of IDs"}, status=status.HTTP_400_BAD_REQUEST)

        STATUS_ACTIVE = GroupMembership.STATUS_ACTIVE
        STATUS_PENDING = GroupMembership.STATUS_PENDING

        # perform update
        GroupMembership.objects.filter(
            group=group, user_id__in=ids, status=STATUS_PENDING
        ).update(status=STATUS_ACTIVE)

        # 🔁 ensure parent memberships if this group is a sub-group
        if group.parent_id:
            for uid in ids:
                try:
                    uid_int = int(uid)
                except Exception:
                    continue
                self._ensure_parent_membership_active(group, uid_int)

        memberships = GroupMembership.objects.filter(group=group).select_related("user")
        return Response({"ok": True,
                        "members": GroupMemberOutSerializer(memberships, many=True).data})

    @extend_schema(
        request=inline_serializer(
            name='RejectMemberRequestsBody',
            fields={'user_ids': serializers.ListField(child=serializers.IntegerField())},
        ),
        examples=[OpenApiExample('Reject one', value={'user_ids': [5]})],
    )
    @action(detail=True, methods=["post"], url_path="reject-member-requests", parser_classes=[JSONParser])
    def reject_member_requests(self, request, pk=None):
        group = self.get_object()
        if not self._can_set_roles(request, group):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        ids = request.data.get("user_ids") or []
        if not isinstance(ids, list):
            return Response({"detail": "user_ids must be a list of IDs"}, status=status.HTTP_400_BAD_REQUEST)

        STATUS_PENDING = GroupMembership.STATUS_PENDING
        deleted, _ = GroupMembership.objects.filter(
            group=group, user_id__in=ids, status=STATUS_PENDING
        ).delete()

        memberships = GroupMemberOutSerializer(
            GroupMembership.objects.filter(group=group).select_related("user"), many=True
        ).data
        return Response({"ok": True, "deleted": deleted, "members": memberships})

    @action(detail=True, methods=["post"], url_path="remove-member")
    def remove_member(self, request, pk=None):
        group = self.get_object()
        if not self._can_manage(request, group):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        uid = request.data.get("user_id")
        if not uid:
            return Response({"detail": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            membership = GroupMembership.objects.get(group=group, user_id=uid)
        except GroupMembership.DoesNotExist:
            return Response({"detail": "Not a member"}, status=status.HTTP_404_NOT_FOUND)

        owner_user_id = getattr(group, "owner_id", None) or getattr(group, "created_by_id", None)
        if owner_user_id is not None and int(membership.user_id) == int(owner_user_id):
            return Response({"detail": "Cannot remove the owner"}, status=status.HTTP_400_BAD_REQUEST)

        membership.delete()
        return Response({"ok": True}, status=status.HTTP_200_OK)

    # ---------- MODERATOR CAPABILITIES ----------
    @action(detail=True, methods=["get"], url_path="moderator/can-i")
    def moderator_can_i(self, request, pk=None):
        group = self.get_object()
        uid = getattr(request.user, "id", None)
        out = {
            "is_owner_or_creator": (group.created_by_id == uid) or (getattr(group, "owner_id", None) == uid),
            "is_admin": self._is_admin(uid, group),
            "is_moderator": self._is_moderator(uid, group),
        }
        can = self._can_moderate_any(request, group)
        out.update({
            "can_moderate_content": can,
            "can_create_post": can,
            "can_delete_post": can,
            "can_hide_post": can,
            "can_unhide_post": can,
            "can_hide_message": can,
            "can_unhide_message": can,
            "can_delete_message": can,
        })
        return Response(out)

    # ===== helpers to access external apps =====
    def _get_feeditem_model(self):
        try:
            return apps.get_model('activity_feed', 'FeedItem')
        except Exception:
            return None

    def _get_message_model(self):
        try:
            return apps.get_model('messaging', 'Message')
        except Exception:
            return None

    # =========================
    # Moderator MANAGEMENT (PROMOTE)
    # =========================

    def _can_moderate_any(self, request, group) -> bool:
        """
        True if the user can moderate content for this group:
        site staff, group owner/creator, group admin, or group moderator.
        """
        uid = getattr(request.user, "id", None)
        return bool(
            request.user and request.user.is_authenticated and (
                request.user.is_staff
                or group.created_by_id == uid
                or getattr(group, "owner_id", None) == uid
                or self._is_admin(uid, group)
                or self._is_moderator(uid, group)
            )
        )

    # ===== FEED POSTS (stored as activity_feed.FeedItem with target=Group) =====
    @action(detail=True, methods=["post"], url_path="moderation/create-post")
    def moderation_create_post(self, request, pk=None):
        group = self.get_object()
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        FeedItem = self._get_feeditem_model()
        if not FeedItem:
            return Response({"detail": "activity_feed.FeedItem not installed"}, status=409)

        if (str(request.data.get("type") or "").lower() == "poll"):
            # seamlessly create a poll instead of a post
            group = self.get_object()
            return self._create_poll_internal(request, group)

        ser = CreateFeedPostSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        content = ser.validated_data["content"]

        ct = ContentType.objects.get_for_model(Group)
        metadata = {
            "type": "post",
            "content": content,
            "is_hidden": False,
            "is_deleted": False,
            "group_id": group.id,
        }
        item = FeedItem.objects.create(
            community=getattr(group, "community", None),
            event=None,
            actor=request.user,
            verb="posted",
            target_content_type=ct,
            target_object_id=group.id,
            metadata=metadata,
        )
        return Response({"ok": True, "feed_item_id": item.id}, status=201)
    
    def _ct_id(self, model):
        try:
            return ContentType.objects.get_for_model(model).id
        except Exception:
            return None

    def _load_group_item(self, group, identifier):
        """
        Return a FeedItem that belongs to this group.
        Accepts:
        - FeedItem.id (preferred), OR
        - poll_id (fallback). If no FeedItem exists for that poll, create one.

        Also: if the given id matches an existing FeedItem **in another group**,
        we try treating it as a poll_id for this group before erroring.
        """
        FeedItem = self._get_feeditem_model()
        if not FeedItem:
            return None, "activity_feed.FeedItem not installed"

        try:
            ident = int(identifier)
        except Exception:
            return None, "Invalid id"

        GroupPoll = apps.get_model("groups", "GroupPoll")
        Message = self._get_message_model()

        # -------- 1) Treat identifier as a FeedItem id --------
        item = FeedItem.objects.filter(pk=ident).first()
        if item:
            ct_group = self._ct_id(Group)
            if item.target_content_type_id == ct_group:
                # feed item targets a Group
                if int(item.target_object_id) == int(group.id):
                    return item, None
                # ⬇️ MISMATCH: try treating ident as a poll_id for this same group
                try:
                    poll = (
                        GroupPoll.objects.select_related("group").prefetch_related("options")
                        .get(pk=ident, group=group)
                    )
                except GroupPoll.DoesNotExist:
                    return None, "Item does not belong to this group"
                # resolve/create feed item for this poll
                ct_poll = self._ct_id(GroupPoll)
                linked = FeedItem.objects.filter(
                    target_content_type_id=ct_poll, target_object_id=poll.id
                ).first()
                if linked:
                    return linked, None
                # build options with vote counts
                counts = dict(
                    GroupPollOption.objects.filter(poll=poll)
                    .annotate(c=Count("votes"))
                    .values_list("id", "c")
                )
                options = [{"id": o.id, "text": o.text, "votes": counts.get(o.id, 0)}
                        for o in poll.options.all()]
                metadata = {
                    "type": "poll",
                    "options": options,
                    "poll_id": poll.id,
                    "group_id": group.id,
                    "question": poll.question,
                    "is_closed": bool(getattr(poll, "is_closed", False)),
                }
                linked = FeedItem.objects.create(
                    community=getattr(group, "community", None),
                    event=None,
                    actor=getattr(self.request, "user", None),
                    verb="created_poll",
                    target_content_type_id=ct_group,
                    target_object_id=group.id,
                    metadata=metadata,
                )
                return linked, None

            # legacy: FeedItem targeted at GroupPoll
            ct_poll = self._ct_id(GroupPoll)
            if ct_poll and item.target_content_type_id == ct_poll:
                poll = GroupPoll.objects.filter(pk=item.target_object_id).only("group_id").first()
                if poll and int(poll.group_id) == int(group.id):
                    return item, None
                return None, "Item does not belong to this group"

            # legacy: FeedItem targeted at Message
            if Message:
                ct_msg = self._ct_id(Message)
                if ct_msg and item.target_content_type_id == ct_msg:
                    msg = (
                        Message.objects.filter(pk=item.target_object_id)
                        .select_related("conversation").first()
                    )
                    if msg and self._ensure_message_in_group(msg, group):
                        return item, None
                    return None, "Item does not belong to this group"

            # metadata group_id fallback
            meta_gid = (item.metadata or {}).get("group_id")
            if meta_gid is not None and int(meta_gid) == int(group.id):
                return item, None

            # Final try: treat ident as poll_id before giving up
            try:
                poll = (
                    GroupPoll.objects.select_related("group").prefetch_related("options")
                    .get(pk=ident, group=group)
                )
            except GroupPoll.DoesNotExist:
                return None, "Item does not belong to this group"
            # resolve/create feed item for this poll
            ct_poll = self._ct_id(GroupPoll)
            linked = FeedItem.objects.filter(
                target_content_type_id=ct_poll, target_object_id=poll.id
            ).first()
            if linked:
                return linked, None
            counts = dict(
                GroupPollOption.objects.filter(poll=poll)
                .annotate(c=Count("votes"))
                .values_list("id", "c")
            )
            options = [{"id": o.id, "text": o.text, "votes": counts.get(o.id, 0)}
                    for o in poll.options.all()]
            metadata = {
                "type": "poll",
                "options": options,
                "poll_id": poll.id,
                "group_id": group.id,
                "question": poll.question,
                "is_closed": bool(getattr(poll, "is_closed", False)),
            }
            linked = FeedItem.objects.create(
                community=getattr(group, "community", None),
                event=None,
                actor=getattr(self.request, "user", None),
                verb="created_poll",
                target_content_type_id=self._ct_id(Group),
                target_object_id=group.id,
                metadata=metadata,
            )
            return linked, None

        # -------- 2) Fallback: identifier is a poll_id (new or existing) --------
        try:
            poll = (
                GroupPoll.objects.select_related("group").prefetch_related("options")
                .get(pk=ident, group=group)
            )
        except GroupPoll.DoesNotExist:
            return None, "FeedItem not found"

        # feed item already linked to this poll?
        ct_poll = self._ct_id(GroupPoll)
        linked = FeedItem.objects.filter(
            target_content_type_id=ct_poll, target_object_id=poll.id
        ).first()
        if linked:
            return linked, None

        # create a new feed item for this poll with your exact metadata shape
        counts = dict(
            GroupPollOption.objects.filter(poll=poll)
            .annotate(c=Count("votes"))
            .values_list("id", "c")
        )
        options = [{"id": o.id, "text": o.text, "votes": counts.get(o.id, 0)}
                for o in poll.options.all()]
        metadata = {
            "type": "poll",
            "options": options,
            "poll_id": poll.id,
            "group_id": group.id,
            "question": poll.question,
            "is_closed": bool(getattr(poll, "is_closed", False)),
        }
        linked = FeedItem.objects.create(
            community=getattr(group, "community", None),
            event=None,
            actor=getattr(self.request, "user", None),
            verb="created_poll",
            target_content_type_id=self._ct_id(Group),
            target_object_id=group.id,
            metadata=metadata,
        )
        return linked, None



    def _load_group_post(self, group, feed_item_id):
        """
        Load a FeedItem for moderation. Accepts:
        A) legacy posts:   target = Group(<group.id>), metadata.type == 'post'
        B) polls:          target = GroupPoll(<poll.id>) whose group_id == group.id
        Returns: (FeedItem | None, error_message | None)
        """
        FeedItem = self._get_feeditem_model()
        if not FeedItem:
            return None, "activity_feed.FeedItem not installed"

        try:
            item = FeedItem.objects.get(pk=feed_item_id)
        except FeedItem.DoesNotExist:
            return None, "FeedItem not found"

        # A) legacy post shape (target is the Group)
        ct_group = ContentType.objects.get_for_model(Group).id
        if item.target_content_type_id == ct_group:
            if item.target_object_id != group.id:
                return None, "Item does not belong to this group"
            meta = item.metadata if isinstance(item.metadata, dict) else {}
            # tolerate missing type; accept 'post' or 'poll' (future-proof)
            t = meta.get("type")
            if t not in (None, "post", "poll"):
                return None, "Item is not a post"
            return item, None

        # B) poll shape (target is GroupPoll)
        GroupPoll = apps.get_model("groups", "GroupPoll")
        if GroupPoll:
            ct_poll = ContentType.objects.get_for_model(GroupPoll).id
            if item.target_content_type_id == ct_poll:
                try:
                    poll = GroupPoll.objects.only("group_id").get(pk=item.target_object_id)
                except GroupPoll.DoesNotExist:
                    return None, "Target poll not found"
                if poll.group_id != group.id:
                    return None, "Item does not belong to this group"
                return item, None

        return None, "Item is not a post"

    @action(detail=True, methods=["post"], url_path="moderation/delete-post")
    def moderation_delete_post(self, request, pk=None):
        group = self.get_object()
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        ser = FeedItemIdSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        fid = ser.validated_data["id"]

        # 🔁 generic now (works for post, poll, image, link, event)
        item, err = self._load_group_item(group, fid)
        if err:
            return Response({"detail": err}, status=400 if "group" in err else 409)

        meta = item.metadata or {}
        meta["is_deleted"] = True
        meta["deleted_at"] = timezone.now().isoformat()
        item.metadata = meta
        item.save(update_fields=["metadata"])
        return Response({"ok": True, "deleted": "soft"}, status=200)
    
    class HidePostIn(serializers.Serializer):
        id = serializers.IntegerField(help_text="Feed item ID to hide")

    @extend_schema(request=HidePostIn)
    @action(detail=True, methods=["post"], url_path="moderation/hide-post")
    def moderation_hide_post(self, request, pk=None):
        group = self.get_object()
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        ser = FeedItemIdSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        fid = ser.validated_data["id"]

        # This loads the feed item and verifies it belongs to the group
        item, err = self._load_group_item(group, fid)
        if err:
            return Response({"detail": err}, status=400)
        
        meta = item.metadata or {}
        meta["is_hidden"] = True
        meta["hidden_at"] = timezone.now().isoformat()

        item.metadata = meta
        item.save(update_fields=["metadata"])

        return Response({"ok": True, "hidden": True}, status=200)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="id",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="Group id or slug"
            )
        ],
        request={"application/json": FeedItemIdSerializer},
    )
    @action(detail=True, methods=["post"], url_path="moderation/unhide-post")
    def moderation_unhide_post(self, request, pk=None):
        group = self.get_object()
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        ser = FeedItemIdSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        fid = ser.validated_data["id"]

        # 🔁 generic now
        item, err = self._load_group_item(group, fid)
        if err:
            return Response({"detail": err}, status=400 if "group" in err else 409)

        meta = item.metadata or {}
        meta["is_hidden"] = False
        item.metadata = meta
        item.save(update_fields=["metadata"])
        return Response({"ok": True, "hidden": False}, status=200)

    # ===== MESSAGE moderation (optional – if you have messaging app) =====
    def _ensure_message_in_group(self, msg, group):
        conv = getattr(msg, "conversation", None)
        if not conv:
            return False

        # Common group chat
        if getattr(conv, "is_group", False) and getattr(conv, "group_id", None) == group.id:
            return True

        # Event live chat → count it if the event belongs to this group (only if Event has group_id)
        if getattr(conv, "is_event_group", False) and getattr(conv, "event", None):
            ev = conv.event
            if hasattr(ev, "group_id") and ev.group_id == group.id:
                return True

        # Legacy fallback by room_key
        rk = (getattr(conv, "room_key", "") or "")
        if rk == f"group:{group.id}":
            return True

        return False

    def _load_message_for_group(self, group, message_id):
        Message = self._get_message_model()
        if not Message:
            return None, "messaging.Message not installed"
        try:
            msg = Message.objects.select_related('conversation').get(pk=message_id)
        except Message.DoesNotExist:
            return None, "Message not found"
        if not self._ensure_message_in_group(msg, group):
            return None, "Message does not belong to this group"
        return msg, None

    @action(detail=True, methods=["post"], url_path="moderation/hide-message")
    def moderation_hide_message(self, request, pk=None):
        group = self.get_object()
        if not self._can_moderate_any(request, group):
            return Response({"detail":"Forbidden"}, status=403)
        mid = request.data.get("message_id")
        if not mid: return Response({"detail":"message_id is required"}, status=400)
        msg, err = self._load_message_for_group(group, mid)
        if err: return Response({"detail": err}, status=409 if "installed" in err else 400)
        if hasattr(msg, "is_hidden"):
            msg.is_hidden = True; msg.save(update_fields=["is_hidden"])
            return Response({"ok": True, "hidden": True})
        return Response({"detail":"This Message model does not support is_hidden"}, status=409)

    @action(detail=True, methods=["post"], url_path="moderation/unhide-message")
    def moderation_unhide_message(self, request, pk=None):
        group = self.get_object()
        if not self._can_moderate_any(request, group):
            return Response({"detail":"Forbidden"}, status=403)
        mid = request.data.get("message_id")
        if not mid: return Response({"detail":"message_id is required"}, status=400)
        msg, err = self._load_message_for_group(group, mid)
        if err: return Response({"detail": err}, status=409 if "installed" in err else 400)
        if hasattr(msg, "is_hidden"):
            msg.is_hidden = False; msg.save(update_fields=["is_hidden"])
            return Response({"ok": True, "hidden": False})
        return Response({"detail":"This Message model does not support is_hidden"}, status=409)

    @action(detail=True, methods=["post"], url_path="moderation/delete-message")
    def moderation_delete_message(self, request, pk=None):
        group = self.get_object()
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        mid = request.data.get("message_id")
        if not mid:
            return Response({"detail": "message_id is required"}, status=400)

        msg, err = self._load_message_for_group(group, mid)
        if err:
            return Response({"detail": err}, status=400)

        # SOFT DELETE (do not .delete())
        msg.is_deleted = True
        msg.deleted_at = timezone.now()
        msg.save(update_fields=["is_deleted", "deleted_at"])

        return Response({"ok": True, "deleted": "soft"})

    # =========================
    # ROLE MANAGEMENT (PROMOTE)
    # =========================
    @action(detail=True, methods=["post"], url_path="set-role")
    def set_role(self, request, pk=None):
        """
        Admin/Owner sets role:
        Body: { "user_id": <int>, "role": "admin"|"moderator"|"member" }
        STAFF-ONLY ADMIN/MOD: Only staff users can be 'admin' or 'moderator'.
        """
        group = self.get_object()
        if not self._can_set_roles(request, group):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        uid = request.data.get("user_id")
        role_in = (request.data.get("role") or "").strip().lower()
        if not uid or role_in not in {"admin", "moderator", "member"}:
            return Response({"detail": "user_id and valid role are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid_int = int(uid)
        except Exception:
            return Response({"detail": "user_id must be an integer"}, status=status.HTTP_400_BAD_REQUEST)

        owner_user_id = getattr(group, "owner_id", None) or getattr(group, "created_by_id", None)
        if owner_user_id is not None and uid_int == int(owner_user_id):
            return Response({"detail": "Cannot change owner's role"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            membership = GroupMembership.objects.get(group=group, user_id=uid_int)
        except GroupMembership.DoesNotExist:
            return Response({"detail": "Not a member"}, status=status.HTTP_404_NOT_FOUND)

        # STAFF-ONLY ADMIN/MOD
        if role_in in {"admin", "moderator"}:
            User = get_user_model()
            target_user = User.objects.filter(pk=uid_int).first()
            if not target_user or not target_user.is_staff:
                return Response(
                    {"detail": "Only staff users can be assigned as admin or moderator."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        role_map = {
            "admin": GroupMembership.ROLE_ADMIN,
            "moderator": GroupMembership.ROLE_MODERATOR,
            "member": GroupMembership.ROLE_MEMBER,
        }
        membership.role = role_map[role_in]
        membership.save(update_fields=["role"])
        return Response({"ok": True}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="change-role")
    def change_role(self, request, pk=None):
        return self.set_role(request, pk)

    @action(detail=True, methods=["post"], url_path="request-promotion", parser_classes=[JSONParser])
    def request_promotion(self, request, pk=None):
        """
        Moderator requests promotion to ADMIN.
        STAFF-ONLY: requester must be a staff moderator.
        Body (optional): {"reason": "string"}
        """
        group = self.get_object()
        requester_id = getattr(request.user, "id", None)
        if not requester_id:
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        try:
            membership = GroupMembership.objects.select_related("user").get(group=group, user_id=requester_id)
        except GroupMembership.DoesNotExist:
            return Response({"detail": "You are not a member of this group."}, status=status.HTTP_400_BAD_REQUEST)

        MOD = GroupMembership.ROLE_MODERATOR
        if membership.role != MOD or not getattr(membership.user, "is_staff", False):
            return Response(
                {"detail": "Only staff moderators can request promotion to admin."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        target_role = GroupMembership.ROLE_ADMIN
        reason = (request.data.get("reason") or "").strip()

        req, created = PromotionRequest.objects.get_or_create(
            group=group, user_id=requester_id, role_requested=target_role,
            defaults={"reason": reason, "status": PromotionRequest.STATUS_PENDING}
        )
        if not created:
            req.status = PromotionRequest.STATUS_PENDING
            req.reason = reason
            req.reviewed_by = None
            req.reviewed_at = None
            req.save(update_fields=["status", "reason", "reviewed_by", "reviewed_at"])

        return Response({"ok": True, "request_id": req.id, "status": req.status}, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["get"], url_path="promotion-requests")
    def promotion_requests(self, request, pk=None):
        group = self.get_object()
        if not self._can_set_roles(request, group):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        status_q = (request.query_params.get("status") or PromotionRequest.STATUS_PENDING).lower()
        if status_q not in {PromotionRequest.STATUS_PENDING, PromotionRequest.STATUS_APPROVED, PromotionRequest.STATUS_REJECTED}:
            status_q = PromotionRequest.STATUS_PENDING

        rows = (PromotionRequest.objects
                .filter(group=group, status=status_q)
                .select_related("user", "reviewed_by")
                .order_by("-created_at"))

        out = []
        for r in rows:
            out.append({
                "id": r.id,
                "user": {
                    "id": r.user_id,
                    "email": getattr(r.user, "email", None),
                    "name": getattr(r.user, "get_full_name", lambda: "")() or getattr(r.user, "username", ""),
                    "is_staff": getattr(r.user, "is_staff", False),
                },
                "role_requested": r.role_requested,
                "reason": r.reason or "",
                "status": r.status,
                "created_at": r.created_at,
                "reviewed_by": r.reviewed_by_id,
                "reviewed_at": r.reviewed_at,
            })
        return Response(out)

    @action(detail=True, methods=["post"], url_path="promotion-requests/approve", parser_classes=[JSONParser])
    def approve_promotion_requests(self, request, pk=None):
        """
        Body: { "request_ids": [int, ...] } OR { "user_ids": [int, ...] }
        Sets membership.role = ADMIN and marks requests APPROVED.
        STAFF-ONLY: if the target user is not staff, auto-reject with reason.
        """
        group = self.get_object()
        decider_id = getattr(request.user, "id", None)
        if not self._can_set_roles(request, group):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        req_ids = request.data.get("request_ids") or []
        user_ids = request.data.get("user_ids") or []
        if not (isinstance(req_ids, list) or isinstance(user_ids, list)):
            return Response({"detail": "Provide request_ids or user_ids as a list."},
                            status=status.HTTP_400_BAD_REQUEST)

        ADMIN = GroupMembership.ROLE_ADMIN

        with transaction.atomic():
            q = PromotionRequest.objects.filter(group=group, status=PromotionRequest.STATUS_PENDING)
            if req_ids:
                q = q.filter(id__in=req_ids)
            elif user_ids:
                q = q.filter(user_id__in=user_ids)

            approved = 0
            for r in q.select_for_update():
                owner_user_id = getattr(group, "owner_id", None) or getattr(group, "created_by_id", None)
                if owner_user_id is not None and r.user_id == int(owner_user_id):
                    r.status = PromotionRequest.STATUS_REJECTED
                    r.reviewed_by_id = decider_id
                    r.reviewed_at = timezone.now()
                    r.reason = (r.reason or "") + " [auto-rejected: owner cannot be promoted]"
                    r.save(update_fields=["status", "reviewed_by", "reviewed_at", "reason"])
                    continue

                try:
                    m = GroupMembership.objects.select_for_update().select_related("user").get(group=group, user_id=r.user_id)
                except GroupMembership.DoesNotExist:
                    r.status = PromotionRequest.STATUS_REJECTED
                    r.reviewed_by_id = decider_id
                    r.reviewed_at = timezone.now()
                    r.reason = (r.reason or "") + " [auto-rejected: not a member]"
                    r.save(update_fields=["status", "reviewed_by", "reviewed_at", "reason"])
                    continue

                # STAFF-ONLY ADMIN/MOD: reject if user is not staff
                if not getattr(m.user, "is_staff", False):
                    r.status = PromotionRequest.STATUS_REJECTED
                    r.reviewed_by_id = decider_id
                    r.reviewed_at = timezone.now()
                    r.reason = (r.reason or "") + " [auto-rejected: user is not staff]"
                    r.save(update_fields=["status", "reviewed_by", "reviewed_at", "reason"])
                    continue

                m.role = ADMIN
                m.save(update_fields=["role"])

                r.status = PromotionRequest.STATUS_APPROVED
                r.reviewed_by_id = decider_id
                r.reviewed_at = timezone.now()
                r.save(update_fields=["status", "reviewed_by", "reviewed_at"])
                approved += 1

        return Response({"ok": True, "approved": approved}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="promotion-requests/reject", parser_classes=[JSONParser])
    def reject_promotion_requests(self, request, pk=None):
        """
        Body: { "request_ids": [int, ...] } OR { "user_ids": [int, ...] }
        Marks requests REJECTED.
        """
        group = self.get_object()
        decider_id = getattr(request.user, "id", None)
        if not self._can_set_roles(request, group):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        req_ids = request.data.get("request_ids") or []
        user_ids = request.data.get("user_ids") or []
        if not (isinstance(req_ids, list) or isinstance(user_ids, list)):
            return Response({"detail": "Provide request_ids or user_ids as a list."},
                            status=status.HTTP_400_BAD_REQUEST)

        q = PromotionRequest.objects.filter(group=group, status=PromotionRequest.STATUS_PENDING)
        if req_ids:
            q = q.filter(id__in=req_ids)
        elif user_ids:
            q = q.filter(user_id__in=user_ids)

        now = timezone.now()
        updated = q.update(status=PromotionRequest.STATUS_REJECTED, reviewed_by_id=decider_id, reviewed_at=now)
        return Response({"ok": True, "rejected": updated}, status=status.HTTP_200_OK)

    # ---------- JOIN / JOIN-LINK ----------
    @action(detail=True, methods=["post"], url_path="join")
    def join(self, request, pk=None):
        group = self.get_object()
        uid = getattr(request.user, "id", None)
        if not uid:
            return Response({"detail": "Authentication required."}, status=401)

        ROLE_MEMBER    = GroupMembership.ROLE_MEMBER
        STATUS_ACTIVE  = GroupMembership.STATUS_ACTIVE
        STATUS_PENDING = GroupMembership.STATUS_PENDING

        if GroupMembership.objects.filter(group=group, user_id=uid).exists():
            # also ensure parent membership if this is a sub-group
            self._ensure_parent_membership_active(group, uid)
            return Response({"ok": True, "status": "already_member"}, status=200)

        jp, vis = group.join_policy, group.visibility

        # open + public => instant join
        if vis == Group.VISIBILITY_PUBLIC and jp == Group.JOIN_OPEN:
            GroupMembership.objects.create(group=group, user_id=uid, role=ROLE_MEMBER, status=STATUS_ACTIVE)
            self._ensure_parent_membership_active(group, uid)
            return Response({"ok": True, "status": "joined"}, status=201)

        # approval + public => pending (but parent can be active)
        if vis == Group.VISIBILITY_PUBLIC and jp == Group.JOIN_APPROVAL:
            GroupMembership.objects.create(group=group, user_id=uid, role=ROLE_MEMBER, status=STATUS_PENDING)
            self._ensure_parent_membership_active(group, uid)
            return Response({"ok": True, "status": "pending_approval"}, status=201)

        # invite + private => only admins can add
        if vis == Group.VISIBILITY_PRIVATE and jp == Group.JOIN_INVITE:
            return Response({"detail": "Only admins can add members to this group."}, status=403)

        # approval + private => must present valid join_token (in body or query)
        if vis == Group.VISIBILITY_PRIVATE and jp == Group.JOIN_APPROVAL:
            token = (
                request.data.get("join_token")
                or request.query_params.get("join_token")
                or request.query_params.get("access_token")
            )
            if not token or not self._validate_join_token(token, group):
                # keep group hidden — don’t leak existence
                raise NotFound("Group not found.")
            GroupMembership.objects.create(group=group, user_id=uid, role=ROLE_MEMBER, status=STATUS_PENDING)
            self._ensure_parent_membership_active(group, uid)
            return Response({"ok": True, "status": "pending_approval"}, status=201)

        return Response({"detail": "Invalid group configuration."}, status=400)

    @action(detail=True, methods=["get"], url_path="join-link")
    def join_link(self, request, pk=None):
        group = self.get_object()
        uid = getattr(request.user, "id", None)
        if not self._is_owner_admin_or_staff(uid, group):
            return Response({"detail": "Forbidden"}, status=403)

        if not (group.visibility == Group.VISIBILITY_PRIVATE and group.join_policy == Group.JOIN_APPROVAL):
            return Response({"detail": "Join link is only for 'approval + private' groups."}, status=400)

        token = self._make_join_token(group)
        rel = f"/groups/{group.slug or group.pk}?join_token={token}"
        return Response({"ok": True, "join_token": token, "relative_link": rel})

    @action(detail=True, methods=["post"], url_path="join-link/rotate")
    def rotate_join_link(self, request, pk=None):
        group = self.get_object()
        uid = getattr(request.user, "id", None)
        if not self._is_owner_admin_or_staff(uid, group):
            return Response({"detail": "Forbidden"}, status=403)

        if not (group.visibility == Group.VISIBILITY_PRIVATE and group.join_policy == Group.JOIN_APPROVAL):
            return Response({"detail": "Join link is only for 'approval + private' groups."}, status=400)

        Group.objects.filter(pk=group.pk).update(updated_at=timezone.now())
        group.refresh_from_db(fields=["updated_at"])

        token = self._make_join_token(group)
        rel = f"/groups/{group.slug or group.pk}?join_token={token}"
        return Response({"ok": True, "join_token": token, "relative_link": rel})

    @action(detail=True, methods=["get", "post"], url_path="settings/message-mode", parser_classes=[JSONParser])
    def settings_message_mode(self, request, pk=None):
        """
        GET  → { "message_mode": "all", "admins_only_effective": false }
        POST → { "admins_only": true }  or  { "message_mode": "admins_only" }
        POST allowed for: owner/admin/mod/staff
        """
        group = self.get_object()
        if request.method.lower() == "get":
            ser = GroupSettingsSerializer(group)
            return Response(ser.data)

        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        ser = GroupSettingsSerializer(instance=group, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data, status=200)

    @action(detail=True, methods=["get"], url_path="can-send")
    def can_send(self, request, pk=None):
        """
        Quick capability probe for the current user.
        """
        group = self.get_object()
        ok, reason = self._can_send_message_to_group(request, group)
        return Response({"ok": ok, "reason": reason, "message_mode": group.message_mode})

    @action(detail=True, methods=["post"], url_path="pin-message", parser_classes=[JSONParser])
    def pin_message(self, request, pk=None):
        group = self.get_object()
        uid = getattr(request.user, "id", None)
        if not uid:
            return Response({"detail": "Authentication required."}, status=401)

        mid = request.data.get("message_id")
        if not mid:
            return Response({"detail": "message_id is required"}, status=400)

        msg, err = self._get_message_for_group(group, mid)
        if err:
            return Response({"detail": err}, status=400)

        # Elevated roles create GLOBAL pin; members create PERSONAL pin
        if self._can_moderate_any(request, group):
            pin, _ = GroupPinnedMessage.objects.get_or_create(
                group=group, message=msg, is_global=True, defaults={"pinned_by_id": uid}
            )
        else:
            pin, _ = GroupPinnedMessage.objects.get_or_create(
                group=group, message=msg, is_global=False, user_id=uid, defaults={"pinned_by_id": uid}
            )
        return Response({"ok": True, "pin": GroupPinnedMessageOutSerializer(pin).data}, status=200)


    @action(detail=True, methods=["post"], url_path="unpin-message", parser_classes=[JSONParser])
    def unpin_message(self, request, pk=None):
        group = self.get_object()
        uid = getattr(request.user, "id", None)
        if not uid:
            return Response({"detail": "Authentication required."}, status=401)

        mid = request.data.get("message_id")
        scope = request.data.get("scope")  # "global" or "personal" (optional hint)
        if not mid:
            return Response({"detail": "message_id is required"}, status=400)

        msg, err = self._get_message_for_group(group, mid)
        if err:
            return Response({"detail": err}, status=400)

        deleted = 0
        if self._can_moderate_any(request, group):
            # elevated can remove global pins; if scope not provided, try both
            if scope == "global" or scope is None:
                d, _ = GroupPinnedMessage.objects.filter(group=group, message=msg, is_global=True).delete()
                deleted += d
            if scope == "personal" or scope is None:
                # can also clean their own personal pin if they made one
                d, _ = GroupPinnedMessage.objects.filter(group=group, message=msg, is_global=False, user_id=uid).delete()
                deleted += d
        else:
            # member can only unpin their personal pin
            d, _ = GroupPinnedMessage.objects.filter(group=group, message=msg, is_global=False, user_id=uid).delete()
            deleted += d

        return Response({"ok": True, "deleted": bool(deleted)}, status=200)

    @action(detail=True, methods=["get"], url_path="pinned-messages")
    def pinned_messages(self, request, pk=None):
        """
        Returns:
        - all GLOBAL pins
        - plus PERSONAL pins for the requesting user only
        """
        group = self.get_object()
        uid = getattr(request.user, "id", None)

        qs = GroupPinnedMessage.objects.filter(group=group, is_global=True).select_related("message", "pinned_by")
        if uid:
            personal = GroupPinnedMessage.objects.filter(group=group, is_global=False, user_id=uid)\
                        .select_related("message", "pinned_by")
            qs = list(qs) + list(personal)
            data = GroupPinnedMessageOutSerializer(qs, many=True).data
            # keep globals first, then personal
            data.sort(key=lambda x: (0 if x["scope"] == "global" else 1, x["pinned_at"]), reverse=True)
            return Response(data)
        return Response(GroupPinnedMessageOutSerializer(qs.order_by("-pinned_at"), many=True).data)
    
    @action(detail=True, methods=["get", "post"], url_path="polls", parser_classes=[JSONParser])
    def polls(self, request, pk=None):
        group = self.get_object()

        if group.parent_id:
            uid = getattr(request.user, "id", None)
            if not (
                self._can_moderate_any(request, group) or
                (uid and self._is_active_member(uid, group))
            ):
                return Response({"detail": "Only sub-group members can view its polls."}, status=403)
            
        if request.method.lower() == "get":
            qs = (
                GroupPoll.objects
                .filter(group=group)
                .annotate(total_votes=Count("votes"))
                .order_by("-created_at")
                .prefetch_related("options")
            )
            # vote counts per option
            opt_counts = dict(
                GroupPollOption.objects.filter(poll__group=group)
                .annotate(c=Count("votes"))
                .values_list("id", "c")
            )
            for poll in qs:
                for opt in poll.options.all():
                    setattr(opt, "vote_count", opt_counts.get(opt.id, 0))
            return Response(GroupPollOutSerializer(qs, many=True, context={"request": request}).data)

        # POST = create poll → owner/admin/mod/staff
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        ser = GroupPollCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        data = ser.validated_data

        poll = GroupPoll.objects.create(
            group=group,
            question=data["question"].strip(),
            allows_multiple=data.get("allows_multiple", False),
            is_anonymous=data.get("is_anonymous", False),
            ends_at=data.get("ends_at"),
            created_by=request.user,
        )
        for idx, text in enumerate(data["options"]):
            GroupPollOption.objects.create(poll=poll, text=text.strip(), index=idx)

        # zero counts for fresh poll
        poll.total_votes = 0
        for opt in poll.options.all():
            setattr(opt, "vote_count", 0)
        return Response(GroupPollOutSerializer(poll, context={"request": request}).data, status=201)
    
    @action(detail=True, methods=["post"], url_path=r"polls/(?P<poll_id>\d+)/vote", parser_classes=[JSONParser])
    def poll_vote(self, request, pk=None, poll_id=None):
        group = self.get_object()
        try:
            poll = GroupPoll.objects.get(pk=int(poll_id), group=group)
        except (ValueError, GroupPoll.DoesNotExist):
            return Response({"detail": "Poll not found"}, status=404)

        # closed / expired?
        if poll.is_closed or (poll.ends_at and timezone.now() > poll.ends_at):
            return Response({"detail": "Poll is closed."}, status=400)

        uid = getattr(request.user, "id", None)
        if not uid:
            return Response({"detail": "Authentication required."}, status=401)

        # only ACTIVE members (or elevated roles) can vote
        if not (
            self._is_active_member(uid, group)
            or self._is_admin(uid, group)
            or self._is_moderator(uid, group)
            or getattr(request.user, "is_staff", False)
            or group.created_by_id == uid
        ):
            return Response({"detail": "Not allowed to vote."}, status=403)

        vin = GroupPollVoteInSerializer(data=request.data)
        vin.is_valid(raise_exception=True)
        option_ids = set(vin.validated_data["option_ids"])

        # ensure options belong to this poll
        valid_ids = set(
            GroupPollOption.objects.filter(poll=poll, id__in=option_ids).values_list("id", flat=True)
        )
        if not valid_ids:
            return Response({"detail": "No valid options selected."}, status=400)

        with transaction.atomic():
            if not poll.allows_multiple:
                GroupPollVote.objects.filter(poll=poll, user_id=uid).delete()
                one = next(iter(valid_ids))
                GroupPollVote.objects.create(poll=poll, option_id=one, user_id=uid)
            else:
                existing = set(
                    GroupPollVote.objects.filter(poll=poll, user_id=uid, option_id__in=valid_ids)
                    .values_list("option_id", flat=True)
                )
                to_add = valid_ids - existing
                GroupPollVote.objects.bulk_create(
                    [GroupPollVote(poll=poll, option_id=oid, user_id=uid) for oid in to_add]
                )

        # refreshed stats
        poll = (
            GroupPoll.objects.filter(pk=poll.id)
            .annotate(total_votes=Count("votes"))
            .prefetch_related("options")
            .first()
        )
        counts = dict(
            GroupPollOption.objects.filter(poll=poll).annotate(c=Count("votes")).values_list("id", "c")
        )
        for opt in poll.options.all():
            setattr(opt, "vote_count", counts.get(opt.id, 0))
        return Response(GroupPollOutSerializer(poll, context={"request": request}).data, status=200)

    @action(detail=True, methods=["post"], url_path=r"polls/(?P<poll_id>\d+)/close")
    def poll_close(self, request, pk=None, poll_id=None):
        group = self.get_object()
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)
        try:
            poll = GroupPoll.objects.get(pk=int(poll_id), group=group)
        except (ValueError, GroupPoll.DoesNotExist):
            return Response({"detail": "Poll not found"}, status=404)
        if poll.is_closed:
            return Response({"ok": True, "closed": True})
        poll.is_closed = True
        poll.save(update_fields=["is_closed"])
        return Response({"ok": True, "closed": True})

    @action(detail=True, methods=["delete"], url_path=r"polls/(?P<poll_id>\d+)")
    def poll_delete(self, request, pk=None, poll_id=None):
        group = self.get_object()
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)
        try:
            poll = GroupPoll.objects.get(pk=int(poll_id), group=group)
        except (ValueError, GroupPoll.DoesNotExist):
            return Response({"detail": "Poll not found"}, status=404)
        poll.delete()
        return Response(status=204)

    def _create_poll_internal(self, request, group):
        """
        Create a poll FeedItem linked to this group and return poll payload.
        Caller (e.g., moderation_create_post) already enforces permissions.
        """
        FeedItem = self._get_feeditem_model()
        if not FeedItem:
            return Response({"detail": "activity_feed.FeedItem not installed"}, status=409)

        # Build & validate from incoming body (same keys the frontend sends to /posts/)
        payload = {
            "question": request.data.get("question"),
            "options": request.data.get("options", []),
            "multi_select": bool(request.data.get("multi_select", False)),
            "closes_at": request.data.get("closes_at"),
        }
        ser = CreatePollSerializer(data=payload)
        ser.is_valid(raise_exception=True)
        data = ser.validated_data

        ct = ContentType.objects.get_for_model(Group)
        metadata = {
            "type": "poll",
            "question": data["question"].strip(),
            "options": [
                {"id": i, "text": opt.strip(), "votes": 0}
                for i, opt in enumerate(data["options"])
            ],
            "multi_select": data.get("multi_select", False),
            "closes_at": data["closes_at"].isoformat() if data.get("closes_at") else None,
            "is_closed": False,
            "group_id": group.id,
        }

        item = FeedItem.objects.create(
            community=getattr(group, "community", None),
            event=None,
            actor=request.user,                       # matches your FeedItem usage
            verb="created_poll",
            target_content_type=ct,                   # link feed item to this group
            target_object_id=group.id,
            metadata=metadata,
        )
        # return a poll-shaped response
        return Response({"ok": True, "feed_item_id": item.id, "poll": metadata}, status=201)

class UsersLookupView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.is_staff:
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        q = (request.query_params.get("search") or "").strip()
        try:
            limit = min(int(request.query_params.get("limit") or 30), 100)
        except Exception:
            limit = 30

        User = get_user_model()
        qs = User.objects.all()
        if q:
            qs = qs.filter(
                Q(username__icontains=q)
                | Q(email__icontains=q)
                | Q(first_name__icontains=q)
                | Q(last_name__icontains=q)
            )
        qs = qs.order_by("id")[:limit]

        out = []
        for u in qs:
            name = getattr(u, "get_full_name", lambda: "")() or getattr(u, "username", "") or getattr(u, "email", "")
            avatar = getattr(u, "avatar", None)
            if not avatar and hasattr(u, "profile") and hasattr(u.profile, "avatar"):
                avatar = getattr(u.profile, "avatar", None)
            if hasattr(avatar, "url"):
                avatar = avatar.url
            out.append({"id": u.pk, "name": name or None, "email": getattr(u, "email", None), "avatar": avatar})
        return Response(out)

    