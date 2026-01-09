from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.db.models import Count, Q, Exists, OuterRef
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import NotFound
from django.utils import timezone
from urllib.parse import urljoin
from django.db import transaction
from django.core import signing
from rest_framework import status, viewsets, serializers, mixins
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from rest_framework.views import APIView
from uuid import uuid4
from pathlib import Path
from django.utils.text import slugify
from storages.backends.s3boto3 import S3Boto3Storage
from django.db import models

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, inline_serializer, OpenApiParameter, OpenApiExample

from community.models import Community
from activity_feed.models import FeedItem
from .models import Group, GroupMembership, PromotionRequest, GroupNotification
from .permissions import GroupCreateByAdminOnly, is_moderator, can_moderate_content
from .serializers import (
    GroupSerializer,
    GroupMemberOutSerializer,
    CreateFeedPostSerializer,
    FeedItemIdSerializer,
    GroupSettingsSerializer,
    PromotionRequestCreateSerializer,
    PromotionRequestOutSerializer,
    GroupNotificationSerializer,
    SuggestedGroupSerializer
)
from friends.models import Friendship
from users.serializers import UserMiniSerializer


class GroupViewSet(viewsets.ModelViewSet):
    """
    Existing:
    - GET   /api/groups/?created_by=me&search=term
    - POST  /api/groups/                  (staff via GroupCreateByAdminOnly)
    - GET   /api/groups/{id-or-slug}/
    - PATCH /api/groups/{id-or-slug}/     (staff or creator)
    - DELETE /api/groups/{id-or-slug}/    (staff or creator)
    - GET   /api/groups/{id-or-slug}/members/
    - POST /api/groups/{id-or-slug}/members/add-member/
    - POST /api/groups/{id-or-slug}/members/remove-member/
    - GET   /api/groups/mine/

    NEW (Moderator-only features):
    - GET  /api/groups/{id}/moderator/can-i/
    - POST /api/groups/{id}/create-post/         {content}
    - POST /api/groups/{id}/posts/delete-post/         {id}
    - POST /api/groups/{id}/posts/hide-post          {id}
    - POST /api/groups/{id}/posts/unhide-post/         {id}
    - POST /api/groups/{id}/message/hide-message/        {message_id}
    - POST /api/groups/{id}/message/unhide-message/      {message_id}
    - POST /api/groups/{id}/message/delete-message/      {message_id}
    - POST /api/groups/{id}/promotion/request/              {reason?}

    Join / Link:
    - POST /api/groups/{id}/join-group           (handles open/public, approval/public, invite/private, approval/private+token)
    - GET  /api/groups/{id}/join-group-link      (owner/admin/staff; approval+private only)
    - POST /api/groups/{id}/join-group-link/rotate (owner/admin/staff; approval+private only)
    """
    JOIN_LINK_MAX_AGE = 7 * 24 * 3600  # 7 days
    serializer_class = GroupSerializer
    parser_classes = [JSONParser, MultiPartParser, FormParser]
    queryset = Group.objects.all()
    lookup_field = "pk"

    # Use: Computes permission classes per action (admin-only vs auth-only vs read-only).
    # Ordering: Not applicable.
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
            "suggested",
            "mutual_members",

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

    # Use: Build a rotating salt for join link signing, tied to updated_at.
    # Ordering: Not applicable.
    def _join_salt(self, group: Group) -> str:
        ts = int(group.updated_at.timestamp()) if group.updated_at else 0
        return f"group-join:{group.pk}:{ts}"

    # Use: Create a signed token for private+approval join links.
    # Ordering: Not applicable.
    def _make_join_token(self, group: Group) -> str:
        return signing.dumps({"gid": group.pk}, salt=self._join_salt(group))

    # Use: Validate a join token (age + signature + group match).
    # Ordering: Not applicable.
    def _validate_join_token(self, token: str, group: Group) -> bool:
        try:
            data = signing.loads(token, max_age=self.JOIN_LINK_MAX_AGE, salt=self._join_salt(group))
            return int(data.get("gid")) == int(group.pk)
        except Exception:
            return False
        
    # Use: Resolve a messaging.Message by id and ensure it belongs to this group's conversation.
    # Ordering: Not applicable (single record lookup).
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
        if not conv:
            return None, "Message not found in a conversation"
        # Group chat: group_id set, event_id null, and matches this group
        if (getattr(conv, "group_id", None) is not None) and (getattr(conv, "event_id", None) is None) and (conv.group_id == group.id):
            return msg, None
        return None, "Message does not belong to this group"
    
    # Use: Decide if current user can send a message to a group (admins/mods vs message_mode=all).
    # Ordering: Not applicable.
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
    
    # Use: Ensure user has ACTIVE membership in parent when joining a sub-group.
    # Ordering: Not applicable (get_or_create).
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

    # Use: Check if a user is ACTIVE member of a group.
    # Ordering: Not applicable (exists()).
    def _is_active_member(self, user_id, group) -> bool:
        return GroupMembership.objects.filter(
            group=group, user_id=user_id, status=GroupMembership.STATUS_ACTIVE
        ).exists()
    
    # Use: Check if user is owner/admin or site staff for a group.
    # Ordering: Not applicable.
    def _is_owner_admin_or_staff(self, user_id, group: Group) -> bool:
        return bool(
            user_id and (
                group.created_by_id == user_id
                or getattr(group, "owner_id", None) == user_id
                or self._is_admin(user_id, group)
                or getattr(self.request.user, "is_staff", False)
            )
        )

    # Use: Lightweight user dict for API responses.
    # Ordering: Not applicable.
    def _user_short(self, u):
        if not u:
            return None
        name = getattr(u, "get_full_name", lambda: "")() or getattr(u, "username", "") or getattr(u, "email", None)
        return {"id": getattr(u, "id", None), "email": getattr(u, "email", None), "name": name}
    
    # Use (Endpoint): GET/POST /api/groups/{id}/posts/
    # - GET: lists feed posts for a group (Ordering: FeedItems ordered by "-created_at")
    # - POST: create a post (text/image/link/poll/event) — moderator/admin/owner/staff only
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
                    .filter(
                        # prefer FK (new rows)
                        models.Q(group_id=group.id)
                        # keep legacy targeting (old rows)
                        | models.Q(target_content_type=ct, target_object_id=group.id)
                    )
                    .filter(community_id=getattr(group, "community_id", None))
                    .exclude(metadata__is_deleted=True) 
                    .order_by("-created_at")
                )

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
                    # DEPRECATED: Do not show event posts (legacy)
                    continue
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
            # Build an S3 key similar to how Event previews do it (slug + short uuid + ext)
            # Events use "previews/event/..." — we’ll use "previews/feed/..." here.
            # If you want EXACTLY the same folder as events, change to "previews/event/".
            name = slugify(Path(f.name).stem) or "image"
            ext = (Path(f.name).suffix or ".jpg").lower()
            key = f"previews/feed/{name}-{uuid4().hex[:8]}{ext}"
            storage = S3Boto3Storage()   # uses AWS_* settings from Django
            path = storage.save(key, f)  # upload the file bytes to S3
            url = storage.url(path)      # public or signed URL depending on AWS_* settings
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
            return Response(
                {"detail": "Create poll via /api/activity/feed/polls/create/ (not under groups)."},
                status=400
            )

        elif t == "event":
            return Response({"detail": "Events are no longer supported via posts."}, status=400)

        else:
            return Response({"detail": f"Unsupported type '{t}'"}, status=400)

        item = FeedItem.objects.create(
            community=self._resolve_group_community(group),
            group=group,
            event=None,
            actor=request.user,
            verb="posted",
            target_content_type=ct,
            target_object_id=group.id,
            metadata=meta,
        )
        return Response({"ok": True, "id": item.id}, status=201)
    
    # Use: Base queryset for groups list (optionally filtered by creator or search).
    # Ordering: No explicit order_by here (natural DB order). Add order_by(...) at call sites if needed.
    def get_queryset(self):
        qs = Group.objects.all().annotate(member_count=Count("memberships")).order_by("-created_at")
        created_by = self.request.query_params.get("created_by")
        search = self.request.query_params.get("search")

        # only top-level (parent is NULL) when filtering by "me"
        if created_by == "me" and self.request.user.is_authenticated:
            qs = qs.filter(created_by=self.request.user, parent__isnull=True)

        if search:
            qs = qs.filter(Q(name__icontains=search) | Q(description__icontains=search))

        return qs
    
    # Use: Same as get_queryset but includes sub-groups (no parent__isnull constraint).
    # Ordering: No explicit order_by here.
    def get_queryset_all(self):
        qs = Group.objects.all().annotate(member_count=Count("memberships"))
        created_by = self.request.query_params.get("created_by")
        search = self.request.query_params.get("search")

        # only top-level (parent is NULL) when filtering by "me"
        if created_by == "me" and self.request.user.is_authenticated:
            qs = qs.filter(created_by=self.request.user)

        if search:
            qs = qs.filter(Q(name__icontains=search) | Q(description__icontains=search))

        return qs

    # Use: Resolve object by pk or slug; falls back across both.
    # Ordering: Not applicable (single object resolution).
    def get_object(self):
        print("---- get_object called with pk =", self.kwargs.get("pk"))
        lookup = self.kwargs.get("pk")
        base = self.get_queryset_all()
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

    # Use: True if user is ADMIN in this group (staff-only restriction applies).
    # Ordering: Not applicable.
    def _is_admin(self, user_id, group) -> bool:
        ADMIN = getattr(GroupMembership, "ROLE_ADMIN", "admin")
        ACTIVE = getattr(GroupMembership, "STATUS_ACTIVE", "active")
        # STAFF-ONLY ADMIN/MOD: must be staff AND active
        return GroupMembership.objects.filter(
            group=group, user_id=user_id, role=ADMIN, status=ACTIVE, user__is_staff=True
        ).exists()

    # Use: True if user is ADMIN in this group (without staff requirement).
    # Ordering: Not applicable.
    def _is_admin_any(self, user_id, group) -> bool:
        return GroupMembership.objects.filter(
            group=group, user_id=user_id, role=GroupMembership.ROLE_ADMIN
        ).exists()
    
    # Use: True if user is MODERATOR in this group (staff-only).
    # Ordering: Not applicable.
    def _is_moderator(self, user_id, group) -> bool:
        MOD = getattr(GroupMembership, "ROLE_MODERATOR", "moderator")
        ACTIVE = getattr(GroupMembership, "STATUS_ACTIVE", "active")
        # STAFF-ONLY ADMIN/MOD: must be staff AND active
        return GroupMembership.objects.filter(
            group=group, user_id=user_id, role=MOD, status=ACTIVE, user__is_staff=True
        ).exists()

    # Use: Can current request user manage this group (owner/creator/staff).
    # Ordering: Not applicable.
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
    
    # Return the Community for this group
    def _resolve_group_community(self, group):
        """
        Always return a Community for this group.
        Fallback: use parent.community if group's own community is null.
        """
        comm = getattr(group, "community", None)
        print(f"++++++++++++++++++++ comm : {comm}")
        if comm:
            return comm
        parent = getattr(group, "parent", None)
        if parent and getattr(parent, "community", None):
            return parent.community
        return None

    # Use: Can current user set roles (manage OR admin(staff)).
    # Ordering: Not applicable.
    def _can_set_roles(self, request, group: Group) -> bool:
        uid = getattr(request.user, "id", None)
        return self._can_manage(request, group) or (uid and self._is_admin(uid, group))

    # Use (Endpoint): POST /api/groups/  (with sub-group support)
    # - Top-level create requires staff; sub-group create allowed for parent owner/admin/staff.
    # Ordering: Not applicable.
    def create(self, request, *args, **kwargs):
        # make a mutable copy
        data = request.data.copy()
        parent_id = data.get("parent_id") or data.get("parent")
        uid = getattr(request.user, "id", None)

        # --- helper: build a unique slug like "test", "test-1", "test-2", ... ---
        from django.utils.text import slugify
        def ensure_unique_slug(text: str) -> str:
            base = slugify(text or "") or "group"
            # respect model's max_length
            try:
                max_len = Group._meta.get_field("slug").max_length or 50
            except Exception:
                max_len = 50
            base = base[:max_len]
            cand = base
            i = 1
            # case-insensitive uniqueness
            while Group.objects.filter(slug__iexact=cand).exists():
                suffix = f"-{i}"
                cand = f"{base[: max_len - len(suffix)]}{suffix}"
                i += 1
            return cand

        # If a slug or name was provided, pre-resolve a unique slug BEFORE validation
        if data.get("slug") or data.get("name"):
            data["slug"] = ensure_unique_slug(data.get("slug") or data.get("name"))

        # -------------------- SUB-GROUP path --------------------
        if parent_id:
            try:
                parent = Group.objects.get(pk=int(parent_id))
            except Exception:
                return Response({"detail": "Invalid parent_id"}, status=400)

            # owner/creator OR admin on parent OR site staff
            if not (
                self._can_manage(request, parent)
                or self._is_admin_any(uid, parent)
                or getattr(request.user, "is_staff", False)
            ):
                return Response({"detail": "Only parent owner/admin can create sub-groups."}, status=403)

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)

            group = serializer.save(
                created_by=request.user,
                owner=request.user,
                parent=parent,
                community=parent.community,
            )

            GroupMembership.objects.get_or_create(
                group=group, user=request.user,
                defaults={"role": GroupMembership.ROLE_MEMBER, "status": GroupMembership.STATUS_ACTIVE}
            )

            out = self.get_serializer(group)
            headers = self.get_success_headers(out.data)
            return Response(out.data, status=status.HTTP_201_CREATED, headers=headers)

        # -------------------- TOP-LEVEL path (staff-only) --------------------
        if not request.user.is_staff:
            return Response({"detail": "Only admins can create groups."}, status=403)

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)

        owner = request.user
        community_id = data.get("community_id") or data.get("community")
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

    # Use (Endpoint): PUT /api/groups/{id}/
    # - Owner/admin/staff-only full update.
    # Ordering: Not applicable.
    def update(self, request, *args, **kwargs):
        group = self.get_object()
        if not self._can_manage(request, group):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
        return super().update(request, *args, **kwargs)

    # Use (Endpoint): PATCH /api/groups/{id}/
    # - Owner/admin/staff-only partial update. Supports removing cover image.
    # Ordering: Not applicable.
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

    # Use (Endpoint): DELETE /api/groups/{id}/
    # - Owner/admin/staff-only delete group.
    # Ordering: Not applicable.
    def destroy(self, request, *args, **kwargs):
        group = self.get_object()
        if not self._can_manage(request, group):
            return Response({"detail": "Only owner/admin can delete a group."}, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)

    # Use: Hook after successful serializer.create to enforce community membership and emit FeedItem.
    # Ordering: Not applicable (single item create).
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
                group=group, 
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

    # Use (Endpoint): GET /api/groups/mine/
    # - Lists groups created by current user.
    # Ordering: No explicit order_by (natural order). Use ?ordering param at view level if needed.
    @action(detail=False, methods=["get"])
    def mine(self, request):
        print("---- fetching my groups for user:", request.user)
        qs = self.get_queryset_all().filter(created_by=request.user)
        page = self.paginate_queryset(qs)
        ser = self.get_serializer(page or qs, many=True)
        return self.get_paginated_response(ser.data) if page is not None else Response(ser.data)

    # Use (Endpoint): GET /api/groups/{id}/members
    # - Returns ACTIVE members of a group.
    # Ordering: No explicit order_by; defaults to model ordering. Add order_by('user__id') if deterministic needed.
    @action(detail=True, methods=["get"], url_path="members")
    def members(self, request, pk=None):
        group = self.get_object()
        memberships = GroupMembership.objects.filter(
            group=group, status=GroupMembership.STATUS_ACTIVE
        ).select_related("user")
        return Response(GroupMemberOutSerializer(memberships, many=True).data)

    # Use (Endpoint): POST /api/groups/{id}/members/add-member
    # - Owner/admin add members directly as ACTIVE.
    # Ordering: Not applicable (mutation).
    @action(detail=True, methods=["post"], url_path="members/add-member")
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

    # Use (Endpoint): POST /api/groups/{id}/moderator/request-add-members
    # - Create PENDING invites (or convert to PENDING if not ACTIVE). Moderator/admin/owner only.
    # Ordering: Not applicable (mutation). Response lists members without explicit ordering.
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
    @action(detail=True, methods=["post"], url_path="moderator/request-add-members", parser_classes=[JSONParser])
    def request_add_members(self, request, pk=None):
        """
        Body (JSON):
        {"user_id": 3}
        (optional) {"group_id": 1}  # sanity check against URL group
        Effect: create/update membership with status=PENDING and invited_by=request.user.
        """
        group = self.get_object()
        requester_id = getattr(request.user, "id", None)

        if not (request.user and request.user.is_authenticated and requester_id):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        # allow if owner/admin OR moderator of this group
        if not (self._can_manage(request, group) or self._is_moderator(requester_id, group)):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        body_gid = request.data.get("group_id")
        if body_gid is not None and int(body_gid) != int(group.pk):
            return Response({"detail": "group_id mismatch with URL"}, status=status.HTTP_400_BAD_REQUEST)

        uid = request.data.get("user_id")
        if uid is None:
            return Response({"detail": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            uid = int(uid)
        except Exception:
            return Response({"detail": "user_id must be an integer"}, status=status.HTTP_400_BAD_REQUEST)

        default_role = GroupMembership.ROLE_MEMBER
        STATUS_ACTIVE = GroupMembership.STATUS_ACTIVE
        STATUS_PENDING = GroupMembership.STATUS_PENDING

        membership, created = GroupMembership.objects.get_or_create(
            group=group,
            user_id=uid,
            defaults={"role": default_role, "status": STATUS_PENDING, "invited_by_id": requester_id},
        )

        updated = False
        if not created:
            updates = {}
            if membership.status != STATUS_ACTIVE:
                updates["status"] = STATUS_PENDING
            if getattr(membership, "invited_by_id", None) is None:
                updates["invited_by_id"] = requester_id
            if updates:
                GroupMembership.objects.filter(pk=membership.pk).update(**updates)
                updated = True

        memberships = GroupMembership.objects.filter(group=group).select_related("user")
        return Response(
            {
                "detail": "Member request processed.",
                "created": bool(created),
                "updated": bool(updated),
                "members": GroupMemberOutSerializer(memberships, many=True).data,
            },
            status=status.HTTP_200_OK,
        )
    
    # Use: Internal helper to activate PENDING members (and parent activation for sub-groups).
    # Ordering: Not applicable.
    def _activate_members(self, group, user_ids):
        STATUS_ACTIVE = GroupMembership.STATUS_ACTIVE
        STATUS_PENDING = GroupMembership.STATUS_PENDING

        updated = GroupMembership.objects.filter(
            group=group, user_id__in=user_ids, status=STATUS_PENDING
        ).update(status=STATUS_ACTIVE)

        # ensure parent membership(s) if this is a sub-group
        if group.parent_id:
            for uid in user_ids:
                try:
                    self._ensure_parent_membership_active(group, int(uid))
                except Exception:
                    pass
        return updated

    # Use (Endpoint): POST /api/groups/{id}/member-requests/approve/{user_id}
    # - Approve a single pending request.
    # Ordering: Not applicable.
    @extend_schema(
        request=None,
        parameters=[OpenApiParameter("user_id", OpenApiTypes.INT, OpenApiParameter.PATH,
                                    description="User ID to approve")],
        examples=[OpenApiExample("Approve one", value=None)],
    )
    @action(detail=True, methods=["post"], url_path=r"member-requests/approve/(?P<user_id>\d+)")
    def approve_member_request_one(self, request, pk=None, user_id=None):
        group = self.get_object()
        if not self._can_set_roles(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        uid = int(user_id)
        updated = self._activate_members(group, [uid])
        return Response({"ok": True, "updated": updated, "user_id": uid})
    
    # Use (Endpoint): POST /api/groups/{id}/member-requests/reject/{user_id}
    # - Reject a single pending request (delete pending membership).
    # Ordering: Not applicable.
    @extend_schema(
        request=None,
        parameters=[OpenApiParameter("user_id", OpenApiTypes.INT, OpenApiParameter.PATH,
                                    description="User ID to reject")],
    )
    @action(detail=True, methods=["post"], url_path=r"member-requests/reject/(?P<user_id>\d+)")
    def reject_member_request_one(self, request, pk=None, user_id=None):
        group = self.get_object()
        if not self._can_set_roles(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        uid = int(user_id)
        STATUS_PENDING = GroupMembership.STATUS_PENDING
        deleted, _ = GroupMembership.objects.filter(
            group=group, user_id=uid, status=STATUS_PENDING
        ).delete()
        return Response({"ok": True, "deleted": deleted, "user_id": uid})

    # Use (Endpoint): POST /api/groups/{id}/members/remove-member
    # - Owner/admin remove a member (cannot remove owner).
    # Ordering: Not applicable.
    @action(detail=True, methods=["post"], url_path="members/remove-member")
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

    # Use (Endpoint): GET /api/groups/{id}/moderator/can-i
    # - Returns capability flags for current user (owner/admin/mod/staff).
    # Ordering: Not applicable.
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

    # Use: Safe getter for activity_feed.FeedItem model.
    # Ordering: Not applicable.
    def _get_feeditem_model(self):
        try:
            return apps.get_model('activity_feed', 'FeedItem')
        except Exception:
            return None

    # Use: Safe getter for messaging.Message model.
    # Ordering: Not applicable.
    def _get_message_model(self):
        try:
            return apps.get_model('messaging', 'Message')
        except Exception:
            return None

    # Use: True if user can moderate content (owner/admin/mod/staff).
    # Ordering: Not applicable.
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

    
    # Use: ContentType id helper for a model class.
    # Ordering: Not applicable.
    def _ct_id(self, model):
        try:
            return ContentType.objects.get_for_model(model).id
        except Exception:
            return None

    # Use: Resolve a FeedItem (or construct one from a poll) ensuring it belongs to current group.
    # - Accepts FeedItem id OR a poll_id fallback scenario.
    # Ordering: When creating linked item, no list ordering; when fetching, first() uses DB default.
    def _load_group_item(self, group, identifier):
        """
        Return a FeedItem that belongs to this group.
        identifier is a FeedItem id (int/str).
        """
        try:
            fid = int(identifier)
        except (TypeError, ValueError):
            return None, "Invalid feed item id"

        from activity_feed.models import FeedItem  # local import to avoid cycles
        item = (FeedItem.objects
                .select_related("group", "community", "actor")
                .filter(id=fid)
                .first())
        if not item:
            return None, "Feed item not found"
        if item.group_id != group.id:
            return None, "Item does not belong to this group"
        return item, None
    
    def _my_friend_ids(self, me_id: int) -> set[int]:
        if not me_id:
            return set()
        pairs = Friendship.objects.filter(
            Q(user1_id=me_id) | Q(user2_id=me_id)
        ).values_list("user1_id", "user2_id")

        out = set()
        for u1, u2 in pairs:
            out.add(u2 if u1 == me_id else u1)
        return out

    @action(detail=False, methods=["get"], url_path="suggested")
    def suggested(self, request):
        """
        Mutual group suggestions:
        - public + top-level groups
        - user is NOT a member (any status)
        - at least 1 of my friends is an ACTIVE member
        """
        me = request.user
        if not (me and me.is_authenticated):
            return Response({"detail": "Authentication required."}, status=401)

        # limit
        try:
            limit = int(request.query_params.get("limit", 12))
        except ValueError:
            limit = 12
        limit = max(1, min(limit, 50))

        # optional community scope
        community_id = request.query_params.get("community_id")
        try:
            community_id = int(community_id) if community_id else None
        except ValueError:
            community_id = None

        friend_ids = self._my_friend_ids(me.id)
        if not friend_ids:
            return Response([])

        # exclude any groups where I already have membership (active/pending/etc)
        my_group_ids = GroupMembership.objects.filter(user_id=me.id).values_list("group_id", flat=True)

        qs = Group.objects.filter(
            visibility=Group.VISIBILITY_PUBLIC,
            parent__isnull=True,
        )

        if community_id:
            qs = qs.filter(community_id=community_id)

        qs = qs.exclude(id__in=my_group_ids)

        # counts
        qs = qs.annotate(
            member_count=Count(
                "memberships",
                filter=Q(memberships__status=GroupMembership.STATUS_ACTIVE),
                distinct=True,
            ),
            mutuals=Count(
                "memberships",
                filter=Q(
                    memberships__status=GroupMembership.STATUS_ACTIVE,
                    memberships__user_id__in=friend_ids,
                ),
                distinct=True,
            ),
        ).filter(mutuals__gt=0).order_by("-mutuals", "-member_count", "-created_at")[:limit]

        groups = list(qs)
        if not groups:
            return Response([])

        group_ids = [g.id for g in groups]

        # mutual preview (3 users per group)
        mutual_memberships = (
            GroupMembership.objects.filter(
                group_id__in=group_ids,
                status=GroupMembership.STATUS_ACTIVE,
                user_id__in=friend_ids,
            )
            .select_related("user")
            .order_by("group_id", "-joined_at")
        )

        mutual_map = {}
        for m in mutual_memberships:
            arr = mutual_map.setdefault(m.group_id, [])
            if len(arr) < 3:
                arr.append(m.user)

        ser = SuggestedGroupSerializer(
            groups,
            many=True,
            context={"request": request, "mutual_members_map": mutual_map},
        )
        return Response(ser.data)

    @action(detail=True, methods=["get"], url_path="mutual-members")
    def mutual_members(self, request, pk=None):
        group = self.get_object()

        me = request.user
        if not (me and me.is_authenticated):
            return Response({"detail": "Authentication required."}, status=401)

        # Only expose mutuals for public groups
        if group.visibility != Group.VISIBILITY_PUBLIC:
            raise NotFound("Group not found.")

        try:
            limit = int(request.query_params.get("limit", 20))
        except ValueError:
            limit = 20
        limit = max(1, min(limit, 50))

        friend_ids = self._my_friend_ids(me.id)
        if not friend_ids:
            return Response([])

        memberships = (
            GroupMembership.objects.filter(
                group=group,
                status=GroupMembership.STATUS_ACTIVE,
                user_id__in=friend_ids,
            )
            .select_related("user")
            .order_by("-joined_at")[:limit]
        )

        users = [m.user for m in memberships]
        return Response(UserMiniSerializer(users, many=True, context={"request": request}).data)


    # Use (Endpoint): GET /api/groups/explore-groups
    # - Public, top-level groups for discovery.
    # Ordering: Explicit order_by("-created_at") (newest first).
    @action(detail=False, methods=["get"], url_path="explore-groups")
    def explore_groups(self, request):
        """
        Public, top-level groups.
        Hides groups where the current user is already an ACTIVE member,
        but keeps groups visible if the user's membership is PENDING.
        """
        qs = (
            self.get_queryset_all()
            .filter(visibility=Group.VISIBILITY_PUBLIC)
            .order_by("-created_at")
        )

        user = request.user
        if user and user.is_authenticated:
            active_membership = GroupMembership.objects.filter(
                group_id=OuterRef("pk"),
                user_id=user.id,
                status=GroupMembership.STATUS_ACTIVE,
            )
            # Exclude groups where ACTIVE membership exists
            qs = qs.annotate(_joined=Exists(active_membership)).filter(_joined=False)

        page = self.paginate_queryset(qs)
        ser = self.get_serializer(page or qs, many=True, context={"request": request})
        return self.get_paginated_response(ser.data) if page is not None else Response(ser.data)

    # Use (Endpoint): GET /api/groups/joined-groups  (auth only)
    # - Lists groups where the user is ACTIVE or PENDING.
    # Ordering: Explicit order_by("-created_at") (newest groups first).
    @action(detail=False, methods=["get"], url_path="joined-groups", permission_classes=[IsAuthenticated])
    def joined(self, request):
        """
        My Groups = active + pending (invited/requested).
        """
        user = request.user
        statuses = [GroupMembership.STATUS_ACTIVE, GroupMembership.STATUS_PENDING]

        # Subquery: does the current user have ACTIVE or PENDING membership in this group?
        user_memberships = GroupMembership.objects.filter(
            group_id=OuterRef("pk"),
            user_id=user.id,
            status__in=statuses,
        )

        qs = (
            Group.objects
            # keep only groups where the above subquery EXISTS
            .annotate(_am_member=Exists(user_memberships))
            .filter(_am_member=True)
            # count ALL ACTIVE members of the group
            .annotate(
                member_count=Count(
                    "memberships",
                    filter=Q(memberships__status=GroupMembership.STATUS_ACTIVE),
                )
            )
            .order_by("-created_at")
            .distinct()
        )

        page = self.paginate_queryset(qs)
        ser = self.get_serializer(page or qs, many=True, context={"request": request})
        return self.get_paginated_response(ser.data) if page is not None else Response(ser.data)



    # Use (Endpoint): POST /api/groups/{id}/posts/delete-post
    # - Soft delete a feed item (post/poll/image/link/event).
    # Ordering: Not applicable (single item update).
    @action(detail=True, methods=["post"], url_path="posts/delete-post")
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
    
    # Use (Endpoint): POST /api/groups/{id}/posts/hide-post
    # - Hide a feed item (soft visibility off).
    # Ordering: Not applicable (single item update).
    class HidePostIn(serializers.Serializer):
        id = serializers.IntegerField(help_text="Feed item ID to hide")

    @extend_schema(request=HidePostIn)
    @action(detail=True, methods=["post"], url_path="posts/hide-post")
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

    # Use (Endpoint): POST /api/groups/{id}/posts/unhide-post
    # - Unhide a previously hidden feed item.
    # Ordering: Not applicable (single item update).
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
    @action(detail=True, methods=["post"], url_path="posts/unhide-post")
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

    # Use: Verify a message truly belongs to the group (group chat or event chat).
    # Ordering: Not applicable.
    def _ensure_message_in_group(self, msg, group):
        conv = getattr(msg, "conversation", None)
        if not conv:
            return False

        # Common group chat: group_id present, event_id null, matches this group
        if (getattr(conv, "group_id", None) is not None) and (getattr(conv, "event_id", None) is None) and (conv.group_id == group.id):
            return True

        # Event live chat: event_id present, group_id null → count it if Event belongs to this group
        if (getattr(conv, "event_id", None) is not None) and (getattr(conv, "group_id", None) is None) and getattr(conv, "event", None):
            ev = conv.event
            if hasattr(ev, "group_id") and ev.group_id == group.id:
                return True


        # Legacy fallback by room_key
        rk = (getattr(conv, "room_key", "") or "")
        if rk == f"group:{group.id}":
            return True

        return False

    # Use: Load a Message; ensure group ownership.
    # Ordering: Not applicable.
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

    # Use (Endpoint): POST /api/groups/{id}/message/hide-message
    # - Hide a message (requires Message model to support is_hidden).
    # Ordering: Not applicable.
    @action(detail=True, methods=["post"], url_path="message/hide-message")
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

    # Use (Endpoint): POST /api/groups/{id}/message/unhide-message
    # - Unhide a message.
    # Ordering: Not applicable.
    @action(detail=True, methods=["post"], url_path="message/unhide-message")
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

    # Use (Endpoint): POST /api/groups/{id}/message/delete-message
    # - Soft delete a message (is_deleted + deleted_at).
    # Ordering: Not applicable.
    @action(detail=True, methods=["post"], url_path="message/delete-message")
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

    # Use (Endpoint): POST /api/groups/{id}/set-role
    # - Owner/admin sets role (admin/mod/member) with staff-only restriction for admin/mod.
    # Ordering: Not applicable.
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

    # Use (Endpoint): POST /api/groups/{id}/change-role
    # - Alias to set_role.
    # Ordering: Not applicable.
    @action(detail=True, methods=["post"], url_path="change-role")
    def change_role(self, request, pk=None):
        return self.set_role(request, pk)

    # Use (Endpoint): POST /api/groups/{id}/promotion/request
    # - Staff moderator requests promotion to admin.
    # Ordering: Not applicable.
    @action(detail=True, methods=["post"], url_path="promotion/request", parser_classes=[JSONParser])
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

    # Use (Endpoint): GET /api/groups/{id}/promotion/request-list?status=pending|approved|rejected
    # - List promotion requests for a group, filterable by status.
    # Ordering: Explicit order_by("-created_at") (newest requests first).
    @action(detail=True, methods=["get"], url_path="promotion/request-list")
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
                .order_by("-created_at"))  # Ordering: newest first

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

    # Use (Endpoint): POST /api/groups/{id}/promotion/request-approve
    # - Approve promotion requests (or by user_ids). Staff-only constraint enforced.
    # Ordering: Not applicable.
    @action(detail=True, methods=["post"], url_path="promotion/request-approve", parser_classes=[JSONParser])
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

    # Use (Endpoint): POST /api/groups/{id}/promotion/request-reject
    # - Reject promotion requests (bulk).
    # Ordering: Not applicable.
    @action(detail=True, methods=["post"], url_path="promotion/request-reject", parser_classes=[JSONParser])
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

    # Use (Endpoint): GET /api/groups/{id}/subgroups
    # - List sub-groups of a parent group.
    # Ordering: Explicit order_by("-created_at") (newest sub-groups first).
    @action(detail=True, methods=['get'])
    def subgroups(self, request, pk=None):
        parent = self.get_object()
        qs = Group.objects.filter(parent=parent).select_related('community', 'created_by').order_by('-created_at')  # Ordering: newest first
        page = self.paginate_queryset(qs)
        ser = GroupSerializer(page or qs, many=True, context={'request': request})
        if page is not None:
            return self.get_paginated_response(ser.data)
        return Response(ser.data)

    # Use (Endpoint): GET /api/groups/{id}/member-requests
    # - List PENDING group memberships (join requests). Owner/admin/mod/staff only.
    # Ordering: Explicit order_by("-joined_at") (latest requests first).
    @action(detail=True, methods=["get"], url_path="member-requests")
    def pending_requests(self, request, pk=None):
        """
        GET /api/groups/{id-or-slug}/member-requests/
        By default shows *user-initiated* pending requests (invited_by is NULL).
        Add ?include=all to also include admin-initiated pending invites.
        """
        group = self.get_object()

        # Owner/Admin/Moderator/Staff can view
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        # include = (request.query_params.get("include") or "").lower()
        qs = GroupMembership.objects.filter(
            group=group,
            status=GroupMembership.STATUS_PENDING,
        )
        # Only show real "requests to join" unless include=all is passed
        # if include != "all":
        #     qs = qs.filter(invited_by__isnull=True)

        qs = qs.select_related("user").order_by("-joined_at")  # Ordering: newest request first

        if not qs.exists():
            return Response(
                {"ok": True, "message": "No pending requests", "requests": []},
                status=200,
            )

        data = GroupMemberOutSerializer(qs, many=True).data
        return Response({"ok": True, "count": len(data), "requests": data}, status=200)
    
    # Use (Endpoint): POST /api/groups/{id}/join-group
    # - Handle join flows for all visibility/policy combos (open/approval/invite + public/private).
    # Ordering: Not applicable.
    @action(detail=True, methods=["post"], url_path="join-group")
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

    # Use (Endpoint): POST /api/groups/{id}/join-group/request/
    # - Purpose: Submit a join request for groups that require approval.
    @action(detail=True, methods=["post"], url_path="join-group/request", parser_classes=[JSONParser])
    def request_join_group(self, request, pk=None):
        """
        POST /api/groups/{id}/join-group/request/
        For groups with join policy = public_approval.
        Creates (or reactivates) a pending membership request for the current user.
        """
        group = self.get_object()
        user = request.user
        if not (user and user.is_authenticated):
            return Response({"detail": "Authentication required."}, status=status.HTTP_403_FORBIDDEN)

        # Join request allowed only for PUBLIC + APPROVAL
        policy = getattr(group, "join_policy", None)
        visibility = getattr(group, "visibility", None)

        pol = str(policy or "").lower()
        vis = str(visibility or "").lower()

        JOIN_OPEN = str(getattr(type(group), "JOIN_OPEN", "open")).lower()
        JOIN_APPROVAL = str(getattr(type(group), "JOIN_APPROVAL", "approval")).lower()
        VIS_PUBLIC = str(getattr(type(group), "VISIBILITY_PUBLIC", "public")).lower()
        VIS_PRIVATE = str(getattr(type(group), "VISIBILITY_PRIVATE", "private")).lower()

        is_public = (vis == VIS_PUBLIC)
        is_open = pol in {JOIN_OPEN, "open"}
        is_approval = pol in {JOIN_APPROVAL, "approval", "public_approval"}

        # If PUBLIC+OPEN, directly invoke the /join-group/ action (no 400)
        if is_public and is_open:
            if hasattr(self, "join_group"):
                return self.join(request, pk=pk)  # delegate to open-join endpoint

            # ---- fallback inline "open join" if join_group action isn't present ----
            default_role = GroupMembership.ROLE_MEMBER
            STATUS_ACTIVE = GroupMembership.STATUS_ACTIVE
            membership, created = GroupMembership.objects.get_or_create(
                group=group,
                user=request.user,
                defaults={"role": default_role, "status": STATUS_ACTIVE},
            )
            if not created and membership.status != STATUS_ACTIVE:
                GroupMembership.objects.filter(pk=membership.pk).update(status=STATUS_ACTIVE)
                membership.refresh_from_db()
            return Response(
                {"detail": "Joined successfully.", "membership": GroupMemberOutSerializer(membership).data},
                status=status.HTTP_200_OK,
            )

        # Allow only PUBLIC+APPROVAL to proceed with pending request logic below
        if not (is_public and is_approval):
            return Response({"detail": "This group doesn't accept join requests."},
                            status=status.HTTP_400_BAD_REQUEST)

        default_role = GroupMembership.ROLE_MEMBER
        STATUS_ACTIVE = GroupMembership.STATUS_ACTIVE
        STATUS_PENDING = GroupMembership.STATUS_PENDING

        membership, created = GroupMembership.objects.get_or_create(
            group=group,
            user=user,
            defaults={"role": default_role, "status": STATUS_PENDING}
        )

        # Already a member
        if not created and membership.status == STATUS_ACTIVE:
            return Response({"detail": "You are already a member."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Already requested
        if not created and membership.status == STATUS_PENDING:
            return Response({
                "detail": "Join request already pending.",
                "membership": GroupMemberOutSerializer(membership).data
            }, status=status.HTTP_200_OK)

        # If membership exists in another status (e.g., left/removed), flip back to pending
        if not created and membership.status != STATUS_PENDING:
            GroupMembership.objects.filter(pk=membership.pk).update(status=STATUS_PENDING)

        # Fresh read for response
        membership = GroupMembership.objects.select_related("user").get(pk=membership.pk)

        return Response({
            "detail": "Join request submitted.",
            "membership": GroupMemberOutSerializer(membership).data
        }, status=status.HTTP_200_OK)

    # Use (Endpoint): GET /api/groups/{id}/join-group-link
    # - Generate a join token + relative URL for approval+private groups. Owner/admin/staff only.
    # Ordering: Not applicable.
    @action(detail=True, methods=["get"], url_path="join-group-link")
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

    # Use (Endpoint): POST /api/groups/{id}/join-group-link/rotate
    # - Rotate the join token by touching updated_at. Owner/admin/staff only.
    # Ordering: Not applicable.
    @action(detail=True, methods=["post"], url_path="join-group-link/rotate")
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

    # Use (Endpoint): GET/POST /api/groups/{id}/settings/message-mode
    # - GET: returns message_mode
    # - POST: set admins_only or message_mode; allowed for owner/admin/mod/staff.
    # Ordering: Not applicable.
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

    # Use (Endpoint): GET /api/groups/{id}/can-send
    # - Probe if current user can send messages to this group.
    # Ordering: Not applicable.
    @action(detail=True, methods=["get"], url_path="can-send")
    def can_send(self, request, pk=None):
        """
        Quick capability probe for the current user.
        """
        group = self.get_object()
        ok, reason = self._can_send_message_to_group(request, group)
        return Response({"ok": ok, "reason": reason, "message_mode": group.message_mode})

    
    # PATCH /api/groups/{id}/posts/{item_id}/edit
    @action(detail=True, methods=["patch"], url_path=r"posts/(?P<item_id>\d+)/edit",
            parser_classes=[JSONParser, FormParser, MultiPartParser])
    def posts_edit(self, request, pk=None, item_id=None):
        group = self.get_object()

        # Only owner/admin/moderator may edit (same rule you use to create) :contentReference[oaicite:9]{index=9}
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        try:
            item_id = int(item_id)
        except Exception:
            return Response({"detail": "Invalid post id"}, status=400)

        it = FeedItem.objects.filter(pk=item_id).first()
        if not it:
            return Response({"detail": "Post not found"}, status=404)

        # Validate that the item belongs to this group
        meta = dict(it.metadata or {})
        if getattr(it, "group_id", None) != group.id and meta.get("group_id") != group.id:
            return Response({"detail": "Post does not belong to this group"}, status=409)

        t = (meta.get("type") or "post").lower()
        if t == "post" and "content" in meta:
            t = "text"   # back-compat with older records :contentReference[oaicite:10]{index=10}

        # Apply updates based on type
        if t == "text":
            if "text" in request.data:
                meta["text"] = (request.data.get("text") or "").strip()

        elif t == "image":
            if "text" in request.data:
                meta["text"] = (request.data.get("text") or "").strip()
            # Optional image replacement via multipart
            f = request.FILES.get("image")
            if f:
                name = slugify(Path(f.name).stem) or "image"
                ext = (Path(f.name).suffix or ".jpg").lower()
                key = f"previews/feed/{name}-{uuid4().hex[:8]}{ext}"
                storage = S3Boto3Storage()
                path = storage.save(key, f)
                url = storage.url(path)  # same pattern as create :contentReference[oaicite:11]{index=11}
                meta["image"] = url

        elif t == "link":
            if "text" in request.data:
                meta["text"] = (request.data.get("text") or "").strip()
            if "url" in request.data:
                meta["url"] = (request.data.get("url") or "").strip()

        elif t == "event":
            # Simple, targeted merge
            for fld in ("title", "starts_at", "ends_at", "text"):
                if fld in request.data:
                    val = request.data.get(fld)
                    meta[fld] = (val or "").strip() if isinstance(val, str) else val

        elif t == "poll":
            return Response({"detail": "Edit polls via /api/activity/feed/polls/update/"}, status=400)

        else:
            # unknown type: shallow merge of primitives
            for k, v in request.data.items():
                if k != "image":
                    meta[k] = v

        meta["edited_at"] = timezone.now().isoformat()
        it.metadata = meta
        it.save(update_fields=["metadata"])
        return Response({"ok": True, "id": it.id})

    # Optional alias: POST/DELETE /api/groups/{id}/posts/{item_id}/delete
    @action(detail=True, methods=["post", "delete"], url_path=r"posts/(?P<item_id>\d+)/delete")
    def posts_delete_by_path(self, request, pk=None, item_id=None):
        group = self.get_object()
        if not self._can_moderate_any(request, group):
            return Response({"detail": "Forbidden"}, status=403)

        it = FeedItem.objects.filter(pk=item_id).first()
        if not it:
            return Response({"detail": "Post not found"}, status=404)
        if getattr(it, "group_id", None) != group.id and (it.metadata or {}).get("group_id") != group.id:
            return Response({"detail": "Post does not belong to this group"}, status=409)

        m = it.metadata or {}
        m["is_deleted"] = True
        m["deleted_at"] = timezone.now().isoformat()
        it.metadata = m
        it.save(update_fields=["metadata"])
        return Response({"ok": True})

    


class UsersLookupView(APIView):
    permission_classes = [IsAuthenticated]

    # Use (Endpoint): GET /api/users-lookup?search=<q>&limit=<n>
    # - Staff-only lightweight user lookup (id, name, email, avatar).
    # Ordering: Explicit order_by("id") then slicing [:limit].
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
        qs = qs.order_by("id")[:limit]  # Ordering: ascending by id

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


class GroupNotificationViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
    List group-related notifications for the current user.
    Example: /api/groups/group-notifications/?unread=1&kind=join_request
    """
    permission_classes = [IsAuthenticated]
    serializer_class = GroupNotificationSerializer

    def get_queryset(self):
        me = self.request.user
        qs = GroupNotification.objects.filter(recipient=me).order_by("-created_at")

        kind = self.request.query_params.get("kind")
        unread = self.request.query_params.get("unread")
        group_id = self.request.query_params.get("group_id")

        if kind:
            qs = qs.filter(kind=kind)
        if unread in {"1", "true", "True"}:
            qs = qs.filter(is_read=False)
        if group_id:
            qs = qs.filter(group_id=group_id)

        return qs

    @action(detail=False, methods=["post"], url_path="mark-read")
    def mark_read(self, request):
        ids = request.data.get("ids", [])
        GroupNotification.objects.filter(
            recipient=request.user,
            id__in=ids,
        ).update(is_read=True)
        return Response({"ok": True})
