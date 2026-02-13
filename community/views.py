# community/view.py
from django.db.models import Q
from friends.models import Friendship
from rest_framework import permissions,viewsets,serializers
from django.shortcuts import get_object_or_404
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.contenttypes.models import ContentType
from rest_framework import status
from django.apps import apps
from uuid import uuid4
from django.core.files.storage import default_storage
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from .models import Community

from .serializers import CommunitySerializer

class CommunityViewSet(viewsets.ModelViewSet):
    serializer_class = CommunitySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Community.objects.filter(Q(owner=user) | Q(members=user)).distinct().order_by("-id")

    def perform_create(self, serializer):
        serializer.save()

    # ---------- Community Feed: create a post ----------
    class _CommunityPostCreateSerializer(serializers.Serializer):
        # common
        type = serializers.ChoiceField(choices=[("text","text"),("image","image"),("link","link"),("poll","poll")], required=False, default="text")
        visibility = serializers.ChoiceField(
            choices=[("public","public"),("community","community"),("friends","friends")],
            required=False  # ← no default
        )
        tags = serializers.ListField(child=serializers.CharField(max_length=50), required=False)

        # text
        content = serializers.CharField(max_length=4000, required=False, allow_blank=True)

        # image
        image = serializers.ImageField(required=False, allow_empty_file=False)
        caption = serializers.CharField(max_length=4000, required=False, allow_blank=True)

        # link
        url = serializers.URLField(required=False)
        title = serializers.CharField(max_length=255, required=False, allow_blank=True)
        description = serializers.CharField(max_length=1000, required=False, allow_blank=True)

        # poll
        question = serializers.CharField(max_length=500, required=False, allow_blank=True)
        options = serializers.ListField(child=serializers.CharField(max_length=120), required=False)

    @action(detail=True, methods=["post"], url_path="posts/create", parser_classes=[MultiPartParser, FormParser, JSONParser])
    def create_post(self, request, pk=None):
        community = self.get_object()
        user = request.user

        # any member/owner/staff
        is_member = community.members.filter(pk=user.id).exists() or getattr(community, "owner_id", None) == getattr(user, "id", None)
        if not is_member and not getattr(user, "is_staff", False):
            return Response({"detail": "Only community members can create posts."}, status=403)

        ser = self._CommunityPostCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        data = ser.validated_data
        typ = data.get("type", "text")
        requested_vis = data.get("visibility") if "visibility" in data else None
        is_owner = getattr(community, "owner_id", None) == getattr(user, "id", None)

        if getattr(user, "is_staff", False) or is_owner:
            # Admin/Owner (community-level): default to community if not provided
            visibility = requested_vis or "community"
        else:
            # Regular member: always friends at community-level
            visibility = "friends"
        tags = data.get("tags") or []

        meta = {"type": typ, "visibility": visibility, "tags": tags}

        # ----- handle types -----
        if typ == "text":
            text = (data.get("content") or "").strip()
            if not text:
                return Response({"detail": "content is required"}, status=400)
            meta["text"] = text

        elif typ == "image":
            file = request.FILES.get("image")
            if not file:
                return Response({"detail": "image file is required"}, status=400)
            key = f"community_posts/{community.id}/{uuid4()}_{file.name}"
            saved_path = default_storage.save(key, file)               # ← uploads to S3 if configured
            meta["image_url"] = default_storage.url(saved_path)
            if data.get("caption"):
                meta["caption"] = data["caption"]

        elif typ == "link":
            if not data.get("url"):
                return Response({"detail": "url is required"}, status=400)
            meta.update({
                "url": data["url"],
                "title": data.get("title") or "",
                "description": data.get("description") or "",
            })

        elif typ == "poll":
            q = (data.get("question") or "").strip()
            opts = [o.strip() for o in (data.get("options") or []) if o and o.strip()]
            if not q or len(opts) < 2:
                return Response({"detail": "poll requires question and at least 2 options"}, status=400)
            meta.update({"question": q, "options": opts})

        else:
            return Response({"detail": f"unsupported type: {typ}"}, status=400)

        # ----- create FeedItem -----
        FeedItem = apps.get_model("activity_feed", "FeedItem")
        ct = ContentType.objects.get_for_model(Community)
        fi = FeedItem.objects.create(
            community=community,
            group=None,
            event=None,
            actor=request.user,
            verb="posted",
            target_content_type=ct,
            target_object_id=community.id,
            metadata=meta,
        )

        # unified response
        # Helper to get avatar
        def get_avatar(u):
            try:
                if hasattr(u, "profile") and u.profile.user_image:
                    return request.build_absolute_uri(u.profile.user_image.url)
            except:
                pass
            return ""

        row = {
            "id": fi.id,
            "type": typ,
            "created_at": fi.created_at,
            "community": {"id": community.id, "name": community.name},
            "actor": {
                "id": fi.actor_id,
                "name": getattr(fi.actor, "get_full_name", lambda: fi.actor.username)(),
                "avatar": get_avatar(fi.actor),
                "kyc_status": getattr(fi.actor.profile, "kyc_status", "not_started") if hasattr(fi.actor, "profile") else "not_started"
            },
            "visibility": visibility,
            "tags": tags,
        }
        if typ == "text":
            row["text"] = meta["text"]
        elif typ == "image":
            row["image_url"] = meta["image_url"]
            row["caption"] = meta.get("caption", "")
        elif typ == "link":
            row["url"] = meta["url"]; row["title"] = meta.get("title"); row["description"] = meta.get("description")
        elif typ == "poll":
            row["question"] = meta["question"]; row["options"] = meta["options"]

        return Response(row, status=201)
    
    # GET /api/communities/{community_id}/posts/?search=...
    @action(detail=True, methods=["get"], url_path="posts")
    def list_posts(self, request, pk=None):
        community = self.get_object()

        # 🔒 Access: only superusers can view
        if not request.user.is_superuser:
            return Response({"detail": "Forbidden"}, status=403)

        FeedItem = apps.get_model("activity_feed", "FeedItem")

        # ONLY admin (community.owner) posts at community level with visibility="community"
        qs = (
            FeedItem.objects.filter(
                community_id=community.id,
                verb="posted",
                group__isnull=True,                 # community-level (not inside a group)
                event__isnull=True,                 # not tied to an event
                actor_id=community.owner_id,        # posted by admin/owner
                metadata__visibility="community",   # community-level visibility
            )
            .order_by("-created_at")
        )

        # optional simple search on text
        q = (request.query_params.get("search") or "").strip()
        if q:
            qs = qs.filter(metadata__text__icontains=q)

        results = []
        for fi in qs:
            meta = fi.metadata or {}
            typ = (meta.get("type") or "text").lower()
            
            # Resolve actor avatar
            actor = fi.actor
            avatar_url = ""
            kyc_status = "not_started"
            if actor:
                try:
                    if hasattr(actor, "profile"):
                        if actor.profile.user_image:
                            avatar_url = request.build_absolute_uri(actor.profile.user_image.url)
                        kyc_status = actor.profile.kyc_status
                except:
                    pass

            row = {
                "id": fi.id,
                "type": typ,
                "created_at": fi.created_at,
                "community": {"id": community.id, "name": community.name},
                "actor": {
                    "id": actor.id if actor else None,
                    "name": getattr(actor, "get_full_name", lambda: actor.username)() if actor else "Unknown",
                    "avatar": avatar_url,
                    "kyc_status": kyc_status,
                },
                "visibility": meta.get("visibility", "public"),
                "tags": meta.get("tags") or [],
            }
            if typ == "text":
                row["text"] = meta.get("text", "")
            elif typ == "image":
                row["image_url"] = meta.get("image_url")
                row["caption"] = meta.get("caption", "")
            elif typ == "link":
                row["url"] = meta.get("url")
                row["title"] = meta.get("title")
                row["description"] = meta.get("description")
            elif typ == "poll":
                row["question"] = meta.get("question")
                row["options"] = meta.get("options") or []
            results.append(row)

        return Response({"results": results}, status=200)

    
    # PATCH/PUT /api/communities/{community_id}/posts/{post_id}/edit/
    @action(
        detail=True,
        methods=["patch", "put"],
        url_path=r"posts/(?P<post_id>\d+)/edit",
    )
    def edit_post(self, request, pk=None, post_id=None):
        community = self.get_object()
        user = request.user

        FeedItem = apps.get_model("activity_feed", "FeedItem")
        ct = ContentType.objects.get_for_model(Community)

        # find the community-level FeedItem (any type)
        post = get_object_or_404(
            FeedItem.objects.filter(
                community_id=community.id,
                group__isnull=True,
                event__isnull=True,
                verb="posted",
                target_content_type=ct,
                target_object_id=community.id,
            ),
            pk=post_id,
        )

        # permissions: owner/staff/original actor
        is_owner = getattr(community, "owner_id", None) == getattr(user, "id", None)
        is_staff = getattr(user, "is_staff", False)
        is_actor = getattr(post, "actor_id", None) == getattr(user, "id", None)
        if not (is_owner or is_staff or is_actor):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        # validate with same serializer you use for create
        ser = self._CommunityPostCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        data = ser.validated_data

        meta = dict(post.metadata or {})
        orig_type = (meta.get("type") or "text").lower()

        # IMPORTANT: we keep the original type; editing doesn't convert types
        if orig_type == "text":
            new_text = (data.get("content") or "").strip()
            if not new_text:
                return Response({"detail": "content is required"}, status=400)
            meta["type"] = "text"
            meta["text"] = new_text

        elif orig_type == "image":
            # optional image replace
            file = request.FILES.get("image")
            if file:
                key = f"community_posts/{community.id}/{uuid4()}_{file.name}"
                saved_path = default_storage.save(key, file)
                meta["image_url"] = default_storage.url(saved_path)
            # caption can always be edited
            if "caption" in data:
                meta["caption"] = data.get("caption") or ""

        elif orig_type == "link":
            # allow partial updates
            if "url" in data:
                meta["url"] = data["url"]
            if "title" in data:
                meta["title"] = data.get("title") or ""
            if "description" in data:
                meta["description"] = data.get("description") or ""

        elif orig_type == "poll":
            # allow editing question/options (careful if you later add votes!)
            q = (data.get("question") or meta.get("question", "")).strip()
            opts = data.get("options") if "options" in data else meta.get("options", [])
            opts = [o.strip() for o in (opts or []) if o and o.strip()]
            if not q or len(opts) < 2:
                return Response({"detail": "poll requires question and at least 2 options"}, status=400)
            meta["question"] = q
            meta["options"] = opts

        else:
            return Response({"detail": f"edit not supported for type: {orig_type}"}, status=400)

        # (optional) update visibility/tags if provided
        if "visibility" in data:
            meta["visibility"] = data["visibility"]
        if "tags" in data:
            meta["tags"] = data.get("tags") or []

        post.metadata = meta
        post.save(update_fields=["metadata"])

        # minimal success payload
        return Response({"ok": True, "id": post.id, "type": orig_type, "metadata": meta}, status=200)


    # DELETE /api/communities/{community_id}/posts/{post_id}/delete/
    @action(
        detail=True,
        methods=["delete"],
        url_path=r"posts/(?P<post_id>\d+)/delete",
    )
    def delete_post(self, request, pk=None, post_id=None):
        community = self.get_object()
        user = request.user

        FeedItem = apps.get_model("activity_feed", "FeedItem")
        ct = ContentType.objects.get_for_model(Community)

        post = get_object_or_404(
            FeedItem.objects.filter(
                community_id=community.id,
                group__isnull=True,
                event__isnull=True,
                verb="posted",
                target_content_type=ct,
                target_object_id=community.id,
            ),
            pk=post_id,
        )

        is_owner = getattr(community, "owner_id", None) == getattr(user, "id", None)
        is_staff = getattr(user, "is_staff", False)
        is_actor = getattr(post, "actor_id", None) == getattr(user, "id", None)
        if not (is_owner or is_staff or is_actor):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        post.delete()
        return Response({"ok": True, "id": int(post_id)}, status=200)
