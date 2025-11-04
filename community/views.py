from django.db.models import Q
from rest_framework import permissions,viewsets,serializers
from django.shortcuts import get_object_or_404
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.contenttypes.models import ContentType
from rest_framework import status
from django.apps import apps
from .models import Community

from .serializers import CommunitySerializer

class CommunityViewSet(viewsets.ModelViewSet):
    serializer_class = CommunitySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Community.objects.filter(Q(owner=user) | Q(members=user)).distinct()

    def perform_create(self, serializer):
        serializer.save()

    # ---------- Community Feed: create a post ----------
    class _CommunityPostCreateSerializer(serializers.Serializer):
        content = serializers.CharField(max_length=4000)

    @action(detail=True, methods=["post"], url_path="posts/create")
    def create_post(self, request, pk=None):
        """
        Create a community-level post (no group).
        Permissions: community owner or staff.
        Body: { "content": "string" }
        """
        community = self.get_object()
        user = request.user
        if (getattr(community, "owner_id", None) != getattr(user, "id", None)) and (not getattr(user, "is_staff", False)):
            return Response({"detail": "Only community owner or staff can create posts."}, status=403)

        ser = self._CommunityPostCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        text = (ser.validated_data["content"] or "").strip()
        if not text:
            return Response({"detail": "content is required"}, status=400)

        FeedItem = apps.get_model("activity_feed", "FeedItem")
        if not FeedItem:
            return Response({"detail": "activity_feed.FeedItem not installed"}, status=409)

        ct = ContentType.objects.get_for_model(Community)
        item = FeedItem.objects.create(
            community=community,
            group=None,
            event=None,
            actor=request.user,
            verb="posted",
            target_content_type=ct,
            target_object_id=community.id,
            metadata={  # align with group-post shape
                "type": "post",
                "text": text,
                # no group_id here → community-level
            },
        )
        return Response({"ok": True, "id": item.id}, status=201)
    
    # PATCH/PUT /api/communities/{community_id}/posts/{post_id}/edit/
    @action(
        detail=True,
        methods=["patch", "put"],
        url_path=r"posts/(?P<post_id>\d+)/edit",
    )
    def edit_post(self, request, pk=None, post_id=None):
        community = self.get_object()
        user = request.user

        # find the exact community-level post FeedItem
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
                metadata__type="post",
            ),
            pk=post_id,
        )

        # permissions: community owner or staff or the original actor
        is_owner = getattr(community, "owner_id", None) == getattr(user, "id", None)
        is_staff = getattr(user, "is_staff", False)
        is_actor = getattr(post, "actor_id", None) == getattr(user, "id", None)
        if not (is_owner or is_staff or is_actor):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        # validate new content using the same schema as create
        ser = self._CommunityPostCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        new_text = (ser.validated_data["content"] or "").strip()
        if not new_text:
            return Response({"detail": "content is required"}, status=400)

        # update the JSON metadata
        meta = dict(post.metadata or {})
        meta["type"] = "post"
        meta["text"] = new_text
        post.metadata = meta
        post.save(update_fields=["metadata"])

        return Response({"ok": True, "id": post.id, "content": new_text}, status=200)

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
                metadata__type="post",
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
