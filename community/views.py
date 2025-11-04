from django.db.models import Q
from rest_framework import permissions, viewsets,serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.contenttypes.models import ContentType
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