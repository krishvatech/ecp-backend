from django.db.models import Q
from rest_framework.viewsets import ReadOnlyModelViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import FeedItem
from .serializers import FeedItemSerializer
from .pagination import FeedPagination
from groups.models import GroupMembership, Group
from friends.models import Friendship           
from community.models import Community

class FeedItemViewSet(ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = FeedItemSerializer
    pagination_class = FeedPagination
    queryset = FeedItem.objects.select_related("actor").order_by("-created_at")  
    
    def _friend_user_ids(self, user_id: int):
        pairs = Friendship.objects.filter(
            Q(user1_id=user_id) | Q(user2_id=user_id)
        ).values_list("user1_id", "user2_id")
        ids = set()
        for u1, u2 in pairs:
            ids.add(u2 if u1 == user_id else u1)
        return ids

    def get_queryset(self):
        qs = super().get_queryset()
        req = self.request
        me = req.user

        scope = req.query_params.get("scope", "member_groups")  # existing default
        # Optional: allow narrowing to one community
        community_id_param = req.query_params.get("community_id")

        if scope == "member_groups":
            # (your existing code path — unchanged) ...
            # Ensure this keeps working as-is.
            member_group_ids = list(
                GroupMembership.objects.filter(
                    user=me,
                    status=GroupMembership.STATUS_ACTIVE
                ).values_list("group_id", flat=True)
            )
            qs = qs.filter(
                Q(group_id__in=member_group_ids) |
                Q(metadata__group_id__in=[str(gid) for gid in member_group_ids])
            )
            gid_param = req.query_params.get("group_id")
            if gid_param:
                try:
                    gid_num = int(gid_param)
                except ValueError:
                    qs = qs.filter(Q(metadata__group_id=gid_param))
                else:
                    qs = qs.filter(
                        Q(group_id=gid_num) |
                        Q(metadata__group_id=gid_num) |
                        Q(metadata__group_id=str(gid_num))
                    )
            return qs

        # --- NEW: community-level user posts with privacy ---
        if scope in ("community", "home", "friends_and_public"):
            # Communities the viewer is in (owner is always a member via your model's save())
            my_comm_ids = list(
                Community.objects.filter(
                    Q(owner_id=me.id) | Q(members=me)
                ).values_list("id", flat=True)
            )

            # Base: community posts only (no group, no event), same shape you already produce
            comm_posts = FeedItem.objects.filter(
                group__isnull=True,
                event__isnull=True,
                community_id__in=my_comm_ids,
                verb="posted",
                metadata__type="post",
            )

            # If caller asked for a specific community
            if community_id_param:
                try:
                    cid = int(community_id_param)
                    comm_posts = comm_posts.filter(community_id=cid)
                except ValueError:
                    # ignore bad community_id
                    pass

            # Friends list (mutual friendships)
            friend_ids = self._friend_user_ids(me.id)

            # Privacy:
            #   - visibility missing or "public"  → visible to everyone in same community
            #   - visibility "friends"            → visible only if actor is in my friends OR it's my own post
            privacy_q = (
                Q(metadata__visibility__isnull=True) |
                Q(metadata__visibility="public") |
                Q(actor_id__in=friend_ids) |
                Q(actor_id=me.id)
            )
            comm_posts = comm_posts.filter(privacy_q)

            if scope == "community":
                return comm_posts

            if scope in ("home", "friends_and_public"):
                # Combine with the existing "member_groups" scope for a single home feed
                member_group_ids = list(
                    GroupMembership.objects.filter(
                        user=me,
                        status=GroupMembership.STATUS_ACTIVE
                    ).values_list("group_id", flat=True)
                )
                group_feed = FeedItem.objects.filter(
                    Q(group_id__in=member_group_ids) |
                    Q(metadata__group_id__in=[str(gid) for gid in member_group_ids])
                )
                # Return union of both
                return group_feed.union(comm_posts).order_by("-created_at")

        # Fallback (unchanged)
        return qs

    def list(self, request, *args, **kwargs):
        qs = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(qs)
        if page is not None:
            page_gids = set()
            for item in page:
                if getattr(item, "group_id", None):
                    page_gids.add(int(item.group_id))
                else:
                    try:
                        gid = item.metadata.get("group_id")
                        if gid is not None:
                            page_gids.add(int(gid))
                    except Exception:
                        pass

            groups_qs = Group.objects.filter(id__in=page_gids)
            names = {g.id: g.name for g in groups_qs}
            covers = {
                g.id: (request.build_absolute_uri(g.cover_image.url) if g.cover_image else None)
                for g in groups_qs
            }

            ser = self.get_serializer(
                page, many=True,
                context={"group_names": names, "group_covers": covers, "request": request}
            )
            return self.get_paginated_response(ser.data)

        ser = self.get_serializer(qs, many=True)
        return Response(ser.data)