from django.db.models import Q
from rest_framework.viewsets import ReadOnlyModelViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import FeedItem
from .serializers import FeedItemSerializer
from .pagination import FeedPagination
from groups.models import GroupMembership, Group

class FeedItemViewSet(ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = FeedItemSerializer
    pagination_class = FeedPagination
    queryset = FeedItem.objects.select_related("actor").order_by("-created_at")  # <—

    def get_queryset(self):
        qs = super().get_queryset()

        scope = self.request.query_params.get("scope", "member_groups")
        if scope == "member_groups":
            member_group_ids = list(
                GroupMembership.objects.filter(
                    user=self.request.user,
                    status=GroupMembership.STATUS_ACTIVE
                ).values_list("group_id", flat=True)
            )
            qs = qs.filter(
                    Q(group_id__in=member_group_ids) |
                    Q(metadata__group_id__in=member_group_ids) |
                    Q(metadata__group_id__in=[str(g) for g in member_group_ids])
                )

            community_id = self.request.query_params.get("community_id")
            if community_id:
                try:
                    qs = qs.filter(community_id=int(community_id))
                except (TypeError, ValueError):
                    qs = qs.none()
        gid_param = self.request.query_params.get("group_id")
        if gid_param:
            try:
                gid_num = int(gid_param)
            except ValueError:
                # string id fallback (very rare)
                qs = qs.filter(Q(metadata__group_id=gid_param))
            else:
                qs = qs.filter(
                    Q(group_id=gid_num) |
                    Q(metadata__group_id=gid_num) |
                    Q(metadata__group_id=str(gid_num))
                )
        return qs

    def list(self, request, *args, **kwargs):
        qs = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(qs)
        if page is not None:
            page_gids = set()
            for item in page:
                # Prefer FK, fall back to metadata
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
