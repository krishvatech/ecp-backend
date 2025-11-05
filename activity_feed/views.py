# activity_feed/view.py
from django.db.models import Q
from rest_framework.viewsets import ReadOnlyModelViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import action
from itertools import chain
from django.utils.dateparse import parse_datetime
from django.utils import timezone
import datetime as dt

from .models import FeedItem
from .serializers import FeedItemSerializer
from .pagination import FeedPagination
from groups.models import GroupMembership, Group
from events.models import Event
from friends.models import Friendship           
from community.models import Community

class FeedItemViewSet(ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = FeedItemSerializer
    pagination_class = FeedPagination
    queryset = FeedItem.objects.select_related("actor").order_by("-created_at")  
    
    def _friend_user_ids(self, user_id: int):
        pairs = Friendship.objects.filter(
            Q(user1_id=user_id) | Q(user2_id=user_id),
        ).values_list("user1_id", "user2_id")
        ids = set()
        for u1, u2 in pairs:
            ids.add(u2 if u1 == user_id else u1)
        return ids
    
    def _parse_actor_id(self, request):
        a = request.query_params.get("actor") or request.query_params.get("actor_id")
        if not a:
            return None
        if str(a).lower() in ("me", "self"):
            return getattr(request.user, "id", None)
        try:
            return int(a)
        except (TypeError, ValueError):
            return None
        
    def get_queryset(self):
        qs = super().get_queryset()
        req = self.request
        me = req.user
        actor_id = self._parse_actor_id(req) 

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
            return qs.select_related("actor").order_by("-created_at")

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
                metadata__type__in=["text", "image", "link", "poll"],
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
            vis_public    = Q(metadata__visibility="public")
            vis_missing   = ~Q(metadata__has_key="visibility")  # missing → public
            vis_community = Q(metadata__visibility="community")
            vis_friends   = Q(metadata__visibility="friends", actor_id__in=friend_ids)
            
            own_posts     = Q(actor_id=me.id)
            comm_posts = comm_posts.filter(vis_public | vis_missing | vis_community | vis_friends | own_posts)

            if scope == "community":
                return comm_posts.select_related("actor").order_by("-created_at")

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
                return (group_feed | comm_posts).select_related("actor").order_by("-created_at")

        # Fallback (unchanged)
        if actor_id:  # <-- NEW
            qs = qs.filter(actor_id=actor_id)
        return qs
    
    def _visible_events_qs(self, request):
        """
        Return the set of events the current user is allowed to see in the feed.
        Tune filters (status/published/community) to your rules.
        """
        qs = Event.objects.all()

        # If you have publish/status flags:
        # qs = qs.filter(status__in=["scheduled", "live"])  # example

        # If your feed scopes by community via ?community_id=<id>:
        cid = request.query_params.get("community_id")
        if cid:
            try:
                qs = qs.filter(community_id=int(cid))
            except ValueError:
                pass
        return qs

    def _event_to_api_row(self, e):
        """
        Convert an Event model instance into the same shape the feed already uses.
        No DB write; just a dict. Your frontend checks metadata.type === "event".
        """
        creator = getattr(e, "created_by", None)
        actor_name = (
            getattr(creator, "get_full_name", lambda: "")() or
            getattr(creator, "username", "") or
            "Event"
        )
        community = getattr(e, "community", None)
        def _iso(v):
            if isinstance(v, dt.datetime):
                if timezone.is_naive(v):
                    v = timezone.make_aware(v, timezone.utc)
                return v.isoformat()
            return v  # already str/None is fine
        created_iso = _iso(getattr(e, "created_at", None) or getattr(e, "start_time", None))
        start_iso   = _iso(getattr(e, "start_time", None))
        return {
            "id": f"event-{e.id}",  # unique vs FeedItem integer ids
            "created_at": created_iso,
            "actor_id": getattr(creator, "id", None),
            "actor_name": actor_name,
            "community_id": getattr(e, "community_id", None),
            "metadata": {
                "type": "event",                     # <- FE uses this to render an Event card
                "event_id": e.id,
                "event_title": getattr(e, "title", "Event"),
                "start_time": start_iso,
                "venue": getattr(e, "location", "") or "",
                "description": getattr(e, "description", "") or "",
                "community_id": getattr(e, "community_id", None),
                "community_name": getattr(community, "name", None) if community else None,
            },
        }

    def list(self, request, *args, **kwargs):

        # Build base queryset with your existing filters
        qs = self.filter_queryset(self.get_queryset())

        # ---- figure out requested page size to build a reasonable working set ----
        try:
            limit_param = getattr(self.paginator, "limit_query_param", "limit")
            req_limit = request.query_params.get(limit_param)
            page_limit = int(req_limit) if req_limit is not None else getattr(self.paginator, "default_limit", 20)
        except Exception:
            page_limit = getattr(self.paginator, "default_limit", 20)

        # Pull a working slice (feed items) big enough to mix with events before final pagination
        workset_size = max(20, (page_limit or 20) * 3)
        feed_qs = qs.order_by("-created_at")[:workset_size]

        # ---- collect group/community ids from the working slice for lookup maps ----
        page_gids = set()
        page_cids = set()
        for item in feed_qs:
            # GROUP ID from column or metadata
            gid = getattr(item, "group_id", None)
            if gid is None:
                m = getattr(item, "metadata", {}) or {}
                gid = m.get("group_id")
            if gid not in (None, "", 0, "0"):
                try:
                    page_gids.add(int(gid))
                except (TypeError, ValueError):
                    pass

            # COMMUNITY ID from column or metadata
            cid = getattr(item, "community_id", None)
            if cid is None:
                m = getattr(item, "metadata", {}) or {}
                cid = m.get("community_id")
            if cid not in (None, "", 0, "0"):
                try:
                    page_cids.add(int(cid))
                except (TypeError, ValueError):
                    pass

        # ---- lookup maps for groups ----
        groups_qs = Group.objects.filter(id__in=page_gids)
        group_names = {g.id: g.name for g in groups_qs}
        group_covers = {
            g.id: (request.build_absolute_uri(g.cover_image.url) if getattr(g, "cover_image", None) else None)
            for g in groups_qs
        }

        # ---- lookup maps for communities ----
        communities_qs = Community.objects.filter(id__in=page_cids)
        community_names = {c.id: c.name for c in communities_qs}
        community_covers = {
            c.id: (request.build_absolute_uri(c.cover_image.url) if getattr(c, "cover_image", None) else None)
            for c in communities_qs
        }

        # ---- serialize the feed items from the working slice ----
        feed_rows = self.get_serializer(
            feed_qs,
            many=True,
            context={
                "group_names": group_names,
                "group_covers": group_covers,
                "community_names": community_names,
                "community_covers": community_covers,
                "request": request,
            },
        ).data

        event_qs = Event.objects.all()

        # Optional scope by community if you pass ?community_id=
        cid_param = request.query_params.get("community_id")
        if cid_param:
            try:
                event_qs = event_qs.filter(community_id=int(cid_param))
            except ValueError:
                pass

        # If you have publish/status flags, apply them here, e.g.:
        # event_qs = event_qs.filter(status__in=["scheduled", "live"])

        event_qs = event_qs.order_by("-created_at", "-start_time")[:workset_size]

        # helper to ISO-ify datetimes so types are consistent with DRF output
        def _iso(v):
            if isinstance(v, dt.datetime):
                if timezone.is_naive(v):
                    v = timezone.make_aware(v, timezone.utc)
                return v.isoformat()
            return v  # str/None stays as-is

        event_rows = []
        for e in event_qs:
            creator = getattr(e, "created_by", None)
            actor_name = (
                getattr(creator, "get_full_name", lambda: "")() or
                getattr(creator, "username", "") or
                "Event"
            )
            community = getattr(e, "community", None)
            group = getattr(e, "group", None)

            created_iso = _iso(getattr(e, "created_at", None) or getattr(e, "start_time", None))
            start_iso = _iso(getattr(e, "start_time", None))

            event_rows.append({
                "id": f"event-{e.id}",  # keep unique vs FeedItem ids
                "created_at": created_iso,
                "actor_id": getattr(creator, "id", None),
                "actor_name": actor_name,
                "community_id": getattr(e, "community_id", None),
                "metadata": {
                    "type": "event",  # your FE checks this to render an event card
                    "event_id": e.id,
                    "event_title": getattr(e, "title", "Event"),
                    "start_time": start_iso,
                    "venue": getattr(e, "location", "") or "",
                    "description": getattr(e, "description", "") or "",
                    "community_id": getattr(e, "community_id", None),
                    "community_name": getattr(community, "name", None) if community else None,
                    "group_id": getattr(e, "group_id", None),
                    "group_name": getattr(group, "name", None) if group else None,
                },
            })

        # ---- merge & sort by timestamp (created_at or event start_time) ----
        combined = list(feed_rows) + event_rows

        def _ts(row):
            m = row.get("metadata") or {}
            v = row.get("created_at") or m.get("start_time")

            # already datetime?
            if isinstance(v, dt.datetime):
                d = v
            else:
                # try to parse string → datetime
                d = parse_datetime(v) if isinstance(v, str) else None
                if d is None and isinstance(v, str):
                    # fallback: handle 'Z' or bare isoformat without timezone
                    try:
                        d = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
                    except Exception:
                        d = None

            if d is None:
                return 0.0  # push unknowns to the end

            if timezone.is_naive(d):
                d = timezone.make_aware(d, timezone.utc)

            return d.timestamp()

        combined.sort(key=_ts, reverse=True)

        # ---- paginate the merged list (single pagination pass) ----
        page = self.paginator.paginate_queryset(combined, request, view=self)
        return self.paginator.get_paginated_response(page)
    
    @action(detail=False, methods=["get"], url_path=r"posts/me")
    def actor_me(self, request, *args, **kwargs):
        # build from the base manager to avoid default scope filtering
        qs = (FeedItem.objects
            .select_related("actor")
            .filter(actor_id=request.user.id)
            .order_by("-created_at"))

        # still allow DRF filter_backends/pagination to run
        qs = self.filter_queryset(qs)
        page = self.paginate_queryset(qs)
        if page is not None:
            data = self.get_serializer(page, many=True).data
            return self.get_paginated_response(data)
        data = self.get_serializer(qs, many=True).data
        return Response(data)
        
    
    @action(detail=False, methods=["get"], url_path=r"posts/(?P<actor_id>\d+)")
    def actor_by_id(self, request, actor_id=None, *args, **kwargs):
        qs = (FeedItem.objects
            .select_related("actor")
            .filter(actor_id=int(actor_id))
            .order_by("-created_at"))

        # still allow DRF filter_backends/pagination to run
        qs = self.filter_queryset(qs)
        page = self.paginate_queryset(qs)
        if page is not None:
            data = self.get_serializer(page, many=True).data
            return self.get_paginated_response(data)
        data = self.get_serializer(qs, many=True).data
        return Response(data)
