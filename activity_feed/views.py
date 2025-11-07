# activity_feed/view.py
from django.db.models import Q
from rest_framework.viewsets import ReadOnlyModelViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import action
from itertools import chain
from rest_framework import status
from django.utils.dateparse import parse_datetime
from django.utils import timezone
from rest_framework.parsers import JSONParser
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
import datetime as dt

from .models import FeedItem
from .serializers import FeedItemSerializer
from .pagination import FeedPagination
from .models import Poll, PollOption, PollVote
from groups.models import GroupMembership, Group
from events.models import Event,EventRegistration
from content.models import Resource
from django.contrib.auth import get_user_model
from friends.models import Friendship           
from community.models import Community

User = get_user_model()

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
            member_group_ids_str = [str(gid) for gid in member_group_ids]
            qs = qs.filter(
                Q(group_id__in=member_group_ids) |
                Q(metadata__group_id__in=member_group_ids) |            # numeric JSON
                Q(metadata__group_id__in=member_group_ids_str) |        # string JSON
                Q(metadata__groupId__in=member_group_ids) |             # camelCase numeric
                Q(metadata__groupId__in=member_group_ids_str) |         # camelCase string
                Q(metadata__group__id__in=member_group_ids) |           # nested numeric
                Q(metadata__group__id__in=member_group_ids_str)         # nested string
            )
            gid_param = req.query_params.get("group_id")
            if gid_param:
                try:
                    gid_num = int(gid_param)
                except ValueError:
                    qs = qs.filter(
                        Q(metadata__group_id=gid_param) |
                        Q(metadata__groupId=gid_param) |
                        Q(metadata__group__id=gid_param)
                    )

                else:
                    qs = qs.filter(
                        Q(group_id=gid_num) |
                        Q(metadata__group_id=gid_num) |
                        Q(metadata__group_id=str(gid_num)) |
                        Q(metadata__groupId=gid_num) |
                        Q(metadata__groupId=str(gid_num)) |
                        Q(metadata__group__id=gid_num) |
                        Q(metadata__group__id=str(gid_num))
                        
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
                member_group_ids_str = [str(gid) for gid in member_group_ids]
                group_feed = FeedItem.objects.filter(
                    Q(group_id__in=member_group_ids) |
                    Q(metadata__group_id__in=member_group_ids) |
                    Q(metadata__group_id__in=member_group_ids_str) |
                    Q(metadata__groupId__in=member_group_ids) |
                    Q(metadata__groupId__in=member_group_ids_str) |
                    Q(metadata__group__id__in=member_group_ids) |
                    Q(metadata__group__id__in=member_group_ids_str)
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
    
    def _registered_event_ids(self, user_id: int):
        return list(
            EventRegistration.objects.filter(user_id=user_id)
            .values_list("event_id", flat=True)
        )

    # --- NEW: Resource queryset restricted to viewer's registrations ---
    def _visible_resources_qs(self, request, workset_size: int):
        """
        Only Resources that are (a) published, (b) attached to an event,
        and (c) that event is one the current user registered for.
        Optional ?community_id filter is respected.
        """
        me = request.user
        if not me.is_authenticated:
            return Resource.objects.none()

        reg_event_ids = self._registered_event_ids(me.id)
        if not reg_event_ids:
            return Resource.objects.none()

        qs = (
            Resource.objects
            .select_related("uploaded_by", "community", "event")
            .filter(is_published=True, event_id__isnull=False, event_id__in=reg_event_ids)
            .order_by("-created_at")
        )

        cid = request.query_params.get("community_id")
        if cid:
            try:
                qs = qs.filter(community_id=int(cid))
            except ValueError:
                pass

        return qs[:workset_size]

    # --- NEW: Convert a Resource to the same API row shape you use for events ---
    def _resource_to_api_row(self, r: Resource, request):
        def _iso(v):
            from django.utils import timezone
            import datetime as dt
            if isinstance(v, (dt.datetime,)):
                if timezone.is_naive(v):
                    v = timezone.make_aware(v, timezone.utc)
                return v.isoformat()
            return v

        actor = getattr(r, "uploaded_by", None)
        actor_name = (
            getattr(actor, "get_full_name", lambda: "")() or
            getattr(actor, "username", "") or
            "Resource"
        )

        # Build absolute URLs where applicable
        file_url = None
        if r.type == Resource.TYPE_FILE and r.file:
            try:
                file_url = request.build_absolute_uri(r.file.url)
            except Exception:
                file_url = r.file.url if r.file else None

        return {
            "id": f"resource-{r.id}",
            "created_at": _iso(getattr(r, "created_at", None)),
            "actor_id": getattr(actor, "id", None),
            "actor_name": actor_name,
            "community_id": r.community_id,
            "metadata": {
                "type": "resource",
                "resource_id": r.id,
                "resource_type": r.type,
                "title": r.title,
                "description": r.description or "",
                "event_id": r.event_id,
                "tags": list(r.tags or []),
                "file_url": file_url,
                "link_url": r.link_url or None,
                "video_url": r.video_url or None,
                # Optional: pass community + group names for convenience
                "community_name": getattr(r.community, "name", None),
                "group_id": getattr(r.event, "group_id", None),
                "group_name": getattr(getattr(r.event, "group", None), "name", None),
            },
        }

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

        resource_qs = self._visible_resources_qs(request, workset_size)
        resource_rows = [self._resource_to_api_row(r, request) for r in resource_qs]
            
        # ---- merge & sort by timestamp (created_at or event start_time) ----
        combined = list(feed_rows) + event_rows + resource_rows

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
    
    def _can_create_poll_for_group(self, request, group: Group) -> bool:
        uid = getattr(request.user, "id", None)
        if not uid or not request.user.is_authenticated:
            return False
        if group.created_by_id == uid or getattr(group, "owner_id", None) == uid or getattr(request.user, "is_staff", False):
            return True
        return GroupMembership.objects.filter(group=group, user_id=uid, role__in=["admin","moderator"]).exists()

    def _active_member(self, user_id: int, group: Group) -> bool:
        return GroupMembership.objects.filter(group=group, user_id=user_id, status=getattr(GroupMembership, "STATUS_ACTIVE", "active")).exists()

    def _serialize_poll(self, poll: Poll, request):
        opts = list(poll.options.all().order_by("index"))
        option_rows = [{"id": o.id, "text": o.text, "index": o.index, "vote_count": o.votes.count()} for o in opts]
        total_votes = sum(x["vote_count"] for x in option_rows)
        uid = getattr(request.user, "id", None)
        user_votes = []
        if uid:
            user_votes = list(poll.votes.filter(user_id=uid).values_list("option_id", flat=True))
        return {
            "id": poll.id,
            "question": poll.question,
            "allows_multiple": bool(poll.allows_multiple),
            "is_anonymous": bool(poll.is_anonymous),
            "is_closed": bool(poll.is_closed),
            "ends_at": poll.ends_at,
            "options": option_rows,
            "total_votes": total_votes,
            "user_votes": user_votes,
        }

    @action(detail=False, methods=["post"], url_path="polls/create", parser_classes=[JSONParser])
    def polls_create(self, request, *args, **kwargs):
        if not request.user or not request.user.is_authenticated:
            return Response({"detail": "Authentication required."}, status=401)

        data = request.data or {}
        question = (data.get("question") or "").strip()
        options  = data.get("options") or []
        multi    = bool(data.get("multi_select", False))
        anon     = bool(data.get("anonymous", False))
        ends_at  = data.get("closes_at")
        gid      = data.get("group_id")
        cid      = data.get("community_id")

        if not question:
            return Response({"detail": "question is required"}, status=400)
        if not isinstance(options, list) or len([str(o).strip() for o in options if str(o).strip()]) < 2:
            return Response({"detail": "options must include at least two non-empty items"}, status=400)

        group = None
        community = None

        if gid:
            try:
                group = Group.objects.get(pk=int(gid))
            except Exception:
                return Response({"detail": "Invalid group_id"}, status=400)
            if not self._can_create_poll_for_group(request, group):
                return Response({"detail": "Forbidden"}, status=403)
            community = getattr(group, "community", None)
        elif cid:
            try:
                community = Community.objects.get(pk=int(cid))
            except Exception:
                return Response({"detail": "Invalid community_id"}, status=400)

        # 1) create poll + options
        poll = Poll.objects.create(
            group=group,
            community=community,
            question=question,
            allows_multiple=multi,
            is_anonymous=anon,
            ends_at=ends_at,
            created_by=request.user,
        )
        for idx, txt in enumerate(options):
            t = (str(txt) or "").strip()
            if t:
                PollOption.objects.create(poll=poll, text=t, index=idx)

        # 2) ensure the FeedItem has options in its metadata
        ct = ContentType.objects.get_for_model(Poll)
        item = (FeedItem.objects
                .filter(target_content_type=ct, target_object_id=poll.id)
                .order_by("-id")
                .first())

        opts_meta = [
            {"id": o.id, "text": o.text, "index": o.index, "vote_count": 0}
            for o in poll.options.order_by("index")
        ]
        meta = {
            "type": "poll",
            "poll_id": poll.id,
            "question": poll.question,
            "options": opts_meta,                     # 👈 now filled
            "is_closed": bool(poll.is_closed),
            "group_id": poll.group_id,
            "community_id": poll.community_id,
            "allows_multiple": bool(poll.allows_multiple),
            "is_anonymous": bool(poll.is_anonymous),
            "ends_at": poll.ends_at,
        }

        if item:
            m = item.metadata or {}
            m.update(meta)
            item.metadata = m
            item.save(update_fields=["metadata"])
        else:
            FeedItem.objects.create(
                community=community or (group.community if group else None),
                group=group,
                actor_id=getattr(request.user, "id", None),
                verb="created_poll",
                target_content_type=ct,
                target_object_id=poll.id,
                metadata=meta,
            )

        # 3) return a fully serialized poll so the UI can render immediately
        return Response({
            "ok": True,
            "feed_item_id": item.id if item else None,
            "poll": self._serialize_poll(poll, request),
        }, status=201)

    @action(detail=True, methods=["post"], url_path=r"poll/vote", parser_classes=[JSONParser])
    def poll_vote(self, request, pk=None, *args, **kwargs):
        item = self.get_object()
        # get underlying Poll
        PollModel = Poll
        ct_poll = ContentType.objects.get_for_model(PollModel)
        poll = None
        if item.target_content_type_id == ct_poll.id:
            poll = PollModel.objects.filter(pk=item.target_object_id).first()
        if not poll:
            pid = (item.metadata or {}).get("poll_id")
            if pid:
                poll = PollModel.objects.filter(pk=pid).first()
        if not poll:
            return Response({"detail": "Poll not found"}, status=404)

        if poll.is_closed or (poll.ends_at and timezone.now() > poll.ends_at):
            return Response({"detail": "Poll is closed."}, status=400)

        uid = getattr(request.user, "id", None)
        if not uid:
            return Response({"detail": "Authentication required."}, status=401)

        if poll.group_id:
            elevated = self._can_create_poll_for_group(request, poll.group)
            member_ok = elevated or self._active_member(uid, poll.group)
            if not member_ok:
                return Response({"detail": "Only active members can vote in this group poll."}, status=403)

        option_ids = request.data.get("option_ids") or request.data.get("choices")
        if not isinstance(option_ids, list) or not option_ids:
            return Response({"detail": "option_ids is required"}, status=400)

        # validate options
        option_ids = [int(x) for x in option_ids]
        valid_ids  = set(poll.options.values_list("id", flat=True))
        if not set(option_ids).issubset(valid_ids):
            return Response({"detail": "Invalid option id(s)"}, status=400)

        if not poll.allows_multiple:
            PollVote.objects.filter(poll=poll, user_id=uid).delete()
            PollVote.objects.get_or_create(poll=poll, option_id=option_ids[0], user_id=uid)
        else:
            for oid in option_ids:
                PollVote.objects.get_or_create(poll=poll, option_id=oid, user_id=uid)
            PollVote.objects.filter(poll=poll, user_id=uid).exclude(option_id__in=option_ids).delete()

        return Response({"ok": True, "poll": self._serialize_poll(poll, request)})

    @action(detail=True, methods=["post"], url_path=r"poll/close")
    def poll_close(self, request, pk=None, *args, **kwargs):
        item = self.get_object()
        ct_poll = ContentType.objects.get_for_model(Poll)
        poll = None
        if item.target_content_type_id == ct_poll.id:
            poll = Poll.objects.filter(pk=item.target_object_id).first()
        if not poll:
            pid = (item.metadata or {}).get("poll_id")
            if pid:
                poll = Poll.objects.filter(pk=pid).first()
        if not poll:
            return Response({"detail": "Poll not found"}, status=404)

        if poll.group_id:
            if not self._can_create_poll_for_group(request, poll.group):
                return Response({"detail": "Forbidden"}, status=403)
        else:
            if not getattr(request.user, "is_staff", False):
                return Response({"detail": "Forbidden"}, status=403)

        poll.is_closed = True
        poll.save(update_fields=["is_closed"])
        return Response({"ok": True, "poll": self._serialize_poll(poll, request)})
    
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
