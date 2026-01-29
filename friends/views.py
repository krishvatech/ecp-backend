from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiTypes
from django.db.models import Count, F
from .models import Friendship, FriendRequest,Notification
from .serializers import (
    friendserializer,
    FriendshipCreateSerializer,
    FriendRequestSerializer,
    FriendRequestCreateSerializer,
    UserTinySerializer,
    NotificationSerializer
)
from .permissions import IsAuthenticatedOnly

User = get_user_model()


class FriendshipViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    permission_classes = [IsAuthenticatedOnly]

    def get_queryset(self):
        me = self.request.user
        return (
            Friendship.objects.select_related("user1", "user2")
            .filter(Q(user1=me) | Q(user2=me))
            .order_by("-created_at")
        )

    def get_serializer_class(self):
        if self.action == "create":
            return FriendshipCreateSerializer
        return friendserializer

    def destroy(self, request, *args, **kwargs):
        """Unfriend by friendship id OR by ?user_id=..."""
        friend_user_id = request.query_params.get("user_id")
        me = request.user
        if friend_user_id:
            try:
                friend_id = int(friend_user_id)
            except ValueError:
                return Response({"detail": "Invalid user_id."}, status=400)
            u1, u2 = (me.id, friend_id) if me.id < friend_id else (friend_id, me.id)
            Friendship.objects.filter(user1_id=u1, user2_id=u2).delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return super().destroy(request, *args, **kwargs)
    
    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="user_id",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                required=True,
                description="User whose friends you want to view",
            )
        ]
    )
    @action(detail=False, methods=["get"], url_path="of")
    def friends_of(self, request):
        """
        List friends of ?user_id=<ID>, but only if:
          - requester == target (view own list), OR
          - requester is already friends with target.
        """
        try:
            target_id = int(request.query_params.get("user_id"))
        except (TypeError, ValueError):
            return Response({"detail": "user_id is required"}, status=400)

        # 404 if target doesn't exist
        get_object_or_404(User, id=target_id)

        me_id = request.user.id
        if me_id != target_id and not Friendship.are_friends(me_id, target_id):
            return Response(
                {"detail": "You can only view friends of users who are your friends."},
                status=403,
            )

        qs = (
            Friendship.objects.select_related("user1", "user2")
            .filter(Q(user1_id=target_id) | Q(user2_id=target_id))
            .order_by("-created_at")
        )
        ser = friendserializer(
            qs, many=True, context={"request": request, "perspective_id": target_id}
        )
        return Response(ser.data)
    
    @action(detail=False, methods=["get"], url_path="suggested")
    def suggested(self, request):
        """
        Friends-of-friends suggestions for the logged-in user.
        Excludes: self, already-friends. Sorted by mutual friend count (desc).
        Query params:
          - limit: int (default 12, max 50)
          - q: optional search on username/first/last/email
        Output items are shaped for your UI: {id, name, avatar, mutuals}
        """
        me = request.user

        # 1) my friend ids
        my_pairs = Friendship.objects.filter(Q(user1=me) | Q(user2=me))
        my_ids = set(
            (p.user1_id if p.user1_id != me.id else p.user2_id) for p in my_pairs
        )

        if not my_ids:
            # Fallback for brand-new users:
            # Show all non-staff users, excluding me and anyone already related (friends or pending requests).
            BLOCKED_PROFILE_STATUSES = ("suspended", "fake", "deceased")
            base = User.objects.filter(is_active=True, is_staff=False).exclude(id=me.id).exclude(
                profile__profile_status__in=BLOCKED_PROFILE_STATUSES
            )

            # Exclude already-friends (should be none if not my_ids, but safe to keep)
            fr_pairs = Friendship.objects.filter(Q(user1=me) | Q(user2=me))
            related_ids = set(fr_pairs.values_list("user1_id", flat=True)) | set(
                fr_pairs.values_list("user2_id", flat=True)
            )

            # Exclude users who have a pending friend-request with me (either direction)
            pending_pairs = FriendRequest.objects.filter(
                Q(from_user=me) | Q(to_user=me),
                status=FriendRequest.PENDING,
            ).values_list("from_user_id", "to_user_id")
            for a, b in pending_pairs:
                related_ids.add(a)
                related_ids.add(b)

            related_ids.add(me.id)
            base = base.exclude(id__in=related_ids)

            # Respect ?limit= (default 12, max 50)
            try:
                limit = int(request.query_params.get("limit", 12))
            except ValueError:
                limit = 12
            limit = max(1, min(limit, 50))

            # Newest-ish first (fallback to id)
            base = base.order_by("-id")[:limit]

            # Local helpers (duplicated here so we don't touch the rest of your code)
            def _name(u):
                full = f"{getattr(u, 'first_name', '')} {getattr(u, 'last_name', '')}".strip()
                return (
                    getattr(u, "display_name", None)
                    or full
                    or getattr(u, "username", None)
                    or getattr(u, "email", "")
                    or f"User #{u.id}"
                )

            def _avatar(u):
                return getattr(u, "avatar_url", "") or getattr(getattr(u, "profile", None), "avatar", "") or ""

            data = [
                {"id": u.id, "name": _name(u), "avatar": _avatar(u), "mutuals": 0}
                for u in base
            ]
            return Response(data)


        # 2) users who are connected to any of my friends (FoF)
        BLOCKED_PROFILE_STATUSES = ("suspended", "fake", "deceased")
        qs = User.objects.filter(
            Q(friends_as_user1__user2_id__in=my_ids) |
            Q(friends_as_user2__user1_id__in=my_ids)
        ).exclude(
            id=me.id
        ).exclude(
            id__in=my_ids
        ).exclude(
            profile__profile_status__in=BLOCKED_PROFILE_STATUSES  # Exclude suspended users
        ).distinct()

        # 3) annotate mutual friend count (how many of *my* friends also friend this candidate)
        qs = qs.annotate(
            mutuals_via_u1=Count(
                "friends_as_user1",
                filter=Q(friends_as_user1__user2_id__in=my_ids),
                distinct=True,
            ),
            mutuals_via_u2=Count(
                "friends_as_user2",
                filter=Q(friends_as_user2__user1_id__in=my_ids),
                distinct=True,
            ),
        ).annotate(
            mutuals=F("mutuals_via_u1") + F("mutuals_via_u2")
        ).order_by("-mutuals", "-id")

        # 4) optional search
        q = (request.query_params.get("q") or "").strip()
        if q:
            qs = qs.filter(
                Q(username__icontains=q) |
                Q(first_name__icontains=q) |
                Q(last_name__icontains=q) |
                Q(email__icontains=q)
            )

        # 5) cap results
        try:
            limit = int(request.query_params.get("limit", 12))
        except ValueError:
            limit = 12
        limit = max(1, min(limit, 50))
        qs = qs[:limit]

        # 6) shape for your front-end slider
        def _name(u):
            # Try common display fields without assuming a specific custom field exists
            full = f"{getattr(u, 'first_name', '')} {getattr(u, 'last_name', '')}".strip()
            return getattr(u, "display_name", None) or full or getattr(u, "username", None) or getattr(u, "email", "") or f"User #{u.id}"

        def _avatar(u):
            # Prefer common custom accessors if present; else empty string
            return getattr(u, "avatar_url", "") or getattr(getattr(u, "profile", None), "avatar", "") or ""

        data = [
            {"id": u.id, "name": _name(u), "avatar": _avatar(u), "mutuals": int(getattr(u, "mutuals", 0))}
            for u in qs
        ]
        return Response(data)


    @action(detail=False, methods=["get"], url_path="mutual")
    def mutual(self, request):
        """List mutual friends with ?user_id=..."""
        try:
            other_id = int(request.query_params.get("user_id"))
        except (TypeError, ValueError):
            return Response({"detail": "user_id is required"}, status=400)

        me = request.user
        my_pairs = Friendship.objects.filter(Q(user1=me) | Q(user2=me))
        my_ids = set(
            [f.user1_id if f.user1_id != me.id else f.user2_id for f in my_pairs]
        )
        their_pairs = Friendship.objects.filter(Q(user1_id=other_id) | Q(user2_id=other_id))
        their_ids = set(
            [
                f.user1_id if f.user1_id != other_id else f.user2_id
                for f in their_pairs
            ]
        )
        mutual_ids = list(my_ids.intersection(their_ids))
        users = User.objects.filter(id__in=mutual_ids)
        return Response(UserTinySerializer(users, many=True).data)

    @extend_schema(
        parameters=[OpenApiParameter(
            name="user_id",
            type=OpenApiTypes.INT,
            location=OpenApiParameter.QUERY,
            required=True,
            description="Target user's ID",
        )]
    )
    @action(detail=False, methods=["get"], url_path="status")
    def status(self, request):
        """Return relationship status with ?user_id=<target>."""
        try:
            target_id = int(request.query_params.get("user_id"))
        except (TypeError, ValueError):
            return Response({"detail": "user_id is required"}, status=400)

        me = request.user
        if target_id == me.id:
            return Response({"status": "self"})

        if Friendship.are_friends(me.id, target_id):
            return Response({"status": "friends"})

        incoming = FriendRequest.objects.filter(
            from_user_id=target_id,
            to_user_id=me.id,
            status=FriendRequest.PENDING,
        ).first()
        if incoming:
            return Response({"status": "incoming_pending", "request_id": incoming.id})

        outgoing = FriendRequest.objects.filter(
            from_user_id=me.id,
            to_user_id=target_id,
            status=FriendRequest.PENDING,
        ).first()
        if outgoing:
            return Response({"status": "outgoing_pending", "request_id": outgoing.id})

        return Response({"status": "none"})


class FriendRequestViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    viewsets.GenericViewSet,
):
    permission_classes = [IsAuthenticatedOnly]

    def get_queryset(self):
        me = self.request.user
        qs = FriendRequest.objects.select_related("from_user", "to_user")

        # For detail actions, include requests where I'm sender OR recipient
        if getattr(self, "action", None) in {"retrieve", "accept", "decline", "cancel"}:
            return qs.filter(Q(from_user=me) | Q(to_user=me)).order_by("-created_at")

        # For list actions, keep your inbox/outbox filter
        box = (self.request.query_params.get("type") or "incoming").lower()
        if box == "outgoing":
            qs = qs.filter(from_user=me)
        else:  # incoming default
            qs = qs.filter(to_user=me)

        status_filter = self.request.query_params.get("status")
        if status_filter:
            qs = qs.filter(status=status_filter)

        return qs.order_by("-created_at")

    def get_serializer_class(self):
        if self.action == "create":
            return FriendRequestCreateSerializer
        return FriendRequestSerializer

    def perform_create(self, serializer):
        serializer.save()

    @action(detail=True, methods=["post"], url_path="accept")
    def accept(self, request, pk=None):
        fr = self.get_object()
        if fr.to_user_id != request.user.id:
            return Response({"detail": "Only the recipient can accept."}, status=403)
        fr.accept()
        return Response(FriendRequestSerializer(fr).data)

    @action(detail=True, methods=["post"], url_path="decline")
    def decline(self, request, pk=None):
        fr = self.get_object()
        if fr.to_user_id != request.user.id:
            return Response({"detail": "Only the recipient can decline."}, status=403)
        fr.decline()
        return Response(FriendRequestSerializer(fr).data)

    @action(detail=True, methods=["post"], url_path="cancel")
    def cancel(self, request, pk=None):
        fr = self.get_object()
        if fr.from_user_id != request.user.id:
            return Response({"detail": "Only the sender can cancel."}, status=403)
        fr.cancel()
        return Response(FriendRequestSerializer(fr).data)
    
    
class NotificationViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = [IsAuthenticatedOnly]
    serializer_class = NotificationSerializer

    def get_queryset(self):
        me = self.request.user
        qs = Notification.objects.filter(recipient=me).order_by("-created_at")
        kind = self.request.query_params.get("kind")
        unread = self.request.query_params.get("unread")
        if kind:
            qs = qs.filter(kind=kind)
        if unread in {"1", "true", "True"}:
            qs = qs.filter(is_read=False)
        return qs

    @action(detail=False, methods=["post"], url_path="mark-read")
    def mark_read(self, request):
        ids = request.data.get("ids", [])
        Notification.objects.filter(recipient=request.user, id__in=ids).update(is_read=True)
        return Response({"ok": True})
