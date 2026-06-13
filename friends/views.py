from django.contrib.auth import get_user_model
from django.db.models import Q
from django.conf import settings
from django.core.cache import cache
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiTypes
from django.db.models import Count, F
import logging

logger = logging.getLogger(__name__)
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
from django.utils import timezone
from datetime import timedelta

User = get_user_model()


def _is_guest_user(user) -> bool:
    return bool(getattr(user, "is_guest", False))


def _viewer_can_manage_hidden_connections(user):
    return bool(user and (user.is_staff or user.is_superuser))


def _can_view_connections_list(request_user, target_user):
    if not request_user or not request_user.is_authenticated:
        return False
    if request_user.id == target_user.id:
        return True
    if _viewer_can_manage_hidden_connections(request_user):
        return True
    target_profile = getattr(target_user, "profile", None)
    if getattr(target_profile, "connections_hidden", False):
        return False
    return Friendship.are_friends(request_user.id, target_user.id)


class FriendshipViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    permission_classes = [IsAuthenticatedOnly]

    def _remove_friendship(self, request):
        friend_user_id = request.query_params.get("user_id")
        if friend_user_id is None:
            return Response({"detail": "user_id is required."}, status=400)
        try:
            friend_id = int(friend_user_id)
        except ValueError:
            return Response({"detail": "Invalid user_id."}, status=400)

        me = request.user
        if friend_id == me.id:
            return Response({"detail": "You cannot remove yourself."}, status=400)

        u1, u2 = (me.id, friend_id) if me.id < friend_id else (friend_id, me.id)
        deleted, _ = Friendship.objects.filter(user1_id=u1, user2_id=u2).delete()
        if not deleted:
            return Response({"detail": "Contact not found."}, status=404)
        return Response(status=status.HTTP_204_NO_CONTENT)

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
        if friend_user_id:
            return self._remove_friendship(request)
        return super().destroy(request, *args, **kwargs)

    @extend_schema(
        parameters=[OpenApiParameter(
            name="user_id",
            type=OpenApiTypes.INT,
            location=OpenApiParameter.QUERY,
            required=True,
            description="Target user ID to remove from contacts",
        )]
    )
    @action(detail=False, methods=["delete"], url_path="remove")
    def remove(self, request):
        """Remove an existing friendship by target user id."""
        return self._remove_friendship(request)
    
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

        target_user = get_object_or_404(User.objects.select_related("profile"), id=target_id)
        me_id = request.user.id
        target_profile = getattr(target_user, "profile", None)
        if me_id != target_id and getattr(target_profile, "connections_hidden", False) and not _viewer_can_manage_hidden_connections(request.user):
            return Response(
                {"detail": "This member has hidden their connections list."},
                status=403,
            )
        if not _can_view_connections_list(request.user, target_user):
            return Response(
                {"detail": "You can only view friends of users who are your friends."},
                status=403,
            )

        qs = (
            Friendship.objects.select_related("user1", "user2")
            .filter(Q(user1_id=target_id) | Q(user2_id=target_id))
            .order_by("-created_at")
        )
        if not _viewer_can_manage_hidden_connections(request.user):
            qs = qs.exclude(
                (
                    Q(user1_id=target_id)
                    & Q(user2__profile__hide_from_others_connections=True)
                    & ~Q(user2_id=request.user.id)
                ) | (
                    Q(user2_id=target_id)
                    & Q(user1__profile__hide_from_others_connections=True)
                    & ~Q(user1_id=request.user.id)
                )
            )
        ser = friendserializer(
            qs, many=True, context={"request": request, "perspective_id": target_id}
        )
        return Response(ser.data)

    def _get_user_statuses(self, me, user_ids):
        """
        Helper to compute friendship status for multiple users.
        Returns: {user_id: {"status": "...", "request_id": ...}}
        """
        if not user_ids:
            return {}

        # Initialize result dict with "none" status for all IDs
        results = {uid: {"status": "none", "request_id": None} for uid in user_ids}

        # Check for "self" status
        for uid in user_ids:
            if uid == me.id:
                results[uid] = {"status": "self", "request_id": None}

        # Remove "self" IDs from further processing
        other_user_ids = [uid for uid in user_ids if uid != me.id]
        if not other_user_ids:
            return results

        # Get all friendships for these users in one query
        friendships = Friendship.objects.filter(
            Q(user1_id=me.id, user2_id__in=other_user_ids) |
            Q(user2_id=me.id, user1_id__in=other_user_ids)
        ).values_list("user1_id", "user2_id")

        for user1_id, user2_id in friendships:
            other_id = user2_id if user1_id == me.id else user1_id
            results[other_id] = {"status": "friends", "request_id": None}

        # Get pending friend requests for remaining users in one query
        pending_requests = FriendRequest.objects.filter(
            Q(from_user_id__in=other_user_ids, to_user_id=me.id) |
            Q(from_user_id=me.id, to_user_id__in=other_user_ids),
            status=FriendRequest.PENDING,
        ).values_list("from_user_id", "to_user_id", "id")

        for from_id, to_id, req_id in pending_requests:
            if from_id == me.id:
                # Outgoing request
                results[to_id] = {"status": "outgoing_pending", "request_id": req_id}
            else:
                # Incoming request
                results[from_id] = {"status": "incoming_pending", "request_id": req_id}

        return results

    @action(detail=False, methods=["get"], url_path="suggested")
    def suggested(self, request):
        """
        Friends-of-friends suggestions for the logged-in user.
        Excludes: self, already-friends. Sorted by mutual friend count (desc).
        Query params:
          - limit: int (default 12, max 50) — for backward compatibility
          - page: int (default 1) — for pagination mode
          - page_size: int (default 20, max 50) — for pagination mode
          - q: optional search on username/first/last/email

        Response format:
          - If no page param: returns array (backward compatible)
          - If page param: returns paginated object {results, page, page_size, has_next, next}
        """
        me = request.user

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

        def _kyc_status(u):
            return getattr(getattr(u, "profile", None), "kyc_status", None)

        # Determine if pagination mode or legacy mode
        has_page_param = "page" in request.query_params

        # 1) my friend ids
        my_pairs = Friendship.objects.filter(Q(user1=me) | Q(user2=me))
        my_ids = set(
            (p.user1_id if p.user1_id != me.id else p.user2_id) for p in my_pairs
        )

        if not my_ids:
            # Fallback for brand-new users:
            # Show all non-staff users, excluding me and anyone already related (friends or pending requests).
            BLOCKED_PROFILE_STATUSES = ("suspended", "fake", "deceased")
            base = (
                User.objects.select_related("profile")
                .filter(is_active=True, is_staff=False)
                .exclude(id=me.id)
                .exclude(profile__profile_status__in=BLOCKED_PROFILE_STATUSES)
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

            # Newest-ish first (fallback to id)
            base = base.order_by("-id")

            # Handle pagination vs legacy mode
            if has_page_param:
                try:
                    page = max(1, int(request.query_params.get("page", 1)))
                    page_size = int(request.query_params.get("page_size", 10))
                except ValueError:
                    page = 1
                    page_size = 10
                page_size = max(1, min(page_size, 50))

                offset = (page - 1) * page_size
                # Fetch one extra to determine has_next
                results = list(base[offset : offset + page_size + 1])
                has_next = len(results) > page_size
                results = results[:page_size]

                # Get friendship statuses for this page's users
                user_ids = [u.id for u in results]
                statuses = self._get_user_statuses(me, user_ids)

                data = [
                    {
                        "id": u.id,
                        "name": _name(u),
                        "avatar": _avatar(u),
                        "mutuals": 0,
                        "kyc_status": _kyc_status(u),
                        "friend_status": statuses.get(u.id, {}).get("status", "none"),
                        "request_id": statuses.get(u.id, {}).get("request_id", None),
                    }
                    for u in results
                ]

                return Response({
                    "results": data,
                    "page": page,
                    "page_size": page_size,
                    "has_next": has_next,
                    "next": page + 1 if has_next else None,
                })
            else:
                # Legacy: limit mode
                try:
                    limit = int(request.query_params.get("limit", 12))
                except ValueError:
                    limit = 12
                limit = max(1, min(limit, 50))

                results = list(base[:limit])

                # Get friendship statuses for these users
                user_ids = [u.id for u in results]
                statuses = self._get_user_statuses(me, user_ids)

                data = [
                    {
                        "id": u.id,
                        "name": _name(u),
                        "avatar": _avatar(u),
                        "mutuals": 0,
                        "kyc_status": _kyc_status(u),
                        "friend_status": statuses.get(u.id, {}).get("status", "none"),
                        "request_id": statuses.get(u.id, {}).get("request_id", None),
                    }
                    for u in results
                ]
                return Response(data)

        # 2) users who are connected to any of my friends (FoF)
        BLOCKED_PROFILE_STATUSES = ("suspended", "fake", "deceased")
        qs = (
            User.objects.select_related("profile")
            .filter(
                Q(friends_as_user1__user2_id__in=my_ids) |
                Q(friends_as_user2__user1_id__in=my_ids)
            )
            .exclude(id=me.id)
            .exclude(id__in=my_ids)
            .exclude(profile__profile_status__in=BLOCKED_PROFILE_STATUSES)
            .distinct()
        )

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

        # 5) pagination vs legacy
        if has_page_param:
            try:
                page = max(1, int(request.query_params.get("page", 1)))
                page_size = int(request.query_params.get("page_size", 10))
            except ValueError:
                page = 1
                page_size = 10
            page_size = max(1, min(page_size, 50))

            offset = (page - 1) * page_size
            # Fetch one extra to determine has_next
            results = list(qs[offset : offset + page_size + 1])
            has_next = len(results) > page_size
            results = results[:page_size]

            # Get friendship statuses for this page's users
            user_ids = [u.id for u in results]
            statuses = self._get_user_statuses(me, user_ids)

            data = [
                {
                    "id": u.id,
                    "name": _name(u),
                    "avatar": _avatar(u),
                    "mutuals": int(getattr(u, "mutuals", 0)),
                    "kyc_status": _kyc_status(u),
                    "friend_status": statuses.get(u.id, {}).get("status", "none"),
                    "request_id": statuses.get(u.id, {}).get("request_id", None),
                }
                for u in results
            ]

            return Response({
                "results": data,
                "page": page,
                "page_size": page_size,
                "has_next": has_next,
                "next": page + 1 if has_next else None,
            })
        else:
            # Legacy: limit mode
            try:
                limit = int(request.query_params.get("limit", 12))
            except ValueError:
                limit = 12
            limit = max(1, min(limit, 50))

            results = list(qs[:limit])

            # Get friendship statuses for these users
            user_ids = [u.id for u in results]
            statuses = self._get_user_statuses(me, user_ids)

            data = [
                {
                    "id": u.id,
                    "name": _name(u),
                    "avatar": _avatar(u),
                    "mutuals": int(getattr(u, "mutuals", 0)),
                    "kyc_status": _kyc_status(u),
                    "friend_status": statuses.get(u.id, {}).get("status", "none"),
                    "request_id": statuses.get(u.id, {}).get("request_id", None),
                }
                for u in results
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
        other_user = get_object_or_404(User.objects.select_related("profile"), id=other_id)
        if me.id != other_id and getattr(getattr(other_user, "profile", None), "connections_hidden", False) and not _viewer_can_manage_hidden_connections(me):
            return Response([])
        if not _can_view_connections_list(me, other_user):
            return Response([])
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
        if not _viewer_can_manage_hidden_connections(me):
            users = users.exclude(profile__hide_from_others_connections=True).exclude(id=me.id)
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

    @action(detail=False, methods=["get"], url_path="status-bulk")
    def status_bulk(self, request):
        """Bulk endpoint to get relationship status for multiple users.
        GET /api/friends/status-bulk/?user_ids=1,2,3,4
        Returns: {
            "results": {
                "1": {"status": "friends", "request_id": null},
                "2": {"status": "outgoing_pending", "request_id": 55},
                ...
            }
        }
        """
        user_ids_raw = request.query_params.get("user_ids", "")
        if not user_ids_raw:
            return Response({"results": {}}, status=200)

        # Parse comma-separated user IDs
        try:
            user_ids = [int(uid.strip()) for uid in user_ids_raw.split(",") if uid.strip().isdigit()]
        except (ValueError, TypeError):
            return Response({"detail": "user_ids must be comma-separated integers"}, status=400)

        if not user_ids:
            return Response({"results": {}}, status=200)

        me = request.user

        # Use helper to get statuses
        results = self._get_user_statuses(me, user_ids)

        # Convert int keys to string keys for JSON response
        results = {str(k): v for k, v in results.items()}

        return Response({"results": results}, status=200)


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

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        fr = serializer.save()
        
        # Return enriched response
        full_ser = FriendRequestSerializer(fr)
        data = full_ser.data
        data.update({
            "status": "outgoing_pending",
            "request_id": fr.id
        })
        return Response(data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["get"], url_path="quota")
    def quota(self, request):
        """
        Return the user's current contact request quota status.
        """
        me = request.user

        WINDOW_DAYS = int(getattr(settings, "FRIEND_REQUEST_WINDOW_DAYS", 30))
        LIMIT_FREE = int(getattr(settings, "FRIEND_REQUEST_LIMIT_FREE", 30))
        LIMIT_PAID = int(getattr(settings, "FRIEND_REQUEST_LIMIT_PAID", 200))

        cutoff = timezone.now() - timedelta(days=WINDOW_DAYS)
        
        # Determine if user is a paid member (KYC Verified)
        is_paid = getattr(me, "profile", None) and me.profile.kyc_status == "approved"

        limit = LIMIT_PAID if is_paid else LIMIT_FREE
        
        if me.is_staff or me.is_superuser:
            return Response({
                "window_days": WINDOW_DAYS,
                "limit": None,
                "used": 0,
                "remaining": None,
                "is_paid_member": is_paid,
                "is_staff": True
            })

        used = FriendRequest.objects.filter(from_user=me, created_at__gte=cutoff).count()
        remaining = max(0, limit - used)

        return Response({
            "window_days": WINDOW_DAYS,
            "limit": limit,
            "used": used,
            "remaining": remaining,
            "is_paid_member": is_paid
        })

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
        if _is_guest_user(me):
            return Notification.objects.none()
        qs = Notification.objects.filter(recipient=me).order_by("-created_at")
        kind = self.request.query_params.get("kind")
        unread = self.request.query_params.get("unread")
        if kind:
            qs = qs.filter(kind=kind)
        if unread in {"1", "true", "True"}:
            qs = qs.filter(is_read=False)
        return qs

    def list(self, request, *args, **kwargs):
        #  Cache unread notification count with 20 second TTL
        unread = request.query_params.get("unread")
        if unread in {"1", "true", "True"}:
            cache_key = f"user:{request.user.id}:notifications:unread:count"
            cached_count = cache.get(cache_key)
            if cached_count is not None:
                logger.debug(f"[NotificationViewSet.list] Cache hit for unread count, user={request.user.id}")
                # Return cached count in response
                return Response({
                    "count": cached_count,
                    "results": [],
                    "next": None,
                    "previous": None
                })

        response = super().list(request, *args, **kwargs)

        # Cache unread count if this was an unread-only query
        if unread in {"1", "true", "True"} and response.status_code == 200 and hasattr(response, 'data'):
            unread_count = len(response.data.get('results', []))
            cache_key = f"user:{request.user.id}:notifications:unread:count"
            cache.set(cache_key, unread_count, timeout=20)
            logger.debug(f"[NotificationViewSet.list] Cached unread count={unread_count} for user={request.user.id} (20s TTL)")

        return response

    @action(detail=False, methods=["post"], url_path="mark-read")
    def mark_read(self, request):
        if _is_guest_user(request.user):
            return Response({"ok": True})
        ids = request.data.get("ids", [])
        Notification.objects.filter(recipient=request.user, id__in=ids).update(is_read=True)

        #  Invalidate unread count cache on mark-read
        cache_key = f"user:{request.user.id}:notifications:unread:count"
        cache.delete(cache_key)
        logger.debug(f"[NotificationViewSet] Invalidated unread count cache for user={request.user.id}")

        return Response({"ok": True})
